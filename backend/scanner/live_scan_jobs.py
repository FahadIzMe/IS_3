from datetime import datetime, timezone
from threading import Lock, Thread
from uuid import uuid4

from .services import (
    ScanExecutionError,
    create_nmap_scanner,
    parse_ports,
    resolve_target,
    scan_single_port_with_nmap,
    scan_single_port_with_socket,
)

_job_lock = Lock()
_scan_jobs: dict[str, dict] = {}


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _progress(scanned_ports: int, total_ports: int) -> dict:
    percent = 0.0
    if total_ports > 0:
        percent = round((scanned_ports / total_ports) * 100, 2)

    return {
        "scanned_ports": scanned_ports,
        "total_ports": total_ports,
        "percent": percent,
    }


def _snapshot(job: dict) -> dict:
    return {
        "job_id": job["job_id"],
        "status": job["status"],
        "target": job["target"],
        "resolved_ip": job["resolved_ip"],
        "scan_type": job["scan_type"],
        "engine": job["engine"],
        "port_count": job["port_count"],
        "progress": _progress(job["scanned_ports"], job["port_count"]),
        "results": list(job["results"]),
        "error": job["error"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
    }


def get_scan_job_snapshot(job_id: str) -> dict | None:
    with _job_lock:
        job = _scan_jobs.get(job_id)
        if not job:
            return None
        return _snapshot(job)


def list_scan_job_snapshots() -> list[dict]:
    with _job_lock:
        jobs = [_snapshot(job) for job in _scan_jobs.values()]

    jobs.sort(key=lambda item: item["started_at"], reverse=True)
    return jobs


def create_scan_job(target: str, scan_type: str, port_range: str, timeout: float) -> dict:
    resolved_ip = resolve_target(target)
    ports = parse_ports(port_range)
    requires_nmap = scan_type in {"tcp_syn", "udp"}

    scanner = create_nmap_scanner()
    if requires_nmap and scanner is None:
        raise ScanExecutionError(
            "Nmap executable is required for tcp_syn and udp scans. "
            "Install Nmap and ensure it is on PATH, or use full_connect."
        )

    job_id = uuid4().hex
    job = {
        "job_id": job_id,
        "status": "queued",
        "target": target,
        "resolved_ip": resolved_ip,
        "scan_type": scan_type,
        "engine": "nmap" if scanner is not None else "socket-fallback",
        "port_count": len(ports),
        "scanned_ports": 0,
        "results": [],
        "error": None,
        "started_at": _iso_now(),
        "finished_at": None,
    }

    with _job_lock:
        _scan_jobs[job_id] = job

    worker = Thread(
        target=_run_scan_job,
        args=(job_id, resolved_ip, scan_type, ports, timeout, scanner),
        daemon=True,
    )
    worker.start()

    return _snapshot(job)


def _run_scan_job(
    job_id: str,
    resolved_ip: str,
    scan_type: str,
    ports: list[int],
    timeout: float,
    scanner,
) -> None:
    requires_nmap = scan_type in {"tcp_syn", "udp"}
    using_nmap = scanner is not None
    fallback_used = False

    with _job_lock:
        job = _scan_jobs[job_id]
        job["status"] = "running"
        job["engine"] = "nmap" if using_nmap else "socket-fallback"

    try:
        for index, port in enumerate(ports, start=1):
            scan_result = None

            if using_nmap and scanner is not None:
                nmap_ok, scan_result = scan_single_port_with_nmap(
                    scanner=scanner,
                    target_ip=resolved_ip,
                    port=port,
                    scan_type=scan_type,
                )

                if not nmap_ok:
                    if requires_nmap:
                        raise ScanExecutionError(
                            "Nmap scan failed during execution. "
                            "tcp_syn and udp scans cannot continue without Nmap."
                        )
                    using_nmap = False
                    fallback_used = True

            if not using_nmap:
                scan_result = scan_single_port_with_socket(
                    target_ip=resolved_ip,
                    port=port,
                    scan_type=scan_type,
                    timeout=timeout,
                )

            with _job_lock:
                job = _scan_jobs[job_id]
                if scan_result is not None:
                    job["results"].append(scan_result.to_dict())
                job["scanned_ports"] = index

        with _job_lock:
            job = _scan_jobs[job_id]
            job["status"] = "completed"
            if fallback_used and job["engine"] == "nmap":
                job["engine"] = "nmap+socket-fallback"
            job["finished_at"] = _iso_now()
    except ScanExecutionError as exc:
        with _job_lock:
            job = _scan_jobs[job_id]
            job["status"] = "failed"
            job["error"] = str(exc)
            job["finished_at"] = _iso_now()
    except Exception as exc:
        with _job_lock:
            job = _scan_jobs[job_id]
            job["status"] = "failed"
            job["error"] = f"Unexpected scan failure: {exc}"
            job["finished_at"] = _iso_now()

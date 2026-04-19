import socket
from dataclasses import dataclass
from typing import Iterable

import nmap
from nmap import PortScannerError

from .models import FirewallRule


class ScanExecutionError(Exception):
    pass


@dataclass
class ScanResult:
    ip: str
    port: int
    protocol: str
    service: str
    status: str

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "status": self.status,
        }


def resolve_target(target: str) -> str:
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ScanExecutionError("Could not resolve target hostname/IP.") from exc


def parse_ports(port_range: str) -> list[int]:
    if not port_range:
        return list(range(1, 1025))

    ports: set[int] = set()
    for chunk in port_range.split(","):
        token = chunk.strip()
        if not token:
            continue

        try:
            if "-" in token:
                start_str, end_str = token.split("-", maxsplit=1)
                start = int(start_str)
                end = int(end_str)
                if start < 1 or end > 65535 or start > end:
                    raise ScanExecutionError("Invalid port range.")
                ports.update(range(start, end + 1))
            else:
                port = int(token)
                if port < 1 or port > 65535:
                    raise ScanExecutionError("Port must be between 1 and 65535.")
                ports.add(port)
        except ValueError as exc:
            raise ScanExecutionError("Port range must contain valid integers.") from exc

    if not ports:
        raise ScanExecutionError("No ports parsed from provided range.")

    if len(ports) > 2048:
        raise ScanExecutionError("Please scan 2048 or fewer ports per request.")

    return sorted(ports)


def nmap_arguments(scan_type: str) -> str:
    if scan_type == "tcp_syn":
        return "-sS -Pn -n"
    if scan_type == "udp":
        return "-sU -Pn -n"
    return "-sT -Pn -n"


def create_nmap_scanner() -> nmap.PortScanner | None:
    try:
        return nmap.PortScanner()
    except (PortScannerError, FileNotFoundError):
        return None


def _nmap_service_scan_arguments(protocol: str) -> str:
    if protocol == "udp":
        return "-sU -sV -Pn -n"
    return "-sT -sV -Pn -n"


def _actual_service_from_nmap_details(details: dict) -> str:
    product = str(details.get("product") or "").strip()
    version = str(details.get("version") or "").strip()
    extra_info = str(details.get("extrainfo") or "").strip()
    name = str(details.get("name") or "").strip()
    method = str(details.get("method") or "").strip().lower()

    try:
        confidence = int(details.get("conf", 0))
    except (TypeError, ValueError):
        confidence = 0

    if method != "probed" or confidence < 7:
        return "unknown"

    if product:
        parts = [product]
        if version:
            parts.append(version)
        if extra_info:
            parts.append(f"({extra_info})")
        return " ".join(parts)

    if name:
        return name

    return "unknown"


def _detect_service_with_nmap(
    scanner: nmap.PortScanner,
    target_ip: str,
    port: int,
    protocol: str,
) -> str:
    try:
        scanner.scan(
            hosts=target_ip,
            ports=str(port),
            arguments=_nmap_service_scan_arguments(protocol),
        )
    except (PortScannerError, FileNotFoundError):
        return "unknown"

    for host in scanner.all_hosts():
        host_data = scanner[host]
        if protocol not in host_data.all_protocols():
            continue

        protocol_data = host_data[protocol]
        if port not in protocol_data:
            continue

        return _actual_service_from_nmap_details(protocol_data[port])

    return "unknown"


def scan_single_port_with_socket(
    target_ip: str,
    port: int,
    scan_type: str,
    timeout: float,
) -> ScanResult:
    if scan_type != "full_connect":
        raise ScanExecutionError(
            "Socket fallback only supports full_connect scans. "
            "Use Nmap for tcp_syn and udp scans."
        )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        state = sock.connect_ex((target_ip, port))
        status = "open" if state == 0 else "closed"
    except OSError:
        status = "filtered"
    finally:
        sock.close()

    return ScanResult(
        ip=target_ip,
        port=port,
        protocol="tcp",
        service="unknown",
        status=status,
    )


def scan_single_port_with_nmap(
    scanner: nmap.PortScanner,
    target_ip: str,
    port: int,
    scan_type: str,
) -> tuple[bool, ScanResult | None]:
    base_protocol = "udp" if scan_type == "udp" else "tcp"

    try:
        scanner.scan(
            hosts=target_ip,
            ports=str(port),
            arguments=nmap_arguments(scan_type),
        )
    except (PortScannerError, FileNotFoundError):
        return False, None

    for host in scanner.all_hosts():
        host_data = scanner[host]
        for protocol in host_data.all_protocols():
            protocol_data = host_data[protocol]
            if port not in protocol_data:
                continue

            details = protocol_data[port]
            status = details.get("state", "unknown")
            service = "unknown"
            if status in {"open", "open|filtered"}:
                service = _detect_service_with_nmap(
                    scanner=scanner,
                    target_ip=target_ip,
                    port=port,
                    protocol=protocol,
                )

            return True, ScanResult(
                ip=host,
                port=port,
                protocol=protocol,
                service=service,
                status=status,
            )

    return True, ScanResult(
        ip=target_ip,
        port=port,
        protocol=base_protocol,
        service="unknown",
        status="unknown",
    )


def serialize_firewall_rule(rule: FirewallRule) -> dict:
    return {
        "id": rule.id,
        "action": rule.action,
        "source_ip": rule.source_ip,
        "port": rule.port,
        "protocol": rule.protocol,
        "priority": rule.priority,
        "enabled": rule.enabled,
        "note": rule.note,
        "created_at": rule.created_at,
    }


def _rule_matches(rule: FirewallRule, packet: dict) -> bool:
    ip_match = not rule.source_ip or rule.source_ip == packet["ip"]
    port_match = rule.port is None or rule.port == packet["port"]
    protocol_match = rule.protocol == "any" or rule.protocol == packet["protocol"]
    return ip_match and port_match and protocol_match


def simulate_firewall(traffic: Iterable[dict], rules: Iterable[FirewallRule]) -> dict:
    ordered_rules = list(rules)

    flows = []
    allowed = 0
    blocked = 0

    for packet in traffic:
        packet_status = str(packet.get("status") or "unknown").strip().lower()

        # Only confirmed open ports are evaluated by firewall rules.
        if packet_status != "open":
            blocked += 1
            flows.append(
                {
                    "ip": packet["ip"],
                    "port": packet["port"],
                    "protocol": packet["protocol"],
                    "scan_status": packet_status,
                    "decision": "deny",
                    "matched_rule": None,
                    "rule_trace": [
                        {
                            "rule_id": None,
                            "action": "deny",
                            "priority": None,
                            "matched": True,
                            "reason": f"scan-status-{packet_status}-not-open",
                        }
                    ],
                }
            )
            continue

        decision = "deny"
        matched_rule = None
        trace = []

        for rule in ordered_rules:
            matched = _rule_matches(rule, packet)
            trace.append(
                {
                    "rule_id": rule.id,
                    "action": rule.action,
                    "priority": rule.priority,
                    "matched": matched,
                }
            )

            if matched:
                matched_rule = rule
                decision = rule.action
                break

        if decision == "allow":
            allowed += 1
        else:
            blocked += 1

        flows.append(
            {
                "ip": packet["ip"],
                "port": packet["port"],
                "protocol": packet["protocol"],
                "scan_status": packet_status,
                "decision": decision,
                "matched_rule": serialize_firewall_rule(matched_rule) if matched_rule else None,
                "rule_trace": trace,
            }
        )

    return {
        "summary": {
            "total": len(flows),
            "allowed": allowed,
            "blocked": blocked,
            "default_decision": "deny",
        },
        "flows": flows,
    }

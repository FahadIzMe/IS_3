import ipaddress
import json

from django.http import HttpRequest, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from .live_scan_jobs import create_scan_job, get_scan_job_snapshot, list_scan_job_snapshots
from .models import FirewallRule
from .services import ScanExecutionError, serialize_firewall_rule, simulate_firewall

VALID_SCAN_TYPES = {"tcp_syn", "udp", "full_connect"}
VALID_RULE_ACTIONS = {"allow", "deny"}
VALID_RULE_PROTOCOLS = {"any", "tcp", "udp"}
VALID_PACKET_PROTOCOLS = {"tcp", "udp"}
VALID_PACKET_STATUSES = {"open", "open|filtered", "closed", "filtered", "unknown"}


def _json_error(message: str, status_code: int = 400) -> JsonResponse:
    return JsonResponse({"detail": message}, status=status_code)


def _parse_json(request: HttpRequest) -> tuple[dict | None, JsonResponse | None]:
    try:
        payload = json.loads(request.body.decode("utf-8"))
    except json.JSONDecodeError:
        return None, _json_error("Invalid JSON body.")

    if not isinstance(payload, dict):
        return None, _json_error("JSON body must be an object.")

    return payload, None


def _validate_scan_payload(payload: dict) -> tuple[dict | None, JsonResponse | None]:
    target = str(payload.get("target", "")).strip()
    if not target:
        return None, _json_error("Target IP/hostname is required.")

    scan_type = str(payload.get("scan_type", "")).strip()
    if scan_type not in VALID_SCAN_TYPES:
        return None, _json_error("Scan type must be one of tcp_syn, udp, full_connect.")

    port_range = str(payload.get("port_range", "1-1024")).strip() or "1-1024"

    try:
        timeout = float(payload.get("timeout", 0.2))
    except (TypeError, ValueError):
        return None, _json_error("Timeout must be a valid number.")

    if timeout < 0.05 or timeout > 3.0:
        return None, _json_error("Timeout must be between 0.05 and 3.0 seconds.")

    return {
        "target": target,
        "scan_type": scan_type,
        "port_range": port_range,
        "timeout": timeout,
    }, None


def _validate_firewall_rule_payload(payload: dict) -> tuple[dict | None, JsonResponse | None]:
    action = str(payload.get("action", "")).strip().lower()
    if action not in VALID_RULE_ACTIONS:
        return None, _json_error("Action must be either allow or deny.")

    protocol = str(payload.get("protocol", "any")).strip().lower() or "any"
    if protocol not in VALID_RULE_PROTOCOLS:
        return None, _json_error("Protocol must be any, tcp, or udp.")

    source_ip = payload.get("source_ip")
    if source_ip in ("", None):
        source_ip = None
    else:
        try:
            ipaddress.ip_address(str(source_ip))
            source_ip = str(source_ip)
        except ValueError:
            return None, _json_error("Source IP must be a valid IP address.")

    port = payload.get("port")
    if port in ("", None):
        port = None
    else:
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None, _json_error("Port must be an integer between 1 and 65535.")
        if port < 1 or port > 65535:
            return None, _json_error("Port must be an integer between 1 and 65535.")

    try:
        priority = int(payload.get("priority", 100))
    except (TypeError, ValueError):
        return None, _json_error("Priority must be a non-negative integer.")
    if priority < 0:
        return None, _json_error("Priority must be a non-negative integer.")

    enabled_raw = payload.get("enabled", True)
    if isinstance(enabled_raw, bool):
        enabled = enabled_raw
    elif isinstance(enabled_raw, str):
        normalized = enabled_raw.strip().lower()
        if normalized in {"true", "1", "yes", "y"}:
            enabled = True
        elif normalized in {"false", "0", "no", "n"}:
            enabled = False
        else:
            return None, _json_error("Enabled must be true or false.")
    elif isinstance(enabled_raw, (int, float)):
        enabled = bool(enabled_raw)
    else:
        return None, _json_error("Enabled must be true or false.")

    note = str(payload.get("note", "")).strip()

    return {
        "action": action,
        "source_ip": source_ip,
        "port": port,
        "protocol": protocol,
        "priority": priority,
        "enabled": enabled,
        "note": note,
    }, None


def _validate_traffic_payload(payload: dict) -> tuple[list[dict] | None, JsonResponse | None]:
    traffic = payload.get("traffic")
    if not isinstance(traffic, list):
        return None, _json_error("Traffic must be an array of packets.")

    parsed: list[dict] = []
    for item in traffic:
        if not isinstance(item, dict):
            return None, _json_error("Each traffic item must be an object.")

        ip_value = item.get("ip")
        try:
            ipaddress.ip_address(str(ip_value))
        except ValueError:
            return None, _json_error("Each packet must include a valid IP address.")

        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            return None, _json_error("Each packet must include a valid port.")

        if port < 1 or port > 65535:
            return None, _json_error("Each packet port must be in the range 1-65535.")

        protocol = str(item.get("protocol", "")).strip().lower()
        if protocol not in VALID_PACKET_PROTOCOLS:
            return None, _json_error("Each packet protocol must be tcp or udp.")

        status_raw = item.get("status")
        if status_raw in (None, ""):
            return None, _json_error(
                "Each packet must include scan status: open, open|filtered, closed, filtered, or unknown."
            )

        status = str(status_raw).strip().lower()
        if status not in VALID_PACKET_STATUSES:
            return None, _json_error(
                "Each packet status must be one of open, open|filtered, closed, filtered, unknown."
            )

        packet = {
            "ip": str(ip_value),
            "port": port,
            "protocol": protocol,
            "status": status,
        }

        parsed.append(packet)

    return parsed, None


@require_http_methods(["GET"])
def health(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"status": "ok", "service": "network-security-scanner-api"})


@csrf_exempt
@require_http_methods(["POST"])
def scan_start(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json(request)
    if error:
        return error

    validated, error = _validate_scan_payload(payload)
    if error:
        return error

    try:
        snapshot = create_scan_job(
            target=validated["target"],
            scan_type=validated["scan_type"],
            port_range=validated["port_range"],
            timeout=validated["timeout"],
        )
    except ScanExecutionError as exc:
        return _json_error(str(exc))

    return JsonResponse(snapshot, status=202)


@require_http_methods(["GET"])
def scan_job_status(request: HttpRequest, job_id: str) -> JsonResponse:
    snapshot = get_scan_job_snapshot(job_id)
    if not snapshot:
        return _json_error("Scan job not found.", status_code=404)
    return JsonResponse(snapshot)


@require_http_methods(["GET"])
def scan_job_list(request: HttpRequest) -> JsonResponse:
    return JsonResponse({"jobs": list_scan_job_snapshots()})


@csrf_exempt
@require_http_methods(["GET", "POST"])
def firewall_rules(request: HttpRequest) -> JsonResponse:
    if request.method == "GET":
        rules = FirewallRule.objects.all().order_by("priority", "id")
        return JsonResponse([serialize_firewall_rule(rule) for rule in rules], safe=False)

    payload, error = _parse_json(request)
    if error:
        return error

    validated, error = _validate_firewall_rule_payload(payload)
    if error:
        return error

    rule = FirewallRule.objects.create(**validated)
    return JsonResponse(serialize_firewall_rule(rule), status=201)


@csrf_exempt
@require_http_methods(["DELETE"])
def firewall_rule_delete(request: HttpRequest, pk: int) -> JsonResponse:
    try:
        rule = FirewallRule.objects.get(pk=pk)
    except FirewallRule.DoesNotExist:
        return _json_error("Firewall rule not found.", status_code=404)

    rule.delete()
    return JsonResponse({"detail": "Firewall rule deleted."})


@csrf_exempt
@require_http_methods(["POST"])
def firewall_simulate(request: HttpRequest) -> JsonResponse:
    payload, error = _parse_json(request)
    if error:
        return error

    traffic, error = _validate_traffic_payload(payload)
    if error:
        return error

    rules = FirewallRule.objects.filter(enabled=True).order_by("priority", "id")
    simulation = simulate_firewall(traffic=traffic, rules=rules)
    return JsonResponse(simulation)

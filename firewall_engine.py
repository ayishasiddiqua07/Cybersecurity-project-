"""Educational firewall rule engine. It evaluates event dictionaries; it does not block OS traffic."""
from datetime import datetime, timezone
import ipaddress

VALID_ACTIONS = {"ALLOW", "BLOCK"}
VALID_DIRECTIONS = {"INBOUND", "OUTBOUND", "ANY"}
VALID_PROTOCOLS = {"TCP", "UDP", "ICMP", "ANY"}

def valid_ip_or_any(value):
    value = (value or "ANY").strip()
    if value.upper() == "ANY" or value == "":
        return "ANY"
    # Accept individual IPv4/IPv6 addresses only for this simple demo.
    return str(ipaddress.ip_address(value))

def normalize_rule(rule):
    action = str(rule.get("action", "BLOCK")).upper()
    direction = str(rule.get("direction", "ANY")).upper()
    protocol = str(rule.get("protocol", "ANY")).upper()
    if action not in VALID_ACTIONS:
        raise ValueError("Action must be ALLOW or BLOCK.")
    if direction not in VALID_DIRECTIONS:
        raise ValueError("Direction must be INBOUND, OUTBOUND, or ANY.")
    if protocol not in VALID_PROTOCOLS:
        raise ValueError("Protocol must be TCP, UDP, ICMP, or ANY.")
    port_raw = str(rule.get("port", "ANY")).strip().upper()
    if port_raw == "" or port_raw == "ANY":
        port = "ANY"
    else:
        port = int(port_raw)
        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")
    return {
        "id": str(rule.get("id", "")),
        "name": str(rule.get("name", "Untitled rule")).strip()[:80] or "Untitled rule",
        "action": action,
        "direction": direction,
        "protocol": protocol,
        "ip": valid_ip_or_any(rule.get("ip", "ANY")),
        "port": port,
        "enabled": bool(rule.get("enabled", True)),
    }

def matches(rule, event):
    if not rule.get("enabled", True):
        return False
    if rule["direction"] not in ("ANY", event["direction"]):
        return False
    if rule["protocol"] not in ("ANY", event["protocol"]):
        return False
    if rule["ip"] != "ANY" and rule["ip"] not in (event["src_ip"], event["dst_ip"]):
        return False
    if rule["port"] != "ANY" and int(rule["port"]) not in (event["src_port"], event["dst_port"]):
        return False
    return True

def evaluate_event(event, rules, default_action="ALLOW"):
    """Return a decision and explanation for one normalized event."""
    normalized = {
        "timestamp": event.get("timestamp") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "direction": str(event.get("direction", "OUTBOUND")).upper(),
        "src_ip": valid_ip_or_any(event.get("src_ip", "0.0.0.0")),
        "dst_ip": valid_ip_or_any(event.get("dst_ip", "0.0.0.0")),
        "src_port": int(event.get("src_port", 0)),
        "dst_port": int(event.get("dst_port", 0)),
        "protocol": str(event.get("protocol", "TCP")).upper(),
    }
    if normalized["direction"] not in ("INBOUND", "OUTBOUND"):
        raise ValueError("Direction must be INBOUND or OUTBOUND.")
    if normalized["protocol"] not in ("TCP", "UDP", "ICMP"):
        raise ValueError("Protocol must be TCP, UDP, or ICMP.")
    for key in ("src_port", "dst_port"):
        if not 0 <= normalized[key] <= 65535:
            raise ValueError("Ports must be between 0 and 65535.")
    for raw_rule in rules:
        rule = normalize_rule(raw_rule)
        if matches(rule, normalized):
            normalized.update({"decision": rule["action"], "reason": f'Matched rule: {rule["name"]}', "rule_id": rule["id"]})
            return normalized
    normalized.update({"decision": default_action, "reason": f"No rule matched; default policy is {default_action}", "rule_id": ""})
    return normalized

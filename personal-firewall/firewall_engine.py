import json
import os

DATA_DIR = "data"
RULES_FILE = os.path.join(DATA_DIR, "rules.json")
LOGS_FILE = os.path.join(DATA_DIR, "logs.json")

class FirewallEngine:
def init(self):
os.makedirs(DATA_DIR, exist_ok=True)
self.rules = []
self.logs = []
self.load_data()

def load_data(self):
    try:
        with open(RULES_FILE, "r") as f:
            self.rules = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        self.rules = []

    try:
        with open(LOGS_FILE, "r") as f:
            self.logs = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        self.logs = []

def save_data(self):
    with open(RULES_FILE, "w") as f:
        json.dump(self.rules, f, indent=2)
    with open(LOGS_FILE, "w") as f:
        json.dump(self.logs, f, indent=2)

def add_rule(self, direction, action, ip, port, protocol):
    rule = {
        "direction": direction.upper(),
        "action": action.upper(),
        "ip": ip.strip() or "*",
        "port": port.strip() or "*",
        "protocol": protocol.upper()
    }
    self.rules.append(rule)
    self.save_data()

def test_traffic(self, direction, ip, port, protocol):
    result = "ALLOW"
    reason = "No matching rule; default action is ALLOW."

    for rule in self.rules:
        direction_match = rule["direction"] == direction.upper()
        ip_match = rule["ip"] in ("*", ip)
        port_match = rule["port"] in ("*", str(port))
        protocol_match = rule["protocol"] in ("*", protocol.upper())

        if direction_match and ip_match and port_match and protocol_match:
            result = rule["action"]
            reason = "Matched firewall rule."
            break

    entry = {
        "direction": direction.upper(),
        "ip": ip,
        "port": str(port),
        "protocol": protocol.upper(),
        "result": result,
        "reason": reason
    }
    self.logs.insert(0, entry)
    self.logs = self.logs[:100]
    self.save_data()
    return entry

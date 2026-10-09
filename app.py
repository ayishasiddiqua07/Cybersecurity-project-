from flask import Flask, request, redirect, url_for, render_template, flash
from pathlib import Path
from datetime import datetime, timezone
import json, uuid
from firewall_engine import evaluate_event, normalize_rule

app = Flask(__name__)
app.secret_key = "local-demo-change-me"
DATA = Path(__file__).parent / "data"
DATA.mkdir(exist_ok=True)
RULES_FILE = DATA / "rules.json"
LOG_FILE = DATA / "events.json"

DEFAULT_RULES = [
    {"id":"r1","name":"Block Telnet","action":"BLOCK","direction":"ANY","protocol":"TCP","ip":"ANY","port":23,"enabled":True},
    {"id":"r2","name":"Allow HTTPS","action":"ALLOW","direction":"OUTBOUND","protocol":"TCP","ip":"ANY","port":443,"enabled":True},
    {"id":"r3","name":"Block demo test IP","action":"BLOCK","direction":"ANY","protocol":"ANY","ip":"203.0.113.25","port":"ANY","enabled":True},
]
SAMPLE_EVENTS = [
    {"direction":"OUTBOUND","src_ip":"192.168.1.20","dst_ip":"93.184.216.34","src_port":51422,"dst_port":443,"protocol":"TCP"},
    {"direction":"OUTBOUND","src_ip":"192.168.1.20","dst_ip":"203.0.113.25","src_port":51423,"dst_port":443,"protocol":"TCP"},
    {"direction":"INBOUND","src_ip":"198.51.100.8","dst_ip":"192.168.1.20","src_port":53000,"dst_port":23,"protocol":"TCP"},
    {"direction":"OUTBOUND","src_ip":"192.168.1.20","dst_ip":"8.8.8.8","src_port":53001,"dst_port":53,"protocol":"UDP"},
]

def read_json(path, default):
    if not path.exists():
        write_json(path, default)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return default

def write_json(path, value):
    path.write_text(json.dumps(value, indent=2), encoding="utf-8")

def get_rules():
    return read_json(RULES_FILE, DEFAULT_RULES)

def get_events():
    return read_json(LOG_FILE, [])

@app.route("/")
def index():
    rules, events = get_rules(), get_events()
    return render_template("index.html", rules=rules, events=events[:100],
        allowed=sum(e.get("decision") == "ALLOW" for e in events),
        blocked=sum(e.get("decision") == "BLOCK" for e in events))

@app.post("/rules/add")
def add_rule():
    try:
        raw = {
            "id": uuid.uuid4().hex[:8], "name": request.form.get("name", ""),
            "action": request.form.get("action", "BLOCK"),
            "direction": request.form.get("direction", "ANY"),
            "protocol": request.form.get("protocol", "ANY"),
            "ip": request.form.get("ip", "ANY") or "ANY",
            "port": request.form.get("port", "ANY") or "ANY", "enabled": True,
        }
        rule = normalize_rule(raw)
        rules = get_rules()
        rules.append(rule)
        write_json(RULES_FILE, rules)
        flash("Rule added successfully.", "success")
    except (ValueError, TypeError) as exc:
        flash(f"Could not add rule: {exc}", "error")
    return redirect(url_for("index"))

@app.post("/rules/delete/<rule_id>")
def delete_rule(rule_id):
    write_json(RULES_FILE, [r for r in get_rules() if r.get("id") != rule_id])
    flash("Rule removed.", "success")
    return redirect(url_for("index"))

@app.post("/demo")
def demo():
    rules, events = get_rules(), get_events()
    for sample in SAMPLE_EVENTS:
        result = evaluate_event(sample, rules)
        events.insert(0, result)
    write_json(LOG_FILE, events[:500])
    flash("Four demonstration events evaluated. No real traffic was changed.", "success")
    return redirect(url_for("index"))

@app.post("/clear")
def clear():
    write_json(LOG_FILE, [])
    flash("Event log cleared.", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    # Bind to localhost only; this dashboard is intended for local use.
    app.run(host="127.0.0.1", port=5000, debug=False)

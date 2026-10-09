# Personal Firewall Simulator

A beginner-friendly Python project that demonstrates how personal firewall rules can allow or block network events. It includes a local dashboard, configurable rules, a sample traffic generator, and an event log.

## Features
- Allow or block traffic based on direction (`INBOUND` / `OUTBOUND`)
- Match source IP, destination IP, port, and protocol
- Explain why each event was allowed or blocked
- Add and delete rules from the dashboard
- Load sample events to demonstrate the logic
- Stores rules and logs locally in JSON files

## Tech stack
Python, Flask, HTML/CSS, JSON. This is an educational simulator, not a system-level firewall.

## Run it
```bash
python -m venv .venv
# Windows:
.venv\\Scripts\\activate
# Linux/macOS:
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000` in your browser.

## Rule behavior
Rules are checked in order; the first matching rule decides the action. If no rule matches, the default action is **ALLOW** for easy demonstration. You can change the default in `firewall_engine.py`. A real firewall should use a carefully designed default policy and operating-system enforcement.

## Example
- Block outbound traffic to destination IP `203.0.113.25`
- Block TCP destination port `23`
- Allow outbound HTTPS traffic to port `443`

`203.0.113.0/24` is a documentation-only IP range used in examples.

## Limitations
This application does not capture raw packets, install drivers, change Windows Firewall, or update Linux `iptables`. The dashboard processes demonstration events only. Do not present it as a production firewall.

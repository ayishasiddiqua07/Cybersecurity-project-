#!/usr/bin/env python3
"""Offline network traffic summary and simple explainable anomaly heuristics."""
import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

SUSPICIOUS_PORTS = {23: "Telnet", 2323: "Alternate Telnet", 4444: "Common lab/backdoor-associated port", 1337: "Unusual/custom service port"}

def load_csv(path):
    rows = []
    required = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol"}
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = required - set(reader.fieldnames or [])
        if missing:
            raise ValueError("CSV is missing columns: " + ", ".join(sorted(missing)))
        for row in reader:
            rows.append({
                "timestamp": row.get("timestamp", ""),
                "src_ip": row["src_ip"].strip(),
                "dst_ip": row["dst_ip"].strip(),
                "src_port": int(row["src_port"] or 0),
                "dst_port": int(row["dst_port"] or 0),
                "protocol": row["protocol"].strip().upper() or "UNKNOWN",
            })
    return rows

def load_pcap(path):
    try:
        from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP
    except ImportError as exc:
        raise RuntimeError("Scapy is required for PCAP input. Install it with: pip install -r requirements.txt") from exc
    packets = rdpcap(str(path))
    rows = []
    for pkt in packets:
        ip_layer = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip_layer is None:
            continue
        proto = "OTHER"
        sport = dport = 0
        if pkt.haslayer(TCP):
            proto, sport, dport = "TCP", int(pkt[TCP].sport), int(pkt[TCP].dport)
        elif pkt.haslayer(UDP):
            proto, sport, dport = "UDP", int(pkt[UDP].sport), int(pkt[UDP].dport)
        elif pkt.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = str(getattr(ip_layer, "proto", "OTHER"))
        try:
            ts = datetime.fromtimestamp(float(pkt.time), timezone.utc).isoformat(timespec="seconds")
        except (ValueError, TypeError, OSError):
            ts = ""
        rows.append({"timestamp": ts, "src_ip": ip_layer.src, "dst_ip": ip_layer.dst,
                     "src_port": sport, "dst_port": dport, "protocol": proto})
    return rows

def analyze(rows, scan_threshold=10, burst_threshold=30):
    protocols = Counter()
    sources = Counter()
    destinations = Counter()
    port_targets = defaultdict(set)
    destination_hits = Counter()
    alerts = []
    for row in rows:
        protocol = row["protocol"].upper()
        protocols[protocol] += 1
        sources[row["src_ip"]] += 1
        destinations[row["dst_ip"]] += 1
        if row["dst_port"]:
            port_targets[row["src_ip"]].add(row["dst_port"])
            destination_hits[(row["src_ip"], row["dst_ip"], row["dst_port"])] += 1
            if row["dst_port"] in SUSPICIOUS_PORTS:
                alerts.append({"severity":"MEDIUM","type":"SUSPICIOUS_PORT",
                    "message":f'{row["src_ip"]} contacted destination port {row["dst_port"]} ({SUSPICIOUS_PORTS[row["dst_port"]]}); verify whether this is expected.',
                    "src_ip":row["src_ip"],"dst_ip":row["dst_ip"],"port":row["dst_port"]})
    for src, ports in port_targets.items():
        if len(ports) >= scan_threshold:
            alerts.append({"severity":"HIGH","type":"POSSIBLE_PORT_SCAN",
                "message":f"{src} contacted {len(ports)} distinct destination ports; this can indicate scanning, but may also be legitimate testing.",
                "src_ip":src,"distinct_ports":len(ports)})
    for (src, dst, port), count in destination_hits.items():
        if count >= burst_threshold:
            alerts.append({"severity":"MEDIUM","type":"REPEATED_CONNECTIONS",
                "message":f"{src} contacted {dst}:{port} {count} times; inspect timing and application context.",
                "src_ip":src,"dst_ip":dst,"port":port,"count":count})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "packet_records_analyzed": len(rows),
        "protocol_counts": dict(protocols.most_common()),
        "top_source_ips": [{"ip":ip,"records":count} for ip,count in sources.most_common(10)],
        "top_destination_ips": [{"ip":ip,"records":count} for ip,count in destinations.most_common(10)],
        "alerts": alerts,
        "disclaimer": "Heuristic indicators only. Alerts are not proof of compromise; validate with additional evidence."
    }

def main():
    parser = argparse.ArgumentParser(description="Analyze an offline PCAP or CSV packet list.")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", help="Path to authorized .pcap/.pcapng capture")
    source.add_argument("--csv", help="Path to CSV packet records")
    parser.add_argument("--json", dest="json_path", help="Write full report to this JSON file")
    parser.add_argument("--scan-threshold", type=int, default=10, help="Distinct destination ports that trigger a possible-scan alert (default: 10)")
    parser.add_argument("--burst-threshold", type=int, default=30, help="Repeated same source/destination/port records that trigger an alert (default: 30)")
    args = parser.parse_args()
    if args.scan_threshold < 2 or args.burst_threshold < 2:
        parser.error("thresholds must be at least 2")
    rows = load_pcap(args.pcap) if args.pcap else load_csv(args.csv)
    report = analyze(rows, args.scan_threshold, args.burst_threshold)
    output = json.dumps(report, indent=2)
    print(output)
    if args.json_path:
        Path(args.json_path).write_text(output + "\n", encoding="utf-8")
        print(f"\nReport written to {args.json_path}")

if __name__ == "__main__":
    main()

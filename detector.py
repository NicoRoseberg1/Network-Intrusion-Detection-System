"""
Network Intrusion Detection System — Core Engine
Provides multi-vector rule-based intrusion detection and realistic network traffic generation.
"""

from collections import defaultdict
from datetime import datetime, timedelta
import random

try:
    from storage import is_ip_blocked, increment_drop_count, get_custom_rules, upsert_network_asset
except ImportError:
    is_ip_blocked = lambda ip: False
    increment_drop_count = lambda ip: None
    get_custom_rules = lambda: []
    upsert_network_asset = lambda *args, **kwargs: None

def _now(offset_seconds=0):
    t = datetime.now() - timedelta(seconds=offset_seconds)
    return t.strftime("%Y-%m-%d %H:%M:%S")

# Well-known sensitive and high-risk administrative ports
SENSITIVE_PORTS = {
    21: "FTP (File Transfer Protocol) - Unencrypted credentials",
    22: "SSH (Secure Shell) - Remote administrative access",
    23: "Telnet - Legacy unencrypted remote shell",
    25: "SMTP (Mail Server) - Potential relay probing",
    445: "SMB (Server Message Block) - Common target for ransomware / exploits",
    1433: "MSSQL Database Server",
    3306: "MySQL Database Server",
    3389: "RDP (Remote Desktop Protocol) - Remote Windows access",
    5432: "PostgreSQL Database Server",
    8080: "HTTP Alternate / Management Console"
}

def analyze_packets(packets, port_scan_threshold=5, syn_flood_threshold=12, icmp_flood_threshold=10):
    """
    Analyzes packet metadata against defensive rule signatures and active firewall blocklists.
    Returns:
        alerts (list of dicts): Detailed security events detected.
        stats (dict): High-level traffic statistics and protocol distribution.
    """
    stats = {
        "total_packets": len(packets),
        "tcp": 0,
        "udp": 0,
        "icmp": 0,
        "other": 0,
        "total_bytes": 0,
        "unique_sources": 0,
        "unique_destinations": 0,
        "threats_detected": 0,
        "packets_blocked": 0,
        "severities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    }

    if not packets:
        return [], stats

    alerts = []
    
    # Aggregation data structures
    ports_per_source = defaultdict(lambda: defaultdict(set)) # src -> dst -> set of ports
    syn_counts = defaultdict(int)                           # (src, dst) -> count
    ack_counts = defaultdict(int)                           # (src, dst) -> count
    icmp_counts = defaultdict(int)                          # (src, dst) -> count
    udp_counts = defaultdict(int)                           # (src, dst) -> count
    stealth_scans = defaultdict(lambda: {"null": 0, "xmas": 0, "fin": 0})
    sensitive_access = defaultdict(list)                    # src -> list of (port, dst)
    custom_rule_hits = defaultdict(int)                     # rule_id -> count
    source_ips = set()
    dest_ips = set()
    blocked_cache = {}

    active_custom_rules = [r for r in get_custom_rules() if r.get("enabled", 1)]

    # Pass 1: Packet inspection, blocklist enforcement, and telemetry aggregation
    for p in packets:
        proto = p.get("protocol", "OTHER").upper()
        stats["total_bytes"] += p.get("length", 64)
        
        src = p.get("src", "Unknown")
        dst = p.get("dst", "Unknown")
        source_ips.add(src)
        dest_ips.add(dst)

        # Active Firewall / IPS Blocklist Check
        if src not in blocked_cache:
            blocked_cache[src] = is_ip_blocked(src)
        if blocked_cache[src]:
            stats["packets_blocked"] += 1
            increment_drop_count(src)
            p["status"] = "BLOCKED (Dropped by Firewall)"
        else:
            p["status"] = "PASSED"

        # Asset inventory registration
        upsert_network_asset(src)
        if dst not in ("Internal Network", "Unknown"):
            upsert_network_asset(dst)

        dst_port = p.get("dst_port")
        flags = str(p.get("flags", "")).upper()

        # Check custom rules
        for crule in active_custom_rules:
            c_proto = crule.get("protocol", "").upper()
            c_port = crule.get("port")
            if (not c_proto or c_proto == proto) and (c_port is None or c_port == dst_port):
                custom_rule_hits[crule["id"]] += 1

        if proto == "TCP":
            stats["tcp"] += 1
            if dst_port is not None:
                ports_per_source[src][dst].add(dst_port)

            is_syn = "S" in flags and "A" not in flags
            is_ack = "A" in flags
            
            if is_syn:
                syn_counts[(src, dst)] += 1
            if is_ack:
                ack_counts[(src, dst)] += 1

            # Stealth Scan Signatures (RFC 793)
            if flags in ("", "0", "NONE"):
                stealth_scans[src]["null"] += 1
            elif "F" in flags and "P" in flags and "U" in flags:
                stealth_scans[src]["xmas"] += 1
            elif flags == "F":
                stealth_scans[src]["fin"] += 1

            # Sensitive port access
            if dst_port in SENSITIVE_PORTS:
                sensitive_access[src].append((dst_port, dst))

        elif proto == "UDP":
            stats["udp"] += 1
            udp_counts[(src, dst)] += 1
            if dst_port is not None:
                ports_per_source[src][dst].add(dst_port)
            if dst_port in SENSITIVE_PORTS:
                sensitive_access[src].append((dst_port, dst))

        elif proto == "ICMP":
            stats["icmp"] += 1
            icmp_counts[(src, dst)] += 1

        else:
            stats["other"] += 1

    # Pass 2: Rule evaluation & Alert synthesis

    # Rule 1: Port Scan Detection (Horizontal & Vertical)
    for src, dst_map in ports_per_source.items():
        for dst, ports in dst_map.items():
            if len(ports) >= port_scan_threshold:
                port_preview = ", ".join(str(pt) for pt in sorted(list(ports))[:6])
                if len(ports) > 6:
                    port_preview += f" ... (+{len(ports)-6} more)"
                alerts.append({
                    "time": _now(),
                    "severity": "HIGH",
                    "type": "Port Scan Reconnaissance",
                    "source": src,
                    "destination": dst,
                    "protocol": "TCP/UDP",
                    "mitre": "T1046 (Network Service Discovery)",
                    "details": f"Source scanned {len(ports)} distinct destination ports on target {dst} (Ports: {port_preview}).",
                    "mitigation": f"iptables -A INPUT -s {src} -p tcp --dport 1:65535 -m state --state NEW -m recent --set --name PORTSCAN && iptables -A INPUT -s {src} -m recent --update --seconds 300 --hitcount {port_scan_threshold} -j DROP"
                })

    # Rule 2: Stealth Scans (NULL, XMAS, FIN)
    for src, counts in stealth_scans.items():
        if counts["xmas"] > 0:
            alerts.append({
                "time": _now(),
                "severity": "CRITICAL",
                "type": "Stealth XMAS Scan",
                "source": src,
                "destination": "Internal Network",
                "protocol": "TCP",
                "mitre": "T1046 (Stealth Network Scanning)",
                "details": f"Detected {counts['xmas']} TCP packets with FIN+PSH+URG flags set. Used to bypass stateless firewalls and fingerprint OS.",
                "mitigation": f"iptables -A INPUT -s {src} -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP"
            })
        if counts["null"] > 0:
            alerts.append({
                "time": _now(),
                "severity": "CRITICAL",
                "type": "Stealth NULL Scan",
                "source": src,
                "destination": "Internal Network",
                "protocol": "TCP",
                "mitre": "T1046 (Stealth Network Scanning)",
                "details": f"Detected {counts['null']} TCP packets with zero flags set. Violates RFC 793 state machine to evade simple packet filters.",
                "mitigation": f"iptables -A INPUT -s {src} -p tcp --tcp-flags ALL NONE -j DROP"
            })
        if counts["fin"] > 0:
            alerts.append({
                "time": _now(),
                "severity": "HIGH",
                "type": "Stealth FIN Scan",
                "source": src,
                "destination": "Internal Network",
                "protocol": "TCP",
                "mitre": "T1046 (Stealth Network Scanning)",
                "details": f"Detected {counts['fin']} unsolicited TCP FIN packets without prior handshake.",
                "mitigation": f"iptables -A INPUT -s {src} -p tcp --tcp-flags ALL FIN -j DROP"
            })

    # Rule 3: TCP SYN Flood / DoS
    for (src, dst), syn_cnt in syn_counts.items():
        ack_cnt = ack_counts.get((src, dst), 0)
        if syn_cnt >= syn_flood_threshold and (syn_cnt > ack_cnt * 3):
            alerts.append({
                "time": _now(),
                "severity": "CRITICAL",
                "type": "TCP SYN Flood (DoS Attack)",
                "source": src,
                "destination": dst,
                "protocol": "TCP",
                "mitre": "T1498.001 (Direct Network Flood)",
                "details": f"High volume of half-open TCP connections: {syn_cnt} SYN packets vs {ack_cnt} ACK responses towards {dst}.",
                "mitigation": f"sysctl -w net.ipv4.tcp_syncookies=1; iptables -A INPUT -p tcp --syn -s {src} -m limit --limit 5/s --limit-burst 10 -j ACCEPT; iptables -A INPUT -p tcp --syn -s {src} -j DROP"
            })

    # Rule 4: ICMP Echo / Ping Flood
    for (src, dst), icmp_cnt in icmp_counts.items():
        if icmp_cnt >= icmp_flood_threshold:
            alerts.append({
                "time": _now(),
                "severity": "HIGH",
                "type": "ICMP Ping Flood (DoS)",
                "source": src,
                "destination": dst,
                "protocol": "ICMP",
                "mitre": "T1498 (Denial of Service - ICMP Flood)",
                "details": f"Excessive ICMP Echo requests detected ({icmp_cnt} packets) targeting {dst}.",
                "mitigation": f"iptables -A INPUT -p icmp --icmp-type echo-request -s {src} -m limit --limit 1/s -j ACCEPT; iptables -A INPUT -p icmp --icmp-type echo-request -s {src} -j DROP"
            })

    # Rule 5: UDP Flood Anomaly
    for (src, dst), udp_cnt in udp_counts.items():
        if udp_cnt >= 25:
            alerts.append({
                "time": _now(),
                "severity": "MEDIUM",
                "type": "UDP Flood Anomaly",
                "source": src,
                "destination": dst,
                "protocol": "UDP",
                "mitre": "T1498.001 (UDP Amplification/Flood)",
                "details": f"Unusually high volume of UDP packets ({udp_cnt} packets) observed from {src} to {dst}.",
                "mitigation": f"iptables -A INPUT -p udp -s {src} -m limit --limit 10/s -j ACCEPT"
            })

    # Rule 6: Sensitive / Administrative Port Probing
    for src, hits in sensitive_access.items():
        if len(hits) >= 3:
            unique_targets = list({f"{p} ({SENSITIVE_PORTS.get(p, 'Custom').split(' - ')[0]})" for p, d in hits})
            alerts.append({
                "time": _now(),
                "severity": "HIGH",
                "type": "Sensitive Service Reconnaissance",
                "source": src,
                "destination": hits[0][1],
                "protocol": "TCP",
                "mitre": "T1021 (Remote Services / Brute Force Prep)",
                "details": f"Repeated connection attempts to privileged services: {', '.join(unique_targets[:4])}.",
                "mitigation": f"fail2ban-client set sshd banip {src} && ufw deny from {src} to any port 22,23,445,3389"
            })

    # Custom Rules Evaluation
    for crule in active_custom_rules:
        hits = custom_rule_hits.get(crule["id"], 0)
        thresh = crule.get("threshold", 5)
        if hits >= thresh:
            alerts.append({
                "time": _now(),
                "severity": crule.get("severity", "MEDIUM"),
                "type": f"Custom Rule Policy: {crule['name']}",
                "source": "Multiple / Internal",
                "destination": f"Port {crule.get('port') or 'Any'}",
                "protocol": crule.get("protocol", "ANY"),
                "mitre": "Custom Policy Heuristic",
                "details": f"Triggered by user-defined security rule '{crule['name']}' ({hits} packet hits >= threshold {thresh}). Action: {crule.get('action')}.",
                "mitigation": f"Active policy enforcement: {crule.get('action')} traffic on port {crule.get('port') or 'all'}."
            })

    # Compute statistics summary & update host risk scores
    stats["unique_sources"] = len(source_ips)
    stats["unique_destinations"] = len(dest_ips)
    stats["threats_detected"] = len(alerts)
    for a in alerts:
        sev = a.get("severity", "MEDIUM")
        if sev in stats["severities"]:
            stats["severities"][sev] += 1
        # Penalize attacker IP risk score in asset directory
        src_ip = a.get("source")
        if src_ip and src_ip not in ("Multiple / Internal", "Unknown"):
            score_delta = 35 if sev == "CRITICAL" else (20 if sev == "HIGH" else 10)
            upsert_network_asset(src_ip, role="Suspected Attacker", risk_score_delta=score_delta)

    return alerts, stats

def demo_packets(scenario="all", n=150):
    """
    Generates realistic, synthetic network packets for demonstration and viva presentation.
    Scenarios:
        - "all": Comprehensive realistic corporate traffic with multiple active attacks
        - "syn_flood": TCP SYN Flood denial-of-service attack
        - "stealth_scan": RFC-violating stealth scans (NULL, XMAS, FIN)
        - "port_scan": Horizontal and vertical TCP port scan
        - "icmp_flood": Volumetric ICMP ping flood
        - "sensitive_ports": Probing critical administrative services (SSH, Telnet, RDP)
        - "benign": Clean, normal corporate network traffic (0 false positives)
    """
    packets = []
    normal_internal_ips = ["192.168.1.15", "192.168.1.25", "192.168.1.42", "192.168.1.50"]
    servers = {
        "web": "192.168.1.100",
        "dns": "192.168.1.1",
        "db": "192.168.1.200",
        "router": "192.168.1.254"
    }

    def make_benign(count):
        pkts = []
        for i in range(count):
            src = random.choice(normal_internal_ips)
            t_offset = random.randint(1, 120)
            traffic_type = random.choice(["web_https", "web_http", "dns", "internal_api"])
            
            if traffic_type == "web_https":
                pkts.append({
                    "timestamp": _now(t_offset),
                    "src": src,
                    "dst": random.choice(["142.250.190.46", "104.244.42.1", servers["web"]]),
                    "protocol": "TCP",
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 443,
                    "flags": random.choice(["PA", "A", "SA", "FA"]),
                    "length": random.randint(64, 1460),
                    "summary": "HTTPS TLS Application Data"
                })
            elif traffic_type == "web_http":
                pkts.append({
                    "timestamp": _now(t_offset),
                    "src": src,
                    "dst": servers["web"],
                    "protocol": "TCP",
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 80,
                    "flags": random.choice(["PA", "A"]),
                    "length": random.randint(128, 900),
                    "summary": "HTTP GET /index.html"
                })
            elif traffic_type == "dns":
                pkts.append({
                    "timestamp": _now(t_offset),
                    "src": src,
                    "dst": servers["dns"],
                    "protocol": "UDP",
                    "src_port": random.randint(49152, 65535),
                    "dst_port": 53,
                    "flags": "",
                    "length": random.randint(60, 120),
                    "summary": "DNS Standard Query A google.com"
                })
            else:
                pkts.append({
                    "timestamp": _now(t_offset),
                    "src": src,
                    "dst": servers["router"],
                    "protocol": "ICMP",
                    "src_port": None,
                    "dst_port": None,
                    "flags": "",
                    "length": 64,
                    "summary": "ICMP Echo (Ping) Request"
                })
        return pkts

    if scenario == "benign":
        return make_benign(n)

    if scenario == "syn_flood":
        packets.extend(make_benign(max(20, n // 5)))
        attacker = "198.51.100.44"
        victim = servers["web"]
        for _ in range(n - len(packets)):
            packets.append({
                "timestamp": _now(random.randint(1, 15)),
                "src": attacker,
                "dst": victim,
                "protocol": "TCP",
                "src_port": random.randint(1024, 65535),
                "dst_port": random.choice([80, 443]),
                "flags": "S",
                "length": 60,
                "summary": "TCP SYN Half-Open Connection Request"
            })
        random.shuffle(packets)
        return packets

    if scenario == "stealth_scan":
        packets.extend(make_benign(max(20, n // 5)))
        attacker = "172.16.50.99"
        victim = servers["db"]
        ports = [21, 22, 23, 25, 80, 443, 1433, 3306, 3389, 8080]
        for p in ports[:4]:
            packets.append({
                "timestamp": _now(random.randint(1, 30)),
                "src": attacker, "dst": victim, "protocol": "TCP",
                "src_port": 55123, "dst_port": p, "flags": "",
                "length": 40, "summary": "TCP Stealth NULL Scan (Zero flags)"
            })
        for p in ports[4:8]:
            packets.append({
                "timestamp": _now(random.randint(1, 30)),
                "src": attacker, "dst": victim, "protocol": "TCP",
                "src_port": 55124, "dst_port": p, "flags": "FPU",
                "length": 40, "summary": "TCP Stealth XMAS Scan (FIN+PSH+URG)"
            })
        for p in ports[8:]:
            packets.append({
                "timestamp": _now(random.randint(1, 30)),
                "src": attacker, "dst": victim, "protocol": "TCP",
                "src_port": 55125, "dst_port": p, "flags": "F",
                "length": 40, "summary": "TCP Stealth FIN Scan"
            })
        random.shuffle(packets)
        return packets

    if scenario == "port_scan":
        packets.extend(make_benign(max(20, n // 5)))
        scanner = "192.168.1.77"
        victim = servers["web"]
        scan_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 3306, 3389, 8080]
        for port in scan_ports:
            packets.append({
                "timestamp": _now(random.randint(1, 45)),
                "src": scanner, "dst": victim, "protocol": "TCP",
                "src_port": random.randint(40000, 50000), "dst_port": port, "flags": "S",
                "length": 60, "summary": f"TCP Port Probe on port {port}"
            })
        random.shuffle(packets)
        return packets

    if scenario == "icmp_flood":
        packets.extend(make_benign(max(20, n // 5)))
        flooder = "203.0.113.88"
        victim = servers["router"]
        for _ in range(n - len(packets)):
            packets.append({
                "timestamp": _now(random.randint(1, 10)),
                "src": flooder, "dst": victim, "protocol": "ICMP",
                "src_port": None, "dst_port": None, "flags": "",
                "length": 84, "summary": "ICMP Echo Request Flood"
            })
        random.shuffle(packets)
        return packets

    if scenario == "sensitive_ports":
        packets.extend(make_benign(max(20, n // 5)))
        prober = "198.51.100.200"
        victim = servers["db"]
        for port in [21, 22, 23, 445, 3389, 3306]:
            for _ in range(3):
                packets.append({
                    "timestamp": _now(random.randint(1, 40)),
                    "src": prober, "dst": victim, "protocol": "TCP",
                    "src_port": random.randint(30000, 60000), "dst_port": port, "flags": "S",
                    "length": 60, "summary": f"Probing privileged service port {port}"
                })
        random.shuffle(packets)
        return packets

    # Scenario: "all" (Comprehensive presentation showcase)
    benign_count = max(40, int(n * 0.45))
    packets.extend(make_benign(benign_count))

    scanner_ip = "192.168.1.99"
    for port in [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 8080]:
        packets.append({
            "timestamp": _now(random.randint(5, 45)),
            "src": scanner_ip, "dst": servers["web"], "protocol": "TCP",
            "src_port": random.randint(40000, 60000), "dst_port": port, "flags": "S",
            "length": 60, "summary": f"Reconnaissance probe port {port}"
        })

    syn_flooder = "10.0.0.88"
    for _ in range(25):
        packets.append({
            "timestamp": _now(random.randint(1, 15)),
            "src": syn_flooder, "dst": servers["web"], "protocol": "TCP",
            "src_port": random.randint(1024, 65535), "dst_port": 80, "flags": "S",
            "length": 60, "summary": "Rapid SYN packet (DoS attempt)"
        })

    stealth_ip = "172.16.0.45"
    for p in [22, 80, 443]:
        packets.append({
            "timestamp": _now(random.randint(1, 30)),
            "src": stealth_ip, "dst": servers["db"], "protocol": "TCP",
            "src_port": 54321, "dst_port": p, "flags": "FPU",
            "length": 40, "summary": "XMAS Scan packet"
        })
        packets.append({
            "timestamp": _now(random.randint(1, 30)),
            "src": stealth_ip, "dst": servers["db"], "protocol": "TCP",
            "src_port": 54322, "dst_port": p, "flags": "",
            "length": 40, "summary": "NULL Scan packet"
        })

    icmp_ip = "192.168.1.150"
    for _ in range(15):
        packets.append({
            "timestamp": _now(random.randint(1, 10)),
            "src": icmp_ip, "dst": servers["router"], "protocol": "ICMP",
            "src_port": None, "dst_port": None, "flags": "",
            "length": 84, "summary": "High-frequency ICMP Echo ping"
        })

    admin_prober = "185.220.101.5"
    for p in [22, 23, 3389]:
        for _ in range(2):
            packets.append({
                "timestamp": _now(random.randint(1, 50)),
                "src": admin_prober, "dst": servers["db"], "protocol": "TCP",
                "src_port": random.randint(40000, 60000), "dst_port": p, "flags": "S",
                "length": 60, "summary": f"Admin service probe port {p}"
            })

    random.shuffle(packets)
    return packets

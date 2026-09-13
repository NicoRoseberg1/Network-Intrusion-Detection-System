import sqlite3
import json
import csv
import io
from pathlib import Path
from datetime import datetime

DB = Path(__file__).parent / "data" / "alerts.db"

def init_db():
    DB.parent.mkdir(exist_ok=True)
    with sqlite3.connect(DB) as con:
        # Alerts Table
        con.execute("""CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            time TEXT,
            severity TEXT,
            type TEXT,
            source TEXT,
            destination TEXT DEFAULT 'N/A',
            protocol TEXT DEFAULT 'TCP',
            details TEXT,
            mitigation TEXT DEFAULT 'N/A',
            mitre TEXT DEFAULT 'N/A')""")
        
        # Schema migration check for older alerts instances
        cur = con.execute("PRAGMA table_info(alerts)")
        existing_cols = [row[1] for row in cur.fetchall()]
        needed_cols = {
            "destination": "TEXT DEFAULT 'N/A'",
            "protocol": "TEXT DEFAULT 'TCP'",
            "mitigation": "TEXT DEFAULT 'N/A'",
            "mitre": "TEXT DEFAULT 'N/A'"
        }
        for col, col_def in needed_cols.items():
            if col not in existing_cols:
                try: con.execute(f"ALTER TABLE alerts ADD COLUMN {col} {col_def}")
                except Exception: pass

        # Active Firewall IP Blocklist (IPS Capability)
        con.execute("""CREATE TABLE IF NOT EXISTS ip_blocklist(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT UNIQUE,
            reason TEXT,
            created_at TEXT,
            active INTEGER DEFAULT 1,
            drop_count INTEGER DEFAULT 0)""")

        # Custom Detection Rules (Snort / Suricata Policy Engine)
        con.execute("""CREATE TABLE IF NOT EXISTS custom_rules(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            protocol TEXT,
            port INTEGER,
            threshold INTEGER,
            severity TEXT,
            action TEXT,
            enabled INTEGER DEFAULT 1)""")

        # Network Asset & Host Inventory
        con.execute("""CREATE TABLE IF NOT EXISTS network_assets(
            ip TEXT PRIMARY KEY,
            mac TEXT,
            hostname TEXT,
            role TEXT,
            risk_score INTEGER DEFAULT 0,
            packet_count INTEGER DEFAULT 1,
            last_seen TEXT)""")

        # Seed initial enterprise rules if empty
        cur = con.execute("SELECT COUNT(*) FROM custom_rules")
        if cur.fetchone()[0] == 0:
            seed_rules = [
                ("Block Telnet Unencrypted Access", "TCP", 23, 2, "HIGH", "DROP", 1),
                ("Alert SSH Brute Force Burst", "TCP", 22, 5, "CRITICAL", "ALERT", 1),
                ("Database Remote Query Flood", "TCP", 3306, 10, "HIGH", "ALERT", 1),
                ("DNS Query Rate Anomaly", "UDP", 53, 30, "MEDIUM", "ALERT", 1)
            ]
            con.executemany("""INSERT INTO custom_rules(name, protocol, port, threshold, severity, action, enabled)
                               VALUES (?, ?, ?, ?, ?, ?, ?)""", seed_rules)

# ----------------- ALERTS OPERATIONS -----------------
def save_alerts(alerts):
    if not alerts:
        return
    with sqlite3.connect(DB) as con:
        for a in alerts:
            con.execute("""INSERT INTO alerts(time, severity, type, source, destination, protocol, details, mitigation, mitre)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (a.get("time", ""),
                         a.get("severity", "MEDIUM"),
                         a.get("type", "Security Event"),
                         a.get("source", "Unknown"),
                         a.get("destination", "N/A"),
                         a.get("protocol", "TCP"),
                         a.get("details", ""),
                         a.get("mitigation", "N/A"),
                         a.get("mitre", "N/A")))

def load_alerts(limit=200):
    with sqlite3.connect(DB) as con:
        cur = con.execute("""SELECT time, severity, type, source, destination, protocol, details, mitigation, mitre
                             FROM alerts ORDER BY id DESC LIMIT ?""", (limit,))
        cols = ["time", "severity", "type", "source", "destination", "protocol", "details", "mitigation", "mitre"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def clear_alerts():
    with sqlite3.connect(DB) as con:
        con.execute("DELETE FROM alerts")

# ----------------- ACTIVE FIREWALL & BLOCKLIST -----------------
def add_blocked_ip(ip, reason="Manual block via SOC console"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(DB) as con:
        con.execute("""INSERT INTO ip_blocklist(ip, reason, created_at, active, drop_count)
                       VALUES (?, ?, ?, 1, 0)
                       ON CONFLICT(ip) DO UPDATE SET active=1, reason=excluded.reason""", (ip, reason, now))

def remove_blocked_ip(ip):
    with sqlite3.connect(DB) as con:
        con.execute("DELETE FROM ip_blocklist WHERE ip = ?", (ip,))

def get_blocked_ips():
    with sqlite3.connect(DB) as con:
        cur = con.execute("SELECT ip, reason, created_at, active, drop_count FROM ip_blocklist WHERE active=1 ORDER BY id DESC")
        cols = ["ip", "reason", "created_at", "active", "drop_count"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def is_ip_blocked(ip):
    with sqlite3.connect(DB) as con:
        cur = con.execute("SELECT 1 FROM ip_blocklist WHERE ip = ? AND active = 1", (ip,))
        return cur.fetchone() is not None

def increment_drop_count(ip):
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE ip_blocklist SET drop_count = drop_count + 1 WHERE ip = ?", (ip,))

# ----------------- CUSTOM DETECTION RULES -----------------
def get_custom_rules():
    with sqlite3.connect(DB) as con:
        cur = con.execute("SELECT id, name, protocol, port, threshold, severity, action, enabled FROM custom_rules ORDER BY id ASC")
        cols = ["id", "name", "protocol", "port", "threshold", "severity", "action", "enabled"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

def add_custom_rule(name, protocol, port, threshold, severity, action):
    with sqlite3.connect(DB) as con:
        con.execute("""INSERT INTO custom_rules(name, protocol, port, threshold, severity, action, enabled)
                       VALUES (?, ?, ?, ?, ?, ?, 1)""", (name, protocol, port, threshold, severity, action))

def toggle_custom_rule(rule_id):
    with sqlite3.connect(DB) as con:
        con.execute("UPDATE custom_rules SET enabled = CASE WHEN enabled=1 THEN 0 ELSE 1 END WHERE id = ?", (rule_id,))

def delete_custom_rule(rule_id):
    with sqlite3.connect(DB) as con:
        con.execute("DELETE FROM custom_rules WHERE id = ?", (rule_id,))

# ----------------- NETWORK ASSET DISCOVERY -----------------
def upsert_network_asset(ip, mac=None, hostname=None, role=None, risk_score_delta=0):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if not mac:
        # Generate predictable simulated MAC for demo if unknown
        parts = [hex(int(p))[2:].zfill(2) for p in ip.split(".") if p.isdigit()]
        mac = f"52:54:00:{parts[1] if len(parts)>1 else '01'}:{parts[2] if len(parts)>2 else '02'}:{parts[3] if len(parts)>3 else '03'}"
    if not hostname:
        hostname = f"host-{ip.replace('.', '-')}"
    if not role:
        if ip.endswith(".1") or ip.endswith(".254"): role = "Gateway / Router"
        elif ip.endswith(".100"): role = "Core Web Server"
        elif ip.endswith(".200"): role = "Database Server"
        else: role = "Workstation"

    with sqlite3.connect(DB) as con:
        con.execute("""INSERT INTO network_assets(ip, mac, hostname, role, risk_score, packet_count, last_seen)
                       VALUES (?, ?, ?, ?, ?, 1, ?)
                       ON CONFLICT(ip) DO UPDATE SET
                       packet_count = packet_count + 1,
                       risk_score = MIN(100, risk_score + ?),
                       last_seen = excluded.last_seen""",
                    (ip, mac, hostname, role, max(0, risk_score_delta), now, risk_score_delta))

def get_network_assets():
    with sqlite3.connect(DB) as con:
        cur = con.execute("SELECT ip, mac, hostname, role, risk_score, packet_count, last_seen FROM network_assets ORDER BY risk_score DESC, packet_count DESC")
        cols = ["ip", "mac", "hostname", "role", "risk_score", "packet_count", "last_seen"]
        return [dict(zip(cols, row)) for row in cur.fetchall()]

# ----------------- EXPORT ENGINES -----------------
def export_alerts_csv(alerts):
    output = io.StringIO()
    if not alerts: return ""
    fieldnames = ["time", "severity", "type", "source", "destination", "protocol", "mitre", "details", "mitigation"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
    writer.writeheader()
    for row in alerts: writer.writerow(row)
    return output.getvalue()

def export_alerts_json(alerts):
    return json.dumps(alerts, indent=2)

def generate_executive_html_report(stats, alerts, blocked_ips, assets):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_pkts = stats.get('total_packets', len(alerts))
    crit_count = sum(1 for a in alerts if a.get('severity') == 'CRITICAL')
    high_count = sum(1 for a in alerts if a.get('severity') == 'HIGH')
    
    html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Executive Network Security Audit Report</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px; }}
        .container {{ max-width: 960px; margin: 0 auto; background: #1e293b; padding: 40px; border-radius: 12px; border: 1px solid #334155; }}
        h1 {{ color: #38bdf8; border-bottom: 2px solid #334155; padding-bottom: 15px; margin-top: 0; }}
        .kpi-row {{ display: flex; gap: 20px; margin: 25px 0; }}
        .kpi {{ flex: 1; background: #0f172a; padding: 20px; border-radius: 8px; border-left: 4px solid #38bdf8; }}
        .kpi-val {{ font-size: 28px; font-weight: bold; margin-top: 5px; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px 15px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; }}
        .badge {{ padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; }}
        .crit {{ background: #ef4444; color: white; }}
        .high {{ background: #f97316; color: white; }}
        .med {{ background: #eab308; color: black; }}
        code {{ background: #0f172a; padding: 3px 6px; border-radius: 4px; color: #38bdf8; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ Executive Network Security Audit & Incident Report</h1>
        <p><strong>Generated At:</strong> {now} | <strong>System:</strong> Enterprise NIDS & IPS SOC Platform</p>
        
        <div class="kpi-row">
            <div class="kpi" style="border-color: #38bdf8;">
                <div>Total Packets Monitored</div>
                <div class="kpi-val" style="color: #38bdf8;">{total_pkts:,}</div>
            </div>
            <div class="kpi" style="border-color: #ef4444;">
                <div>Threats Detected</div>
                <div class="kpi-val" style="color: #ef4444;">{len(alerts)}</div>
            </div>
            <div class="kpi" style="border-color: #f59e0b;">
                <div>Active Blocked Attackers</div>
                <div class="kpi-val" style="color: #f59e0b;">{len(blocked_ips)}</div>
            </div>
            <div class="kpi" style="border-color: #10b981;">
                <div>Subnet Assets Monitored</div>
                <div class="kpi-val" style="color: #10b981;">{len(assets)}</div>
            </div>
        </div>

        <h2>🚨 Incident Log & Remediation Rules</h2>
        <table>
            <thead>
                <tr>
                    <th>Time</th>
                    <th>Severity</th>
                    <th>Attack Vector</th>
                    <th>Source IP</th>
                    <th>Target IP</th>
                    <th>MITRE ATT&CK</th>
                    <th>Recommended Firewall Defense</th>
                </tr>
            </thead>
            <tbody>"""
    
    for a in alerts[:25]:
        sev = a.get("severity", "MEDIUM")
        b_class = "crit" if sev == "CRITICAL" else ("high" if sev == "HIGH" else "med")
        html += f"""
                <tr>
                    <td>{a.get('time')}</td>
                    <td><span class="badge {b_class}">{sev}</span></td>
                    <td>{a.get('type')}</td>
                    <td><code>{a.get('source')}</code></td>
                    <td><code>{a.get('destination')}</code></td>
                    <td>{a.get('mitre', 'N/A')}</td>
                    <td><code>{a.get('mitigation', 'N/A')[:40]}...</code></td>
                </tr>"""

    html += f"""
            </tbody>
        </table>

        <h2>🚫 Active Firewall Blocklist (IPS Drops)</h2>
        <table>
            <thead>
                <tr>
                    <th>Banned IP Address</th>
                    <th>Reason</th>
                    <th>Banned Timestamp</th>
                    <th>Dropped Packets Counter</th>
                </tr>
            </thead>
            <tbody>"""
    for b in blocked_ips:
        html += f"""
                <tr>
                    <td><code>{b.get('ip')}</code></td>
                    <td>{b.get('reason')}</td>
                    <td>{b.get('created_at')}</td>
                    <td><strong style="color: #ef4444;">{b.get('drop_count', 0)} dropped</strong></td>
                </tr>"""
    html += """
            </tbody>
        </table>

        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #334155; color: #94a3b8; font-size: 13px;">
            Certified Defense Audit generated by Network Intrusion Detection & Telemetry System.
        </div>
    </div>
</body>
</html>"""
    return html



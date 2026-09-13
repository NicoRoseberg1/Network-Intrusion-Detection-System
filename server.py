"""
AegisNIDS — Cyber Security Operations Center (SOC)
Production-grade FastAPI Web Application & RESTful SIEM Engine
"""

import os
import asyncio
from datetime import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel

from detector import analyze_packets, demo_packets
from storage import (
    init_db, save_alerts, load_alerts, clear_alerts,
    get_blocked_ips, add_blocked_ip, remove_blocked_ip,
    get_custom_rules, add_custom_rule, toggle_custom_rule, delete_custom_rule,
    get_network_assets, export_alerts_csv, export_alerts_json,
    generate_executive_html_report
)

# Initialize database schema
init_db()

app = FastAPI(
    title="SecurityShells Security Operations Center API",
    description="Enterprise Network Intrusion Detection System & Autonomous IPS Firewall (https://securityshells.com)",
    version="3.0.0"
)

# In-memory runtime telemetry state
current_packets: List[Dict[str, Any]] = []
current_alerts: List[Dict[str, Any]] = []
current_stats: Dict[str, Any] = {
    "total_packets": 0,
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

# Initial baseline simulation on startup
def run_initial_seed():
    global current_packets, current_alerts, current_stats
    current_packets = demo_packets(scenario="all", n=130)
    current_alerts, current_stats = analyze_packets(current_packets)
    save_alerts(current_alerts)

run_initial_seed()

# Request Models
class SimulationRequest(BaseModel):
    scenario: str = "all"
    count: int = 120

class BlockIPRequest(BaseModel):
    ip: str
    reason: Optional[str] = "Manual administrative block"

class CustomRuleRequest(BaseModel):
    name: str
    protocol: str = "TCP"
    port: Optional[int] = None
    threshold: int = 5
    severity: str = "HIGH"
    action: str = "ALERT"

# ----------------- WEB FRONTEND ROUTE -----------------
@app.get("/", response_class=HTMLResponse, tags=["Dashboard"])
async def get_dashboard():
    index_path = Path(__file__).parent / "templates" / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Template not found")
    return HTMLResponse(content=index_path.read_text(encoding="utf-8"))

# ----------------- REST API ENDPOINTS -----------------
@app.get("/api/stats", tags=["Telemetry"])
async def get_stats():
    return current_stats

@app.get("/api/packets", tags=["Telemetry"])
async def get_packets(limit: int = 100):
    return current_packets[:limit]

@app.get("/api/alerts", tags=["Threat Intelligence"])
async def get_alerts():
    db_alerts = load_alerts(limit=50)
    return current_alerts if current_alerts else db_alerts

@app.post("/api/alerts/clear", tags=["Threat Intelligence"])
async def clear_alert_logs():
    global current_alerts
    current_alerts = []
    clear_alerts()
    return {"status": "success", "message": "Incident logs cleared"}

@app.post("/api/simulate", tags=["Attack Simulation"])
async def simulate_traffic(req: SimulationRequest):
    global current_packets, current_alerts, current_stats
    packets = demo_packets(scenario=req.scenario, n=req.count)
    alerts, stats = analyze_packets(packets)
    save_alerts(alerts)
    current_packets = packets
    current_alerts = alerts
    current_stats = stats
    return {
        "status": "success",
        "scenario": req.scenario,
        "packets_processed": len(packets),
        "threats_detected": len(alerts)
    }

# ----------------- FIREWALL & BLOCKLIST (IPS) -----------------
@app.get("/api/blocklist", tags=["Active Firewall"])
async def list_blocklist():
    return get_blocked_ips()

@app.post("/api/blocklist", tags=["Active Firewall"])
async def block_ip(req: BlockIPRequest):
    add_blocked_ip(req.ip, req.reason or "Manual ban")
    # Re-evaluate current packets against new blocklist
    global current_packets, current_alerts, current_stats
    current_alerts, current_stats = analyze_packets(current_packets)
    return {"status": "success", "ip": req.ip, "action": "BLOCKED"}

@app.delete("/api/blocklist/{ip}", tags=["Active Firewall"])
async def unblock_ip(ip: str):
    remove_blocked_ip(ip)
    return {"status": "success", "ip": ip, "action": "UNBLOCKED"}

# ----------------- CUSTOM RULES (POLICY ENGINE) -----------------
@app.get("/api/rules", tags=["Policy Engine"])
async def list_rules():
    return get_custom_rules()

@app.post("/api/rules", tags=["Policy Engine"])
async def create_rule(req: CustomRuleRequest):
    add_custom_rule(req.name, req.protocol, req.port, req.threshold, req.severity, req.action)
    return {"status": "success", "message": f"Rule '{req.name}' deployed"}

@app.post("/api/rules/{rule_id}/toggle", tags=["Policy Engine"])
async def toggle_rule(rule_id: int):
    toggle_custom_rule(rule_id)
    return {"status": "success", "rule_id": rule_id}

@app.delete("/api/rules/{rule_id}", tags=["Policy Engine"])
async def delete_rule(rule_id: int):
    delete_custom_rule(rule_id)
    return {"status": "success", "rule_id": rule_id}

# ----------------- ASSET INVENTORY -----------------
@app.get("/api/assets", tags=["Network Asset Discovery"])
async def list_assets():
    return get_network_assets()

# ----------------- EXPORT ENGINES -----------------
@app.get("/api/report/html", tags=["Reporting & Compliance"])
async def download_html_report():
    blocked = get_blocked_ips()
    assets = get_network_assets()
    html = generate_executive_html_report(current_stats, current_alerts, blocked, assets)
    return HTMLResponse(content=html)

@app.get("/api/report/csv", tags=["Reporting & Compliance"])
async def download_csv_report():
    alerts = load_alerts(limit=500)
    csv_str = export_alerts_csv(alerts)
    return Response(content=csv_str, media_type="text/csv", headers={"Content-Disposition": "attachment; filename=nids_alerts.csv"})

@app.get("/api/report/json", tags=["Reporting & Compliance"])
async def download_json_report():
    alerts = load_alerts(limit=500)
    json_str = export_alerts_json(alerts)
    return Response(content=json_str, media_type="application/json", headers={"Content-Disposition": "attachment; filename=nids_alerts.json"})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)

import streamlit as st
import pandas as pd
import altair as alt
from datetime import datetime

import importlib
import storage
import detector
import capture
importlib.reload(storage)
importlib.reload(detector)
importlib.reload(capture)

from detector import analyze_packets, demo_packets
from storage import (
    init_db, save_alerts, load_alerts, clear_alerts,
    export_alerts_csv, export_alerts_json, generate_security_audit_report
)
from capture import capture_packets, get_available_interfaces

# Page Configuration
st.set_page_config(
    page_title="Network Intrusion Detection & Monitoring System (NIDS)",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Initialize Database Schema
init_db()

# Custom Styling for Security Operations Center (SOC) Look
st.markdown("""
<style>
    .block-container {
        padding-top: 3.5rem !important;
        padding-bottom: 2rem !important;
    }
    h1 {
        padding-top: 0.5rem !important;
        margin-top: 0.5rem !important;
        line-height: 1.25 !important;
        word-break: break-word;
    }
    .metric-card {
        background-color: #1e293b;
        border-radius: 8px;
        padding: 15px;
        border-left: 4px solid #38bdf8;
        margin-bottom: 10px;
    }
    .badge-critical {
        background-color: #ef4444;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-high {
        background-color: #f97316;
        color: white;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .badge-medium {
        background-color: #eab308;
        color: black;
        padding: 3px 8px;
        border-radius: 4px;
        font-weight: bold;
        font-size: 0.8rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 12px;
        margin-top: 10px;
    }
    .stTabs [data-baseweb="tab"] {
        padding: 10px 18px;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Application Header
col_title, col_badge = st.columns([3, 1])
with col_title:
    st.title("🛡️ Network Intrusion Detection & Monitoring System")
    st.caption("Advanced Computer Networks & Cyber Defense Project — Rule-based Deep Packet Inspection & Telemetry")
with col_badge:
    st.markdown("""
    <div style="text-align: right; padding-top: 15px;">
        <span style="background: #0284c7; color: white; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">RFC 793 Validated</span>
        <span style="background: #16a34a; color: white; padding: 4px 10px; border-radius: 20px; font-size: 0.8rem; font-weight: 600;">SOC v2.0</span>
    </div>
    """, unsafe_allow_html=True)

# ----------------- SIDEBAR CONTROLS -----------------
st.sidebar.image("https://img.icons8.com/fluency/96/shield.png", width=64)
st.sidebar.title("Configuration & Controls")

mode = st.sidebar.radio(
    "Monitoring Mode",
    ["Demo / Attack Simulation", "Live Packet Capture"],
    help="Select simulation mode to reproduce specific cyber attacks or live capture for real local network interface traffic."
)

st.sidebar.markdown("---")
st.sidebar.subheader("⚙️ Detection Thresholds")
port_scan_thresh = st.sidebar.slider(
    "Port Scan Threshold (Distinct Ports)",
    min_value=3, max_value=25, value=5,
    help="Minimum distinct destination ports targeted by an IP before triggering a Port Scan alert."
)
syn_flood_thresh = st.sidebar.slider(
    "SYN Flood Threshold (Packets)",
    min_value=5, max_value=40, value=12,
    help="Threshold for half-open TCP SYN packets without ACK responses."
)
icmp_flood_thresh = st.sidebar.slider(
    "ICMP Flood Threshold (Echo Requests)",
    min_value=5, max_value=30, value=10,
    help="Maximum acceptable ICMP ping packets from a single source before flagging a DoS flood."
)

st.sidebar.markdown("---")

scenario = "all"
packet_count = 150
if mode == "Demo / Attack Simulation":
    st.sidebar.subheader("🎯 Attack Simulation Scenarios")
    scenario_map = {
        "⚡ Multi-Attack Showcase (Mixed Traffic)": "all",
        "🌊 TCP SYN Flood (Denial of Service)": "syn_flood",
        "🕵️ Stealth Scans (NULL, XMAS & FIN Scans)": "stealth_scan",
        "🎯 TCP Horizontal & Vertical Port Scan": "port_scan",
        "💥 ICMP Ping Flood (Bandwidth DoS)": "icmp_flood",
        "🔑 Sensitive Service Probing (SSH/RDP/MySQL)": "sensitive_ports",
        "🛡️ Benign Baseline (Clean Traffic - 0 Alerts)": "benign"
    }
    selected_scenario_label = st.sidebar.selectbox("Select Scenario", list(scenario_map.keys()))
    scenario = scenario_map[selected_scenario_label]
    packet_count = st.sidebar.slider("Packet Volume to Generate", 50, 500, 150, step=25)

    if st.sidebar.button("▶ Run Traffic Simulation", type="primary", use_container_width=True):
        with st.spinner("Simulating network packets and executing detection heuristics..."):
            packets = demo_packets(scenario=scenario, n=packet_count)
            alerts, stats = analyze_packets(
                packets,
                port_scan_threshold=port_scan_thresh,
                syn_flood_threshold=syn_flood_thresh,
                icmp_flood_threshold=icmp_flood_thresh
            )
            save_alerts(alerts)
            st.session_state["packets"] = packets
            st.session_state["alerts"] = alerts
            st.session_state["stats"] = stats
            st.session_state["last_run_mode"] = f"Simulation: {selected_scenario_label}"
            st.toast(f"Analyzed {len(packets)} packets. Detected {len(alerts)} threat(s)!", icon="🛡️")

else:
    st.sidebar.subheader("📡 Live Interface Sniffer")
    interfaces = get_available_interfaces()
    selected_iface_name = st.sidebar.selectbox("Network Interface", list(interfaces.keys()))
    selected_iface_id = interfaces[selected_iface_name]
    capture_seconds = st.sidebar.slider("Capture Window (Seconds)", 5, 30, 10)
    capture_limit = st.sidebar.slider("Max Packets to Capture", 50, 500, 200, step=50)

    if st.sidebar.button("▶ Start Live Capture", type="primary", use_container_width=True):
        with st.spinner(f"Sniffing packets on '{selected_iface_name}' for {capture_seconds}s..."):
            packets = capture_packets(seconds=capture_seconds, iface=selected_iface_id, packet_limit=capture_limit)
        if not packets:
            st.sidebar.warning("No IP packets captured. Ensure administrative privileges and active network traffic.")
        else:
            alerts, stats = analyze_packets(
                packets,
                port_scan_threshold=port_scan_thresh,
                syn_flood_threshold=syn_flood_thresh,
                icmp_flood_threshold=icmp_flood_thresh
            )
            save_alerts(alerts)
            st.session_state["packets"] = packets
            st.session_state["alerts"] = alerts
            st.session_state["stats"] = stats
            st.session_state["last_run_mode"] = f"Live Capture: {selected_iface_name}"
            st.toast(f"Captured {len(packets)} packets. Detected {len(alerts)} threat(s)!", icon="📡")

st.sidebar.markdown("---")
if st.sidebar.button("🗑️ Clear Stored Alert Database", use_container_width=True):
    clear_alerts()
    st.sidebar.success("Database cleared!")
    st.rerun()

# ----------------- MAIN CONTENT & TABS -----------------
packets = st.session_state.get("packets", [])
stats = st.session_state.get("stats")
alerts = st.session_state.get("alerts", [])
last_mode = st.session_state.get("last_run_mode", "No run executed yet")

# If user hasn't run anything yet, run an initial default simulation so the dashboard is immediately live and beautiful!
if not stats:
    packets = demo_packets(scenario="all", n=150)
    alerts, stats = analyze_packets(
        packets,
        port_scan_threshold=port_scan_thresh,
        syn_flood_threshold=syn_flood_thresh,
        icmp_flood_threshold=icmp_flood_thresh
    )
    save_alerts(alerts)
    st.session_state["packets"] = packets
    st.session_state["alerts"] = alerts
    st.session_state["stats"] = stats
    st.session_state["last_run_mode"] = "Initial Showcase: Multi-Attack Mixed Traffic"

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 SOC Telemetry & Analytics",
    "🚨 Detected Threats & Mitigations",
    "🔍 Deep Packet Inspection (DPI)",
    "📜 Alert History & Export"
])

# ----------------- TAB 1: SOC TELEMETRY & ANALYTICS -----------------
with tab1:
    st.markdown(f"**Current Telemetry Stream:** `{st.session_state.get('last_run_mode', 'Active')}`")
    
    # Executive KPI Metrics Row
    kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)
    kpi1.metric("Total Packets", f"{stats['total_packets']:,}", help="Total packets inspected in the observation window")
    kpi2.metric("Threats Flagged", stats["threats_detected"], delta=f"{stats['threats_detected']} Alert(s)", delta_color="inverse")
    
    crit_high = stats["severities"]["CRITICAL"] + stats["severities"]["HIGH"]
    kpi3.metric("Critical / High", crit_high, delta="Immediate Action" if crit_high > 0 else "Clear", delta_color="inverse")
    kpi4.metric("Unique Sources", stats["unique_sources"], help="Unique source IP addresses communicating on the wire")
    
    traffic_kb = round(stats.get("total_bytes", 0) / 1024, 2)
    kpi5.metric("Payload Volume", f"{traffic_kb} KB", help="Total raw packet bytes analyzed")

    st.markdown("---")

    # Visual Analytics Grid
    col_chart_left, col_chart_right = st.columns(2)

    with col_chart_left:
        st.subheader("🌐 Protocol Distribution")
        proto_data = pd.DataFrame([
            {"Protocol": "TCP", "Packets": stats["tcp"]},
            {"Protocol": "UDP", "Packets": stats["udp"]},
            {"Protocol": "ICMP", "Packets": stats["icmp"]},
            {"Protocol": "Other", "Packets": stats["other"]}
        ])
        
        # Altair bar chart with clean styling
        proto_chart = (
            alt.Chart(proto_data)
            .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
            .encode(
                x=alt.X("Protocol:N", sort="-y", title="Network Protocol"),
                y=alt.Y("Packets:Q", title="Packet Count"),
                color=alt.Color("Protocol:N", legend=None, scale=alt.Scale(scheme="tableau10")),
                tooltip=["Protocol", "Packets"]
            )
            .properties(height=280)
        )
        st.altair_chart(proto_chart, use_container_width=True)

    with col_chart_right:
        st.subheader("⚠️ Threat Severity Breakdown")
        sev_counts = stats.get("severities", {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0})
        sev_data = pd.DataFrame([
            {"Severity": "CRITICAL", "Count": sev_counts["CRITICAL"], "Color": "#ef4444"},
            {"Severity": "HIGH", "Count": sev_counts["HIGH"], "Color": "#f97316"},
            {"Severity": "MEDIUM", "Count": sev_counts["MEDIUM"], "Color": "#eab308"},
            {"Severity": "LOW", "Count": sev_counts["LOW"], "Color": "#3b82f6"}
        ])
        
        sev_chart = (
            alt.Chart(sev_data)
            .mark_bar(cornerRadiusTopLeft=6, cornerRadiusTopRight=6)
            .encode(
                x=alt.X("Severity:N", sort=["CRITICAL", "HIGH", "MEDIUM", "LOW"], title="Severity Level"),
                y=alt.Y("Count:Q", title="Number of Incidents"),
                color=alt.Color("Color:N", scale=None),
                tooltip=["Severity", "Count"]
            )
            .properties(height=280)
        )
        st.altair_chart(sev_chart, use_container_width=True)

    # Secondary Charts: Top Talkers and Destination Ports
    col_talkers, col_ports = st.columns(2)
    
    with col_talkers:
        st.subheader("📡 Top Talkers / Communicating IPs")
        if packets:
            ip_counts = pd.Series([p.get("src", "Unknown") for p in packets]).value_counts().reset_index()
            ip_counts.columns = ["Source IP", "Packets"]
            top_talkers_chart = (
                alt.Chart(ip_counts.head(7))
                .mark_bar()
                .encode(
                    x=alt.X("Packets:Q"),
                    y=alt.Y("Source IP:N", sort="-x"),
                    color=alt.value("#38bdf8"),
                    tooltip=["Source IP", "Packets"]
                )
                .properties(height=240)
            )
            st.altair_chart(top_talkers_chart, use_container_width=True)
        else:
            st.info("No packets to display.")

    with col_ports:
        st.subheader("🎯 Most Targeted Destination Ports")
        if packets:
            dest_ports = [p.get("dst_port") for p in packets if p.get("dst_port") is not None]
            if dest_ports:
                port_counts = pd.Series(dest_ports).value_counts().reset_index()
                port_counts.columns = ["Port", "Count"]
                port_counts["Port"] = port_counts["Port"].astype(str)
                ports_chart = (
                    alt.Chart(port_counts.head(7))
                    .mark_bar()
                    .encode(
                        x=alt.X("Count:Q", title="Hit Count"),
                        y=alt.Y("Port:N", sort="-x", title="Destination Port"),
                        color=alt.value("#a855f7"),
                        tooltip=["Port", "Count"]
                    )
                    .properties(height=240)
                )
                st.altair_chart(ports_chart, use_container_width=True)
            else:
                st.info("No port-targeted packets recorded.")
        else:
            st.info("No packets to display.")

# ----------------- TAB 2: DETECTED THREATS & MITIGATIONS -----------------
with tab2:
    st.subheader(f"🚨 Security Incidents Feed ({len(alerts)} Active Threats)")
    
    if not alerts:
        st.success("✅ Clean Network Traffic: No suspicious signatures or policy violations detected.")
    else:
        # Filter controls
        sev_filter = st.selectbox(
            "Filter by Severity",
            ["All Severities", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0
        )
        filtered_alerts = [
            a for a in alerts
            if sev_filter == "All Severities" or a.get("severity") == sev_filter
        ]

        st.caption(f"Displaying {len(filtered_alerts)} of {len(alerts)} alerts")

        for idx, alert in enumerate(filtered_alerts):
            sev = alert.get("severity", "MEDIUM")
            badge_class = "badge-critical" if sev == "CRITICAL" else ("badge-high" if sev == "HIGH" else "badge-medium")
            
            with st.expander(f"[{sev}] {alert.get('type')} — Source: {alert.get('source')} ➔ Target: {alert.get('destination')}", expanded=(idx < 2)):
                c1, c2, c3 = st.columns([1, 1, 1])
                c1.markdown(f"**Severity:** <span class='{badge_class}'>{sev}</span>", unsafe_allow_html=True)
                c2.markdown(f"**Protocol:** `{alert.get('protocol', 'N/A')}`")
                c3.markdown(f"**MITRE ATT&CK:** `{alert.get('mitre', 'N/A')}`")
                
                st.markdown(f"**Incident Summary:** {alert.get('details')}")
                st.markdown(f"**Timestamp:** `{alert.get('time')}`")
                
                st.markdown("##### 🛡️ Recommended Firewall Mitigation & Defense Rule:")
                st.code(alert.get("mitigation", "N/A"), language="bash")

# ----------------- TAB 3: DEEP PACKET INSPECTION (DPI) -----------------
with tab3:
    st.subheader("🔍 Deep Packet Inspection (Raw Telemetry)")
    st.caption("Inspect individual layer-3 and layer-4 packet headers, TCP flags, and payload summaries.")
    
    if packets:
        raw_df = pd.DataFrame(packets)
        
        # Display filtering
        f_col1, f_col2 = st.columns(2)
        with f_col1:
            proto_filter = st.multiselect("Filter Protocol", options=list(raw_df["protocol"].unique()), default=list(raw_df["protocol"].unique()))
        with f_col2:
            search_query = st.text_input("Search by IP or Port", "")

        df_display = raw_df[raw_df["protocol"].isin(proto_filter)]
        if search_query:
            df_display = df_display[
                df_display["src"].str.contains(search_query, na=False) |
                df_display["dst"].str.contains(search_query, na=False) |
                df_display["dst_port"].astype(str).str.contains(search_query, na=False)
            ]

        st.dataframe(
            df_display,
            use_container_width=True,
            hide_index=True,
            column_config={
                "timestamp": "Time",
                "src": "Source IP",
                "dst": "Target IP",
                "protocol": "Proto",
                "src_port": "Src Port",
                "dst_port": "Dst Port",
                "flags": "TCP Flags",
                "length": "Length (Bytes)",
                "summary": "Packet Dissection Summary"
            }
        )
        st.caption(f"Showing {len(df_display)} packets of {len(raw_df)} total packets captured.")
    else:
        st.info("No packet telemetry captured yet. Run a simulation or live capture from the sidebar.")

# ----------------- TAB 4: ALERT HISTORY & EXPORT -----------------
with tab4:
    st.subheader("📜 Persistent Incident Database (SQLite)")
    history = load_alerts(limit=300)
    
    if history:
        hist_df = pd.DataFrame(history)
        st.dataframe(hist_df, use_container_width=True, hide_index=True)

        st.markdown("---")
        st.subheader("📥 Export & Reporting Tools")
        st.caption("Generate presentation-ready audit logs and compliance reports for academic evaluation.")

        exp_col1, exp_col2, exp_col3 = st.columns(3)
        
        with exp_col1:
            csv_data = export_alerts_csv(history)
            st.download_button(
                label="📄 Download Alerts as CSV",
                data=csv_data,
                file_name=f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
                use_container_width=True
            )

        with exp_col2:
            json_data = export_alerts_json(history)
            st.download_button(
                label="📦 Download Alerts as JSON",
                data=json_data,
                file_name=f"nids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )

        with exp_col3:
            audit_report = generate_security_audit_report(stats if stats else {}, alerts if alerts else history)
            st.download_button(
                label="📑 Download Full Incident Audit Report",
                data=audit_report,
                file_name=f"network_security_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown",
                use_container_width=True
            )

        with st.expander("👁️ Preview Generated Incident Audit Report"):
            st.markdown(audit_report)
    else:
        st.info("No stored alerts in SQLite database yet.")




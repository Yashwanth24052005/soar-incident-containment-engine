"""
Home Page - Polished dashboard overview with live alert feed.
"""

import streamlit as st
import pandas as pd
import requests
import time
from datetime import datetime
from dashboard.components.cards import stat_card, alert_feed_card
from dashboard.components.styles import page_header, section_header, empty_state
from dashboard.rbac import SEVERITY_EMOJI, STATUS_EMOJI

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render():
    page_header("Dashboard", "Real-time security operations overview", "📊")

    col1, col2, col3 = st.columns([4, 1, 1])
    with col1:
        st.markdown(f"<p style='color:#475569; font-size:12px; margin:0; font-family:JetBrains Mono,monospace;'>Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>", unsafe_allow_html=True)
    with col2:
        auto_refresh = st.toggle("Auto", value=False)
    with col3:
        interval = st.selectbox("s", [10, 30, 60], index=1, label_visibility="collapsed")

    st.divider()

    stats          = api_get("/alerts/stats") or {}
    playbook_stats = api_get("/playbooks/stats") or {}
    timeline_stats = api_get("/timeline/stats") or {}

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        stat_card("Total Alerts",  stats.get("total_ingested", 0),             "ingested",         "#60a5fa", "📥")
    with col2:
        stat_card("Rejected",      stats.get("total_rejected", 0),             "invalid/duplicate","#64748b", "🚫")
    with col3:
        stat_card("Playbooks Run", playbook_stats.get("total_executions", 0),  "automated actions","#4ade80", "🎯")
    with col4:
        stat_card("Cases Tracked", timeline_stats.get("total_alerts_tracked", 0), "with timelines","#fb923c", "📋")

    st.divider()

    section_header("Live Alert Feed", "10 most recent alerts")

    alerts   = api_get("/alerts", params={"limit": 10}) or []
    statuses = api_get("/alerts/statuses") or {}

    if alerts:
        for alert in alerts:
            status = statuses.get(alert["alert_id"], "new")
            alert_feed_card(alert, status)
    else:
        empty_state("No alerts yet", "Run: python simulator/siem_simulator.py --count 10 --type all")

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        section_header("Alerts by Severity")
        by_sev = stats.get("by_severity", {})
        if by_sev:
            df = pd.DataFrame(list(by_sev.items()), columns=["Severity", "Count"])
            st.bar_chart(df.set_index("Severity"), color="#60a5fa")
        else:
            empty_state("No severity data yet")

    with col2:
        section_header("Alerts by Attack Type")
        by_atk = stats.get("by_attack_type", {})
        if by_atk:
            df = pd.DataFrame(list(by_atk.items()), columns=["Attack Type", "Count"])
            st.bar_chart(df.set_index("Attack Type"), color="#fb923c")
        else:
            empty_state("No attack type data yet")

    st.divider()

    section_header("Playbook Summary", "Automated containment actions")
    total_pb = playbook_stats.get("total_executions", 0)
    if total_pb > 0:
        col1, col2, col3 = st.columns(3)
        with col1:
            stat_card("Successful", playbook_stats.get("successful", 0), "", "#4ade80", "✅")
        with col2:
            stat_card("Failed", playbook_stats.get("failed", 0), "", "#ff4444", "❌")
        with col3:
            rate = round(playbook_stats.get("successful", 0) / total_pb * 100, 1)
            stat_card("Success Rate", f"{rate}%", "", "#facc15", "📊")

        if playbook_stats.get("by_action"):
            st.markdown("<div style='margin-top:16px;'>", unsafe_allow_html=True)
            for action, count in playbook_stats["by_action"].items():
                st.markdown(f"""
                <div style='display:flex; justify-content:space-between;
                            padding:8px 12px; background:#1e2330; border-radius:6px; margin-bottom:4px;'>
                    <code style='color:#94a3b8; font-size:12px;'>{action}</code>
                    <span style='color:#4ade80; font-weight:600; font-family:JetBrains Mono,monospace;'>{count}</span>
                </div>
                """, unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)
    else:
        empty_state("No playbooks executed yet", "Ingest alerts to trigger automated containment")

    st.divider()

    section_header("Timeline Events", "Automated actions recorded")
    total_events = timeline_stats.get("total_events_recorded", 0)
    st.markdown(f"""
    <p style='color:#64748b; font-size:13px; margin:0 0 12px;'>
        <span style='color:#e2e8f0; font-weight:600; font-family:JetBrains Mono,monospace;'>{total_events}</span>
        events across
        <span style='color:#e2e8f0; font-weight:600; font-family:JetBrains Mono,monospace;'>{timeline_stats.get("total_alerts_tracked", 0)}</span>
        alerts
    </p>
    """, unsafe_allow_html=True)

    if timeline_stats.get("events_by_type"):
        df = pd.DataFrame(list(timeline_stats["events_by_type"].items()), columns=["Event Type", "Count"]).sort_values("Count", ascending=False)
        st.dataframe(df, use_container_width=True, hide_index=True)

    if auto_refresh:
        time.sleep(interval)
        st.rerun()
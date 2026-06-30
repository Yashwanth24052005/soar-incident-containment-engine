"""
Home Page - Dashboard overview with key metrics and charts.
"""

import streamlit as st
import pandas as pd
import requests
from dashboard.components.cards import metric_card

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render():
    st.title("📊 Dashboard Overview")
    st.caption("Real-time security operations overview")
    st.divider()

    stats = api_get("/alerts/stats") or {}
    playbook_stats = api_get("/playbooks/stats") or {}
    timeline_stats = api_get("/timeline/stats") or {}
    dedup_stats = api_get("/alerts/dedup-stats") or {}

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        metric_card("Total Alerts", stats.get("total_ingested", 0), "ingested", "#60a5fa")
    with col2:
        metric_card("Rejected", stats.get("total_rejected", 0), "invalid/duplicate", "#94a3b8")
    with col3:
        metric_card("Playbooks Run", playbook_stats.get("total_executions", 0), "automated actions", "#4ade80")
    with col4:
        metric_card("Cases Tracked", timeline_stats.get("total_alerts_tracked", 0), "with timelines", "#fb923c")

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("🎯 Alerts by Severity")
        by_sev = stats.get("by_severity", {})
        if by_sev:
            df = pd.DataFrame(list(by_sev.items()), columns=["Severity", "Count"])
            st.bar_chart(df.set_index("Severity"))
        else:
            st.info("No data yet.")

    with col2:
        st.subheader("⚔️ Alerts by Attack Type")
        by_atk = stats.get("by_attack_type", {})
        if by_atk:
            df = pd.DataFrame(list(by_atk.items()), columns=["Attack Type", "Count"])
            st.bar_chart(df.set_index("Attack Type"))
        else:
            st.info("No data yet.")

    st.divider()

    st.subheader("🎮 Playbook Summary")
    total_pb = playbook_stats.get("total_executions", 0)
    if total_pb > 0:
        col1, col2, col3 = st.columns(3)
        with col1:
            metric_card("Successful", playbook_stats.get("successful", 0), "", "#4ade80")
        with col2:
            metric_card("Failed", playbook_stats.get("failed", 0), "", "#ff4444")
        with col3:
            rate = round(playbook_stats.get("successful", 0) / total_pb * 100, 1)
            metric_card("Success Rate", f"{rate}%", "", "#facc15")

        if playbook_stats.get("by_action"):
            st.write("**Actions taken:**")
            for action, count in playbook_stats["by_action"].items():
                st.write(f"- `{action}`: {count}")
    else:
        st.info("No playbooks executed yet.")

    st.divider()

    st.subheader("🔁 Deduplication Status")
    active = dedup_stats.get("active_entries", 0)
    window = dedup_stats.get("dedup_window_minutes", 5)
    st.write(f"**{active}** IPs currently in dedup window ({window} min)")

    st.divider()

    st.subheader("📋 Timeline Events")
    total_events = timeline_stats.get("total_events_recorded", 0)
    st.write(f"**{total_events}** total events across **{timeline_stats.get('total_alerts_tracked', 0)}** alerts")
    if timeline_stats.get("events_by_type"):
        df = pd.DataFrame(list(timeline_stats["events_by_type"].items()), columns=["Event Type", "Count"])
        st.dataframe(df.sort_values("Count", ascending=False), use_container_width=True)
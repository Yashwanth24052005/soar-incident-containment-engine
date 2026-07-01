"""
Home Page - Dashboard overview with live alert feed and auto-refresh.
"""

import streamlit as st
import pandas as pd
import requests
import time
from datetime import datetime
from dashboard.components.cards import metric_card
from dashboard.rbac import SEVERITY_EMOJI, STATUS_EMOJI

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render():
    st.title("📊 Dashboard Overview")

    # ── Auto-refresh control ──────────────────────────────────────────────────
    col1, col2, col3 = st.columns([3, 1, 1])
    with col1:
        st.caption(f"Last updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    with col2:
        auto_refresh = st.toggle("Auto-refresh", value=False)
    with col3:
        refresh_interval = st.selectbox("Interval", [10, 30, 60], index=1, label_visibility="collapsed")

    st.divider()

    # Fetch all stats
    stats = api_get("/alerts/stats") or {}
    playbook_stats = api_get("/playbooks/stats") or {}
    timeline_stats = api_get("/timeline/stats") or {}
    dedup_stats = api_get("/alerts/dedup-stats") or {}

    # ── Key Metrics ──────────────────────────────────────────────────────────
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

    # ── Live Alert Feed ───────────────────────────────────────────────────────
    st.subheader("🔴 Live Alert Feed")
    st.caption("Most recent alerts — updates automatically")

    alerts = api_get("/alerts", params={"limit": 10}) or []
    statuses = api_get("/alerts/statuses") or {}

    if alerts:
        for alert in alerts[:10]:
            alert_id = alert["alert_id"]
            severity = alert.get("severity", "unknown")
            attack_type = alert.get("attack_type", "unknown")
            source_ip = alert.get("source_ip", "N/A")
            current_status = statuses.get(alert_id, "new")
            s_emoji = SEVERITY_EMOJI.get(severity, "⚪")
            st_emoji = STATUS_EMOJI.get(current_status, "")
            received = alert.get("received_at", "")[:19]

            severity_colors = {
                "critical": "#2d0000",
                "high": "#2d1a00",
                "medium": "#2d2500",
                "low": "#002d0f",
            }
            border_colors = {
                "critical": "#ff4444",
                "high": "#ff8c00",
                "medium": "#facc15",
                "low": "#4ade80",
            }
            bg = severity_colors.get(severity, "#1e2330")
            border = border_colors.get(severity, "#2d3748")

            st.markdown(f"""
            <div style='background:{bg}; border-left:4px solid {border};
                        border-radius:8px; padding:12px 16px; margin-bottom:8px;'>
                <div style='display:flex; justify-content:space-between;'>
                    <span style='font-weight:600;'>{s_emoji} {attack_type.replace("_", " ").title()}</span>
                    <span style='color:#64748b; font-size:12px;'>{received}</span>
                </div>
                <div style='display:flex; justify-content:space-between; margin-top:4px;'>
                    <span style='color:#94a3b8; font-size:12px;'>
                        ID: <code>{alert_id}</code> | IP: <code>{source_ip}</code>
                    </span>
                    <span style='font-size:12px;'>{st_emoji} {current_status}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)
    else:
        st.info("No alerts yet. Run the SIEM simulator to generate test data.")

    st.divider()

    # ── Charts ────────────────────────────────────────────────────────────────
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

    # ── Playbook summary ──────────────────────────────────────────────────────
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

    # ── Timeline Events Summary ───────────────────────────────────────────────
    st.subheader("📋 Timeline Events")
    total_events = timeline_stats.get("total_events_recorded", 0)
    st.write(
        f"**{total_events}** total events across "
        f"**{timeline_stats.get('total_alerts_tracked', 0)}** alerts"
    )
    if timeline_stats.get("events_by_type"):
        df = pd.DataFrame(
            list(timeline_stats["events_by_type"].items()),
            columns=["Event Type", "Count"]
        )
        st.dataframe(df.sort_values("Count", ascending=False), use_container_width=True)

    # ── Auto-refresh logic ────────────────────────────────────────────────────
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()
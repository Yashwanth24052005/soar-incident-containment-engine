"""
Cases Page - Alert list with filters and status management.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.rbac import SEVERITY_EMOJI, STATUS_EMOJI
from dashboard.components.cards import timeline_event_row

API_BASE = "http://localhost:8000/api/v1"


def api_get(endpoint, params=None):
    try:
        r = requests.get(f"{API_BASE}{endpoint}", params=params, timeout=5)
        return r.json() if r.status_code == 200 else None
    except Exception:
        return None


def render():
    user = get_current_user()
    api_key = user["api_key"]

    st.title("🚨 Case Management")
    st.caption("View, filter, and manage security alerts")
    st.divider()

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col2:
        attack_filter = st.selectbox("Attack Type", ["All", "brute_force", "malware", "port_scan", "data_exfiltration", "unknown"])
    with col3:
        from_date = st.date_input("From Date", value=None)
    with col4:
        to_date = st.date_input("To Date", value=None)

    params = {"limit": 100}
    if severity_filter != "All":
        params["severity"] = severity_filter
    if attack_filter != "All":
        params["attack_type"] = attack_filter
    if from_date:
        params["from_date"] = str(from_date)
    if to_date:
        params["to_date"] = str(to_date)

    alerts = api_get("/alerts", params=params)
    statuses = api_get("/alerts/statuses") or {}

    if not alerts:
        st.info("No alerts found. Use the SIEM simulator to generate test alerts.")
        return

    st.caption(f"Showing {len(alerts)} alerts")
    st.divider()

    for alert in alerts:
        alert_id = alert["alert_id"]
        severity = alert.get("severity", "unknown")
        attack_type = alert.get("attack_type", "unknown")
        source_ip = alert.get("source_ip", "N/A")
        current_status = statuses.get(alert_id, "new")
        s_emoji = SEVERITY_EMOJI.get(severity, "⚪")
        st_emoji = STATUS_EMOJI.get(current_status, "")

        with st.expander(f"{s_emoji} `{alert_id}` | {attack_type.replace('_', ' ').title()} | `{source_ip}` | {st_emoji} {current_status.upper()}"):
            col1, col2 = st.columns(2)

            with col1:
                st.markdown(f"**Alert ID:** `{alert_id}`")
                st.markdown(f"**Source IP:** `{source_ip}`")
                st.markdown(f"**Attack Type:** {attack_type.replace('_', ' ').title()}")
                st.markdown(f"**Severity:** {severity.upper()}")
                st.markdown(f"**Description:** {alert.get('description', 'N/A')}")
                if alert.get("hostname"):
                    st.markdown(f"**Hostname:** `{alert['hostname']}`")
                if alert.get("file_hash"):
                    st.markdown(f"**File Hash:** `{alert['file_hash'][:32]}...`")
                if alert.get("iocs"):
                    st.markdown(f"**IoCs:** {', '.join(alert['iocs'])}")

            with col2:
                st.markdown(f"**Status:** `{current_status}`")
                st.markdown(f"**Received:** {alert.get('received_at', '')[:19]}")

                status_options = ["new", "investigating", "contained", "resolved", "false_positive"]
                current_idx = status_options.index(current_status) if current_status in status_options else 0
                new_status = st.selectbox("Update Status", status_options, index=current_idx, key=f"status_{alert_id}")

                col_a, col_b = st.columns(2)
                with col_a:
                    if st.button("Update", key=f"upd_{alert_id}", use_container_width=True):
                        try:
                            r = requests.patch(
                                f"{API_BASE}/alerts/{alert_id}/status",
                                params={"new_status": new_status},
                                headers={"X-API-Key": api_key},
                                timeout=5,
                            )
                            if r.status_code == 200:
                                st.success(f"→ {new_status}")
                                st.rerun()
                            else:
                                st.error(r.json().get("detail", "Error"))
                        except Exception as e:
                            st.error(str(e))

                with col_b:
                    if st.button("Geolocate", key=f"geo_{alert_id}", use_container_width=True):
                        geo = api_get(f"/alerts/{alert_id}/geolocate")
                        if geo:
                            st.info(f"📍 {geo.get('city')}, {geo.get('region')}, {geo.get('country')} | ISP: {geo.get('isp')}")
                        else:
                            st.warning("Could not geolocate.")

            st.divider()
            timeline = api_get(f"/timeline/{alert_id}")
            if timeline and timeline.get("events"):
                st.markdown("**📋 Timeline:**")
                for event in timeline["events"][-3:]:
                    timeline_event_row(event)
                if len(timeline["events"]) > 3:
                    st.caption(f"+ {len(timeline['events']) - 3} more events")
"""
Cases Page - Polished alert list with filters and status management.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.components.cards import severity_pill, status_pill, timeline_event_row
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
    user = get_current_user()
    api_key = user["api_key"]

    page_header("Cases", "View, filter, and manage security alerts", "🚨")
    st.divider()

    st.markdown("<p style='font-size:11px; font-weight:600; color:#334155; text-transform:uppercase; letter-spacing:0.1em; margin:0 0 10px;'>Filters</p>", unsafe_allow_html=True)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        severity_filter = st.selectbox("Severity", ["All", "critical", "high", "medium", "low"])
    with col2:
        attack_filter = st.selectbox("Attack Type", ["All", "brute_force", "malware", "port_scan", "data_exfiltration", "unknown"])
    with col3:
        from_date = st.date_input("From", value=None)
    with col4:
        to_date = st.date_input("To", value=None)

    params = {"limit": 100}
    if severity_filter != "All": params["severity"] = severity_filter
    if attack_filter != "All": params["attack_type"] = attack_filter
    if from_date: params["from_date"] = str(from_date)
    if to_date: params["to_date"] = str(to_date)

    alerts   = api_get("/alerts", params=params)
    statuses = api_get("/alerts/statuses") or {}

    st.divider()

    if not alerts:
        empty_state("No alerts found", "Use the SIEM simulator to generate test alerts.")
        return

    st.markdown(f"<p style='color:#475569; font-size:12px; margin:0 0 16px; font-family:JetBrains Mono,monospace;'>Showing <span style='color:#e2e8f0; font-weight:600;'>{len(alerts)}</span> alerts</p>", unsafe_allow_html=True)

    for alert in alerts:
        alert_id    = alert["alert_id"]
        severity    = alert.get("severity", "unknown")
        attack_type = alert.get("attack_type", "unknown")
        source_ip   = alert.get("source_ip", "N/A")
        cur_status  = statuses.get(alert_id, "new")
        s_emoji     = SEVERITY_EMOJI.get(severity, "⚪")
        st_emoji    = STATUS_EMOJI.get(cur_status, "")

        with st.expander(f"{s_emoji} `{alert_id[:16]}` · {attack_type.replace('_',' ').title()} · `{source_ip}` · {st_emoji} {cur_status.upper()}"):
            col1, col2 = st.columns(2)

            with col1:
                st.markdown(f"""
                <div style='display:flex; flex-direction:column; gap:8px;'>
                    <div>
                        <p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase; letter-spacing:0.08em;'>Alert ID</p>
                        <code style='font-size:12px;'>{alert_id}</code>
                    </div>
                    <div>
                        <p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase; letter-spacing:0.08em;'>Source IP</p>
                        <code style='font-size:13px; color:#e2e8f0;'>{source_ip}</code>
                    </div>
                    <div>
                        <p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase; letter-spacing:0.08em;'>Attack Type</p>
                        <p style='color:#e2e8f0; font-size:13px; margin:0;'>{attack_type.replace("_"," ").title()}</p>
                    </div>
                    <div style='display:flex; gap:8px; flex-wrap:wrap;'>
                        {severity_pill(severity)}
                        {status_pill(cur_status)}
                    </div>
                    <div>
                        <p style='color:#475569; font-size:11px; margin:0;'>{alert.get("description","N/A")}</p>
                    </div>
                    {f"<div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>Hostname</p><code>{alert['hostname']}</code></div>" if alert.get("hostname") else ""}
                    {f"<div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>File Hash</p><code style='font-size:11px; color:#94a3b8;'>{alert['file_hash'][:40]}...</code></div>" if alert.get("file_hash") else ""}
                </div>
                """, unsafe_allow_html=True)

            with col2:
                st.markdown(f"""
                <div style='display:flex; flex-direction:column; gap:8px; margin-bottom:16px;'>
                    <div>
                        <p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase; letter-spacing:0.08em;'>Received</p>
                        <p style='color:#94a3b8; font-size:12px; margin:0; font-family:JetBrains Mono,monospace;'>{alert.get("received_at","")[:19].replace("T"," ")}</p>
                    </div>
                    <div>
                        <p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase; letter-spacing:0.08em;'>IoCs</p>
                        <p style='color:#94a3b8; font-size:12px; margin:0;'>{", ".join(alert.get("iocs",[])) or "None"}</p>
                    </div>
                </div>
                """, unsafe_allow_html=True)

                status_options = ["new","investigating","contained","resolved","false_positive"]
                cur_idx = status_options.index(cur_status) if cur_status in status_options else 0
                new_status = st.selectbox("Update Status", status_options, index=cur_idx, key=f"sel_{alert_id}")

                col_a, col_b = st.columns(2)
                with col_a:
                    if st.button("Save", key=f"save_{alert_id}", use_container_width=True):
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
                                st.error(r.json().get("detail","Error"))
                        except Exception as e:
                            st.error(str(e))

                with col_b:
                    if st.button("📍 Locate", key=f"geo_{alert_id}", use_container_width=True):
                        geo = api_get(f"/alerts/{alert_id}/geolocate")
                        if geo:
                            st.markdown(f"""
                            <div style='background:#1e2330; border:1px solid #2d3748;
                                        border-radius:8px; padding:10px; margin-top:8px;'>
                                <p style='margin:0; font-size:12px; color:#94a3b8;'>
                                    📍 {geo.get("city")}, {geo.get("region")}, {geo.get("country")}<br/>
                                    ISP: {geo.get("isp","N/A")}<br/>
                                    Proxy: {"Yes 🚨" if geo.get("is_proxy") else "No"} | Hosting: {"Yes" if geo.get("is_hosting") else "No"}
                                </p>
                            </div>
                            """, unsafe_allow_html=True)
                        else:
                            st.warning("Could not geolocate.")

            timeline = api_get(f"/timeline/{alert_id}")
            if timeline and timeline.get("events"):
                st.divider()
                st.markdown("<p style='color:#475569; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; margin:0 0 8px;'>Recent Timeline Events</p>", unsafe_allow_html=True)
                for event in timeline["events"][-4:]:
                    timeline_event_row(event)
                if len(timeline["events"]) > 4:
                    st.markdown(f"<p style='color:#475569; font-size:11px; margin:6px 0 0;'>+ {len(timeline['events'])-4} more events</p>", unsafe_allow_html=True)
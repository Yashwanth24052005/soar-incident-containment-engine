"""
Playbooks Page - Polished playbook execution center.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.components.cards import stat_card, ip_block_card
from dashboard.components.styles import page_header, section_header, empty_state

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

    page_header("Playbook Center", "Automated containment actions and execution history", "🎯")
    st.divider()

    ps = api_get("/playbooks/stats") or {}
    total_pb = ps.get("total_executions", 0)

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        stat_card("Executions",  total_pb,                         "", "#60a5fa", "⚡")
    with col2:
        stat_card("Successful",  ps.get("successful", 0),          "", "#4ade80", "✅")
    with col3:
        stat_card("Failed",      ps.get("failed", 0),              "", "#ff4444", "❌")
    with col4:
        rate = round(ps.get("successful", 0) / max(total_pb, 1) * 100, 1)
        stat_card("Success Rate", f"{rate}%",                      "", "#facc15", "📊")

    st.divider()

    col1, col2, col3 = st.columns(3)
    with col1:
        section_header("Blocked IPs", "Brute force containment")
        blocked = api_get("/playbooks/blocked-ips") or {}
        if blocked:
            for ip, data in blocked.items():
                ip_block_card(ip, data, "blocked")
        else:
            empty_state("No IPs blocked yet")

    with col2:
        section_header("Isolated Hosts", "Malware containment")
        isolated = api_get("/playbooks/isolated-hosts") or {}
        if isolated:
            for host, data in isolated.items():
                ip_block_card(host, data, "isolated")
        else:
            empty_state("No hosts isolated yet")

    with col3:
        section_header("Rate Limited", "Port scan containment")
        rate_limited = api_get("/playbooks/rate-limited-ips") or {}
        if rate_limited:
            for ip, data in rate_limited.items():
                ip_block_card(ip, data, "ratelimited")
        else:
            empty_state("No IPs rate limited yet")

    st.divider()

    section_header("Manual Playbook Trigger", "Senior Analyst required for high-impact")

    with st.form("manual_pb"):
        col1, col2 = st.columns(2)
        with col1:
            alert_id_input = st.text_input("Alert ID", placeholder="e.g. INC-47832")
        with col2:
            score_input = st.slider("Composite Risk Score", 0, 100, 75)

        action_label = "block_and_isolate" if score_input >= 80 else "block" if score_input >= 55 else "isolate" if score_input >= 25 else "monitor"
        action_color = "#ff4444" if score_input >= 80 else "#ff8c00" if score_input >= 55 else "#facc15" if score_input >= 25 else "#4ade80"
        st.markdown(f"<p style='color:#475569; font-size:12px; margin:4px 0;'>Score {score_input} → <span style='color:{action_color}; font-weight:600;'>{action_label}</span></p>", unsafe_allow_html=True)

        submitted = st.form_submit_button("Execute Playbook", use_container_width=True)

        if submitted and alert_id_input:
            try:
                r = requests.post(
                    f"{API_BASE}/playbooks/execute/{alert_id_input}",
                    params={"composite_score": score_input},
                    headers={"X-API-Key": api_key},
                    timeout=10,
                )
                if r.status_code == 200:
                    result = r.json()
                    if result.get("message"):
                        st.info(result["message"])
                    else:
                        st.success(f"✅ {result.get('action_taken', 'Executed')}")
                        st.json(result)
                elif r.status_code == 403:
                    st.error(f"🔒 {r.json().get('detail','Access denied — Senior Analyst required')}")
                else:
                    st.error(r.json().get("detail", "Error"))
            except Exception as e:
                st.error(str(e))
        elif submitted:
            st.warning("Enter an Alert ID first.")

    st.divider()

    section_header("Execution Log", "Full audit trail of all playbook runs")
    log = api_get("/playbooks/log")

    if log:
        for entry in log:
            success  = entry.get("success", False)
            icon     = "✅" if success else "❌"
            pb_name  = entry.get("playbook_name", "Unknown")
            action   = entry.get("action_taken", "N/A")
            executed = entry.get("executed_at", "")[:19].replace("T", " ")

            with st.expander(f"{icon} {pb_name} · `{action}` · {executed}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                    <div style='display:flex; flex-direction:column; gap:8px;'>
                        <div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>Alert ID</p><code>{entry.get("alert_id","N/A")}</code></div>
                        <div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>Source IP</p><code style='color:#e2e8f0;'>{entry.get("source_ip","N/A")}</code></div>
                        <div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>Risk Level</p><p style='color:#e2e8f0; margin:0;'>{entry.get("risk_level","N/A").upper()}</p></div>
                    </div>
                    """, unsafe_allow_html=True)
                with col2:
                    st.markdown(f"""
                    <div style='display:flex; flex-direction:column; gap:8px;'>
                        <div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>Action</p><code>{action}</code></div>
                        <div><p style='color:#475569; font-size:11px; margin:0; text-transform:uppercase;'>Execution Time</p><p style='color:#4ade80; margin:0; font-family:JetBrains Mono,monospace;'>{entry.get("execution_time_ms",0):.1f}ms</p></div>
                    </div>
                    """, unsafe_allow_html=True)

                if entry.get("details"):
                    st.markdown(f"<p style='color:#94a3b8; font-size:12px; margin:8px 0 0;'>{entry['details']}</p>", unsafe_allow_html=True)

                if entry.get("recommended_followup"):
                    st.markdown(f"""
                    <div style='background:#0c1a2e; border-left:3px solid #3b82f6;
                                border-radius:8px; padding:12px; margin-top:12px;'>
                        <p style='color:#60a5fa; font-size:11px; font-weight:600; margin:0 0 4px; text-transform:uppercase;'>Follow-up Actions</p>
                        <p style='color:#94a3b8; font-size:12px; margin:0;'>{entry["recommended_followup"]}</p>
                    </div>
                    """, unsafe_allow_html=True)
    else:
        empty_state("No playbooks executed yet", "Ingest alerts with sufficient risk scores to trigger playbooks")
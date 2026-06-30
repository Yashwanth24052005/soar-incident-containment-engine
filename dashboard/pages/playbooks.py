"""
Playbooks Page - Playbook execution center (Senior Analyst + Admin only).
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user

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

    st.title("🎯 Playbook Execution Center")
    st.caption("Automated containment actions — Senior Analyst access")
    st.divider()

    col1, col2, col3 = st.columns(3)

    with col1:
        st.subheader("🚫 Blocked IPs")
        blocked = api_get("/playbooks/blocked-ips")
        if blocked:
            for ip, data in blocked.items():
                st.write(f"**`{ip}`**")
                st.caption(f"Blocked: {data.get('blocked_at', 'N/A')[:19]}")
        else:
            st.info("No IPs blocked yet.")

    with col2:
        st.subheader("🔒 Isolated Hosts")
        isolated = api_get("/playbooks/isolated-hosts")
        if isolated:
            for host, data in isolated.items():
                st.write(f"**`{host}`**")
                st.caption(f"Isolated: {data.get('isolated_at', 'N/A')[:19]}")
        else:
            st.info("No hosts isolated yet.")

    with col3:
        st.subheader("⚡ Rate Limited")
        rate_limited = api_get("/playbooks/rate-limited-ips")
        if rate_limited:
            for ip, data in rate_limited.items():
                st.write(f"**`{ip}`**")
                st.caption(f"Since: {data.get('rate_limited_at', 'N/A')[:19]}")
        else:
            st.info("No IPs rate limited yet.")

    st.divider()
    st.subheader("⚡ Manually Trigger Playbook")
    with st.form("manual_playbook"):
        col1, col2 = st.columns(2)
        with col1:
            alert_id_input = st.text_input("Alert ID", placeholder="e.g. INC-47832")
        with col2:
            score_input = st.slider("Composite Risk Score", 0, 100, 75)
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
                    st.success(f"✅ {result.get('action_taken', 'Executed')}")
                    st.json(result)
                elif r.status_code == 403:
                    st.error(f"🔒 {r.json().get('detail', 'Access denied')}")
                else:
                    st.error(r.json().get("detail", "Error"))
            except Exception as e:
                st.error(str(e))

    st.divider()
    st.subheader("📜 Playbook Execution Log")
    log = api_get("/playbooks/log")
    if log:
        for entry in log:
            success_icon = "✅" if entry.get("success") else "❌"
            with st.expander(f"{success_icon} {entry.get('playbook_name')} | {entry.get('action_taken')} | {entry.get('executed_at', '')[:19]}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Alert ID:** `{entry.get('alert_id')}`")
                    st.write(f"**Source IP:** `{entry.get('source_ip')}`")
                    st.write(f"**Risk Level:** {entry.get('risk_level', 'N/A').upper()}")
                with col2:
                    st.write(f"**Execution Time:** {entry.get('execution_time_ms', 0):.1f}ms")
                    st.write(f"**Action:** `{entry.get('action_taken')}`")
                st.write(f"**Details:** {entry.get('details')}")
                if entry.get("recommended_followup"):
                    st.info(f"📋 **Follow-up:** {entry['recommended_followup']}")
    else:
        st.info("No playbooks executed yet.")
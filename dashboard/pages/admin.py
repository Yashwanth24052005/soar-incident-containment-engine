"""
Admin Page - Admin-only panel for RBAC management and system overview.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.rbac import ROLE_BADGES, ROLE_COLORS

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

    if user["role"] != "admin":
        st.error("⛔ Access Denied. This page requires Admin role.")
        return

    st.title("⚙️ Admin Panel")
    st.caption("System management — Admin access only")
    st.divider()

    st.subheader("👥 RBAC Configuration")
    rbac = api_get("/rbac/summary") or {}

    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Total Users", rbac.get("total_users", 0))
    with col2:
        st.metric("High-Impact Playbooks", len(rbac.get("high_impact_playbooks", [])))
    with col3:
        st.metric("Senior Approval Threshold", rbac.get("senior_approval_threshold", 70))

    st.divider()

    col1, col2 = st.columns(2)
    with col1:
        st.subheader("Roles")
        for role, count in rbac.get("roles", {}).items():
            color = ROLE_COLORS.get(role, "#94a3b8")
            badge = ROLE_BADGES.get(role, role)
            st.markdown(f"<span style='color:{color};'>{badge}</span>: **{count} users**", unsafe_allow_html=True)

    with col2:
        st.subheader("High-Impact Playbooks")
        for pb in rbac.get("high_impact_playbooks", []):
            st.write(f"🔒 {pb}")
        st.caption(f"Require Senior Analyst role when score ≥ {rbac.get('senior_approval_threshold', 70)}")

    st.divider()

    st.subheader("🚫 AWS Security Group — Blocked IPs")
    aws_blocked = api_get("/playbooks/aws-blocked-ips") or {}

    if aws_blocked:
        for ip, data in aws_blocked.items():
            col1, col2, col3 = st.columns([2, 2, 1])
            with col1:
                st.write(f"`{ip}`")
            with col2:
                st.write(f"Mode: {data.get('mode', 'N/A')}")
            with col3:
                if st.button("Unblock", key=f"unblock_{ip}"):
                    try:
                        r = requests.delete(
                            f"{API_BASE}/playbooks/aws-blocked-ips/{ip}",
                            headers={"X-API-Key": api_key},
                            timeout=5,
                        )
                        if r.status_code == 200:
                            st.success(f"Unblocked {ip}")
                            st.rerun()
                        else:
                            st.error(r.json().get("detail", "Error"))
                    except Exception as e:
                        st.error(str(e))
    else:
        st.info("No IPs currently blocked via AWS Security Group.")

    st.divider()
    st.subheader("📊 System Stats")
    stats = api_get("/alerts/stats") or {}
    playbook_stats = api_get("/playbooks/stats") or {}

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Alerts", stats.get("total_ingested", 0))
    with col2:
        st.metric("Rejected", stats.get("total_rejected", 0))
    with col3:
        st.metric("Playbooks Run", playbook_stats.get("total_executions", 0))
    with col4:
        total = playbook_stats.get("total_executions", 1)
        st.metric("Success Rate", f"{round(playbook_stats.get('successful', 0) / max(total, 1) * 100, 1)}%")
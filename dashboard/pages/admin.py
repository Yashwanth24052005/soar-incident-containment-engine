"""
Admin Page - Polished admin panel for RBAC and system management.
"""

import streamlit as st
import requests
from dashboard.auth import get_current_user
from dashboard.components.cards import stat_card, ip_block_card
from dashboard.components.styles import page_header, section_header, empty_state
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
        st.markdown("""
        <div style='background:#1a0000; border:1px solid #ff444444;
                    border-left:3px solid #ff4444; border-radius:10px;
                    padding:20px; text-align:center; margin-top:40px;'>
            <p style='font-size:32px; margin:0;'>⛔</p>
            <p style='color:#ff4444; font-size:16px; font-weight:600; margin:8px 0 4px;'>Access Denied</p>
            <p style='color:#64748b; font-size:13px; margin:0;'>This page requires Admin role.</p>
        </div>
        """, unsafe_allow_html=True)
        return

    page_header("Admin Panel", "System management — Admin access only", "⚙️")
    st.divider()

    section_header("System Overview")
    stats          = api_get("/alerts/stats") or {}
    playbook_stats = api_get("/playbooks/stats") or {}
    timeline_stats = api_get("/timeline/stats") or {}

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        stat_card("Total Alerts",  stats.get("total_ingested", 0),             "ingested",  "#60a5fa", "📥")
    with col2:
        stat_card("Rejected",      stats.get("total_rejected", 0),             "blocked",   "#64748b", "🚫")
    with col3:
        stat_card("Playbooks Run", playbook_stats.get("total_executions", 0),  "automated", "#4ade80", "🎯")
    with col4:
        total = playbook_stats.get("total_executions", 1)
        rate  = round(playbook_stats.get("successful", 0) / max(total, 1) * 100, 1)
        stat_card("Success Rate",  f"{rate}%",                                  "",          "#facc15", "📊")

    st.divider()

    section_header("RBAC Configuration", "Role-based access control settings")
    rbac = api_get("/rbac/summary") or {}

    col1, col2 = st.columns(2)
    with col1:
        st.markdown("<p style='color:#475569; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.1em; margin:0 0 10px;'>Roles</p>", unsafe_allow_html=True)
        for role, count in rbac.get("roles", {}).items():
            color = ROLE_COLORS.get(role, "#94a3b8")
            badge = ROLE_BADGES.get(role, role)
            st.markdown(f"""
            <div style='background:#1e2330; border:1px solid #2d3748; border-radius:8px;
                        padding:12px 14px; margin-bottom:6px;
                        display:flex; justify-content:space-between; align-items:center;'>
                <span style='color:{color}; font-weight:500; font-size:13px;'>{badge}</span>
                <span style='color:#475569; font-size:12px; font-family:JetBrains Mono,monospace;'>{count} users</span>
            </div>
            """, unsafe_allow_html=True)

    with col2:
        st.markdown("<p style='color:#475569; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.1em; margin:0 0 10px;'>High-Impact Playbooks</p>", unsafe_allow_html=True)
        for pb in rbac.get("high_impact_playbooks", []):
            st.markdown(f"""
            <div style='background:#1e2330; border:1px solid #2d3748; border-left:3px solid #fb923c;
                        border-radius:8px; padding:10px 14px; margin-bottom:6px;'>
                <span style='color:#e2e8f0; font-size:13px;'>🔒 {pb}</span>
            </div>
            """, unsafe_allow_html=True)
        st.markdown(f"<p style='color:#475569; font-size:12px; margin:8px 0 0;'>Senior Analyst required for score ≥ <span style='color:#fb923c; font-weight:600; font-family:JetBrains Mono,monospace;'>{rbac.get('senior_approval_threshold', 70)}</span></p>", unsafe_allow_html=True)

    st.divider()

    section_header("API Keys", "Demo credentials for testing")
    col1, col2, col3 = st.columns(3)
    keys_config = [
        (col1, "Analyst", [("analyst-key-001","john.doe"),("analyst-key-002","jane.smith")], "#60a5fa", "#0c1a2e"),
        (col2, "Senior Analyst", [("senior-key-001","alice.senior"),("senior-key-002","bob.senior")], "#fb923c", "#1a0d00"),
        (col3, "Admin", [("admin-key-001","admin")], "#f43f5e", "#1a0008"),
    ]
    for col, role_name, keys, color, bg in keys_config:
        with col:
            st.markdown(f"<div style='background:#1e2330; border:1px solid #2d3748; border-top:3px solid {color}; border-radius:10px; padding:16px;'><p style='color:{color}; font-size:11px; font-weight:600; text-transform:uppercase; letter-spacing:0.1em; margin:0 0 12px;'>{role_name}</p>", unsafe_allow_html=True)
            for key, username in keys:
                st.markdown(f"<div style='margin-bottom:8px;'><p style='color:#94a3b8; font-size:11px; margin:0;'>{username}</p><code style='color:{color}; font-size:11px; background:{bg}; padding:3px 8px; border-radius:4px; display:block; margin-top:3px;'>{key}</code></div>", unsafe_allow_html=True)
            st.markdown("</div>", unsafe_allow_html=True)

    st.divider()

    section_header("AWS Security Group", "IPs blocked via boto3 integration")
    aws_blocked = api_get("/playbooks/aws-blocked-ips") or {}

    if aws_blocked:
        for ip, data in aws_blocked.items():
            col1, col2 = st.columns([4, 1])
            with col1:
                ip_block_card(ip, data, "blocked")
            with col2:
                st.markdown("<div style='margin-top:8px;'>", unsafe_allow_html=True)
                if st.button("Unblock", key=f"unblock_{ip}", use_container_width=True):
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
                            st.error(r.json().get("detail","Error"))
                    except Exception as e:
                        st.error(str(e))
                st.markdown("</div>", unsafe_allow_html=True)
    else:
        empty_state("No IPs blocked via AWS Security Group", "Brute force playbooks will populate this when triggered")
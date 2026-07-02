"""
Sidebar Component - Polished role-aware navigation.
"""

import streamlit as st
from dashboard.auth import get_current_user, logout
from dashboard.rbac import get_pages_for_role, ROLE_BADGES, ROLE_COLORS


def render_sidebar() -> str:
    user = get_current_user()
    role = user["role"]
    username = user["username"]
    pages = get_pages_for_role(role)

    with st.sidebar:
        st.markdown("""
        <div style='padding: 20px 8px 16px;'>
            <div style='display:flex; align-items:center; gap:10px;'>
                <span style='font-size:28px;'>🛡️</span>
                <div>
                    <p style='margin:0; font-size:15px; font-weight:700;
                              color:#f8fafc; letter-spacing:-0.02em;'>SOAR Engine</p>
                    <p style='margin:0; font-size:11px; color:#475569;'>Infotact Solutions</p>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        badge = ROLE_BADGES.get(role, role)
        color = ROLE_COLORS.get(role, "#94a3b8")
        st.markdown(f"""
        <div style='background:#141720; border:1px solid #1e2330;
                    border-radius:10px; padding:12px 14px; margin-bottom:16px;'>
            <p style='margin:0; font-size:13px; font-weight:600; color:#e2e8f0;'>@{username}</p>
            <p style='margin:3px 0 0; font-size:11px; color:{color}; font-weight:500;'>{badge}</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("<p style='font-size:10px; font-weight:600; color:#334155; text-transform:uppercase; letter-spacing:0.12em; margin:0 0 8px;'>Navigation</p>", unsafe_allow_html=True)

        selected = st.radio("nav", pages, label_visibility="collapsed")

        st.divider()

        col1, col2 = st.columns(2)
        with col1:
            if st.button("↺ Refresh", use_container_width=True):
                st.rerun()
        with col2:
            if st.button("→ Logout", use_container_width=True):
                logout()
                st.rerun()

    return selected
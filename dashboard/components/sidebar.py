"""
Sidebar Component - Role-aware navigation sidebar.
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
        <div style='text-align:center; padding: 10px 0;'>
            <h2>🛡️ SOAR Engine</h2>
            <p style='color:#94a3b8; font-size:12px;'>Infotact Solutions & Co.</p>
        </div>
        """, unsafe_allow_html=True)

        st.divider()

        badge = ROLE_BADGES.get(role, role)
        color = ROLE_COLORS.get(role, "#94a3b8")
        st.markdown(f"""
        <div style='background:#1e2330; border:1px solid #2d3748;
                    border-radius:8px; padding:12px; margin-bottom:12px;'>
            <p style='margin:0; font-weight:600;'>{username}</p>
            <p style='margin:0; color:{color}; font-size:12px;'>{badge}</p>
        </div>
        """, unsafe_allow_html=True)

        st.divider()
        st.caption("NAVIGATION")
        selected = st.radio("nav", pages, label_visibility="collapsed")

        st.divider()
        col1, col2 = st.columns(2)
        with col1:
            if st.button("🔄 Refresh", use_container_width=True):
                st.rerun()
        with col2:
            if st.button("🚪 Logout", use_container_width=True):
                logout()
                st.rerun()

        st.divider()
        st.caption("v1.0.0 | Week 4")

    return selected
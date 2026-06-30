"""
SOAR Case Management Dashboard - Main Entry Point
Week 4: Streamlit dashboard with RBAC-aware navigation.
"""

import streamlit as st
from dashboard.auth import is_authenticated, show_login_page
from dashboard.components.sidebar import render_sidebar
from dashboard.pages import home, cases, incidents, playbooks, admin

st.set_page_config(
    page_title="SOAR Case Management Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .stButton > button {
        background-color: #1d4ed8;
        color: white;
        border-radius: 8px;
        border: none;
    }
    .stButton > button:hover {
        background-color: #2563eb;
    }
</style>
""", unsafe_allow_html=True)


def main():
    if not is_authenticated():
        show_login_page()
        st.stop()

    selected_page = render_sidebar()

    page_map = {
        "🏠 Home": home,
        "🚨 Cases": cases,
        "📋 Incidents": incidents,
        "🎯 Playbooks": playbooks,
        "⚙️ Admin": admin,
    }

    module = page_map.get(selected_page)
    if module:
        module.render()
    else:
        st.error("Page not found.")


if __name__ == "__main__":
    main()
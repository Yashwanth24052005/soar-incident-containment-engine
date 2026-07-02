"""
SOAR Case Management Dashboard - Main Entry Point
Week 4: Streamlit dashboard with RBAC-aware navigation.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
from dashboard.auth import is_authenticated, show_login_page
from dashboard.components.sidebar import render_sidebar
from dashboard.components.styles import GLOBAL_CSS
from dashboard.pages import home, cases, incidents, analytics, playbooks, admin

st.set_page_config(
    page_title="SOAR Engine — Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(GLOBAL_CSS, unsafe_allow_html=True)


def main():
    if not is_authenticated():
        show_login_page()
        st.stop()

    selected_page = render_sidebar()

    page_map = {
        "🏠 Home":       home,
        "🚨 Cases":      cases,
        "📋 Incidents":  incidents,
        "📈 Analytics":  analytics,
        "🎯 Playbooks":  playbooks,
        "⚙️ Admin":      admin,
    }

    module = page_map.get(selected_page)
    if module:
        module.render()
    else:
        st.error("Page not found.")


if __name__ == "__main__":
    main()
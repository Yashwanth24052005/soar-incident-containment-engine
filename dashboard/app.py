import streamlit as st
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from auth import login_page, is_logged_in
from components.sidebar import render_sidebar
from pages.home import render_home

st.set_page_config(
    page_title="SOAR Dashboard",
    page_icon="🛡️",
    layout="wide"
)

if not is_logged_in():
    login_page()
else:
    page = render_sidebar()

    if page == "🏠 Home":
        render_home()
    elif page == "📋 Cases":
        st.title("📋 Case Management")
        st.info("Coming on Day 2 — Case list with filters and RBAC actions.")
    elif page == "⚡ Incidents":
        st.title("⚡ Incident Timeline")
        st.info("Coming on Day 3 — Full incident timeline view.")
    elif page == "⚙️ Admin Panel":
        st.title("⚙️ Admin Panel")
        st.info("Coming on Day 4 — User management and audit logs.")
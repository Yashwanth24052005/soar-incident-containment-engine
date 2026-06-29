import streamlit as st
from auth import logout
from rbac import ROLES

def render_sidebar():
    role = st.session_state.get("role", "viewer")
    email = st.session_state.get("email", "")
    role_label = ROLES[role]["label"]

    with st.sidebar:
        st.image("https://img.icons8.com/color/96/security-shield-green.png", width=60)
        st.markdown(f"### 🛡️ SOAR Dashboard")
        st.markdown(f"**User:** {email}")
        st.markdown(f"**Role:** `{role_label}`")
        st.divider()

        page = st.radio("Navigate", [
            "🏠 Home",
            "📋 Cases",
            "⚡ Incidents",
            *(["⚙️ Admin Panel"] if role == "admin" else [])
        ])

        st.divider()
        if st.button("🚪 Logout"):
            logout()

    return page
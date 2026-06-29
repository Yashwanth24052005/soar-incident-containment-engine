import streamlit as st
from rbac import ROLES

DEMO_USERS = {
    "admin@soar.com":   {"password": "admin123",   "role": "admin"},
    "analyst@soar.com": {"password": "analyst123", "role": "analyst"},
    "viewer@soar.com":  {"password": "viewer123",  "role": "viewer"},
}

def login_page():
    st.title("🔐 SOAR Incident Containment Engine")
    st.subheader("Login to Dashboard")

    email = st.text_input("Email")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        user = DEMO_USERS.get(email)
        if user and user["password"] == password:
            st.session_state["logged_in"] = True
            st.session_state["email"] = email
            st.session_state["role"] = user["role"]
            st.rerun()
        else:
            st.error("Invalid credentials. Try again.")

def logout():
    for key in ["logged_in", "email", "role"]:
        st.session_state.pop(key, None)
    st.rerun()

def is_logged_in():
    return st.session_state.get("logged_in", False)
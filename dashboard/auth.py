"""
Auth Module - Login and session management for the SOAR dashboard.
"""

import streamlit as st
import requests

API_BASE = "http://localhost:8000/api/v1"

DEMO_KEYS = {
    "analyst-key-001":  {"username": "john.doe",     "role": "analyst"},
    "analyst-key-002":  {"username": "jane.smith",   "role": "analyst"},
    "senior-key-001":   {"username": "alice.senior", "role": "senior_analyst"},
    "senior-key-002":   {"username": "bob.senior",   "role": "senior_analyst"},
    "admin-key-001":    {"username": "admin",         "role": "admin"},
}


def login(api_key: str) -> bool:
    try:
        r = requests.get(f"{API_BASE}/rbac/me", headers={"X-API-Key": api_key}, timeout=5)
        if r.status_code == 200:
            data = r.json()
            st.session_state["authenticated"] = True
            st.session_state["api_key"] = api_key
            st.session_state["username"] = data["username"]
            st.session_state["role"] = data["role"]
            st.session_state["permissions"] = data["permissions"]
            return True
        return False
    except Exception:
        if api_key in DEMO_KEYS:
            user = DEMO_KEYS[api_key]
            st.session_state["authenticated"] = True
            st.session_state["api_key"] = api_key
            st.session_state["username"] = user["username"]
            st.session_state["role"] = user["role"]
            st.session_state["permissions"] = {
                "view_alerts": True,
                "view_timelines": True,
                "update_alert_status": True,
                "execute_low_impact_playbooks": True,
                "execute_high_impact_playbooks": user["role"] in ("senior_analyst", "admin"),
                "manage_users": user["role"] == "admin",
            }
            return True
        return False


def logout():
    for key in ["authenticated", "api_key", "username", "role", "permissions"]:
        st.session_state.pop(key, None)


def is_authenticated() -> bool:
    return st.session_state.get("authenticated", False)


def get_current_user() -> dict:
    return {
        "username": st.session_state.get("username", ""),
        "role": st.session_state.get("role", ""),
        "api_key": st.session_state.get("api_key", ""),
        "permissions": st.session_state.get("permissions", {}),
    }


def require_auth():
    if not is_authenticated():
        show_login_page()
        st.stop()


def show_login_page():
    st.markdown("""
    <div style='text-align:center; padding: 40px 0 20px;'>
        <h1>🛡️ SOAR Engine</h1>
        <p style='color:#94a3b8;'>Incident Containment Dashboard</p>
        <p style='color:#64748b; font-size:13px;'>Infotact Solutions & Co.</p>
    </div>
    """, unsafe_allow_html=True)

    with st.form("login_form"):
        api_key = st.text_input("API Key", type="password", placeholder="Enter your API key (e.g. analyst-key-001)")
        submitted = st.form_submit_button("Login", use_container_width=True)

        if submitted:
            if login(api_key):
                user = get_current_user()
                st.success(f"Welcome, {user['username']}!")
                st.rerun()
            else:
                st.error("Invalid API key. Please try again.")

    st.divider()
    st.caption("Demo keys: `analyst-key-001` | `senior-key-001` | `admin-key-001`")
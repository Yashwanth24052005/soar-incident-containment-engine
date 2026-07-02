"""
Auth Module - Polished login page and session management.
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
            st.session_state.update({
                "authenticated": True,
                "api_key": api_key,
                "username": data["username"],
                "role": data["role"],
                "permissions": data["permissions"],
            })
            return True
        return False
    except Exception:
        if api_key in DEMO_KEYS:
            user = DEMO_KEYS[api_key]
            st.session_state.update({
                "authenticated": True,
                "api_key": api_key,
                "username": user["username"],
                "role": user["role"],
                "permissions": {
                    "view_alerts": True,
                    "view_timelines": True,
                    "update_alert_status": True,
                    "execute_low_impact_playbooks": True,
                    "execute_high_impact_playbooks": user["role"] in ("senior_analyst", "admin"),
                    "manage_users": user["role"] == "admin",
                },
            })
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


def show_login_page():
    st.markdown("""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
    #MainMenu, footer, header { visibility: hidden; }
    .block-container { padding-top: 0 !important; }
    .stButton > button {
        background: #1d4ed8 !important; color: white !important;
        border: none !important; border-radius: 8px !important;
        font-weight: 600 !important; height: 44px !important;
    }
    .stTextInput > div > div > input {
        background: #1e2330 !important; border: 1px solid #2d3748 !important;
        border-radius: 8px !important; color: #e2e8f0 !important;
        font-family: 'JetBrains Mono', monospace !important;
        height: 44px !important; font-size: 13px !important;
    }
    </style>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<div style='height:80px;'></div>", unsafe_allow_html=True)

        st.markdown("""
        <div style='text-align:center; margin-bottom:32px;'>
            <div style='font-size:56px; margin-bottom:16px;'>🛡️</div>
            <h1 style='font-size:24px; font-weight:700; color:#f8fafc;
                       letter-spacing:-0.02em; margin:0;'>SOAR Engine</h1>
            <p style='color:#475569; font-size:14px; margin:6px 0 0;'>Incident Containment Dashboard</p>
            <p style='color:#334155; font-size:12px; margin:4px 0 0;'>Infotact Solutions & Co. · 2026</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("""
        <div style='background:#1e2330; border:1px solid #2d3748;
                    border-radius:16px; padding:28px;'>
        """, unsafe_allow_html=True)

        st.markdown("<p style='color:#94a3b8; font-size:13px; margin:0 0 16px; font-weight:500;'>API Key</p>", unsafe_allow_html=True)

        with st.form("login_form", clear_on_submit=False):
            api_key = st.text_input(
                "API Key", type="password",
                placeholder="Enter your API key...",
                label_visibility="collapsed",
            )
            submitted = st.form_submit_button("Sign in", use_container_width=True)

            if submitted:
                if not api_key:
                    st.error("Please enter your API key.")
                elif login(api_key):
                    user = get_current_user()
                    st.success(f"Welcome back, {user['username']}!")
                    st.rerun()
                else:
                    st.error("Invalid API key. Please try again.")

        st.markdown("</div>", unsafe_allow_html=True)

        st.markdown("""
        <div style='margin-top:20px; background:#141720; border:1px solid #1e2330;
                    border-radius:10px; padding:16px;'>
            <p style='color:#475569; font-size:11px; font-weight:600;
                      text-transform:uppercase; letter-spacing:0.1em; margin:0 0 10px;'>Demo Access</p>
            <div style='display:flex; flex-direction:column; gap:6px;'>
                <div style='display:flex; justify-content:space-between;'>
                    <span style='color:#64748b; font-size:12px;'>Analyst</span>
                    <code style='color:#60a5fa; font-size:11px; background:#0c1a2e; padding:2px 8px; border-radius:4px;'>analyst-key-001</code>
                </div>
                <div style='display:flex; justify-content:space-between;'>
                    <span style='color:#64748b; font-size:12px;'>Senior Analyst</span>
                    <code style='color:#fb923c; font-size:11px; background:#1a0d00; padding:2px 8px; border-radius:4px;'>senior-key-001</code>
                </div>
                <div style='display:flex; justify-content:space-between;'>
                    <span style='color:#64748b; font-size:12px;'>Admin</span>
                    <code style='color:#f43f5e; font-size:11px; background:#1a0008; padding:2px 8px; border-radius:4px;'>admin-key-001</code>
                </div>
            </div>
        </div>
        """, unsafe_allow_html=True)
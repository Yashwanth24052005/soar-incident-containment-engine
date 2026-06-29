import streamlit as st
import requests
from components.cards import stat_card

API_BASE = "http://localhost:8000"

def render_home():
    st.title("🏠 Dashboard Overview")
    st.markdown("Welcome to the SOAR Incident Containment Engine dashboard.")

    # Fetch cases from FastAPI
    try:
        response = requests.get(f"{API_BASE}/cases", timeout=5)
        cases = response.json() if response.status_code == 200 else []
    except Exception:
        cases = []
        st.warning("⚠️ Could not connect to FastAPI backend. Showing mock data.")
        cases = [
            {"status": "open", "severity": "high"},
            {"status": "open", "severity": "medium"},
            {"status": "closed", "severity": "low"},
            {"status": "in_progress", "severity": "high"},
        ]

    total = len(cases)
    open_cases = sum(1 for c in cases if c.get("status") == "open")
    closed_cases = sum(1 for c in cases if c.get("status") == "closed")
    high_sev = sum(1 for c in cases if c.get("severity") == "high")

    col1, col2, col3, col4 = st.columns(4)
    with col1: stat_card("Total Cases", total, "#1f77b4")
    with col2: stat_card("Open", open_cases, "#ff7f0e")
    with col3: stat_card("Closed", closed_cases, "#2ca02c")
    with col4: stat_card("High Severity", high_sev, "#d62728")

    st.divider()
    st.subheader("📊 Case Status Breakdown")

    import pandas as pd
    import plotly.express as px

    df = pd.DataFrame(cases)
    if not df.empty and "status" in df.columns:
        fig = px.pie(df, names="status", title="Cases by Status",
                     color_discrete_sequence=px.colors.qualitative.Set2)
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No case data available to chart.")
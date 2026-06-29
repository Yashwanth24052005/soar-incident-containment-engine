import streamlit as st

def stat_card(label, value, color="#1f77b4"):
    st.markdown(f"""
    <div style="
        background-color: {color}22;
        border-left: 4px solid {color};
        padding: 16px 20px;
        border-radius: 8px;
        margin-bottom: 10px;
    ">
        <div style="font-size: 13px; color: #888;">{label}</div>
        <div style="font-size: 28px; font-weight: bold; color: {color};">{value}</div>
    </div>
    """, unsafe_allow_html=True)
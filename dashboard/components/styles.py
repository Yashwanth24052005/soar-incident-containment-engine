"""
Global CSS styles for the SOAR dashboard.
Dark security-ops theme with terminal-inspired monospace accents.
"""

GLOBAL_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

/* ── Base ───────────────────────────────────────────────────────────── */
html, body, [class*="css"] {
    font-family: 'Inter', system-ui, sans-serif;
}

/* Hide Streamlit default elements */
#MainMenu, footer, header { visibility: hidden; }
.stDeployButton { display: none; }
.block-container { padding-top: 1.5rem !important; padding-bottom: 2rem !important; }

/* ── Sidebar ────────────────────────────────────────────────────────── */
[data-testid="stSidebar"] {
    background: #0a0d14 !important;
    border-right: 1px solid #1e2330 !important;
}
[data-testid="stSidebar"] * { color: #e2e8f0 !important; }

/* ── Radio nav buttons ──────────────────────────────────────────────── */
[data-testid="stSidebar"] .stRadio label {
    display: block;
    padding: 10px 14px;
    border-radius: 8px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
    transition: background 0.15s;
    margin-bottom: 2px;
}
[data-testid="stSidebar"] .stRadio label:hover {
    background: #1e2330 !important;
}

/* ── Buttons ────────────────────────────────────────────────────────── */
.stButton > button {
    background: #1d4ed8 !important;
    color: white !important;
    border: none !important;
    border-radius: 8px !important;
    font-weight: 600 !important;
    font-size: 13px !important;
    padding: 8px 16px !important;
    transition: background 0.15s !important;
}
.stButton > button:hover {
    background: #2563eb !important;
}

/* ── Inputs ─────────────────────────────────────────────────────────── */
.stTextInput > div > div > input,
.stSelectbox > div > div,
.stTextArea > div > div > textarea {
    background: #1e2330 !important;
    border: 1px solid #2d3748 !important;
    border-radius: 8px !important;
    color: #e2e8f0 !important;
    font-family: 'Inter', sans-serif !important;
}
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus {
    border-color: #3b82f6 !important;
    box-shadow: 0 0 0 2px rgba(59,130,246,0.15) !important;
}

/* ── Expander ───────────────────────────────────────────────────────── */
.streamlit-expanderHeader {
    background: #1e2330 !important;
    border: 1px solid #2d3748 !important;
    border-radius: 8px !important;
    font-weight: 500 !important;
}
.streamlit-expanderContent {
    background: #141720 !important;
    border: 1px solid #2d3748 !important;
    border-top: none !important;
    border-radius: 0 0 8px 8px !important;
}

/* ── Dataframe ──────────────────────────────────────────────────────── */
[data-testid="stDataFrame"] {
    border: 1px solid #2d3748 !important;
    border-radius: 8px !important;
    overflow: hidden !important;
}

/* ── Divider ────────────────────────────────────────────────────────── */
hr { border-color: #1e2330 !important; margin: 1.5rem 0 !important; }

/* ── Metric ─────────────────────────────────────────────────────────── */
[data-testid="stMetric"] {
    background: #1e2330;
    border: 1px solid #2d3748;
    border-radius: 10px;
    padding: 16px !important;
}
[data-testid="stMetricValue"] { font-family: 'JetBrains Mono', monospace !important; }

/* ── Code / pre ─────────────────────────────────────────────────────── */
code {
    background: #1e2330 !important;
    color: #60a5fa !important;
    border-radius: 4px !important;
    padding: 1px 5px !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 12px !important;
}

/* ── Alert boxes ────────────────────────────────────────────────────── */
.stAlert { border-radius: 8px !important; border: none !important; }
.stSuccess { background: #052e16 !important; border-left: 4px solid #4ade80 !important; }
.stError   { background: #2d0000 !important; border-left: 4px solid #ff4444 !important; }
.stWarning { background: #2d1a00 !important; border-left: 4px solid #ff8c00 !important; }
.stInfo    { background: #0c1a2e !important; border-left: 4px solid #3b82f6 !important; }

/* ── Scrollbar ──────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: #0a0d14; }
::-webkit-scrollbar-thumb { background: #2d3748; border-radius: 3px; }
::-webkit-scrollbar-thumb:hover { background: #3d4a5e; }
</style>
"""


def page_header(title: str, subtitle: str = "", icon: str = ""):
    import streamlit as st
    st.markdown(f"""
    <div style='margin-bottom: 24px;'>
        <h1 style='font-size:28px; font-weight:700; color:#f8fafc;
                   margin:0; letter-spacing:-0.02em;'>
            {icon} {title}
        </h1>
        {f"<p style='color:#64748b; font-size:14px; margin:4px 0 0;'>{subtitle}</p>" if subtitle else ""}
    </div>
    """, unsafe_allow_html=True)


def section_header(title: str, subtitle: str = ""):
    import streamlit as st
    st.markdown(f"""
    <div style='margin: 8px 0 16px;'>
        <h3 style='font-size:16px; font-weight:600; color:#e2e8f0; margin:0;'>{title}</h3>
        {f"<p style='color:#64748b; font-size:12px; margin:2px 0 0;'>{subtitle}</p>" if subtitle else ""}
    </div>
    """, unsafe_allow_html=True)


def empty_state(message: str, hint: str = ""):
    import streamlit as st
    st.markdown(f"""
    <div style='background:#1e2330; border:1px dashed #2d3748;
                border-radius:12px; padding:40px; text-align:center; margin:16px 0;'>
        <p style='color:#94a3b8; font-size:14px; margin:0;'>{message}</p>
        {f"<p style='color:#475569; font-size:12px; margin:8px 0 0;'>{hint}</p>" if hint else ""}
    </div>
    """, unsafe_allow_html=True)
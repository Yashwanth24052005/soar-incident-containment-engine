"""
Cards Component - Reusable stat cards and UI elements.
"""

import streamlit as st


def metric_card(title: str, value, subtitle: str = "", color: str = "#60a5fa"):
    st.markdown(f"""
    <div style='background:#1e2330; border:1px solid #2d3748;
                border-radius:12px; padding:20px; text-align:center;
                margin-bottom:8px;'>
        <p style='color:#94a3b8; font-size:12px; margin:0;
                  text-transform:uppercase; letter-spacing:0.08em;'>{title}</p>
        <p style='color:{color}; font-size:32px; font-weight:700;
                  margin:8px 0 4px;'>{value}</p>
        <p style='color:#64748b; font-size:12px; margin:0;'>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    colors = {
        "critical": ("#ff4444", "#2d0000"),
        "high": ("#ff8c00", "#2d1a00"),
        "medium": ("#facc15", "#2d2500"),
        "low": ("#4ade80", "#002d0f"),
    }
    text_color, bg_color = colors.get(severity, ("#94a3b8", "#1e2330"))
    return f"""<span style='background:{bg_color}; color:{text_color};
               border:1px solid {text_color}; border-radius:4px;
               padding:2px 8px; font-size:11px; font-weight:700;'>
               {severity.upper()}</span>"""


def status_badge(status: str) -> str:
    colors = {
        "new": "#60a5fa",
        "investigating": "#facc15",
        "contained": "#fb923c",
        "resolved": "#4ade80",
        "false_positive": "#94a3b8",
    }
    color = colors.get(status, "#94a3b8")
    return f"""<span style='color:{color}; border:1px solid {color};
               border-radius:4px; padding:2px 8px; font-size:11px;
               font-weight:600;'>{status.replace("_", " ").upper()}</span>"""


def timeline_event_row(event: dict):
    from dashboard.rbac import EVENT_EMOJI
    event_type = event.get("event_type", "")
    emoji = EVENT_EMOJI.get(event_type, "📌")
    ts = event.get("timestamp", "")[:19]
    actor = event.get("actor", "system")
    summary = event.get("summary", "")
    success = event.get("success", True)
    status_icon = "✅" if success else "❌"

    st.markdown(f"""
    <div style='display:flex; gap:12px; padding:8px 0;
                border-bottom:1px solid #2d374844;'>
        <span style='font-size:18px;'>{emoji}</span>
        <div style='flex:1;'>
            <p style='margin:0; font-size:13px;'>{status_icon} {summary}</p>
            <p style='margin:0; color:#64748b; font-size:11px;'>
                {ts} | actor: {actor}
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)
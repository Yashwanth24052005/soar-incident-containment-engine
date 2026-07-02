"""
Cards Component - Polished reusable UI elements.
"""

import streamlit as st


def stat_card(title: str, value, subtitle: str = "", color: str = "#60a5fa", icon: str = ""):
    st.markdown(f"""
    <div style='background:#1e2330; border:1px solid #2d3748;
                border-radius:12px; padding:20px 24px;
                position:relative; overflow:hidden;'>
        <div style='position:absolute; top:0; left:0; width:3px;
                    height:100%; background:{color};'></div>
        <p style='color:#64748b; font-size:11px; font-weight:600; margin:0;
                  text-transform:uppercase; letter-spacing:0.1em;'>{icon} {title}</p>
        <p style='color:{color}; font-size:34px; font-weight:700; margin:6px 0 2px;
                  font-family:"JetBrains Mono",monospace; line-height:1;'>{value}</p>
        <p style='color:#475569; font-size:12px; margin:0;'>{subtitle}</p>
    </div>
    """, unsafe_allow_html=True)


def metric_card(title: str, value, subtitle: str = "", color: str = "#60a5fa"):
    stat_card(title, value, subtitle, color)


def alert_feed_card(alert: dict, status: str = "new"):
    severity = alert.get("severity", "unknown")
    attack_type = alert.get("attack_type", "unknown")
    source_ip = alert.get("source_ip", "N/A")
    alert_id = alert.get("alert_id", "N/A")
    received = alert.get("received_at", "")[:19]

    severity_config = {
        "critical": {"bg": "#1a0000", "border": "#ff4444", "badge_bg": "#2d0000", "emoji": "🔴"},
        "high":     {"bg": "#1a0d00", "border": "#ff8c00", "badge_bg": "#2d1a00", "emoji": "🟠"},
        "medium":   {"bg": "#1a1500", "border": "#facc15", "badge_bg": "#2d2500", "emoji": "🟡"},
        "low":      {"bg": "#001a08", "border": "#4ade80", "badge_bg": "#002d0f", "emoji": "🟢"},
    }
    cfg = severity_config.get(severity, {"bg": "#1e2330", "border": "#3d4a5e", "badge_bg": "#1e2330", "emoji": "⚪"})
    attack_label = attack_type.replace("_", " ").title()

    st.markdown(f"""
    <div style='background:{cfg["bg"]}; border:1px solid {cfg["border"]}33;
                border-left:3px solid {cfg["border"]}; border-radius:10px;
                padding:14px 16px; margin-bottom:8px;'>
        <div style='display:flex; justify-content:space-between; align-items:flex-start;'>
            <div style='flex:1;'>
                <div style='display:flex; align-items:center; gap:8px; margin-bottom:6px;'>
                    <span style='font-size:13px; font-weight:600; color:#f1f5f9;'>
                        {cfg["emoji"]} {attack_label}
                    </span>
                    <span style='background:{cfg["badge_bg"]}; color:{cfg["border"]};
                                 border:1px solid {cfg["border"]}55; border-radius:4px;
                                 padding:1px 7px; font-size:10px; font-weight:700;
                                 font-family:"JetBrains Mono",monospace;'>
                        {severity.upper()}
                    </span>
                </div>
                <div style='display:flex; gap:16px;'>
                    <span style='color:#64748b; font-size:12px; font-family:"JetBrains Mono",monospace;'>
                        {alert_id[:20]}
                    </span>
                    <span style='color:#94a3b8; font-size:12px; font-family:"JetBrains Mono",monospace;'>
                        {source_ip}
                    </span>
                </div>
            </div>
            <div style='text-align:right;'>
                <p style='color:#475569; font-size:11px; margin:0;'>{received.replace("T", " ")}</p>
                <p style='color:#64748b; font-size:11px; margin:2px 0 0;'>{status}</p>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)


def timeline_event_row(event: dict):
    from dashboard.rbac import EVENT_EMOJI
    event_type = event.get("event_type", "")
    emoji = EVENT_EMOJI.get(event_type, "📌")
    ts = event.get("timestamp", "")[:19].replace("T", " ")
    actor = event.get("actor", "system")
    summary = event.get("summary", "")
    success = event.get("success", True)
    status_color = "#4ade80" if success else "#ff4444"

    actor_color = {
        "system": "#64748b",
        "playbook": "#fb923c",
        "analyst": "#60a5fa",
    }.get(actor, "#94a3b8")

    st.markdown(f"""
    <div style='display:flex; gap:14px; padding:10px 0; border-bottom:1px solid #1e233088;'>
        <div style='width:24px; text-align:center; font-size:16px; padding-top:2px; flex-shrink:0;'>{emoji}</div>
        <div style='flex:1; min-width:0;'>
            <p style='margin:0; font-size:13px; color:#e2e8f0; line-height:1.4;'>
                <span style='color:{status_color}; margin-right:6px;'>●</span>{summary}
            </p>
            <p style='margin:3px 0 0; color:#475569; font-size:11px; font-family:"JetBrains Mono",monospace;'>
                {ts} <span style='color:{actor_color}; margin-left:8px;'>● {actor}</span>
            </p>
        </div>
    </div>
    """, unsafe_allow_html=True)


def severity_pill(severity: str) -> str:
    colors = {
        "critical": ("#ff4444", "#2d0000"),
        "high":     ("#ff8c00", "#2d1a00"),
        "medium":   ("#facc15", "#2d2500"),
        "low":      ("#4ade80", "#002d0f"),
    }
    c, bg = colors.get(severity, ("#94a3b8", "#1e2330"))
    return f"""<span style='background:{bg}; color:{c}; border:1px solid {c}55;
               border-radius:4px; padding:2px 8px; font-size:10px; font-weight:700;
               font-family:"JetBrains Mono",monospace;'>{severity.upper()}</span>"""


def status_pill(status: str) -> str:
    colors = {
        "new":            "#60a5fa",
        "investigating":  "#facc15",
        "contained":      "#fb923c",
        "resolved":       "#4ade80",
        "false_positive": "#94a3b8",
    }
    c = colors.get(status, "#94a3b8")
    return f"""<span style='color:{c}; border:1px solid {c}55; border-radius:4px;
               padding:2px 8px; font-size:10px; font-weight:600;
               font-family:"JetBrains Mono",monospace;'>{status.replace("_", " ").upper()}</span>"""


def ip_block_card(ip: str, data: dict, card_type: str = "blocked"):
    configs = {
        "blocked":     {"icon": "🚫", "color": "#ff4444", "label": "Blocked"},
        "isolated":    {"icon": "🔒", "color": "#fb923c", "label": "Isolated"},
        "monitored":   {"icon": "👁️", "color": "#facc15", "label": "Monitored"},
        "ratelimited": {"icon": "⚡", "color": "#a78bfa", "label": "Rate Limited"},
    }
    cfg = configs.get(card_type, configs["blocked"])
    since_key = {
        "blocked": "blocked_at",
        "isolated": "isolated_at",
        "ratelimited": "rate_limited_at",
        "monitored": "monitored_since",
    }.get(card_type, "blocked_at")
    since = data.get(since_key, "N/A")
    if since and since != "N/A":
        since = since[:19].replace("T", " ")

    st.markdown(f"""
    <div style='background:#1e2330; border:1px solid #2d3748;
                border-radius:10px; padding:14px 16px; margin-bottom:8px;'>
        <div style='display:flex; justify-content:space-between; align-items:center;'>
            <div>
                <span style='font-size:13px;'>{cfg["icon"]}</span>
                <code style='font-size:13px; margin-left:8px; color:#e2e8f0;'>{ip}</code>
            </div>
            <span style='color:{cfg["color"]}; font-size:11px; font-weight:600;
                         border:1px solid {cfg["color"]}44; border-radius:4px; padding:2px 8px;'>
                {cfg["label"]}
            </span>
        </div>
        <p style='color:#475569; font-size:11px; margin:6px 0 0; font-family:"JetBrains Mono",monospace;'>
            Since {since}
            {f" | Risk: {data.get('risk_level', '')}" if data.get('risk_level') else ""}
            {f" | Score: {data.get('composite_score', '')}" if data.get('composite_score') else ""}
        </p>
    </div>
    """, unsafe_allow_html=True)
ROLE_PAGES = {
    "analyst": ["🏠 Home", "🚨 Cases", "📋 Incidents"],
    "senior_analyst": ["🏠 Home", "🚨 Cases", "📋 Incidents", "🎯 Playbooks"],
    "admin": ["🏠 Home", "🚨 Cases", "📋 Incidents", "🎯 Playbooks", "⚙️ Admin"],
}

ROLE_COLORS = {
    "analyst": "#60a5fa",
    "senior_analyst": "#fb923c",
    "admin": "#f43f5e",
}

ROLE_BADGES = {
    "analyst": "🔵 Analyst",
    "senior_analyst": "🟠 Senior Analyst",
    "admin": "🔴 Admin",
}

SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff8c00",
    "medium": "#facc15",
    "low": "#4ade80",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "unknown": "⚪",
}

STATUS_EMOJI = {
    "new": "🆕",
    "investigating": "🔍",
    "contained": "🔒",
    "resolved": "✅",
    "false_positive": "❎",
}

EVENT_EMOJI = {
    "alert_ingested": "📥",
    "alert_deduplicated": "🔁",
    "enrichment_started": "🔄",
    "enrichment_complete": "🧠",
    "geolocation_complete": "📍",
    "risk_score_calculated": "📊",
    "playbook_triggered": "⚡",
    "playbook_complete": "🎯",
    "status_changed": "🔄",
    "slack_notified": "💬",
    "aws_block_applied": "🚫",
    "host_isolated": "🔒",
    "file_quarantined": "🗑️",
    "manual_action": "✍️",
}


def can_access_page(role: str, page: str) -> bool:
    return page in ROLE_PAGES.get(role, [])


def get_pages_for_role(role: str) -> list:
    return ROLE_PAGES.get(role, ["🏠 Home"])
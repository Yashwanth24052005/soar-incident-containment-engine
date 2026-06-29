ROLES = {
    "admin": {
        "label": "Admin",
        "permissions": ["view_cases", "edit_cases", "close_cases", "assign_cases", "view_admin", "delete_cases"]
    },
    "analyst": {
        "label": "SOC Analyst",
        "permissions": ["view_cases", "edit_cases", "close_cases", "assign_cases"]
    },
    "viewer": {
        "label": "Read-Only Viewer",
        "permissions": ["view_cases"]
    }
}

def has_permission(role: str, permission: str) -> bool:
    return permission in ROLES.get(role, {}).get("permissions", [])
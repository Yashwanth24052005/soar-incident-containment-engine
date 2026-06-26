"""
Role-Based Access Control (RBAC) - Week 3 Day 5
Controls access to high-impact playbook execution based on analyst role.
Roles:
- analyst: view alerts, timelines, stats. Cannot execute high-impact playbooks.
- senior_analyst: full access including high-impact playbook approval.
- admin: full access including user management.
"""

import logging
from datetime import datetime, timezone
from typing import Dict, Optional
from enum import Enum
from pydantic import BaseModel
from fastapi import HTTPException, status, Header

logger = logging.getLogger("soar.rbac")


class Role(str, Enum):
    ANALYST        = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    ADMIN          = "admin"


class User(BaseModel):
    username: str
    role: Role
    created_at: datetime


DEMO_USERS: Dict[str, Dict] = {
    "analyst-key-001": {
        "username": "john.doe",
        "role": Role.ANALYST,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    },
    "analyst-key-002": {
        "username": "jane.smith",
        "role": Role.ANALYST,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    },
    "senior-key-001": {
        "username": "alice.senior",
        "role": Role.SENIOR_ANALYST,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    },
    "senior-key-002": {
        "username": "bob.senior",
        "role": Role.SENIOR_ANALYST,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    },
    "admin-key-001": {
        "username": "admin",
        "role": Role.ADMIN,
        "created_at": datetime(2026, 1, 1, tzinfo=timezone.utc),
    },
}

HIGH_IMPACT_PLAYBOOKS = ["BruteForceContainment", "MalwareContainment"]
SENIOR_APPROVAL_THRESHOLD = 70


def get_current_user(x_api_key: Optional[str] = Header(None)) -> User:
    """Validates the API key from X-API-Key header. Returns authenticated user or raises 401."""
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Pass your key via X-API-Key header.",
        )
    if x_api_key not in DEMO_USERS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key.",
        )
    user_data = DEMO_USERS[x_api_key]
    logger.info(f"[RBAC] Authenticated | user={user_data['username']} | role={user_data['role']}")
    return User(**user_data)


def require_senior_analyst(x_api_key: Optional[str] = Header(None)) -> User:
    """Requires senior analyst or admin role. Raises 403 for regular analysts."""
    user = get_current_user(x_api_key)
    if user.role == Role.ANALYST:
        logger.warning(f"[RBAC] Access denied | user={user.username} | role={user.role}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied. Requires Senior Analyst or Admin role. Your role: {user.role.value}.",
        )
    logger.info(f"[RBAC] Senior access granted | user={user.username} | role={user.role}")
    return user


def check_playbook_permission(user: User, playbook_name: str, composite_score: int) -> bool:
    """Checks if user can execute a playbook based on role and risk score."""
    is_high_impact = (
        playbook_name in HIGH_IMPACT_PLAYBOOKS
        and composite_score >= SENIOR_APPROVAL_THRESHOLD
    )
    if is_high_impact and user.role == Role.ANALYST:
        logger.warning(
            f"[RBAC] Playbook denied | user={user.username} | "
            f"playbook={playbook_name} | score={composite_score}"
        )
        return False
    return True


def get_rbac_summary() -> dict:
    """Returns a summary of RBAC configuration."""
    role_counts = {}
    for user_data in DEMO_USERS.values():
        role = user_data["role"]
        role_counts[role] = role_counts.get(role, 0) + 1
    return {
        "total_users": len(DEMO_USERS),
        "roles": role_counts,
        "high_impact_playbooks": HIGH_IMPACT_PLAYBOOKS,
        "senior_approval_threshold": SENIOR_APPROVAL_THRESHOLD,
        "available_roles": [r.value for r in Role],
    }
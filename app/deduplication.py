"""
Alert Deduplication - Advanced Feature
Prevents the same IP from flooding the engine with duplicate alerts.
If the same source IP triggers alerts within a 5 minute window,
duplicates are suppressed and the count is updated instead.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Tuple

logger = logging.getLogger("soar.deduplication")

DEDUP_WINDOW_MINUTES = 5

# In-memory dedup cache: {source_ip: (first_seen, count)}
_dedup_cache: Dict[str, Tuple[datetime, int]] = {}


def is_duplicate(source_ip: str) -> Tuple[bool, int]:
    """
    Checks if an alert from this IP is a duplicate within the dedup window.
    Returns (is_duplicate, occurrence_count).
    """
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DEDUP_WINDOW_MINUTES)

    if source_ip in _dedup_cache:
        first_seen, count = _dedup_cache[source_ip]
        if first_seen >= window_start:
            _dedup_cache[source_ip] = (first_seen, count + 1)
            logger.warning(
                f"[DEDUP] Duplicate alert suppressed for {source_ip} | "
                f"occurrence={count + 1} | window={DEDUP_WINDOW_MINUTES}min"
            )
            return True, count + 1
        else:
            _dedup_cache[source_ip] = (now, 1)
            return False, 1
    else:
        _dedup_cache[source_ip] = (now, 1)
        return False, 1


def get_dedup_stats() -> dict:
    """Returns current deduplication cache stats."""
    now = datetime.now(timezone.utc)
    window_start = now - timedelta(minutes=DEDUP_WINDOW_MINUTES)
    active = {
        ip: {"first_seen": str(first_seen), "count": count}
        for ip, (first_seen, count) in _dedup_cache.items()
        if first_seen >= window_start
    }
    return {
        "dedup_window_minutes": DEDUP_WINDOW_MINUTES,
        "active_entries": len(active),
        "entries": active,
    }
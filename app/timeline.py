"""
Case Management Timeline - Week 3 Day 4
Records every automated action taken by the SOAR engine
in a chronological timeline per alert.
Used by the Week 4 dashboard for case management visibility.
"""

import logging
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional
from enum import Enum
from pydantic import BaseModel

logger = logging.getLogger("soar.timeline")


# ─── Timeline event types ─────────────────────────────────────────────────────

class EventType(str, Enum):
    ALERT_INGESTED        = "alert_ingested"
    ALERT_DEDUPLICATED    = "alert_deduplicated"
    ENRICHMENT_STARTED    = "enrichment_started"
    ENRICHMENT_COMPLETE   = "enrichment_complete"
    GEOLOCATION_COMPLETE  = "geolocation_complete"
    RISK_SCORE_CALCULATED = "risk_score_calculated"
    PLAYBOOK_TRIGGERED    = "playbook_triggered"
    PLAYBOOK_COMPLETE     = "playbook_complete"
    STATUS_CHANGED        = "status_changed"
    SLACK_NOTIFIED        = "slack_notified"
    AWS_BLOCK_APPLIED     = "aws_block_applied"
    HOST_ISOLATED         = "host_isolated"
    FILE_QUARANTINED      = "file_quarantined"
    MANUAL_ACTION         = "manual_action"


# ─── Timeline event schema ────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    """A single event in the alert timeline."""
    event_id: str
    alert_id: str
    event_type: EventType
    timestamp: datetime
    actor: str
    summary: str
    details: Optional[Dict] = None
    success: bool = True


class AlertTimeline(BaseModel):
    """Complete timeline for a single alert."""
    alert_id: str
    total_events: int
    first_seen: datetime
    last_updated: datetime
    events: List[TimelineEvent]


# ─── In-memory timeline store ─────────────────────────────────────────────────
_timelines: Dict[str, List[TimelineEvent]] = {}


# ─── Timeline management functions ───────────────────────────────────────────

def add_event(
    alert_id: str,
    event_type: EventType,
    summary: str,
    actor: str = "system",
    details: Optional[Dict] = None,
    success: bool = True,
) -> TimelineEvent:
    """
    Adds a new event to the alert's timeline.
    Creates the timeline if it doesn't exist yet.
    """
    event = TimelineEvent(
        event_id=str(uuid.uuid4())[:8],
        alert_id=alert_id,
        event_type=event_type,
        timestamp=datetime.now(timezone.utc),
        actor=actor,
        summary=summary,
        details=details,
        success=success,
    )

    if alert_id not in _timelines:
        _timelines[alert_id] = []

    _timelines[alert_id].append(event)

    logger.info(
        f"[TIMELINE] alert_id={alert_id} | "
        f"event={event_type.value} | "
        f"summary={summary}"
    )

    return event


def get_timeline(alert_id: str) -> Optional[AlertTimeline]:
    """Returns the complete timeline for an alert."""
    if alert_id not in _timelines:
        return None

    events = _timelines[alert_id]
    return AlertTimeline(
        alert_id=alert_id,
        total_events=len(events),
        first_seen=events[0].timestamp,
        last_updated=events[-1].timestamp,
        events=events,
    )


def get_all_timelines() -> List[AlertTimeline]:
    """Returns timelines for all alerts, most recently updated first."""
    timelines = []
    for alert_id in _timelines:
        timeline = get_timeline(alert_id)
        if timeline:
            timelines.append(timeline)
    return sorted(timelines, key=lambda t: t.last_updated, reverse=True)


def get_timeline_stats() -> dict:
    """Returns summary statistics across all timelines."""
    total_events = sum(len(events) for events in _timelines.values())
    event_counts = {}
    for events in _timelines.values():
        for event in events:
            et = event.event_type.value
            event_counts[et] = event_counts.get(et, 0) + 1

    return {
        "total_alerts_tracked": len(_timelines),
        "total_events_recorded": total_events,
        "events_by_type": event_counts,
    }
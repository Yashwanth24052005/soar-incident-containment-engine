"""
Alerts Router - Week 2 Day 5
Wires the complete Week 2 pipeline into the ingest endpoint:
  - Rate limiting  (rate_limiter)   → blocks abusive clients
  - Deduplication  (deduplication)  → suppresses repeated alerts from the same IP
  - Full enrichment (background)    → geo + AbuseIPDB + VirusTotal + Slack, all async
"""

import logging
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status

from app.models.alert import RawSIEMAlert, NormalizedAlert, SeverityLevel, AttackType
from app.normalizer import normalize_alert
from app.store import alert_store, AlertStatus, update_alert_status, get_alert_status, get_all_statuses, get_dedup_stats_from_store
from app.rate_limiter import check_rate_limit
from app.deduplication import is_duplicate, get_dedup_stats
from app.background import auto_enrich_alert

logger = logging.getLogger("soar.router.alerts")

router = APIRouter()


# ── Ingest ────────────────────────────────────────────────────────────────────

@router.post(
    "/alerts/ingest",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest a raw SIEM alert",
    description=(
        "Accepts a raw webhook payload from any SIEM vendor. "
        "The engine normalizes the payload, checks for duplicates, "
        "stores the alert, then launches the full enrichment pipeline "
        "(AbuseIPDB + VirusTotal + Geolocation + Slack) in the background."
    ),
)
async def ingest_alert(
    raw: RawSIEMAlert,
    background_tasks: BackgroundTasks,
    request: Request,
):
    # ── Gate 1: Rate limiting ─────────────────────────────────────────────────
    check_rate_limit(request)

    # ── Gate 2: Normalize the raw payload ────────────────────────────────────
    normalized = normalize_alert(raw)

    # ── Gate 3: Deduplication check ──────────────────────────────────────────
    duplicate, occurrence = is_duplicate(normalized.source_ip)

    if duplicate:
        logger.warning(
            f"[INGEST] Duplicate suppressed | ip={normalized.source_ip} | "
            f"occurrence={occurrence} | alert_id={normalized.alert_id}"
        )
        return {
            "status": "duplicate_suppressed",
            "message": (
                f"Alert from {normalized.source_ip} was suppressed. "
                f"This is occurrence #{occurrence} within the deduplication window."
            ),
            "alert_id": normalized.alert_id,
            "source_ip": normalized.source_ip,
            "occurrence": occurrence,
        }

    # ── Store the normalized alert ────────────────────────────────────────────
    alert_store.add(normalized)

    logger.info(
        f"[INGEST] Alert accepted | alert_id={normalized.alert_id} | "
        f"src={normalized.source_ip} | type={normalized.attack_type.value} | "
        f"severity={normalized.severity.value}"
    )

    # ── Launch full enrichment pipeline in the background ────────────────────
    background_tasks.add_task(
        auto_enrich_alert,
        alert_id=normalized.alert_id,
        source_ip=normalized.source_ip,
        attack_type=normalized.attack_type.value,
        severity=normalized.severity.value,
        file_hash=normalized.file_hash,
    )

    return {
        "status": "accepted",
        "message": "Alert ingested and enrichment pipeline started.",
        "alert_id": normalized.alert_id,
        "source_ip": normalized.source_ip,
        "attack_type": normalized.attack_type.value,
        "severity": normalized.severity.value,
        "iocs": normalized.iocs,
        "enrichment": "running in background (AbuseIPDB + VirusTotal + Geolocation + Slack)",
    }


# ── List alerts ───────────────────────────────────────────────────────────────

```python
@router.get(
    "/alerts",
    summary="List normalized alerts",
    description="Returns stored alerts with advanced filtering and search capabilities.",
)
def list_alerts(
    severity: SeverityLevel = None,
    attack_type: AttackType = None,
    source_ip: str = None,
    status_filter: str = None,
    keyword: str = None,
    limit: int = 50,
):
    """
    Advanced alert search endpoint.

    Supported filters:
    - severity
    - attack_type
    - source_ip
    - alert status
    - keyword search in description
    """

    alerts = alert_store.get_all()

    if severity:
        alerts = [a for a in alerts if a.severity == severity]

    if attack_type:
        alerts = [a for a in alerts if a.attack_type == attack_type]

    if source_ip:
        alerts = [a for a in alerts if a.source_ip == source_ip]

    if status_filter:
        alerts = [
            a for a in alerts
            if get_alert_status(a.alert_id) == status_filter
        ]

    if keyword:
        keyword_lower = keyword.lower()

        alerts = [
            a for a in alerts
            if (
                keyword_lower in (a.description or "").lower()
                or keyword_lower in a.source_ip.lower()
                or keyword_lower in a.attack_type.value.lower()
                or keyword_lower in a.severity.value.lower()
            )
        ]

    alerts = alerts[:limit]

    return {
        "total": len(alerts),
        "filters": {
            "severity": severity.value if severity else None,
            "attack_type": attack_type.value if attack_type else None,
            "source_ip": source_ip,
            "status": status_filter,
            "keyword": keyword,
            "limit": limit,
        },
        "alerts": alerts,
    }
```



# ── Single alert ──────────────────────────────────────────────────────────────

@router.get(
    "/alerts/{alert_id}",
    summary="Get a single alert by ID",
)
def get_alert(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )
    return {
        "alert": alert,
        "status": get_alert_status(alert_id),
    }


# ── Update alert status ───────────────────────────────────────────────────────

@router.patch(
    "/alerts/{alert_id}/status",
    summary="Update alert investigation status",
    description=(
        "Allows SOC analysts to move an alert through the workflow: "
        "new → investigating → contained → resolved / false_positive."
    ),
)
def update_status(alert_id: str, new_status: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found.",
        )

    valid = [s.value for s in AlertStatus]
    if new_status not in valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status '{new_status}'. Choose from: {valid}",
        )

    update_alert_status(alert_id, new_status)
    logger.info(f"[STATUS] alert_id={alert_id} → {new_status}")
    return {
        "alert_id": alert_id,
        "status": new_status,
        "message": f"Alert status updated to '{new_status}'.",
    }


# ── Stats ─────────────────────────────────────────────────────────────────────

@router.get(
    "/alerts/stats",
    summary="Engine health and alert statistics",
    description="Returns ingestion counts, severity/attack-type breakdown, and deduplication cache stats.",
)
def get_stats():
    return {
        "engine": "SentinelX SOAR — Week 2 Day 5",
        "pipeline_modules": [
            "rate_limiter",
            "deduplication",
            "normalizer",
            "enricher (AbuseIPDB)",
            "virustotal",
            "geolocation",
            "risk_scorer",
            "notifier (Slack)",
        ],
        "alert_stats": alert_store.stats(),
        "deduplication": get_dedup_stats(),
        "statuses": get_all_statuses(),
    }
"""
Alerts Router - Webhook ingestion endpoint
Receives raw SIEM alerts, normalizes them, stores in memory for now (Week 2 will add DB)
"""

import logging
from fastapi import APIRouter, HTTPException, status, Query
from typing import List, Optional

from app.models.alert import RawSIEMAlert, NormalizedAlert, AlertResponse, AttackType, SeverityLevel
from app.normalizer import normalize_alert

logger = logging.getLogger("soar.alerts")
router = APIRouter()

# In-memory store for Week 1 (replaced with DB in Week 2)
_alert_store: List[NormalizedAlert] = []

# Rejected alert counter for monitoring
_rejected_count = 0


def _validate_payload(payload: RawSIEMAlert) -> None:
    """
    Validates the incoming SIEM payload before normalization.
    Raises HTTPException if the payload is missing critical fields
    or contains clearly invalid data.
    """
    # Must have at least one IP field
    has_ip = any([
        payload.src_ip,
        payload.source_ip,
        payload.sourceIPAddress,
    ])
    if not has_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one IP field (src_ip, source_ip, or sourceIPAddress)."
        )

    # Must have at least one description field
    has_description = any([
        payload.alert_type,
        payload.event_type,
        payload.message,
        payload.description,
    ])
    if not has_description:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one descriptive field (alert_type, event_type, message, or description)."
        )


@router.post(
    "/alerts/ingest",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest raw SIEM webhook alert"
)
async def ingest_alert(payload: RawSIEMAlert):
    """
    Accepts a raw SIEM webhook payload in any format.
    Validates, normalizes, and stores it.
    This endpoint acts as the SOAR listener.
    """
    global _rejected_count

    # Validate before normalizing
    try:
        _validate_payload(payload)
    except HTTPException as e:
        _rejected_count += 1
        logger.warning(f"[REJECTED] Invalid payload: {e.detail}")
        raise

    try:
        normalized = normalize_alert(payload)
        _alert_store.append(normalized)

        logger.info(
            f"[INGESTED] alert_id={normalized.alert_id} | "
            f"type={normalized.attack_type.value} | "
            f"severity={normalized.severity.value} | "
            f"src={normalized.source_ip}"
        )

        return AlertResponse(
            success=True,
            message="Alert ingested and normalized successfully.",
            alert_id=normalized.alert_id,
            normalized_alert=normalized
        )

    except HTTPException:
        raise
    except Exception as e:
        _rejected_count += 1
        logger.error(f"[ERROR] Normalization failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Alert normalization failed: {str(e)}"
        )


@router.get(
    "/alerts",
    response_model=List[NormalizedAlert],
    summary="List all ingested and normalized alerts"
)
async def list_alerts(
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity level"),
    attack_type: Optional[AttackType] = Query(None, description="Filter by attack type"),
    limit: int = Query(50, ge=1, le=500, description="Max number of alerts to return"),
):
    """
    Returns normalized alerts. Supports optional filtering by severity and attack type.
    """
    results = _alert_store

    if severity:
        results = [a for a in results if a.severity == severity]

    if attack_type:
        results = [a for a in results if a.attack_type == attack_type]

    # Return most recent first
    return list(reversed(results))[:limit]


@router.get(
    "/alerts/stats",
    summary="Get alert ingestion statistics"
)
async def get_stats():
    """Returns a summary of all ingested alerts — useful for monitoring the SOAR engine."""
    if not _alert_store:
        return {
            "total_ingested": 0,
            "total_rejected": _rejected_count,
            "by_severity": {},
            "by_attack_type": {},
        }

    by_severity = {}
    by_attack_type = {}

    for alert in _alert_store:
        sev = alert.severity.value
        atk = alert.attack_type.value
        by_severity[sev] = by_severity.get(sev, 0) + 1
        by_attack_type[atk] = by_attack_type.get(atk, 0) + 1

    return {
        "total_ingested": len(_alert_store),
        "total_rejected": _rejected_count,
        "by_severity": by_severity,
        "by_attack_type": by_attack_type,
    }


@router.get(
    "/alerts/{alert_id}",
    response_model=NormalizedAlert,
    summary="Get a specific normalized alert by ID"
)
async def get_alert(alert_id: str):
    """Fetch a specific alert by its ID."""
    for alert in _alert_store:
        if alert.alert_id == alert_id:
            return alert
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Alert '{alert_id}' not found."
    )
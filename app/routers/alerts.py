"""
Alerts Router - Webhook ingestion endpoint
Receives raw SIEM alerts, normalizes them, stores in memory for now (Week 2 will add DB)
"""

import logging
from fastapi import APIRouter, HTTPException, status
from typing import List

from app.models.alert import RawSIEMAlert, NormalizedAlert, AlertResponse
from app.normalizer import normalize_alert

logger = logging.getLogger("soar.alerts")
router = APIRouter()

# In-memory store for Week 1 (replaced with DB in Week 2)
_alert_store: List[NormalizedAlert] = []


@router.post(
    "/alerts/ingest",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest raw SIEM webhook alert"
)
async def ingest_alert(payload: RawSIEMAlert):
    """
    Accepts a raw SIEM webhook payload in any format.
    Normalizes it into the standard schema and stores it.
    This endpoint acts as the SOAR listener.
    """
    try:
        normalized = normalize_alert(payload)
        _alert_store.append(normalized)

        logger.info(
            f"Alert ingested: {normalized.alert_id} | "
            f"{normalized.attack_type.value} | {normalized.severity.value}"
        )

        return AlertResponse(
            success=True,
            message=f"Alert ingested and normalized successfully.",
            alert_id=normalized.alert_id,
            normalized_alert=normalized
        )

    except Exception as e:
        logger.error(f"Failed to normalize alert: {e}")
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Alert normalization failed: {str(e)}"
        )


@router.get(
    "/alerts",
    response_model=List[NormalizedAlert],
    summary="List all ingested and normalized alerts"
)
async def list_alerts():
    """Returns all normalized alerts ingested so far (in-memory, resets on restart)."""
    return _alert_store


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

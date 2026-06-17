"""
Alerts Router - Webhook ingestion endpoint
Receives raw SIEM alerts, normalizes them, and persists them via AlertStore.
Auto-enrichment runs in the background after every ingestion.
"""

import logging
import asyncio
from fastapi import APIRouter, HTTPException, status, Query, BackgroundTasks
from typing import List, Optional

from app.models.alert import RawSIEMAlert, NormalizedAlert, AlertResponse, AttackType, SeverityLevel
from app.normalizer import normalize_alert
from app.store import alert_store
from app.enricher import enrich_alert, EnrichedAlert
from app.virustotal import lookup_hash, HashReputation
from app.risk_scorer import calculate_composite_score, CompositeRiskScore
from app.background import auto_enrich_alert

logger = logging.getLogger("soar.alerts")
router = APIRouter()


def _validate_payload(payload: RawSIEMAlert) -> None:
    has_ip = any([payload.src_ip, payload.source_ip, payload.sourceIPAddress])
    if not has_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one IP field (src_ip, source_ip, or sourceIPAddress)."
        )
    has_description = any([payload.alert_type, payload.event_type, payload.message, payload.description])
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
async def ingest_alert(payload: RawSIEMAlert, background_tasks: BackgroundTasks):
    """
    Accepts a raw SIEM webhook payload in any format.
    Validates, normalizes, persists to disk, and returns the normalized alert.
    Automatically triggers threat enrichment in the background.
    """
    try:
        _validate_payload(payload)
    except HTTPException as e:
        alert_store.increment_rejected()
        logger.warning(f"[REJECTED] Invalid payload: {e.detail}")
        raise

    try:
        normalized = normalize_alert(payload)
        alert_store.add(normalized)

        # Trigger background enrichment without blocking the response
        background_tasks.add_task(
            auto_enrich_alert,
            alert_id=normalized.alert_id,
            source_ip=normalized.source_ip,
            file_hash=normalized.file_hash,
        )

        logger.info(
            f"[INGESTED] alert_id={normalized.alert_id} | "
            f"type={normalized.attack_type.value} | "
            f"severity={normalized.severity.value} | "
            f"src={normalized.source_ip} | "
            f"background_enrichment=queued"
        )

        return AlertResponse(
            success=True,
            message="Alert ingested and normalized. Threat enrichment running in background.",
            alert_id=normalized.alert_id,
            normalized_alert=normalized
        )

    except HTTPException:
        raise
    except Exception as e:
        alert_store.increment_rejected()
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
    """Returns normalized alerts with optional filtering. Most recent first."""
    return alert_store.filter(severity=severity, attack_type=attack_type, limit=limit)


@router.get(
    "/alerts/stats",
    summary="Get alert ingestion statistics"
)
async def get_stats():
    """Returns a live summary of all ingested alerts."""
    return alert_store.stats()


@router.get(
    "/alerts/{alert_id}",
    response_model=NormalizedAlert,
    summary="Get a specific normalized alert by ID"
)
async def get_alert(alert_id: str):
    """Fetch a specific alert by its ID."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found."
        )
    return alert


# ─── Week 2 Day 1: AbuseIPDB Enrichment ──────────────────────────────────────

@router.post(
    "/alerts/{alert_id}/enrich",
    response_model=EnrichedAlert,
    summary="Enrich an alert with AbuseIPDB threat intelligence"
)
async def enrich_alert_endpoint(alert_id: str):
    """
    Queries AbuseIPDB for the reputation of the alert's source IP.
    Returns abuse confidence score, risk level, ISP, country, and recommended action.
    Requires ABUSEIPDB_API_KEY to be set in the .env file.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found."
        )
    enriched = await enrich_alert(alert.alert_id, alert.source_ip)
    return enriched


# ─── Week 2 Day 2: VirusTotal Hash Lookup ────────────────────────────────────

@router.post(
    "/alerts/{alert_id}/scan-hash",
    response_model=HashReputation,
    summary="Scan alert file hash against VirusTotal"
)
async def scan_hash_endpoint(alert_id: str):
    """
    Queries VirusTotal for the reputation of the file hash in a malware alert.
    Returns detection ratio, threat label, and risk level.
    Requires VIRUSTOTAL_API_KEY to be set in the .env file.
    Only works for alerts that contain a file_hash field.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found."
        )
    if not alert.file_hash:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Alert '{alert_id}' does not contain a file hash. Only malware alerts have hashes."
        )
    result = await lookup_hash(alert.file_hash)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="VirusTotal lookup failed. Check your API key in .env file."
        )
    return result


# ─── Week 2 Day 3: Composite Risk Score ──────────────────────────────────────

@router.post(
    "/alerts/{alert_id}/risk-score",
    response_model=CompositeRiskScore,
    summary="Calculate composite risk score using all threat intelligence sources"
)
async def risk_score_endpoint(alert_id: str):
    """
    Runs a full threat assessment by querying both AbuseIPDB and VirusTotal
    in parallel, then combines them into a single composite risk score
    with a recommended containment action.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert '{alert_id}' not found."
        )

    tasks = [enrich_alert(alert.alert_id, alert.source_ip)]
    if alert.file_hash:
        tasks.append(lookup_hash(alert.file_hash))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    enriched = results[0] if not isinstance(results[0], Exception) else None
    hash_rep = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else None
    ip_rep = enriched.ip_reputation if enriched else None

    score = calculate_composite_score(
        alert_id=alert.alert_id,
        source_ip=alert.source_ip,
        file_hash=alert.file_hash,
        ip_reputation=ip_rep,
        hash_reputation=hash_rep,
    )

    return score
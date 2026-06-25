"""
Alerts Router - Webhook ingestion endpoint
Receives raw SIEM alerts, normalizes them, and persists them via AlertStore.
Full pipeline with case management timeline recording.
"""

import logging
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, Query, BackgroundTasks, Request
from typing import List, Optional

from app.models.alert import RawSIEMAlert, NormalizedAlert, AlertResponse, AttackType, SeverityLevel
from app.normalizer import normalize_alert
from app.store import alert_store, get_alert_status, update_alert_status, get_all_statuses, AlertStatus
from app.enricher import enrich_alert, EnrichedAlert
from app.virustotal import lookup_hash, HashReputation
from app.risk_scorer import calculate_composite_score, CompositeRiskScore
from app.background import auto_enrich_alert
from app.deduplication import is_duplicate, get_dedup_stats
from app.rate_limiter import check_rate_limit
from app.geolocation import get_geolocation, GeoLocation
from app.playbook_engine import execute_playbook, get_execution_log, get_execution_stats
from app.playbooks.brute_force import get_blocked_ips
from app.playbooks.malware import get_isolated_hosts
from app.playbooks.port_scan import get_rate_limited_ips, get_monitored_ips
from app.aws_integration import get_aws_blocked_ips, unblock_ip_in_security_group
from app.timeline import add_event, get_timeline, get_all_timelines, get_timeline_stats, EventType

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


# ─── Alert Ingestion ──────────────────────────────────────────────────────────

@router.post(
    "/alerts/ingest",
    response_model=AlertResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest raw SIEM webhook alert"
)
async def ingest_alert(
    payload: RawSIEMAlert,
    background_tasks: BackgroundTasks,
    request: Request,
):
    """
    Accepts a raw SIEM webhook payload.
    Pipeline: validate → deduplicate → normalize → persist →
    background(enrich + geolocate + risk score + playbook + timeline + notify)
    """
    check_rate_limit(request)

    try:
        _validate_payload(payload)
    except HTTPException as e:
        alert_store.increment_rejected()
        logger.warning(f"[REJECTED] Invalid payload: {e.detail}")
        raise

    try:
        normalized = normalize_alert(payload)

        duplicate, occurrence = is_duplicate(normalized.source_ip)
        if duplicate:
            add_event(
                alert_id=normalized.alert_id,
                event_type=EventType.ALERT_DEDUPLICATED,
                summary=f"Duplicate suppressed. Same IP seen {occurrence} times in last 5 minutes.",
            )
            return AlertResponse(
                success=False,
                message=f"Duplicate alert suppressed. Same IP seen {occurrence} times in last 5 minutes.",
                alert_id=normalized.alert_id,
                normalized_alert=normalized
            )

        alert_store.add(normalized)

        # Record alert ingestion in timeline
        add_event(
            alert_id=normalized.alert_id,
            event_type=EventType.ALERT_INGESTED,
            summary=f"Alert ingested: {normalized.attack_type.value} from {normalized.source_ip} | severity={normalized.severity.value}",
            details={
                "source_ip": normalized.source_ip,
                "attack_type": normalized.attack_type.value,
                "severity": normalized.severity.value,
                "hostname": normalized.hostname,
                "file_hash": normalized.file_hash,
            }
        )

        background_tasks.add_task(
            auto_enrich_alert,
            alert_id=normalized.alert_id,
            source_ip=normalized.source_ip,
            attack_type=normalized.attack_type.value,
            severity=normalized.severity.value,
            hostname=normalized.hostname,
            file_hash=normalized.file_hash,
        )

        logger.info(
            f"[INGESTED] alert_id={normalized.alert_id} | "
            f"type={normalized.attack_type.value} | "
            f"severity={normalized.severity.value} | "
            f"src={normalized.source_ip}"
        )

        return AlertResponse(
            success=True,
            message="Alert ingested. Enrichment and playbook execution running in background.",
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


# ─── Alert Listing + Date Range Search ───────────────────────────────────────

@router.get(
    "/alerts",
    response_model=List[NormalizedAlert],
    summary="List alerts with optional filters and date range search"
)
async def list_alerts(
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity level"),
    attack_type: Optional[AttackType] = Query(None, description="Filter by attack type"),
    limit: int = Query(50, ge=1, le=500, description="Max number of alerts to return"),
    from_date: Optional[str] = Query(None, description="Start date filter (YYYY-MM-DD)"),
    to_date: Optional[str] = Query(None, description="End date filter (YYYY-MM-DD)"),
):
    """Returns normalized alerts with optional filtering. Most recent first."""
    results = alert_store.filter(severity=severity, attack_type=attack_type, limit=500)

    if from_date:
        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            results = [a for a in results if a.received_at >= from_dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date format. Use YYYY-MM-DD.")

    if to_date:
        try:
            to_dt = datetime.strptime(to_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            results = [a for a in results if a.received_at <= to_dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date format. Use YYYY-MM-DD.")

    return results[:limit]


# ─── Stats ────────────────────────────────────────────────────────────────────

@router.get("/alerts/stats", summary="Get alert ingestion statistics")
async def get_stats():
    return alert_store.stats()


@router.get("/alerts/dedup-stats", summary="Get deduplication cache statistics")
async def dedup_stats():
    return get_dedup_stats()


@router.get("/alerts/statuses", summary="Get status of all alerts")
async def get_statuses():
    return get_all_statuses()


# ─── Timeline Endpoints ───────────────────────────────────────────────────────

@router.get("/timeline", summary="Get all alert timelines")
async def all_timelines():
    """Returns chronological timelines for all alerts. Most recently updated first."""
    return get_all_timelines()


@router.get("/timeline/stats", summary="Get timeline statistics")
async def timeline_stats():
    """Returns summary statistics across all alert timelines."""
    return get_timeline_stats()


@router.get("/timeline/{alert_id}", summary="Get timeline for a specific alert")
async def alert_timeline(alert_id: str):
    """
    Returns the complete chronological timeline of all automated
    actions taken for a specific alert.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    timeline = get_timeline(alert_id)
    if not timeline:
        return {"alert_id": alert_id, "message": "No timeline events recorded yet.", "events": []}

    return timeline


@router.post("/timeline/{alert_id}/note", summary="Add manual note to alert timeline")
async def add_timeline_note(alert_id: str, note: str = Query(..., description="Note to add to the timeline")):
    """
    Allows a SOC analyst to add a manual note to an alert's timeline.
    Useful for documenting investigation steps and decisions.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    event = add_event(
        alert_id=alert_id,
        event_type=EventType.MANUAL_ACTION,
        summary=f"Analyst note: {note}",
        actor="analyst",
        details={"note": note},
    )

    return {"message": "Note added to timeline.", "event_id": event.event_id}


# ─── Playbook Endpoints ───────────────────────────────────────────────────────

@router.get("/playbooks/log", summary="Get playbook execution audit log")
async def playbook_log():
    return get_execution_log()


@router.get("/playbooks/stats", summary="Get playbook execution statistics")
async def playbook_stats():
    return get_execution_stats()


@router.get("/playbooks/blocked-ips", summary="Get IPs blocked by brute force playbook")
async def blocked_ips():
    return get_blocked_ips()


@router.get("/playbooks/isolated-hosts", summary="Get hosts isolated by malware playbook")
async def isolated_hosts():
    return get_isolated_hosts()


@router.get("/playbooks/rate-limited-ips", summary="Get rate limited IPs")
async def rate_limited_ips():
    return get_rate_limited_ips()


@router.get("/playbooks/monitored-ips", summary="Get IPs under enhanced monitoring")
async def monitored_ips():
    return get_monitored_ips()


@router.get("/playbooks/aws-blocked-ips", summary="Get IPs blocked via AWS Security Group")
async def aws_blocked_ips():
    return get_aws_blocked_ips()


@router.delete("/playbooks/aws-blocked-ips/{ip_address}", summary="Unblock an IP from AWS Security Group")
async def unblock_ip(ip_address: str):
    result = await unblock_ip_in_security_group(ip_address)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    return result


@router.post("/playbooks/execute/{alert_id}", summary="Manually trigger playbook for an alert")
async def manual_playbook_execute(alert_id: str, composite_score: int = Query(75)):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    from app.risk_scorer import _risk_level_from_score
    risk_level = _risk_level_from_score(composite_score)

    result = await execute_playbook(
        alert_id=alert.alert_id,
        source_ip=alert.source_ip,
        attack_type=alert.attack_type.value,
        risk_level=risk_level,
        composite_score=composite_score,
        hostname=alert.hostname,
        file_hash=alert.file_hash,
    )

    if not result:
        return {"message": "No playbook matched for this alert type and risk score."}

    add_event(
        alert_id=alert_id,
        event_type=EventType.MANUAL_ACTION,
        summary=f"Manual playbook execution: {result.playbook_name} | action={result.action_taken}",
        actor="analyst",
    )

    return result


# ─── Alert Status Tracking ────────────────────────────────────────────────────

@router.patch("/alerts/{alert_id}/status", summary="Update alert investigation status")
async def update_status(alert_id: str, new_status: AlertStatus):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    success = update_alert_status(alert_id, new_status.value)
    if not success:
        raise HTTPException(status_code=400, detail=f"Invalid status '{new_status}'.")

    add_event(
        alert_id=alert_id,
        event_type=EventType.STATUS_CHANGED,
        summary=f"Alert status updated to: {new_status.value}",
        actor="analyst",
        details={"new_status": new_status.value},
    )

    logger.info(f"[STATUS] Alert {alert_id} → {new_status.value}")
    return {
        "alert_id": alert_id,
        "status": new_status.value,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }


# ─── Get Single Alert ─────────────────────────────────────────────────────────

@router.get("/alerts/{alert_id}", response_model=NormalizedAlert, summary="Get a specific alert by ID")
async def get_alert(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


# ─── AbuseIPDB Enrichment ─────────────────────────────────────────────────────

@router.post("/alerts/{alert_id}/enrich", response_model=EnrichedAlert, summary="Enrich alert with AbuseIPDB")
async def enrich_alert_endpoint(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return await enrich_alert(alert.alert_id, alert.source_ip)


# ─── VirusTotal Hash Lookup ───────────────────────────────────────────────────

@router.post("/alerts/{alert_id}/scan-hash", response_model=HashReputation, summary="Scan file hash on VirusTotal")
async def scan_hash_endpoint(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    if not alert.file_hash:
        raise HTTPException(status_code=400, detail="Alert does not contain a file hash.")
    result = await lookup_hash(alert.file_hash)
    if not result:
        raise HTTPException(status_code=503, detail="VirusTotal lookup failed.")
    return result


# ─── Composite Risk Score ─────────────────────────────────────────────────────

@router.post("/alerts/{alert_id}/risk-score", response_model=CompositeRiskScore, summary="Calculate composite risk score")
async def risk_score_endpoint(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    tasks = [enrich_alert(alert.alert_id, alert.source_ip)]
    if alert.file_hash:
        tasks.append(lookup_hash(alert.file_hash))
    results = await asyncio.gather(*tasks, return_exceptions=True)
    enriched = results[0] if not isinstance(results[0], Exception) else None
    hash_rep = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else None
    ip_rep = enriched.ip_reputation if enriched else None
    return calculate_composite_score(
        alert_id=alert.alert_id,
        source_ip=alert.source_ip,
        file_hash=alert.file_hash,
        ip_reputation=ip_rep,
        hash_reputation=hash_rep,
    )


# ─── Geolocation ──────────────────────────────────────────────────────────────

@router.get("/alerts/{alert_id}/geolocate", response_model=GeoLocation, summary="Geolocate alert source IP")
async def geolocate_alert(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    geo = await get_geolocation(alert.source_ip)
    if not geo:
        raise HTTPException(status_code=404, detail=f"Could not geolocate IP {alert.source_ip}.")
    return geo
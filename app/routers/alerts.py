"""
Alerts Router - Week 3 Day 5
Full pipeline with RBAC protection on high-impact playbook execution.
"""

import logging
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException, status, Query, BackgroundTasks, Request, Depends
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
from app.rbac import get_current_user, require_senior_analyst, check_playbook_permission, get_rbac_summary, User, HIGH_IMPACT_PLAYBOOKS, SENIOR_APPROVAL_THRESHOLD

logger = logging.getLogger("soar.alerts")
router = APIRouter()


def _validate_payload(payload: RawSIEMAlert) -> None:
    has_ip = any([payload.src_ip, payload.source_ip, payload.sourceIPAddress])
    if not has_ip:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one IP field."
        )
    has_description = any([payload.alert_type, payload.event_type, payload.message, payload.description])
    if not has_description:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Payload must contain at least one descriptive field."
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


# ─── Alert Listing ────────────────────────────────────────────────────────────

@router.get("/alerts", response_model=List[NormalizedAlert], summary="List alerts with filters")
async def list_alerts(
    severity: Optional[SeverityLevel] = Query(None),
    attack_type: Optional[AttackType] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    from_date: Optional[str] = Query(None, description="YYYY-MM-DD"),
    to_date: Optional[str] = Query(None, description="YYYY-MM-DD"),
):
    """Returns normalized alerts with optional filtering. Most recent first."""
    results = alert_store.filter(severity=severity, attack_type=attack_type, limit=500)
    if from_date:
        try:
            from_dt = datetime.strptime(from_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            results = [a for a in results if a.received_at >= from_dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date. Use YYYY-MM-DD.")
    if to_date:
        try:
            to_dt = datetime.strptime(to_date, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            results = [a for a in results if a.received_at <= to_dt]
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date. Use YYYY-MM-DD.")
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


# ─── RBAC Endpoints ───────────────────────────────────────────────────────────

@router.get("/rbac/summary", summary="Get RBAC configuration summary")
async def rbac_summary():
    """Returns the current RBAC configuration — roles, users, and permissions."""
    return get_rbac_summary()


@router.get("/rbac/me", summary="Get current authenticated user info")
async def get_me(user: User = Depends(get_current_user)):
    """Returns the currently authenticated user's role and permissions."""
    return {
        "username": user.username,
        "role": user.role,
        "permissions": {
            "view_alerts": True,
            "view_timelines": True,
            "update_alert_status": True,
            "execute_low_impact_playbooks": True,
            "execute_high_impact_playbooks": user.role in ("senior_analyst", "admin"),
            "manage_users": user.role == "admin",
        }
    }


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
    """Returns the complete chronological timeline of all automated actions for an alert."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    timeline = get_timeline(alert_id)
    if not timeline:
        return {"alert_id": alert_id, "message": "No timeline events recorded yet.", "events": []}
    return timeline


@router.post("/timeline/{alert_id}/note", summary="Add manual note to alert timeline")
async def add_timeline_note(
    alert_id: str,
    note: str = Query(..., description="Note to add"),
    user: User = Depends(get_current_user),
):
    """Allows a SOC analyst to add a manual note to an alert's timeline."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    event = add_event(
        alert_id=alert_id,
        event_type=EventType.MANUAL_ACTION,
        summary=f"[{user.username}] {note}",
        actor=user.username,
        details={"note": note, "added_by": user.username, "role": user.role},
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


@router.delete(
    "/playbooks/aws-blocked-ips/{ip_address}",
    summary="Unblock IP from AWS Security Group — Senior Analyst only"
)
async def unblock_ip(
    ip_address: str,
    user: User = Depends(require_senior_analyst),
):
    """Removes block rule for an IP. Requires Senior Analyst or Admin role."""
    result = await unblock_ip_in_security_group(ip_address)
    if not result["success"]:
        raise HTTPException(status_code=404, detail=result["message"])
    add_event(
        alert_id="system",
        event_type=EventType.MANUAL_ACTION,
        summary=f"[{user.username}] Unblocked IP {ip_address} from AWS Security Group",
        actor=user.username,
    )
    return result


@router.post(
    "/playbooks/execute/{alert_id}",
    summary="Manually trigger playbook — Senior Analyst required for high-impact"
)
async def manual_playbook_execute(
    alert_id: str,
    composite_score: int = Query(75),
    user: User = Depends(get_current_user),
):
    """
    Manually triggers playbook execution for a specific alert.
    High-impact playbooks (score ≥ 70) require Senior Analyst role.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    from app.risk_scorer import _risk_level_from_score
    risk_level = _risk_level_from_score(composite_score)

    attack_to_playbook = {
        "brute_force": "BruteForceContainment",
        "malware": "MalwareContainment",
    }
    playbook_name = attack_to_playbook.get(alert.attack_type.value, "")

    if not check_playbook_permission(user, playbook_name, composite_score):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"High-impact playbook execution requires Senior Analyst role. "
                f"Score {composite_score} ≥ threshold {SENIOR_APPROVAL_THRESHOLD}. "
                f"Your role: {user.role}."
            )
        )

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
        summary=f"[{user.username}] Manual playbook: {result.playbook_name} | action={result.action_taken}",
        actor=user.username,
    )

    return result


# ─── Alert Status Tracking ────────────────────────────────────────────────────

@router.patch("/alerts/{alert_id}/status", summary="Update alert investigation status")
async def update_status(
    alert_id: str,
    new_status: AlertStatus,
    user: User = Depends(get_current_user),
):
    """Updates the investigation status of an alert."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    success = update_alert_status(alert_id, new_status.value)
    if not success:
        raise HTTPException(status_code=400, detail=f"Invalid status '{new_status}'.")
    add_event(
        alert_id=alert_id,
        event_type=EventType.STATUS_CHANGED,
        summary=f"[{user.username}] Status updated to: {new_status.value}",
        actor=user.username,
        details={"new_status": new_status.value, "updated_by": user.username},
    )
    logger.info(f"[STATUS] Alert {alert_id} → {new_status.value} by {user.username}")
    return {
        "alert_id": alert_id,
        "status": new_status.value,
        "updated_by": user.username,
        "updated_at": datetime.now(timezone.utc).isoformat()
    }


# ─── Get Single Alert ─────────────────────────────────────────────────────────

@router.get("/alerts/{alert_id}", response_model=NormalizedAlert, summary="Get a specific alert by ID")
async def get_alert(alert_id: str):
    """Fetch a specific alert by its ID."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


# ─── AbuseIPDB Enrichment ─────────────────────────────────────────────────────

@router.post("/alerts/{alert_id}/enrich", response_model=EnrichedAlert, summary="Enrich alert with AbuseIPDB")
async def enrich_alert_endpoint(alert_id: str):
    """Queries AbuseIPDB for the reputation of the alert source IP."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return await enrich_alert(alert.alert_id, alert.source_ip)


# ─── VirusTotal Hash Lookup ───────────────────────────────────────────────────

@router.post("/alerts/{alert_id}/scan-hash", response_model=HashReputation, summary="Scan file hash on VirusTotal")
async def scan_hash_endpoint(alert_id: str):
    """Queries VirusTotal for the reputation of the file hash in a malware alert."""
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
    """Queries AbuseIPDB and VirusTotal in parallel and returns composite risk score."""
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
    """Fetches geographic location of the attacking IP address."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    geo = await get_geolocation(alert.source_ip)
    if not geo:
        raise HTTPException(status_code=404, detail=f"Could not geolocate IP {alert.source_ip}.")
    return geo
"""
Background Task Runner - Week 2 Day 4
Automatically enriches alerts with threat intelligence after ingestion.
Runs enrichment in the background so the API response stays fast.
"""

import logging
from app.enricher import enrich_alert
from app.virustotal import lookup_hash
from app.risk_scorer import calculate_composite_score
from app.store import alert_store

logger = logging.getLogger("soar.background")


async def auto_enrich_alert(alert_id: str, source_ip: str, file_hash: str = None):
    """
    Background task that runs automatically after every alert ingestion.
    Queries AbuseIPDB and VirusTotal, calculates composite risk score,
    and logs the final verdict without blocking the API response.
    """
    import asyncio

    logger.info(f"[BACKGROUND] Starting auto-enrichment for alert {alert_id}")

    try:
        tasks = [enrich_alert(alert_id, source_ip)]
        if file_hash:
            tasks.append(lookup_hash(file_hash))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched = results[0] if not isinstance(results[0], Exception) else None
        hash_rep = results[1] if len(results) > 1 and not isinstance(results[1], Exception) else None
        ip_rep = enriched.ip_reputation if enriched else None

        score = calculate_composite_score(
            alert_id=alert_id,
            source_ip=source_ip,
            file_hash=file_hash,
            ip_reputation=ip_rep,
            hash_reputation=hash_rep,
        )

        logger.info(
            f"[BACKGROUND] Auto-enrichment complete for {alert_id} | "
            f"composite_score={score.composite_score} | "
            f"risk={score.risk_level} | "
            f"action={score.recommended_action}"
        )

        if score.risk_level == "critical":
            logger.critical(
                f"[BACKGROUND] *** CRITICAL THREAT DETECTED *** | "
                f"alert_id={alert_id} | src={source_ip} | "
                f"action={score.recommended_action} | "
                f"score={score.composite_score}"
            )
        elif score.risk_level == "high":
            logger.warning(
                f"[BACKGROUND] HIGH RISK alert {alert_id} | "
                f"src={source_ip} | action={score.recommended_action}"
            )

    except Exception as e:
        logger.error(f"[BACKGROUND] Auto-enrichment failed for {alert_id}: {e}")
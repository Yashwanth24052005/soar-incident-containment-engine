"""
Background Task Runner - Week 2 Day 5
Ties together the full enrichment pipeline:
  - AbuseIPDB IP reputation (enricher)
  - VirusTotal file hash lookup (virustotal)
  - Geolocation data (geolocation)
  - Composite risk scoring (risk_scorer)
  - Slack notifications for high/critical alerts (notifier)

Runs entirely in the background so the API response stays fast.
"""

import asyncio
import logging

from app.enricher import enrich_alert
from app.virustotal import lookup_hash
from app.geolocation import get_geolocation
from app.risk_scorer import calculate_composite_score
from app.notifier import send_slack_alert
from app.store import alert_store

logger = logging.getLogger("soar.background")


async def auto_enrich_alert(
    alert_id: str,
    source_ip: str,
    attack_type: str = "unknown",
    severity: str = "medium",
    file_hash: str = None,
):
    """
    Full background enrichment pipeline triggered after every alert ingestion.

    Stage 1 — Parallel API calls:
        • AbuseIPDB  → IP abuse reputation score
        • VirusTotal → File hash malware detection (if hash present)
        • ip-api.com → Geolocation data for the attacking IP

    Stage 2 — Composite risk scoring:
        • Combines IP score (60%) + hash score (40%) into a final risk level

    Stage 3 — Conditional alerting:
        • Sends a Slack notification for high or critical risk alerts
        • Logs a CRITICAL or WARNING entry based on risk level
    """
    logger.info(
        f"[BACKGROUND] Starting full enrichment pipeline for alert {alert_id} | "
        f"src={source_ip} | attack={attack_type} | severity={severity}"
    )

    try:
        # ── Stage 1: Run all external API calls concurrently ──────────────────
        enrichment_tasks = [
            enrich_alert(alert_id, source_ip),
            get_geolocation(source_ip),
        ]
        if file_hash:
            enrichment_tasks.append(lookup_hash(file_hash))

        results = await asyncio.gather(*enrichment_tasks, return_exceptions=True)

        enriched   = results[0] if not isinstance(results[0], Exception) else None
        geo        = results[1] if not isinstance(results[1], Exception) else None
        hash_rep   = results[2] if len(results) > 2 and not isinstance(results[2], Exception) else None
        ip_rep     = enriched.ip_reputation if enriched else None

        # Log geolocation result
        if geo:
            logger.info(
                f"[BACKGROUND] Geolocation for {source_ip} | "
                f"location={geo.city}, {geo.region}, {geo.country} ({geo.country_code}) | "
                f"isp={geo.isp} | proxy={geo.is_proxy} | hosting={geo.is_hosting}"
            )
        else:
            logger.warning(f"[BACKGROUND] Geolocation unavailable for {source_ip}")

        # ── Stage 2: Composite risk scoring ───────────────────────────────────
        score = calculate_composite_score(
            alert_id=alert_id,
            source_ip=source_ip,
            file_hash=file_hash,
            ip_reputation=ip_rep,
            hash_reputation=hash_rep,
        )

        logger.info(
            f"[BACKGROUND] Enrichment complete for {alert_id} | "
            f"composite_score={score.composite_score} | "
            f"risk={score.risk_level} | "
            f"confidence={score.confidence} | "
            f"action={score.recommended_action}"
        )

        # ── Stage 3: Conditional alerting ─────────────────────────────────────
        if score.risk_level in ("critical", "high"):

            # Structured log entry for SOC audit trail
            if score.risk_level == "critical":
                logger.critical(
                    f"[BACKGROUND] *** CRITICAL THREAT DETECTED *** | "
                    f"alert_id={alert_id} | src={source_ip} | "
                    f"attack={attack_type} | score={score.composite_score} | "
                    f"action={score.recommended_action}"
                )
            else:
                logger.warning(
                    f"[BACKGROUND] HIGH RISK alert {alert_id} | "
                    f"src={source_ip} | attack={attack_type} | "
                    f"score={score.composite_score} | action={score.recommended_action}"
                )

            # Send Slack notification (non-blocking; failure is logged, not raised)
            slack_sent = await send_slack_alert(
                alert_id=alert_id,
                source_ip=source_ip,
                attack_type=attack_type,
                severity=severity,
                risk_level=score.risk_level,
                composite_score=score.composite_score,
                recommended_action=score.recommended_action,
            )

            if slack_sent:
                logger.info(f"[BACKGROUND] Slack notification sent for {alert_id}")
            else:
                logger.warning(
                    f"[BACKGROUND] Slack notification skipped or failed for {alert_id} "
                    f"(check SLACK_WEBHOOK_URL in .env)"
                )

    except Exception as e:
        logger.error(
            f"[BACKGROUND] Enrichment pipeline failed for {alert_id}: {e}",
            exc_info=True,
        )
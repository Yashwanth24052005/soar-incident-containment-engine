"""
Threat Enrichment Module - Week 2 Day 1
Queries AbuseIPDB to get reputation score for attacking IP addresses.
Automatically enriches normalized alerts with threat intelligence data.
"""

import logging
import os
import httpx
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("soar.enricher")

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"


class IPReputation(BaseModel):
    """Structured result from AbuseIPDB lookup."""
    ip_address: str
    abuse_confidence_score: int
    total_reports: int
    country_code: Optional[str] = None
    isp: Optional[str] = None
    domain: Optional[str] = None
    is_tor: bool = False
    is_whitelisted: bool = False
    risk_level: str = "unknown"
    enrichment_source: str = "AbuseIPDB"


class EnrichedAlert(BaseModel):
    """Alert enriched with threat intelligence data."""
    alert_id: str
    source_ip: str
    ip_reputation: Optional[IPReputation] = None
    composite_risk_score: int = 0
    recommended_action: str = "monitor"


def _calculate_risk_level(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 20:
        return "medium"
    else:
        return "low"


def _recommended_action(score: int) -> str:
    if score >= 80:
        return "block"
    elif score >= 50:
        return "isolate"
    elif score >= 20:
        return "monitor"
    else:
        return "log_only"


async def lookup_ip(ip_address: str) -> Optional[IPReputation]:
    """
    Queries AbuseIPDB for the reputation of an IP address.
    Returns None if the API key is missing or the request fails.
    """
    api_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()

    if not api_key:
        logger.warning(
            "[ENRICHER] ABUSEIPDB_API_KEY not set. "
            "Add it to your .env file to enable threat enrichment."
        )
        return None

    private_prefixes = ("10.", "192.168.", "172.", "127.", "0.0.0.0")
    if any(ip_address.startswith(p) for p in private_prefixes):
        logger.info(f"[ENRICHER] Skipping private IP: {ip_address}")
        return None

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                ABUSEIPDB_URL,
                headers={"Key": api_key, "Accept": "application/json"},
                params={"ipAddress": ip_address, "maxAgeInDays": 90, "verbose": True}
            )

            if response.status_code == 401:
                logger.error("[ENRICHER] Invalid AbuseIPDB API key.")
                return None

            if response.status_code == 429:
                logger.warning("[ENRICHER] AbuseIPDB rate limit hit.")
                return None

            response.raise_for_status()
            data = response.json().get("data", {})
            score = data.get("abuseConfidenceScore", 0)

            reputation = IPReputation(
                ip_address=ip_address,
                abuse_confidence_score=score,
                total_reports=data.get("totalReports", 0),
                country_code=data.get("countryCode"),
                isp=data.get("isp"),
                domain=data.get("domain"),
                is_tor=data.get("isTor", False),
                is_whitelisted=data.get("isWhitelisted", False),
                risk_level=_calculate_risk_level(score),
            )

            logger.info(
                f"[ENRICHER] {ip_address} | score={score} | "
                f"risk={reputation.risk_level} | reports={reputation.total_reports} | "
                f"country={reputation.country_code} | isp={reputation.isp}"
            )

            return reputation

    except httpx.TimeoutException:
        logger.error(f"[ENRICHER] AbuseIPDB request timed out for {ip_address}")
        return None
    except Exception as e:
        logger.error(f"[ENRICHER] Unexpected error enriching {ip_address}: {e}")
        return None


async def enrich_alert(alert_id: str, source_ip: str) -> EnrichedAlert:
    """Enriches a normalized alert with AbuseIPDB threat intelligence."""
    logger.info(f"[ENRICHER] Enriching alert {alert_id} | IP: {source_ip}")

    reputation = await lookup_ip(source_ip)

    if reputation:
        composite_score = reputation.abuse_confidence_score
        action = _recommended_action(composite_score)
    else:
        composite_score = 0
        action = "monitor"

    return EnrichedAlert(
        alert_id=alert_id,
        source_ip=source_ip,
        ip_reputation=reputation,
        composite_risk_score=composite_score,
        recommended_action=action,
    )
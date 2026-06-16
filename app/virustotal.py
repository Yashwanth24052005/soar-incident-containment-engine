"""
VirusTotal Integration - Week 2 Day 2
Queries VirusTotal to check if a file hash is known malware.
Used to enrich malware alerts with threat intelligence data.
"""

import logging
import os
import httpx
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("soar.virustotal")

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/files"


class HashReputation(BaseModel):
    """Structured result from VirusTotal hash lookup."""
    file_hash: str
    malicious_votes: int = 0
    suspicious_votes: int = 0
    harmless_votes: int = 0
    total_engines: int = 0
    detection_ratio: str = "0/0"
    threat_label: Optional[str] = None
    risk_level: str = "unknown"
    enrichment_source: str = "VirusTotal"


def _calculate_hash_risk(malicious: int, total: int) -> str:
    if total == 0:
        return "unknown"
    ratio = malicious / total
    if ratio >= 0.5:
        return "critical"
    elif ratio >= 0.2:
        return "high"
    elif ratio >= 0.05:
        return "medium"
    elif malicious > 0:
        return "low"
    else:
        return "clean"


async def lookup_hash(file_hash: str) -> Optional[HashReputation]:
    """
    Queries VirusTotal for the reputation of a file hash (MD5, SHA-1, or SHA-256).
    Returns None if the API key is missing or the request fails.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()

    if not api_key:
        logger.warning(
            "[VIRUSTOTAL] VIRUSTOTAL_API_KEY not set. "
            "Add it to your .env file to enable hash reputation lookups."
        )
        return None

    if not file_hash or len(file_hash) < 32:
        logger.warning(f"[VIRUSTOTAL] Invalid hash format: {file_hash}")
        return None

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{VIRUSTOTAL_URL}/{file_hash}",
                headers={"x-apikey": api_key, "Accept": "application/json"}
            )

            if response.status_code == 401:
                logger.error("[VIRUSTOTAL] Invalid VirusTotal API key.")
                return None

            if response.status_code == 404:
                logger.info(f"[VIRUSTOTAL] Hash not found in database: {file_hash}")
                return HashReputation(
                    file_hash=file_hash,
                    risk_level="unknown",
                    detection_ratio="not found",
                )

            if response.status_code == 429:
                logger.warning("[VIRUSTOTAL] Rate limit hit. Try again later.")
                return None

            response.raise_for_status()

            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values()) if stats else 0

            threat_label = None
            results = attributes.get("last_analysis_results", {})
            labels = [
                v.get("result") for v in results.values()
                if v.get("category") == "malicious" and v.get("result")
            ]
            if labels:
                threat_label = max(set(labels), key=labels.count)

            reputation = HashReputation(
                file_hash=file_hash,
                malicious_votes=malicious,
                suspicious_votes=suspicious,
                harmless_votes=harmless,
                total_engines=total,
                detection_ratio=f"{malicious}/{total}",
                threat_label=threat_label,
                risk_level=_calculate_hash_risk(malicious, total),
            )

            logger.info(
                f"[VIRUSTOTAL] {file_hash[:16]}... | "
                f"detection={reputation.detection_ratio} | "
                f"risk={reputation.risk_level} | "
                f"threat={threat_label}"
            )

            return reputation

    except httpx.TimeoutException:
        logger.error(f"[VIRUSTOTAL] Request timed out for hash {file_hash}")
        return None
    except Exception as e:
        logger.error(f"[VIRUSTOTAL] Unexpected error for hash {file_hash}: {e}")
        return None
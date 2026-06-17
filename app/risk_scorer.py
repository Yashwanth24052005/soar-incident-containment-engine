"""
Composite Risk Scorer - Week 2 Day 3
Combines AbuseIPDB IP reputation and VirusTotal hash results
into a single composite risk score for playbook decision making.
"""

import logging
from typing import Optional
from pydantic import BaseModel

from app.enricher import IPReputation
from app.virustotal import HashReputation

logger = logging.getLogger("soar.risk_scorer")


class CompositeRiskScore(BaseModel):
    """Final combined risk assessment for an alert."""
    alert_id: str
    source_ip: str
    file_hash: Optional[str] = None
    ip_score: int = 0
    hash_score: int = 0
    composite_score: int = 0
    risk_level: str = "unknown"
    confidence: str = "low"
    recommended_action: str = "monitor"
    ip_reputation: Optional[IPReputation] = None
    hash_reputation: Optional[HashReputation] = None
    scoring_notes: list[str] = []


def _hash_to_score(hash_rep: Optional[HashReputation]) -> int:
    if not hash_rep or hash_rep.total_engines == 0:
        return 0
    ratio = hash_rep.malicious_votes / hash_rep.total_engines
    return min(int(ratio * 100), 100)


def _risk_level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    elif score >= 55:
        return "high"
    elif score >= 25:
        return "medium"
    elif score > 0:
        return "low"
    else:
        return "unknown"


def _recommended_action(score: int, risk: str) -> str:
    if risk == "critical":
        return "block_and_isolate"
    elif risk == "high":
        return "block"
    elif risk == "medium":
        return "isolate"
    elif risk == "low":
        return "monitor"
    else:
        return "log_only"


def _confidence_level(ip_rep, hash_rep) -> str:
    sources = sum([ip_rep is not None, hash_rep is not None])
    if sources == 2:
        return "high"
    elif sources == 1:
        return "medium"
    else:
        return "low"


def calculate_composite_score(
    alert_id: str,
    source_ip: str,
    file_hash: Optional[str] = None,
    ip_reputation: Optional[IPReputation] = None,
    hash_reputation: Optional[HashReputation] = None,
) -> CompositeRiskScore:
    """
    Combines IP reputation (60% weight) and hash reputation (40% weight)
    into a single composite risk score.
    """
    notes = []
    ip_score = 0
    hash_score = 0

    if ip_reputation:
        ip_score = ip_reputation.abuse_confidence_score
        notes.append(f"AbuseIPDB: score={ip_score}, reports={ip_reputation.total_reports}, country={ip_reputation.country_code}")
        if ip_reputation.is_tor:
            ip_score = min(ip_score + 20, 100)
            notes.append("TOR exit node detected: +20 penalty applied to IP score.")
    else:
        notes.append("AbuseIPDB: no data available.")

    if hash_reputation:
        hash_score = _hash_to_score(hash_reputation)
        notes.append(f"VirusTotal: detection={hash_reputation.detection_ratio}, threat={hash_reputation.threat_label or 'unknown'}, score={hash_score}")
    else:
        if file_hash:
            notes.append("VirusTotal: no data available.")

    if ip_reputation and hash_reputation:
        composite = int(ip_score * 0.6 + hash_score * 0.4)
        notes.append(f"Composite: (IP×0.6) + (Hash×0.4) = {composite}")
    elif ip_reputation:
        composite = ip_score
        notes.append("Composite: IP score only.")
    elif hash_reputation:
        composite = hash_score
        notes.append("Composite: Hash score only.")
    else:
        composite = 0
        notes.append("Composite: No threat intelligence data available.")

    risk_level = _risk_level_from_score(composite)
    action = _recommended_action(composite, risk_level)
    confidence = _confidence_level(ip_reputation, hash_reputation)

    logger.info(
        f"[RISK] alert_id={alert_id} | ip_score={ip_score} | "
        f"hash_score={hash_score} | composite={composite} | "
        f"risk={risk_level} | action={action}"
    )

    return CompositeRiskScore(
        alert_id=alert_id,
        source_ip=source_ip,
        file_hash=file_hash,
        ip_score=ip_score,
        hash_score=hash_score,
        composite_score=composite,
        risk_level=risk_level,
        confidence=confidence,
        recommended_action=action,
        ip_reputation=ip_reputation,
        hash_reputation=hash_reputation,
        scoring_notes=notes,
    )
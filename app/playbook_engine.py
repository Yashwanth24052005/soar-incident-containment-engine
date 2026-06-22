"""
Playbook Engine - Week 3 Day 1
Selects and executes the appropriate playbook based on
alert attack type and composite risk score.
"""

import logging
from typing import List, Optional

from app.playbooks.base import PlaybookResult
from app.playbooks.brute_force import BruteForcePlaybook

logger = logging.getLogger("soar.playbook_engine")

_execution_log: List[PlaybookResult] = []


def _select_playbook(attack_type, alert_id, source_ip, risk_level, composite_score):
    if attack_type == "brute_force" and composite_score >= BruteForcePlaybook.min_risk_score:
        return BruteForcePlaybook(
            alert_id=alert_id,
            source_ip=source_ip,
            risk_level=risk_level,
            composite_score=composite_score,
        )
    logger.info(f"[ENGINE] No playbook matched | attack_type={attack_type} | score={composite_score}")
    return None


async def execute_playbook(
    alert_id: str,
    source_ip: str,
    attack_type: str,
    risk_level: str,
    composite_score: int,
) -> Optional[PlaybookResult]:
    """Selects and executes the right playbook. Returns None if no match."""
    logger.info(
        f"[ENGINE] Evaluating | alert_id={alert_id} | "
        f"attack_type={attack_type} | risk={risk_level} | score={composite_score}"
    )

    playbook = _select_playbook(attack_type, alert_id, source_ip, risk_level, composite_score)
    if not playbook:
        return None

    logger.info(f"[ENGINE] Executing: {playbook.name}")
    result = await playbook.execute()
    _execution_log.append(result)

    logger.info(
        f"[ENGINE] Complete | playbook={result.playbook_name} | "
        f"success={result.success} | action={result.action_taken} | "
        f"time={result.execution_time_ms:.1f}ms"
    )
    return result


def get_execution_log() -> List[PlaybookResult]:
    return list(reversed(_execution_log))


def get_execution_stats() -> dict:
    if not _execution_log:
        return {"total_executions": 0, "successful": 0, "failed": 0, "by_playbook": {}, "by_action": {}}

    by_playbook = {}
    by_action = {}
    successful = 0
    for result in _execution_log:
        by_playbook[result.playbook_name] = by_playbook.get(result.playbook_name, 0) + 1
        by_action[result.action_taken] = by_action.get(result.action_taken, 0) + 1
        if result.success:
            successful += 1

    return {
        "total_executions": len(_execution_log),
        "successful": successful,
        "failed": len(_execution_log) - successful,
        "by_playbook": by_playbook,
        "by_action": by_action,
    }
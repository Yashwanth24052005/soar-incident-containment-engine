"""
Brute Force Playbook - Week 3 Day 1
Automatically blocks attacking IPs detected in brute force attacks.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Dict

from app.playbooks.base import BasePlaybook, PlaybookResult

logger = logging.getLogger("soar.playbook.brute_force")

_blocked_ips: Dict[str, Dict] = {}


def get_blocked_ips() -> Dict[str, Dict]:
    return dict(_blocked_ips)


class BruteForcePlaybook(BasePlaybook):
    """
    Playbook triggered on brute force attacks with medium+ risk score.
    Actions: validate → simulate firewall block → audit log → recommend followup.
    """

    name = "BruteForceContainment"
    description = "Blocks source IP on detection of brute force attack"
    min_risk_score = 25

    async def execute(self) -> PlaybookResult:
        start_time = time.perf_counter()

        logger.info(
            f"[PLAYBOOK] {self.name} triggered | "
            f"alert_id={self.alert_id} | src={self.source_ip} | "
            f"risk={self.risk_level} | score={self.composite_score}"
        )

        if self.source_ip in _blocked_ips:
            elapsed = (time.perf_counter() - start_time) * 1000
            return self._build_result(
                success=True,
                action_taken="already_blocked",
                details=f"IP {self.source_ip} was already blocked on {_blocked_ips[self.source_ip]['blocked_at']}.",
                execution_time_ms=elapsed,
                recommended_followup="Review login logs for compromised accounts."
            )

        try:
            block_result = await self._simulate_firewall_block(self.source_ip)

            if block_result:
                _blocked_ips[self.source_ip] = {
                    "blocked_at": datetime.now(timezone.utc).isoformat(),
                    "alert_id": self.alert_id,
                    "risk_level": self.risk_level,
                    "composite_score": self.composite_score,
                    "playbook": self.name,
                }

                elapsed = (time.perf_counter() - start_time) * 1000

                logger.warning(
                    f"[PLAYBOOK] *** IP BLOCKED *** | "
                    f"ip={self.source_ip} | alert_id={self.alert_id} | "
                    f"score={self.composite_score} | time={elapsed:.1f}ms"
                )

                return self._build_result(
                    success=True,
                    action_taken="ip_blocked",
                    details=(
                        f"IP {self.source_ip} successfully blocked via firewall API. "
                        f"Risk score: {self.composite_score}/100."
                    ),
                    execution_time_ms=elapsed,
                    recommended_followup=(
                        "1. Review SSH logs for successful logins from this IP. "
                        "2. Check for lateral movement. "
                        "3. Reset credentials for targeted accounts."
                    )
                )

        except Exception as e:
            elapsed = (time.perf_counter() - start_time) * 1000
            logger.error(f"[PLAYBOOK] Firewall block failed for {self.source_ip}: {e}")
            return self._build_result(
                success=False,
                action_taken="block_failed",
                details=f"Failed to block IP {self.source_ip}: {str(e)}",
                execution_time_ms=elapsed,
                recommended_followup="Manual intervention required."
            )

    async def _simulate_firewall_block(self, ip_address: str) -> bool:
        import asyncio
        logger.info(f"[PLAYBOOK] Calling firewall API to block {ip_address}...")
        await asyncio.sleep(0.1)
        logger.info(f"[PLAYBOOK] Firewall API: 200 OK | {ip_address} blocked")
        return True
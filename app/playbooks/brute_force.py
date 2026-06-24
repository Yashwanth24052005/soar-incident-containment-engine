"""
Brute Force Playbook - Week 3 Day 3 (Updated)
Now uses real AWS Security Group integration via boto3.
Falls back to simulation if AWS credentials are not configured.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Dict

from app.playbooks.base import BasePlaybook, PlaybookResult
from app.aws_integration import block_ip_in_security_group

logger = logging.getLogger("soar.playbook.brute_force")

_blocked_ips: Dict[str, Dict] = {}


def get_blocked_ips() -> Dict[str, Dict]:
    return dict(_blocked_ips)


class BruteForcePlaybook(BasePlaybook):
    name = "BruteForceContainment"
    description = "Blocks source IP via AWS Security Group on brute force detection"
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

        aws_result = await block_ip_in_security_group(
            ip_address=self.source_ip,
            alert_id=self.alert_id,
            description=f"Brute force attack | risk={self.risk_level} | score={self.composite_score}",
        )

        elapsed = (time.perf_counter() - start_time) * 1000

        if aws_result["success"]:
            _blocked_ips[self.source_ip] = {
                "blocked_at": datetime.now(timezone.utc).isoformat(),
                "alert_id": self.alert_id,
                "risk_level": self.risk_level,
                "composite_score": self.composite_score,
                "mode": aws_result.get("mode", "unknown"),
                "playbook": self.name,
            }
            logger.warning(
                f"[PLAYBOOK] *** IP BLOCKED *** | ip={self.source_ip} | "
                f"mode={aws_result.get('mode')} | time={elapsed:.1f}ms"
            )
            return self._build_result(
                success=True,
                action_taken="ip_blocked",
                details=(
                    f"{aws_result['message']} | "
                    f"Mode: {aws_result.get('mode')} | "
                    f"Risk score: {self.composite_score}/100"
                ),
                execution_time_ms=elapsed,
                recommended_followup=(
                    "1. Review SSH logs for successful logins from this IP. "
                    "2. Check for lateral movement. "
                    "3. Reset credentials for targeted accounts. "
                    "4. Verify AWS Security Group rule was applied."
                )
            )
        else:
            return self._build_result(
                success=False,
                action_taken="block_failed",
                details=f"AWS block failed: {aws_result['message']}",
                execution_time_ms=elapsed,
                recommended_followup="Manual intervention required. Block IP on AWS console."
            )
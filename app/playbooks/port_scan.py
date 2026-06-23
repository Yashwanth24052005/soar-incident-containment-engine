"""
Port Scan Playbook - Week 3 Day 2 (Additional)
Automatically rate-limits and monitors IPs detected performing port scans.
"""

import logging
import time
from datetime import datetime, timezone
from typing import Dict

from app.playbooks.base import BasePlaybook, PlaybookResult

logger = logging.getLogger("soar.playbook.port_scan")

_rate_limited_ips: Dict[str, Dict] = {}
_monitored_ips: Dict[str, Dict] = {}


def get_rate_limited_ips() -> Dict[str, Dict]:
    return dict(_rate_limited_ips)


def get_monitored_ips() -> Dict[str, Dict]:
    return dict(_monitored_ips)


class PortScanPlaybook(BasePlaybook):
    """
    Playbook triggered on port scan alerts with low+ risk score.
    Actions: rate limit → enhanced monitoring → audit log → recommendations.
    """

    name = "PortScanContainment"
    description = "Rate-limits scanning IP and activates enhanced monitoring"
    min_risk_score = 10

    async def execute(self) -> PlaybookResult:
        start_time = time.perf_counter()

        logger.info(
            f"[PLAYBOOK] {self.name} triggered | "
            f"alert_id={self.alert_id} | src={self.source_ip} | "
            f"risk={self.risk_level} | score={self.composite_score}"
        )

        actions_taken = []

        if self.source_ip not in _rate_limited_ips:
            try:
                rate_limit_result = await self._simulate_rate_limit(self.source_ip)
                if rate_limit_result:
                    _rate_limited_ips[self.source_ip] = {
                        "rate_limited_at": datetime.now(timezone.utc).isoformat(),
                        "alert_id": self.alert_id,
                        "risk_level": self.risk_level,
                        "composite_score": self.composite_score,
                        "playbook": self.name,
                    }
                    actions_taken.append(f"Rate limit applied to {self.source_ip}")
                    logger.warning(f"[PLAYBOOK] *** RATE LIMITED *** | ip={self.source_ip}")
            except Exception as e:
                actions_taken.append(f"Rate limit FAILED: {str(e)}")
        else:
            actions_taken.append(f"{self.source_ip} already rate limited")

        if self.source_ip not in _monitored_ips:
            try:
                monitor_result = await self._simulate_enhanced_monitoring(self.source_ip)
                if monitor_result:
                    _monitored_ips[self.source_ip] = {
                        "monitored_since": datetime.now(timezone.utc).isoformat(),
                        "alert_id": self.alert_id,
                        "risk_level": self.risk_level,
                        "playbook": self.name,
                    }
                    actions_taken.append(f"Enhanced monitoring activated for {self.source_ip}")
                    logger.info(f"[PLAYBOOK] Enhanced monitoring activated | ip={self.source_ip}")
            except Exception as e:
                actions_taken.append(f"Monitoring FAILED: {str(e)}")
        else:
            actions_taken.append(f"{self.source_ip} already under enhanced monitoring")

        elapsed = (time.perf_counter() - start_time) * 1000

        return self._build_result(
            success=True,
            action_taken="rate_limited_and_monitored",
            details=(
                f"Port scan containment completed in {elapsed:.1f}ms. "
                f"Actions: {' | '.join(actions_taken)}. "
                f"Risk score: {self.composite_score}/100."
            ),
            execution_time_ms=elapsed,
            recommended_followup=(
                "1. Review which ports were probed to identify attacker intent. "
                "2. Check if any probed services have known vulnerabilities. "
                "3. If scanning continues, escalate to full IP block. "
                "4. Verify firewall rules are hiding sensitive service ports. "
                "5. Check for follow-up exploitation attempts from this IP."
            )
        )

    async def _simulate_rate_limit(self, ip_address: str) -> bool:
        import asyncio
        logger.info(f"[PLAYBOOK] Applying network ACL rate limit for {ip_address}...")
        await asyncio.sleep(0.1)
        logger.info(f"[PLAYBOOK] Network ACL updated: {ip_address} rate limited to 10 req/s")
        return True

    async def _simulate_enhanced_monitoring(self, ip_address: str) -> bool:
        import asyncio
        logger.info(f"[PLAYBOOK] Enabling enhanced monitoring for {ip_address}...")
        await asyncio.sleep(0.08)
        logger.info(f"[PLAYBOOK] IDS rule activated: full packet capture for {ip_address}")
        return True
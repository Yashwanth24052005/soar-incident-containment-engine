"""
Base Playbook - Week 3 Day 1
Defines the abstract base class for all SOAR playbooks.
Every playbook must implement the execute() method.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("soar.playbook")


class PlaybookResult(BaseModel):
    """Standardized result returned by every playbook execution."""
    playbook_name: str
    alert_id: str
    source_ip: str
    success: bool
    action_taken: str
    details: str
    executed_at: datetime
    execution_time_ms: float
    risk_level: str
    recommended_followup: Optional[str] = None


class BasePlaybook(ABC):
    """Abstract base class for all SOAR playbooks."""

    name: str = "BasePlaybook"
    description: str = "Base playbook"
    min_risk_score: int = 0

    def __init__(self, alert_id: str, source_ip: str, risk_level: str, composite_score: int):
        self.alert_id = alert_id
        self.source_ip = source_ip
        self.risk_level = risk_level
        self.composite_score = composite_score
        self.logger = logging.getLogger(f"soar.playbook.{self.name}")

    @abstractmethod
    async def execute(self) -> PlaybookResult:
        pass

    def _build_result(
        self,
        success: bool,
        action_taken: str,
        details: str,
        execution_time_ms: float,
        recommended_followup: Optional[str] = None,
    ) -> PlaybookResult:
        return PlaybookResult(
            playbook_name=self.name,
            alert_id=self.alert_id,
            source_ip=self.source_ip,
            success=success,
            action_taken=action_taken,
            details=details,
            executed_at=datetime.now(timezone.utc),
            execution_time_ms=execution_time_ms,
            risk_level=self.risk_level,
            recommended_followup=recommended_followup,
        )
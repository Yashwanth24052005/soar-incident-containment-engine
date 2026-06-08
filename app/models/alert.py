"""
Alert data models - raw SIEM payloads and normalized schema
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Any, Dict
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AttackType(str, Enum):
    BRUTE_FORCE = "brute_force"
    MALWARE = "malware"
    PORT_SCAN = "port_scan"
    DATA_EXFILTRATION = "data_exfiltration"
    UNKNOWN = "unknown"


# ─── Raw SIEM webhook payloads (various formats from different SIEMs) ───────

class RawSIEMAlert(BaseModel):
    """Accepts any raw SIEM payload - flexible schema"""
    model_config = {"extra": "allow"}

    # Common fields across SIEM vendors (all optional since formats vary)
    event_id: Optional[str] = None
    timestamp: Optional[Any] = None          # Could be epoch, ISO, custom string
    src_ip: Optional[str] = None
    source_ip: Optional[str] = None          # Alternate field name
    sourceIPAddress: Optional[str] = None    # AWS CloudTrail style
    dst_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    alert_type: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[Any] = None           # Could be int (1-10) or string
    message: Optional[str] = None
    description: Optional[str] = None
    host: Optional[str] = None
    hostname: Optional[str] = None
    user: Optional[str] = None
    username: Optional[str] = None
    failed_attempts: Optional[int] = None
    file_hash: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None


# ─── Normalized alert schema (standard output regardless of SIEM source) ────

class NormalizedAlert(BaseModel):
    """Standard normalized schema for all ingested alerts"""
    alert_id: str
    received_at: datetime
    normalized_timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    attack_type: AttackType
    severity: SeverityLevel
    description: str
    hostname: Optional[str] = None
    username: Optional[str] = None
    failed_attempts: Optional[int] = None
    file_hash: Optional[str] = None
    raw_payload: Dict[str, Any] = Field(default_factory=dict)
    iocs: List[str] = Field(default_factory=list)   # Indicators of Compromise


class AlertResponse(BaseModel):
    """API response wrapper"""
    success: bool
    message: str
    alert_id: str
    normalized_alert: NormalizedAlert

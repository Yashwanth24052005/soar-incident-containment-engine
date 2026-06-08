"""
Alert Normalization Service
Converts raw SIEM payloads into a standardized schema regardless of source format.
Handles:
- Timestamp normalization (epoch, ISO 8601, custom strings)
- IP extraction from various field names
- Severity mapping (numeric 1-10 or string → enum)
- Attack type classification
- IoC (Indicator of Compromise) extraction
"""

import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Optional, Any, Dict, List, Tuple

from app.models.alert import (
    RawSIEMAlert, NormalizedAlert, SeverityLevel, AttackType
)

logger = logging.getLogger("soar.normalizer")

# ─── Timestamp normalization ─────────────────────────────────────────────────

# Known custom timestamp formats from various SIEM vendors
TIMESTAMP_FORMATS = [
    "%Y-%m-%dT%H:%M:%SZ",           # ISO 8601 UTC
    "%Y-%m-%dT%H:%M:%S.%fZ",        # ISO 8601 with microseconds
    "%Y-%m-%dT%H:%M:%S%z",          # ISO 8601 with timezone offset
    "%Y-%m-%d %H:%M:%S",            # Common log format
    "%d/%b/%Y:%H:%M:%S %z",         # Apache/NGINX log format
    "%b %d %H:%M:%S",               # Syslog format (no year)
    "%m/%d/%Y %H:%M:%S",            # US date format
    "%d-%m-%Y %H:%M:%S",            # EU date format
]


def normalize_timestamp(raw_ts: Any) -> datetime:
    """
    Converts any timestamp format to a timezone-aware UTC datetime.
    Handles: Unix epoch (int/float), ISO strings, vendor-specific formats.
    Falls back to current UTC time if parsing fails.
    """
    if raw_ts is None:
        logger.warning("No timestamp in payload, defaulting to current UTC time.")
        return datetime.now(timezone.utc)

    # Unix epoch (integer or float)
    if isinstance(raw_ts, (int, float)):
        try:
            # Handle millisecond epoch (13 digits) vs second epoch (10 digits)
            if raw_ts > 1e12:
                raw_ts = raw_ts / 1000.0
            return datetime.fromtimestamp(raw_ts, tz=timezone.utc)
        except (OSError, OverflowError, ValueError) as e:
            logger.error(f"Failed to parse epoch timestamp {raw_ts}: {e}")
            return datetime.now(timezone.utc)

    # String timestamp
    if isinstance(raw_ts, str):
        raw_ts = raw_ts.strip()

        # Try ISO format first (handles most modern SIEMs)
        try:
            dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass

        # Try known vendor formats
        for fmt in TIMESTAMP_FORMATS:
            try:
                dt = datetime.strptime(raw_ts, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except ValueError:
                continue

        # Last resort: extract timestamp-like numeric string
        epoch_match = re.search(r"\d{10,13}", raw_ts)
        if epoch_match:
            return normalize_timestamp(int(epoch_match.group()))

    logger.warning(f"Could not parse timestamp '{raw_ts}', defaulting to now.")
    return datetime.now(timezone.utc)


# ─── IP address extraction ────────────────────────────────────────────────────

IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def extract_ip(raw: RawSIEMAlert) -> Tuple[str, Optional[str]]:
    """
    Extracts source and destination IPs from various field names used by
    different SIEM vendors. Returns (source_ip, destination_ip).
    """
    src = (
        raw.src_ip
        or raw.source_ip
        or raw.sourceIPAddress
        or _search_extra_for_ip(raw.extra, ["src", "source", "attacker", "client"])
        or "0.0.0.0"
    )

    dst = (
        raw.dst_ip
        or raw.destination_ip
        or _search_extra_for_ip(raw.extra, ["dst", "dest", "target", "server"])
    )

    return src.strip(), dst.strip() if dst else None


def _search_extra_for_ip(extra: Optional[Dict], keywords: List[str]) -> Optional[str]:
    """Searches extra/unknown fields for IP addresses matching keywords."""
    if not extra:
        return None
    for key, val in extra.items():
        if any(kw in key.lower() for kw in keywords):
            if isinstance(val, str) and IPV4_PATTERN.match(val.strip()):
                return val
    return None


def extract_all_iocs(raw: RawSIEMAlert, src_ip: str) -> List[str]:
    """Extracts all Indicators of Compromise from the alert payload."""
    iocs = []

    if src_ip and src_ip != "0.0.0.0":
        iocs.append(f"ip:{src_ip}")

    if raw.file_hash:
        iocs.append(f"hash:{raw.file_hash}")

    # Extract any IPs found in message/description fields
    for field in [raw.message, raw.description]:
        if field:
            found = IPV4_PATTERN.findall(field)
            for ip in found:
                ioc = f"ip:{ip}"
                if ioc not in iocs:
                    iocs.append(ioc)

    return iocs


# ─── Severity mapping ─────────────────────────────────────────────────────────

SEVERITY_STRING_MAP = {
    "low": SeverityLevel.LOW,
    "1": SeverityLevel.LOW, "2": SeverityLevel.LOW, "3": SeverityLevel.LOW,
    "medium": SeverityLevel.MEDIUM, "med": SeverityLevel.MEDIUM,
    "4": SeverityLevel.MEDIUM, "5": SeverityLevel.MEDIUM, "6": SeverityLevel.MEDIUM,
    "high": SeverityLevel.HIGH,
    "7": SeverityLevel.HIGH, "8": SeverityLevel.HIGH,
    "critical": SeverityLevel.CRITICAL, "crit": SeverityLevel.CRITICAL,
    "9": SeverityLevel.CRITICAL, "10": SeverityLevel.CRITICAL,
}


def map_severity(raw_severity: Any) -> SeverityLevel:
    """Maps raw severity (int 1-10 or string) to SeverityLevel enum."""
    if raw_severity is None:
        return SeverityLevel.MEDIUM

    key = str(raw_severity).lower().strip()
    return SEVERITY_STRING_MAP.get(key, SeverityLevel.MEDIUM)


# ─── Attack type classification ───────────────────────────────────────────────

ATTACK_KEYWORDS = {
    AttackType.BRUTE_FORCE: [
        "brute", "brute_force", "brute-force", "failed login",
        "multiple failed", "authentication failure", "ssh"
    ],
    AttackType.MALWARE: [
        "malware", "virus", "trojan", "ransomware", "exploit",
        "payload", "file_hash", "suspicious file"
    ],
    AttackType.PORT_SCAN: [
        "port scan", "portscan", "nmap", "scan detected", "probe"
    ],
    AttackType.DATA_EXFILTRATION: [
        "exfil", "data transfer", "large upload", "outbound", "exfiltration"
    ],
}


def classify_attack(raw: RawSIEMAlert) -> AttackType:
    """Classifies attack type from alert_type, event_type, or message fields."""
    combined = " ".join(filter(None, [
        raw.alert_type,
        raw.event_type,
        raw.message,
        raw.description,
    ])).lower()

    for attack_type, keywords in ATTACK_KEYWORDS.items():
        if any(kw in combined for kw in keywords):
            return attack_type

    # If file_hash present but no keyword match, likely malware
    if raw.file_hash:
        return AttackType.MALWARE

    return AttackType.UNKNOWN


# ─── Main normalization entry point ──────────────────────────────────────────

def normalize_alert(raw: RawSIEMAlert) -> NormalizedAlert:
    """
    Master normalization function.
    Takes any raw SIEM payload and returns a clean, standardized NormalizedAlert.
    """
    alert_id = raw.event_id or str(uuid.uuid4())
    received_at = datetime.now(timezone.utc)
    normalized_ts = normalize_timestamp(raw.timestamp)
    src_ip, dst_ip = extract_ip(raw)
    severity = map_severity(raw.severity)
    attack_type = classify_attack(raw)
    iocs = extract_all_iocs(raw, src_ip)
    hostname = raw.host or raw.hostname
    username = raw.user or raw.username
    description = raw.description or raw.message or f"{attack_type.value} detected from {src_ip}"

    logger.info(
        f"[NORMALIZED] alert_id={alert_id} | type={attack_type.value} "
        f"| src={src_ip} | severity={severity.value}"
    )

    return NormalizedAlert(
        alert_id=alert_id,
        received_at=received_at,
        normalized_timestamp=normalized_ts,
        source_ip=src_ip,
        destination_ip=dst_ip,
        attack_type=attack_type,
        severity=severity,
        description=description,
        hostname=hostname,
        username=username,
        failed_attempts=raw.failed_attempts,
        file_hash=raw.file_hash,
        raw_payload=raw.model_dump(),
        iocs=iocs,
    )

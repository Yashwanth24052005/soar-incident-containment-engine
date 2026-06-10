"""
Alert Store - JSON file-based persistence layer
Replaces the in-memory list with a persistent store that survives server restarts.
Alerts are saved to data/alerts.json on every write.
"""

import json
import logging
import os
from pathlib import Path
from typing import List, Optional

from app.models.alert import NormalizedAlert

logger = logging.getLogger("soar.store")

DATA_DIR = Path(__file__).parent.parent / "data"
ALERTS_FILE = DATA_DIR / "alerts.json"


def _ensure_data_dir() -> None:
    DATA_DIR.mkdir(exist_ok=True)


def _load_from_disk() -> List[NormalizedAlert]:
    _ensure_data_dir()
    if not ALERTS_FILE.exists():
        logger.info("[STORE] No existing alerts file found. Starting fresh.")
        return []
    try:
        with open(ALERTS_FILE, "r", encoding="utf-8") as f:
            raw = json.load(f)
        alerts = [NormalizedAlert(**item) for item in raw]
        logger.info(f"[STORE] Loaded {len(alerts)} alerts from disk.")
        return alerts
    except Exception as e:
        logger.error(f"[STORE] Failed to load alerts from disk: {e}. Starting fresh.")
        return []


def _save_to_disk(alerts: List[NormalizedAlert]) -> None:
    _ensure_data_dir()
    temp_file = ALERTS_FILE.with_suffix(".tmp")
    try:
        data = [json.loads(alert.model_dump_json()) for alert in alerts]
        with open(temp_file, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(temp_file, ALERTS_FILE)
    except Exception as e:
        logger.error(f"[STORE] Failed to save alerts to disk: {e}")
        if temp_file.exists():
            temp_file.unlink()


class AlertStore:
    def __init__(self):
        self._alerts: List[NormalizedAlert] = _load_from_disk()
        self._rejected_count: int = 0
        logger.info(f"[STORE] Initialized with {len(self._alerts)} existing alerts.")

    def add(self, alert: NormalizedAlert) -> None:
        self._alerts.append(alert)
        _save_to_disk(self._alerts)
        logger.info(f"[STORE] Saved alert {alert.alert_id} to disk. Total: {len(self._alerts)}")

    def get_all(self) -> List[NormalizedAlert]:
        return list(reversed(self._alerts))

    def get_by_id(self, alert_id: str) -> Optional[NormalizedAlert]:
        for alert in self._alerts:
            if alert.alert_id == alert_id:
                return alert
        return None

    def filter(self, severity=None, attack_type=None, limit: int = 50) -> List[NormalizedAlert]:
        results = list(reversed(self._alerts))
        if severity:
            results = [a for a in results if a.severity == severity]
        if attack_type:
            results = [a for a in results if a.attack_type == attack_type]
        return results[:limit]

    def stats(self) -> dict:
        if not self._alerts:
            return {"total_ingested": 0, "total_rejected": self._rejected_count, "by_severity": {}, "by_attack_type": {}}
        by_severity = {}
        by_attack_type = {}
        for alert in self._alerts:
            sev = alert.severity.value
            atk = alert.attack_type.value
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_attack_type[atk] = by_attack_type.get(atk, 0) + 1
        return {"total_ingested": len(self._alerts), "total_rejected": self._rejected_count, "by_severity": by_severity, "by_attack_type": by_attack_type}

    def increment_rejected(self) -> None:
        self._rejected_count += 1


alert_store = AlertStore()
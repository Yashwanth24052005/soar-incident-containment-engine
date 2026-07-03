"""
End-to-End Pipeline Tests - Week 4 Day 5
Covers the full incident lifecycle exactly as it exists today:
    ingest -> normalize -> dedupe -> background enrichment
    -> RBAC-gated manual containment -> timeline recording

This does NOT hit real AbuseIPDB / VirusTotal — no API key is configured in
the test environment, so app.enricher.lookup_ip() and app.virustotal.lookup_hash()
both gracefully degrade to a 0/None score (see their own docstrings). That's
intentional: these are pipeline-shape and RBAC-contract tests, not threat-intel
accuracy tests.

Demo API keys below come straight from app/rbac.py DEMO_USERS — they are
placeholder identifiers for a hardcoded demo table, not real credentials.
"""

import time
import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

ANALYST_KEY = "analyst-key-001"
SENIOR_KEY = "senior-key-001"
HIGH_RISK_SCORE = 90  # >= SENIOR_APPROVAL_THRESHOLD (70) in app/rbac.py


def _unique_ip():
    """Avoids tripping the 5-minute dedup window across test runs."""
    return f"203.0.113.{uuid.uuid4().int % 250 + 1}"


def _ingest_brute_force_alert(src_ip: str) -> dict:
    payload = {
        "src_ip": src_ip,
        "alert_type": "brute_force",
        "message": "20 failed SSH logins in 60 seconds",
        "hostname": "prod-db-01",
        "failed_attempts": 20,
    }
    response = client.post("/api/v1/alerts/ingest", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


# ─── Core pipeline shape ──────────────────────────────────────────────────────

def test_ingest_normalizes_and_persists_alert():
    body = _ingest_brute_force_alert(_unique_ip())
    assert body["success"] is True
    alert = body["normalized_alert"]
    assert alert["attack_type"] == "brute_force"
    assert alert["source_ip"]
    assert alert["alert_id"]

    # Alert must be retrievable straight after ingestion (store write is synchronous)
    get_resp = client.get(f"/api/v1/alerts/{alert['alert_id']}")
    assert get_resp.status_code == 200
    assert get_resp.json()["alert_id"] == alert["alert_id"]


def test_duplicate_ip_within_window_is_suppressed():
    ip = _unique_ip()
    first = _ingest_brute_force_alert(ip)
    second_response = client.post(
        "/api/v1/alerts/ingest",
        json={"src_ip": ip, "alert_type": "brute_force", "message": "more failed logins"},
    )
    assert second_response.status_code == 201
    body = second_response.json()
    assert body["success"] is False
    assert "duplicate" in body["message"].lower()


def test_ingestion_writes_a_timeline_event():
    body = _ingest_brute_force_alert(_unique_ip())
    alert_id = body["normalized_alert"]["alert_id"]
    timeline = client.get(f"/api/v1/timeline/{alert_id}").json()
    event_types = [e["event_type"] for e in timeline["events"]] if "events" in timeline else [
        e["event_type"] for e in timeline
    ]
    assert "alert_ingested" in event_types


# ─── RBAC-gated containment ────────────────────────────────────────────────────

def test_analyst_is_blocked_from_high_impact_playbook():
    body = _ingest_brute_force_alert(_unique_ip())
    alert_id = body["normalized_alert"]["alert_id"]

    response = client.post(
        f"/api/v1/playbooks/execute/{alert_id}",
        params={"composite_score": HIGH_RISK_SCORE},
        headers={"X-API-Key": ANALYST_KEY},
    )
    assert response.status_code == 403
    assert "senior analyst" in response.json()["detail"].lower()


def test_senior_analyst_can_execute_high_impact_playbook():
    body = _ingest_brute_force_alert(_unique_ip())
    alert_id = body["normalized_alert"]["alert_id"]

    response = client.post(
        f"/api/v1/playbooks/execute/{alert_id}",
        params={"composite_score": HIGH_RISK_SCORE},
        headers={"X-API-Key": SENIOR_KEY},
    )
    assert response.status_code == 200
    result = response.json()
    assert result["playbook_name"] == "BruteForceContainment"
    assert result["success"] is True


def test_missing_api_key_is_rejected():
    body = _ingest_brute_force_alert(_unique_ip())
    alert_id = body["normalized_alert"]["alert_id"]
    response = client.post(
        f"/api/v1/playbooks/execute/{alert_id}",
        params={"composite_score": HIGH_RISK_SCORE},
    )
    assert response.status_code == 401


# ─── MTTR: the doc's actual KPI ────────────────────────────────────────────────

def test_ingestion_to_containment_is_under_five_seconds():
    """
    Mirrors the spec's KPI: 'execute a complete containment playbook — from
    alert ingestion to threat isolation — in under 5 seconds.'

    This times ingestion + the senior-analyst-approved containment call
    back-to-back, which is the realistic bound on MTTR for this API.
    """
    start = time.perf_counter()

    body = _ingest_brute_force_alert(_unique_ip())
    alert_id = body["normalized_alert"]["alert_id"]

    response = client.post(
        f"/api/v1/playbooks/execute/{alert_id}",
        params={"composite_score": HIGH_RISK_SCORE},
        headers={"X-API-Key": SENIOR_KEY},
    )
    elapsed = time.perf_counter() - start

    assert response.status_code == 200
    assert elapsed < 5.0, f"Ingestion-to-containment took {elapsed:.2f}s, exceeds 5s KPI"


# ─── Known gap: malware/port-scan playbooks aren't wired into the engine ──────

def test_malware_playbook_selection_currently_returns_none():
    """
    DOCUMENTS A KNOWN GAP, does not celebrate it.

    app/playbooks/malware.py and app/playbooks/port_scan.py exist and are
    fully implemented, but app/playbook_engine.py's _select_playbook() only
    ever imports and matches on BruteForcePlaybook. A malware alert routed
    through the manual execute endpoint currently passes the RBAC check
    (since "MalwareContainment" is in HIGH_IMPACT_PLAYBOOKS) but then finds
    no matching playbook in the engine and silently no-ops.

    This test pins that behavior so it fails loudly — as a TODO, not a
    surprise — once malware/port_scan wiring is added to playbook_engine.py.
    """
    payload = {
        "src_ip": _unique_ip(),
        "alert_type": "malware",
        "message": "known-bad binary executed",
        "hostname": "prod-web-03",
        "file_hash": "d41d8cd98f00b204e9800998ecf8427e",
    }
    ingest = client.post("/api/v1/alerts/ingest", json=payload)
    alert_id = ingest.json()["normalized_alert"]["alert_id"]

    response = client.post(
        f"/api/v1/playbooks/execute/{alert_id}",
        params={"composite_score": HIGH_RISK_SCORE},
        headers={"X-API-Key": SENIOR_KEY},
    )
    assert response.status_code == 200
    # TODO(playbook_engine): once malware.py is wired in, this should become
    # result["playbook_name"] == "MalwareContainment" and success is True.
    assert response.json() == {"message": "No playbook matched for this alert type and risk score."}

"""
Unit Tests - Background Enrichment Pipeline
Week 2 Day 5 Part 2

Tests app/background.py with every external dependency mocked:
  - enrich_alert (AbuseIPDB)
  - lookup_hash (VirusTotal)
  - get_geolocation (ip-api.com)
  - send_slack_alert (Slack webhook)

No real network calls are made. We only verify that auto_enrich_alert
orchestrates these pieces correctly and reacts to risk level as expected.
"""

import pytest
from unittest.mock import AsyncMock, patch

from app.enricher import IPReputation, EnrichedAlert
from app.virustotal import HashReputation
from app.geolocation import GeoLocation
from app.risk_scorer import CompositeRiskScore
from app import background


def make_ip_reputation(score=10, is_tor=False):
    return IPReputation(
        ip_address="203.0.113.10",
        abuse_confidence_score=score,
        total_reports=score // 5,
        country_code="US",
        isp="Example ISP",
        is_tor=is_tor,
        risk_level="low",
    )


def make_enriched_alert(alert_id, source_ip, ip_rep):
    return EnrichedAlert(
        alert_id=alert_id,
        source_ip=source_ip,
        ip_reputation=ip_rep,
        composite_risk_score=ip_rep.abuse_confidence_score if ip_rep else 0,
        recommended_action="monitor",
    )


def make_geo(source_ip="203.0.113.10"):
    return GeoLocation(
        ip_address=source_ip,
        country="United States",
        country_code="US",
        region="California",
        city="San Francisco",
        isp="Example ISP",
        is_proxy=False,
        is_hosting=False,
    )


def make_composite_score(alert_id, source_ip, score, risk_level, action):
    return CompositeRiskScore(
        alert_id=alert_id,
        source_ip=source_ip,
        ip_score=score,
        hash_score=0,
        composite_score=score,
        risk_level=risk_level,
        confidence="medium",
        recommended_action=action,
        scoring_notes=["test note"],
    )


@pytest.mark.asyncio
class TestAutoEnrichAlert:

    async def test_low_risk_alert_does_not_trigger_slack(self):
        """Low/medium risk alerts should never call send_slack_alert."""
        ip_rep = make_ip_reputation(score=5)
        enriched = make_enriched_alert("alert-1", "203.0.113.10", ip_rep)
        geo = make_geo()
        score = make_composite_score("alert-1", "203.0.113.10", 5, "low", "log_only")

        with patch("app.background.enrich_alert", new=AsyncMock(return_value=enriched)), \
             patch("app.background.get_geolocation", new=AsyncMock(return_value=geo)), \
             patch("app.background.calculate_composite_score", return_value=score), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)) as mock_slack:

            await background.auto_enrich_alert(
                alert_id="alert-1",
                source_ip="203.0.113.10",
                attack_type="port_scan",
                severity="low",
            )

            mock_slack.assert_not_called()

    async def test_high_risk_alert_triggers_slack(self):
        """High risk alerts must call send_slack_alert with the right fields."""
        ip_rep = make_ip_reputation(score=65)
        enriched = make_enriched_alert("alert-2", "198.51.100.5", ip_rep)
        geo = make_geo("198.51.100.5")
        score = make_composite_score("alert-2", "198.51.100.5", 65, "high", "block")

        with patch("app.background.enrich_alert", new=AsyncMock(return_value=enriched)), \
             patch("app.background.get_geolocation", new=AsyncMock(return_value=geo)), \
             patch("app.background.calculate_composite_score", return_value=score), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)) as mock_slack:

            await background.auto_enrich_alert(
                alert_id="alert-2",
                source_ip="198.51.100.5",
                attack_type="brute_force",
                severity="high",
            )

            mock_slack.assert_awaited_once()
            _, kwargs = mock_slack.call_args
            assert kwargs["alert_id"] == "alert-2"
            assert kwargs["risk_level"] == "high"
            assert kwargs["composite_score"] == 65
            assert kwargs["recommended_action"] == "block"

    async def test_critical_risk_alert_triggers_slack(self):
        """Critical risk alerts must also call send_slack_alert."""
        ip_rep = make_ip_reputation(score=95)
        enriched = make_enriched_alert("alert-3", "198.51.100.66", ip_rep)
        geo = make_geo("198.51.100.66")
        score = make_composite_score("alert-3", "198.51.100.66", 95, "critical", "block_and_isolate")

        with patch("app.background.enrich_alert", new=AsyncMock(return_value=enriched)), \
             patch("app.background.get_geolocation", new=AsyncMock(return_value=geo)), \
             patch("app.background.calculate_composite_score", return_value=score), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)) as mock_slack:

            await background.auto_enrich_alert(
                alert_id="alert-3",
                source_ip="198.51.100.66",
                attack_type="malware",
                severity="critical",
            )

            mock_slack.assert_awaited_once()

    async def test_hash_lookup_only_called_when_file_hash_present(self):
        """lookup_hash must be skipped entirely when no file_hash is given."""
        ip_rep = make_ip_reputation(score=10)
        enriched = make_enriched_alert("alert-4", "203.0.113.10", ip_rep)
        geo = make_geo()
        score = make_composite_score("alert-4", "203.0.113.10", 10, "low", "log_only")

        with patch("app.background.enrich_alert", new=AsyncMock(return_value=enriched)), \
             patch("app.background.get_geolocation", new=AsyncMock(return_value=geo)), \
             patch("app.background.lookup_hash", new=AsyncMock()) as mock_vt, \
             patch("app.background.calculate_composite_score", return_value=score), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)):

            await background.auto_enrich_alert(
                alert_id="alert-4",
                source_ip="203.0.113.10",
                attack_type="port_scan",
                severity="low",
                file_hash=None,
            )

            mock_vt.assert_not_called()

    async def test_hash_lookup_called_when_file_hash_present(self):
        """lookup_hash must be invoked when a file_hash is supplied."""
        ip_rep = make_ip_reputation(score=10)
        enriched = make_enriched_alert("alert-5", "203.0.113.10", ip_rep)
        geo = make_geo()
        hash_rep = HashReputation(
            file_hash="a" * 64,
            malicious_votes=10,
            total_engines=70,
            detection_ratio="10/70",
            risk_level="medium",
        )
        score = make_composite_score("alert-5", "203.0.113.10", 30, "medium", "isolate")

        with patch("app.background.enrich_alert", new=AsyncMock(return_value=enriched)), \
             patch("app.background.get_geolocation", new=AsyncMock(return_value=geo)), \
             patch("app.background.lookup_hash", new=AsyncMock(return_value=hash_rep)) as mock_vt, \
             patch("app.background.calculate_composite_score", return_value=score), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)):

            await background.auto_enrich_alert(
                alert_id="alert-5",
                source_ip="203.0.113.10",
                attack_type="malware",
                severity="medium",
                file_hash="a" * 64,
            )

            mock_vt.assert_awaited_once_with("a" * 64)

    async def test_pipeline_does_not_raise_when_an_api_call_fails(self):
        """If enrich_alert or get_geolocation raises, the pipeline should log
        the error and return gracefully rather than propagating the exception."""
        with patch("app.background.enrich_alert", new=AsyncMock(side_effect=Exception("AbuseIPDB down"))), \
             patch("app.background.get_geolocation", new=AsyncMock(side_effect=Exception("GeoIP down"))), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)) as mock_slack:

            # Should not raise
            await background.auto_enrich_alert(
                alert_id="alert-6",
                source_ip="203.0.113.10",
                attack_type="unknown",
                severity="medium",
            )

            # With no enrichment data, composite score is "unknown" risk —
            # Slack should not be triggered for a non-actionable risk level.
            mock_slack.assert_not_called()

    async def test_geolocation_failure_does_not_block_scoring(self):
        """A failed geolocation lookup (returns None) must not prevent
        the risk score from being calculated and Slack from firing."""
        ip_rep = make_ip_reputation(score=75)
        enriched = make_enriched_alert("alert-7", "198.51.100.9", ip_rep)
        score = make_composite_score("alert-7", "198.51.100.9", 75, "high", "block")

        with patch("app.background.enrich_alert", new=AsyncMock(return_value=enriched)), \
             patch("app.background.get_geolocation", new=AsyncMock(return_value=None)), \
             patch("app.background.calculate_composite_score", return_value=score), \
             patch("app.background.send_slack_alert", new=AsyncMock(return_value=True)) as mock_slack:

            await background.auto_enrich_alert(
                alert_id="alert-7",
                source_ip="198.51.100.9",
                attack_type="brute_force",
                severity="high",
            )

            mock_slack.assert_awaited_once()

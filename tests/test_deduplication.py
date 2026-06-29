"""
Unit Tests - Deduplication
Week 2 Day 5 Part 2

Tests app/deduplication.py in isolation. The module keeps an in-memory
_dedup_cache dict, so each test resets it to avoid bleed-over.
"""

import pytest
from datetime import datetime, timezone, timedelta

from app import deduplication


@pytest.fixture(autouse=True)
def reset_dedup_state():
    """Clears the in-memory dedup cache before and after every test."""
    deduplication._dedup_cache.clear()
    yield
    deduplication._dedup_cache.clear()


class TestDeduplication:

    def test_first_alert_from_ip_is_not_a_duplicate(self):
        is_dup, count = deduplication.is_duplicate("203.0.113.10")
        assert is_dup is False
        assert count == 1

    def test_second_alert_within_window_is_a_duplicate(self):
        deduplication.is_duplicate("203.0.113.10")
        is_dup, count = deduplication.is_duplicate("203.0.113.10")

        assert is_dup is True
        assert count == 2

    def test_repeated_alerts_increment_occurrence_count(self):
        ip = "203.0.113.10"
        deduplication.is_duplicate(ip)  # 1st - not dup
        deduplication.is_duplicate(ip)  # 2nd - dup
        deduplication.is_duplicate(ip)  # 3rd - dup
        is_dup, count = deduplication.is_duplicate(ip)  # 4th - dup

        assert is_dup is True
        assert count == 4

    def test_different_ips_tracked_independently(self):
        is_dup_a, count_a = deduplication.is_duplicate("203.0.113.10")
        is_dup_b, count_b = deduplication.is_duplicate("198.51.100.5")

        assert is_dup_a is False
        assert is_dup_b is False
        assert count_a == 1
        assert count_b == 1

    def test_alert_outside_window_resets_as_new(self):
        """An alert from an IP whose first_seen is older than the dedup window
        should be treated as a fresh occurrence, not a duplicate."""
        ip = "203.0.113.10"
        stale_time = datetime.now(timezone.utc) - timedelta(
            minutes=deduplication.DEDUP_WINDOW_MINUTES + 5
        )
        deduplication._dedup_cache[ip] = (stale_time, 9)  # simulate old burst of 9 alerts

        is_dup, count = deduplication.is_duplicate(ip)

        assert is_dup is False
        assert count == 1

    def test_get_dedup_stats_reports_active_entries_only(self):
        active_ip = "203.0.113.10"
        stale_ip = "198.51.100.5"

        deduplication.is_duplicate(active_ip)

        stale_time = datetime.now(timezone.utc) - timedelta(
            minutes=deduplication.DEDUP_WINDOW_MINUTES + 5
        )
        deduplication._dedup_cache[stale_ip] = (stale_time, 3)

        stats = deduplication.get_dedup_stats()

        assert stats["dedup_window_minutes"] == deduplication.DEDUP_WINDOW_MINUTES
        assert active_ip in stats["entries"]
        assert stale_ip not in stats["entries"]
        assert stats["active_entries"] == 1

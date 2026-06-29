"""
Unit Tests - Rate Limiter
Week 2 Day 5 Part 2

Tests app/rate_limiter.py in isolation. No external services involved.
The module keeps an in-memory _request_log dict, so each test resets it
to avoid bleed-over between test cases.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import MagicMock
from fastapi import HTTPException

from app import rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limit_state():
    """Clears the in-memory request log before and after every test."""
    rate_limiter._request_log.clear()
    yield
    rate_limiter._request_log.clear()


def make_request(client_ip: str = "203.0.113.10", forwarded_for: str = None) -> MagicMock:
    """Builds a minimal mock FastAPI Request with just the headers/client we need."""
    request = MagicMock()
    request.headers = {}
    if forwarded_for:
        request.headers["X-Forwarded-For"] = forwarded_for
    request.client.host = client_ip
    return request


class TestRateLimiter:

    def test_allows_requests_under_the_limit(self):
        """Requests below MAX_REQUESTS should pass without raising."""
        request = make_request()
        for _ in range(rate_limiter.MAX_REQUESTS - 1):
            rate_limiter.check_rate_limit(request)  # should not raise

        assert len(rate_limiter._request_log["203.0.113.10"]) == rate_limiter.MAX_REQUESTS - 1

    def test_blocks_requests_over_the_limit(self):
        """The (MAX_REQUESTS + 1)th request in the window should raise HTTP 429."""
        request = make_request()
        for _ in range(rate_limiter.MAX_REQUESTS):
            rate_limiter.check_rate_limit(request)

        with pytest.raises(HTTPException) as exc_info:
            rate_limiter.check_rate_limit(request)

        assert exc_info.value.status_code == 429
        assert "Rate limit exceeded" in exc_info.value.detail

    def test_separate_ips_have_independent_limits(self):
        """One IP hitting the limit must not affect a different IP."""
        attacker = make_request(client_ip="198.51.100.5")
        normal_user = make_request(client_ip="203.0.113.99")

        for _ in range(rate_limiter.MAX_REQUESTS):
            rate_limiter.check_rate_limit(attacker)

        with pytest.raises(HTTPException):
            rate_limiter.check_rate_limit(attacker)

        # Different IP should still be allowed
        rate_limiter.check_rate_limit(normal_user)  # should not raise
        assert len(rate_limiter._request_log["203.0.113.99"]) == 1

    def test_old_requests_outside_window_are_pruned(self):
        """Requests older than WINDOW_SECONDS should not count toward the limit."""
        client_ip = "203.0.113.10"
        stale_time = datetime.now(timezone.utc) - timedelta(seconds=rate_limiter.WINDOW_SECONDS + 30)

        # Manually seed the log with MAX_REQUESTS stale timestamps
        rate_limiter._request_log[client_ip] = [stale_time] * rate_limiter.MAX_REQUESTS

        request = make_request(client_ip=client_ip)
        rate_limiter.check_rate_limit(request)  # should not raise — stale entries get pruned

        # Only the new request should remain after pruning
        assert len(rate_limiter._request_log[client_ip]) == 1

    def test_x_forwarded_for_header_takes_priority(self):
        """When X-Forwarded-For is present, it should be used over request.client.host."""
        request = make_request(client_ip="10.0.0.1", forwarded_for="198.51.100.77, 10.0.0.1")
        rate_limiter.check_rate_limit(request)

        assert "198.51.100.77" in rate_limiter._request_log
        assert "10.0.0.1" not in rate_limiter._request_log

    def test_x_real_ip_used_when_forwarded_for_missing(self):
        """Falls back to X-Real-IP when X-Forwarded-For is absent."""
        request = make_request(client_ip="10.0.0.1")
        request.headers["X-Real-IP"] = "198.51.100.22"
        rate_limiter.check_rate_limit(request)

        assert "198.51.100.22" in rate_limiter._request_log

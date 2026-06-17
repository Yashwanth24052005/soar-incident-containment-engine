"""
Rate Limiting - Advanced Feature
Limits the number of alerts a single IP can send to the ingest endpoint
per minute to prevent abuse and DoS attacks on the SOAR engine itself.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, List
from fastapi import HTTPException, status, Request

logger = logging.getLogger("soar.ratelimiter")

MAX_REQUESTS = 30
WINDOW_SECONDS = 60

_request_log: Dict[str, List[datetime]] = {}


def check_rate_limit(request: Request) -> None:
    """
    Checks if the requesting client has exceeded the rate limit.
    Raises HTTP 429 if limit is exceeded.
    """
    client_ip = (
        request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
        or request.headers.get("X-Real-IP", "")
        or (request.client.host if request.client else "unknown")
    )

    now = datetime.now(timezone.utc)
    window_start = now - timedelta(seconds=WINDOW_SECONDS)

    if client_ip not in _request_log:
        _request_log[client_ip] = []

    _request_log[client_ip] = [
        ts for ts in _request_log[client_ip] if ts >= window_start
    ]

    count = len(_request_log[client_ip])

    if count >= MAX_REQUESTS:
        logger.warning(
            f"[RATELIMIT] Rate limit exceeded for {client_ip} | "
            f"requests={count}/{MAX_REQUESTS} in {WINDOW_SECONDS}s"
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {MAX_REQUESTS} requests per {WINDOW_SECONDS} seconds."
        )

    _request_log[client_ip].append(now)
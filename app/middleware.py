"""
Request Logging Middleware
Logs every incoming HTTP request with method, path, status code, and response time.
Provides a complete audit trail of all API activity for security monitoring.
"""

import logging
import time
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("soar.middleware")


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware that intercepts every HTTP request and logs:
    - HTTP method and path
    - Client IP address
    - Response status code
    - Response time in milliseconds
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        start_time = time.perf_counter()

        # Extract client IP (handles reverse proxy headers)
        client_ip = (
            request.headers.get("X-Forwarded-For", "").split(",")[0].strip()
            or request.headers.get("X-Real-IP", "")
            or (request.client.host if request.client else "unknown")
        )

        try:
            response = await call_next(request)
        except Exception as e:
            elapsed = (time.perf_counter() - start_time) * 1000
            logger.error(
                f"[REQUEST] {request.method} {request.url.path} | "
                f"client={client_ip} | ERROR={str(e)} | {elapsed:.1f}ms"
            )
            raise

        elapsed = (time.perf_counter() - start_time) * 1000

        # Log level based on status code
        status_code = response.status_code
        if status_code >= 500:
            log_fn = logger.error
        elif status_code >= 400:
            log_fn = logger.warning
        else:
            log_fn = logger.info

        log_fn(
            f"[REQUEST] {request.method} {request.url.path} | "
            f"status={status_code} | client={client_ip} | {elapsed:.1f}ms"
        )

        response.headers["X-Response-Time"] = f"{elapsed:.1f}ms"
        return response
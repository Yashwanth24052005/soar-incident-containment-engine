"""
Geolocation Module - Week 2 Day 4
Fetches geographic location data for attacking IP addresses.
Uses ip-api.com (free, no API key required, 45 requests/minute).
"""

import logging
import httpx
from typing import Optional
from pydantic import BaseModel

logger = logging.getLogger("soar.geolocation")

GEOIP_URL = "http://ip-api.com/json"


class GeoLocation(BaseModel):
    """Geographic location data for an IP address."""
    ip_address: str
    country: Optional[str] = None
    country_code: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    org: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    timezone: Optional[str] = None
    is_proxy: bool = False
    is_hosting: bool = False
    source: str = "ip-api.com"


async def get_geolocation(ip_address: str) -> Optional[GeoLocation]:
    """
    Fetches geolocation data for an IP address using ip-api.com.
    Free tier: 45 requests/minute, no API key required.
    Returns None for private/reserved IPs or on failure.
    """
    private_prefixes = ("10.", "192.168.", "172.", "127.", "0.0.0.0")
    if any(ip_address.startswith(p) for p in private_prefixes):
        logger.info(f"[GEO] Skipping private IP: {ip_address}")
        return None

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(
                f"{GEOIP_URL}/{ip_address}",
                params={
                    "fields": "status,message,country,countryCode,region,"
                              "regionName,city,isp,org,lat,lon,timezone,proxy,hosting"
                }
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") != "success":
                logger.warning(f"[GEO] Geolocation failed for {ip_address}: {data.get('message')}")
                return None

            geo = GeoLocation(
                ip_address=ip_address,
                country=data.get("country"),
                country_code=data.get("countryCode"),
                region=data.get("regionName"),
                city=data.get("city"),
                isp=data.get("isp"),
                org=data.get("org"),
                latitude=data.get("lat"),
                longitude=data.get("lon"),
                timezone=data.get("timezone"),
                is_proxy=data.get("proxy", False),
                is_hosting=data.get("hosting", False),
            )

            logger.info(
                f"[GEO] {ip_address} | "
                f"{geo.city}, {geo.region}, {geo.country} ({geo.country_code}) | "
                f"isp={geo.isp} | proxy={geo.is_proxy} | hosting={geo.is_hosting}"
            )

            return geo

    except httpx.TimeoutException:
        logger.error(f"[GEO] Geolocation request timed out for {ip_address}")
        return None
    except Exception as e:
        logger.error(f"[GEO] Unexpected error for {ip_address}: {e}")
        return None
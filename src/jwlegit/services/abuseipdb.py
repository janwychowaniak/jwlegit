from __future__ import annotations

import os
import socket
from urllib.parse import urlparse

import httpx

from jwlegit.models import ServiceResult, Verdict

API_CHECK = "https://api.abuseipdb.com/api/v2/check"
GUI_LINK = "https://www.abuseipdb.com/check/{ip}"


async def check_abuseipdb(url: str) -> ServiceResult:
    api_key = os.environ.get("ABUSEIPDB_API_SECRET")
    if not api_key:
        return ServiceResult(
            service_name="AbuseIPDB",
            verdict=Verdict.SKIPPED,
            error="ABUSEIPDB_API_SECRET not set",
        )

    hostname = urlparse(url).hostname
    if not hostname:
        return ServiceResult(
            service_name="AbuseIPDB",
            verdict=Verdict.ERROR,
            error="Could not extract hostname from URL",
        )

    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as e:
        return ServiceResult(
            service_name="AbuseIPDB",
            verdict=Verdict.ERROR,
            error=f"DNS resolution failed: {e}",
        )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(
                API_CHECK,
                params={"ipAddress": ip, "maxAgeInDays": "90"},
                headers={"Key": api_key, "Accept": "application/json"},
            )
            resp.raise_for_status()
            data = resp.json()["data"]
            return _parse_result(ip, data)
    except Exception as e:
        return ServiceResult(
            service_name="AbuseIPDB",
            verdict=Verdict.ERROR,
            error=str(e),
        )


def _parse_result(ip: str, data: dict) -> ServiceResult:
    confidence = data.get("abuseConfidencePercentage", 0)
    total_reports = data.get("totalReports", 0)
    country = data.get("countryCode", "")
    isp = data.get("isp", "")
    domain = data.get("domain", "")
    is_public = data.get("isPublic", True)

    if confidence >= 50:
        verdict = Verdict.MALICIOUS
    elif confidence > 0 or total_reports > 0:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    details: dict[str, str] = {
        "IP": ip,
        "Abuse confidence": f"{confidence}%",
        "Total reports (90 days)": str(total_reports),
    }
    if country:
        details["Country"] = country
    if isp:
        details["ISP"] = isp
    if domain:
        details["Domain"] = domain

    return ServiceResult(
        service_name="AbuseIPDB",
        verdict=verdict,
        details=details,
        link=GUI_LINK.format(ip=ip),
    )

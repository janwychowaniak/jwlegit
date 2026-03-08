from __future__ import annotations

import os

import httpx

from jwlegit.models import ServiceResult, Verdict

API_LOOKUP = "https://safebrowsing.googleapis.com/v4/threatMatches:find"


async def check_safebrowsing(url: str) -> ServiceResult:
    api_key = os.environ.get("GOOGLE_SAFEBROWSING_API_SECRET")
    if not api_key:
        return ServiceResult(
            service_name="Google Safe Browsing",
            verdict=Verdict.SKIPPED,
            error="GOOGLE_SAFEBROWSING_API_SECRET not set",
        )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                API_LOOKUP,
                params={"key": api_key},
                json={
                    "client": {
                        "clientId": "jwlegit",
                        "clientVersion": "1.0.0",
                    },
                    "threatInfo": {
                        "threatTypes": [
                            "MALWARE",
                            "SOCIAL_ENGINEERING",
                            "UNWANTED_SOFTWARE",
                            "POTENTIALLY_HARMFUL_APPLICATION",
                        ],
                        "platformTypes": ["ANY_PLATFORM"],
                        "threatEntryTypes": ["URL"],
                        "threatEntries": [{"url": url}],
                    },
                },
            )
            resp.raise_for_status()
            data = resp.json()
            return _parse_result(data)
    except Exception as e:
        return ServiceResult(
            service_name="Google Safe Browsing",
            verdict=Verdict.ERROR,
            error=str(e),
        )


def _parse_result(data: dict) -> ServiceResult:
    matches = data.get("matches", [])

    if not matches:
        return ServiceResult(
            service_name="Google Safe Browsing",
            verdict=Verdict.CLEAN,
            details={"Threats found": "None"},
        )

    threat_types = sorted({m.get("threatType", "UNKNOWN") for m in matches})
    platforms = sorted({m.get("platformType", "UNKNOWN") for m in matches})

    details: dict[str, str] = {
        "Threats found": str(len(matches)),
        "Threat types": ", ".join(threat_types),
        "Platforms": ", ".join(platforms),
    }

    return ServiceResult(
        service_name="Google Safe Browsing",
        verdict=Verdict.MALICIOUS,
        details=details,
    )

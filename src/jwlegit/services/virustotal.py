from __future__ import annotations

import asyncio
import base64
import os

import httpx

from jwlegit.models import ServiceResult, Verdict

API_URLS = "https://www.virustotal.com/api/v3/urls"
API_ANALYSIS = "https://www.virustotal.com/api/v3/analyses/{id}"
GUI_LINK = "https://www.virustotal.com/gui/url/{url_id}"

POLL_INTERVAL = 5
TIMEOUT = 60


async def check_virustotal(url: str) -> ServiceResult:
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key:
        return ServiceResult(
            service_name="VirusTotal",
            verdict=Verdict.SKIPPED,
            error="VIRUSTOTAL_API_KEY not set",
        )

    try:
        headers = {"x-apikey": api_key}
        async with httpx.AsyncClient(timeout=30) as client:
            # Submit URL for scanning
            resp = await client.post(
                API_URLS,
                headers=headers,
                data={"url": url},
            )
            resp.raise_for_status()
            analysis_id = resp.json()["data"]["id"]

            # Poll for analysis completion
            analysis_url = API_ANALYSIS.format(id=analysis_id)
            elapsed = 0
            while elapsed < TIMEOUT:
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL
                poll = await client.get(analysis_url, headers=headers)
                poll.raise_for_status()
                data = poll.json()["data"]
                if data["attributes"]["status"] == "completed":
                    return _parse_result(url, data)

            return ServiceResult(
                service_name="VirusTotal",
                verdict=Verdict.ERROR,
                error=f"Analysis timed out after {TIMEOUT}s",
                link=_gui_link(url),
            )
    except Exception as e:
        return ServiceResult(
            service_name="VirusTotal",
            verdict=Verdict.ERROR,
            error=str(e),
        )


def _gui_link(url: str) -> str:
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return GUI_LINK.format(url_id=url_id)


def _parse_result(url: str, data: dict) -> ServiceResult:
    stats = data["attributes"].get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    if malicious > 0:
        verdict = Verdict.MALICIOUS
    elif suspicious > 0:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    details: dict[str, str] = {
        "Malicious": f"{malicious}/{total}",
        "Suspicious": f"{suspicious}/{total}",
        "Harmless": f"{harmless}/{total}",
        "Undetected": f"{undetected}/{total}",
    }

    return ServiceResult(
        service_name="VirusTotal",
        verdict=verdict,
        details=details,
        link=_gui_link(url),
    )

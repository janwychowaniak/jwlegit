from __future__ import annotations

import asyncio
import os

import httpx

from jwlegit.models import ServiceResult, Verdict

API_SUBMIT = "https://urlscan.io/api/v1/scan/"
API_RESULT = "https://urlscan.io/api/v1/result/{uuid}/"
RESULT_LINK = "https://urlscan.io/result/{uuid}/"

POLL_INTERVAL = 5
TIMEOUT = 60


async def check_urlscan(url: str) -> ServiceResult:
    api_key = os.environ.get("URLSCAN_API_KEY")
    if not api_key:
        return ServiceResult(
            service_name="urlscan.io",
            verdict=Verdict.SKIPPED,
            error="URLSCAN_API_KEY not set",
        )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Submit scan
            resp = await client.post(
                API_SUBMIT,
                json={"url": url, "visibility": "unlisted"},
                headers={"API-Key": api_key, "Content-Type": "application/json"},
            )
            resp.raise_for_status()
            uuid = resp.json()["uuid"]

            # Poll for result
            result_url = API_RESULT.format(uuid=uuid)
            elapsed = 0
            while elapsed < TIMEOUT:
                await asyncio.sleep(POLL_INTERVAL)
                elapsed += POLL_INTERVAL
                poll = await client.get(result_url)
                if poll.status_code == 200:
                    data = poll.json()
                    return _parse_result(uuid, data)
                # 404 means still processing
                if poll.status_code != 404:
                    poll.raise_for_status()

            return ServiceResult(
                service_name="urlscan.io",
                verdict=Verdict.ERROR,
                error=f"Scan timed out after {TIMEOUT}s",
                link=RESULT_LINK.format(uuid=uuid),
            )
    except Exception as e:
        return ServiceResult(
            service_name="urlscan.io",
            verdict=Verdict.ERROR,
            error=str(e),
        )


def _parse_result(uuid: str, data: dict) -> ServiceResult:
    verdicts = data.get("verdicts", {})
    overall = verdicts.get("overall", {})
    score = overall.get("score", 0)
    malicious = overall.get("malicious", False)
    categories = overall.get("categories", [])

    if malicious:
        verdict = Verdict.MALICIOUS
    elif score > 0:
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.CLEAN

    details: dict[str, str] = {
        "Score": str(score),
        "Malicious": str(malicious),
    }
    if categories:
        details["Categories"] = ", ".join(categories)

    # Add community verdict info if available
    community = verdicts.get("community", {})
    if community.get("score", 0) != 0:
        details["Community Score"] = str(community["score"])

    return ServiceResult(
        service_name="urlscan.io",
        verdict=verdict,
        details=details,
        link=RESULT_LINK.format(uuid=uuid),
    )

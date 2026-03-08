from __future__ import annotations

import asyncio
import os
from urllib.parse import urlparse

import httpx

from jwlegit.models import ServiceResult, Verdict

API_ANALYZE = "https://api.ssllabs.com/api/v4/analyze"
API_REGISTER = "https://api.ssllabs.com/api/v4/register"
GUI_LINK = "https://www.ssllabs.com/ssltest/analyze.html?d={hostname}"

POLL_INTERVAL = 10
TIMEOUT = 300


async def check_ssllabs(url: str) -> ServiceResult:
    email = os.environ.get("QUALYS_API_SECRET")
    if not email:
        return ServiceResult(
            service_name="SSL Labs",
            verdict=Verdict.SKIPPED,
            error="QUALYS_API_SECRET not set",
        )

    hostname = urlparse(url).hostname
    if not hostname:
        return ServiceResult(
            service_name="SSL Labs",
            verdict=Verdict.ERROR,
            error="Could not extract hostname from URL",
        )

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            result = await _analyze(client, hostname, email, register_attempted=False)
            return result
    except Exception as e:
        return ServiceResult(
            service_name="SSL Labs",
            verdict=Verdict.ERROR,
            error=str(e),
            link=GUI_LINK.format(hostname=hostname),
        )


async def _analyze(
    client: httpx.AsyncClient,
    hostname: str,
    email: str,
    *,
    register_attempted: bool,
) -> ServiceResult:
    headers = {"email": email}
    params = {"host": hostname, "startNew": "on", "all": "done"}

    resp = await client.get(API_ANALYZE, params=params, headers=headers)

    # Lazy auto-registration: if we get a 401/403, register and retry once
    if resp.status_code in (401, 403) and not register_attempted:
        await _register(client, email)
        return await _analyze(
            client, hostname, email, register_attempted=True
        )

    resp.raise_for_status()
    data = resp.json()

    # Poll until READY or ERROR
    elapsed = 0
    while data.get("status") not in ("READY", "ERROR") and elapsed < TIMEOUT:
        await asyncio.sleep(POLL_INTERVAL)
        elapsed += POLL_INTERVAL
        # Don't use startNew on subsequent polls
        poll_params = {"host": hostname, "all": "done"}
        poll = await client.get(API_ANALYZE, params=poll_params, headers=headers)
        poll.raise_for_status()
        data = poll.json()

    if data.get("status") == "ERROR":
        return ServiceResult(
            service_name="SSL Labs",
            verdict=Verdict.ERROR,
            error=data.get("statusMessage", "Unknown error"),
            link=GUI_LINK.format(hostname=hostname),
        )

    if data.get("status") != "READY":
        return ServiceResult(
            service_name="SSL Labs",
            verdict=Verdict.ERROR,
            error=f"Analysis timed out after {TIMEOUT}s",
            link=GUI_LINK.format(hostname=hostname),
        )

    return _parse_result(hostname, data)


async def _register(client: httpx.AsyncClient, email: str) -> None:
    resp = await client.post(
        API_REGISTER,
        json={"firstName": "jwlegit", "lastName": "user", "email": email, "organization": "personal"},
    )
    resp.raise_for_status()


def _parse_result(hostname: str, data: dict) -> ServiceResult:
    endpoints = data.get("endpoints", [])
    details: dict[str, str] = {}
    worst_grade = ""
    grade_order = ["A+", "A", "A-", "B", "C", "D", "E", "F", "T", "M"]

    for ep in endpoints:
        grade = ep.get("grade", "")
        ip = ep.get("ipAddress", "unknown")
        if grade:
            details[f"Grade ({ip})"] = grade
            if not worst_grade or (
                grade in grade_order
                and grade_order.index(grade) > grade_order.index(worst_grade)
            ):
                worst_grade = grade

        if ep.get("hasWarnings"):
            details[f"Warnings ({ip})"] = "Yes"

    if not worst_grade:
        verdict = Verdict.ERROR
        details["Note"] = "No grade available"
    elif worst_grade in ("A+", "A", "A-"):
        verdict = Verdict.CLEAN
    elif worst_grade in ("B", "C"):
        verdict = Verdict.SUSPICIOUS
    else:
        verdict = Verdict.MALICIOUS

    # Protocol info
    protocols = data.get("protocols", [])
    if protocols:
        proto_strs = [f"{p.get('name', '')} {p.get('version', '')}" for p in protocols]
        details["Protocols"] = ", ".join(proto_strs)

    return ServiceResult(
        service_name="SSL Labs",
        verdict=verdict,
        details=details,
        link=GUI_LINK.format(hostname=hostname),
    )

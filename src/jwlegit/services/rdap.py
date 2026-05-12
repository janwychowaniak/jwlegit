from __future__ import annotations

from datetime import UTC, datetime
from urllib.parse import urlparse

import httpx

from jwlegit.models import ServiceResult, Verdict

RDAP_BOOTSTRAP = "https://rdap.org/domain/{domain}"


def _registrable_domain(hostname: str) -> str:
    """Extract the registrable domain (last two labels, or three for a
    two-letter SLD like .co.uk).  Simple heuristic without a PSL dependency:
    if the second-level label is <= 3 chars (co, com, org, net in co.uk,
    com.au) keep three labels, otherwise two.
    """
    parts = hostname.lower().split(".")
    if len(parts) > 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return hostname.lower()


async def check_rdap(url: str) -> ServiceResult:
    hostname = urlparse(url).hostname
    if not hostname:
        return ServiceResult(
            service_name="RDAP / WHOIS",
            verdict=Verdict.ERROR,
            error="Could not extract hostname from URL",
        )

    domain = _registrable_domain(hostname)

    try:
        async with httpx.AsyncClient(timeout=15, follow_redirects=True) as client:
            resp = await client.get(RDAP_BOOTSTRAP.format(domain=domain))
            resp.raise_for_status()
            data = resp.json()
            return _parse_result(domain, data)
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            return ServiceResult(
                service_name="RDAP / WHOIS",
                verdict=Verdict.SKIPPED,
                error=f"No RDAP record found for {domain}",
            )
        return ServiceResult(
            service_name="RDAP / WHOIS",
            verdict=Verdict.ERROR,
            error=str(e),
        )
    except Exception as e:
        return ServiceResult(
            service_name="RDAP / WHOIS",
            verdict=Verdict.ERROR,
            error=str(e),
        )


def _parse_result(domain: str, data: dict) -> ServiceResult:
    events = {e["eventAction"]: e["eventDate"] for e in data.get("events", [])}

    created_str = events.get("registration")
    updated_str = events.get("last changed")
    expires_str = events.get("expiration")

    details: dict[str, str] = {"Domain": domain}

    now = datetime.now(UTC)
    domain_age_days: int | None = None

    if created_str:
        created = _parse_date(created_str)
        if created:
            details["Registered"] = created.strftime("%Y-%m-%d")
            domain_age_days = (now - created).days
            details["Domain age"] = _format_age(domain_age_days)

    if updated_str:
        updated = _parse_date(updated_str)
        if updated:
            details["Last updated"] = updated.strftime("%Y-%m-%d")

    if expires_str:
        expires = _parse_date(expires_str)
        if expires:
            details["Expires"] = expires.strftime("%Y-%m-%d")

    # Registrar
    for entity in data.get("entities", []):
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray", [None, []])
            for entry in vcard[1] if len(vcard) > 1 else []:
                if entry[0] == "fn":
                    details["Registrar"] = entry[3]
                    break
            break

    # Verdict based on domain age
    if domain_age_days is not None:
        if domain_age_days < 7:
            verdict = Verdict.MALICIOUS
        elif domain_age_days < 30:
            verdict = Verdict.SUSPICIOUS
        else:
            verdict = Verdict.CLEAN
    else:
        verdict = Verdict.CLEAN

    return ServiceResult(
        service_name="RDAP / WHOIS",
        verdict=verdict,
        details=details,
    )


def _parse_date(date_str: str) -> datetime | None:
    """Parse an ISO 8601 / RFC 3339 date string from RDAP."""
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except (ValueError, AttributeError):
        return None


def _plural(n: int, unit: str) -> str:
    return f"{n} {unit}{'' if n == 1 else 's'}"


def _format_age(days: int) -> str:
    if days < 1:
        return "less than a day"
    if days < 30:
        return f"{days} days"
    if days < 365:
        return f"~{_plural(days // 30, 'month')}"
    years = days // 365
    remainder_months = (days % 365) // 30
    if remainder_months:
        return f"~{_plural(years, 'year')}, {_plural(remainder_months, 'month')}"
    return f"~{_plural(years, 'year')}"

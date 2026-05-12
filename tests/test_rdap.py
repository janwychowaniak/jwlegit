from __future__ import annotations

from datetime import UTC, datetime, timedelta

import httpx
import pytest
import respx

from jwlegit.models import Verdict
from jwlegit.services.rdap import (
    RDAP_BOOTSTRAP,
    _format_age,
    _parse_date,
    _parse_result,
    _registrable_domain,
    check_rdap,
)


@pytest.mark.parametrize(
    "hostname, expected",
    [
        ("example.com", "example.com"),
        ("www.example.com", "example.com"),
        ("a.b.example.com", "example.com"),
        ("EXAMPLE.COM", "example.com"),
        # two-letter SLD heuristic kicks in
        ("example.co.uk", "example.co.uk"),
        ("www.example.co.uk", "example.co.uk"),
        ("example.com.au", "example.com.au"),
        # known limitation: a short 2nd-level label trips the heuristic
        # even when it's a real domain (foo.io is registrable, not bar.foo.io)
        ("bar.foo.io", "bar.foo.io"),
        # single-label fallback
        ("localhost", "localhost"),
    ],
)
def test_registrable_domain(hostname, expected):
    assert _registrable_domain(hostname) == expected


def test_parse_date_handles_z_suffix():
    assert _parse_date("2024-01-02T03:04:05Z") == datetime(2024, 1, 2, 3, 4, 5, tzinfo=UTC)


def test_parse_date_returns_none_on_garbage():
    assert _parse_date("not-a-date") is None
    assert _parse_date(None) is None  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "days, expected",
    [
        (0, "less than a day"),
        (5, "5 days"),
        (60, "~2 months"),
        (365, "~1 year"),
        (400, "~1 year, 1 month"),
        (800, "~2 years, 2 months"),
    ],
)
def test_format_age(days, expected):
    assert _format_age(days) == expected


def _events(created_offset_days: int | None = None, **extra):
    events = []
    now = datetime.now(UTC)
    if created_offset_days is not None:
        events.append(
            {
                "eventAction": "registration",
                "eventDate": (now - timedelta(days=-created_offset_days))
                .isoformat()
                .replace("+00:00", "Z"),
            }
        )
    for action, offset in extra.items():
        events.append(
            {
                "eventAction": action.replace("_", " "),
                "eventDate": (now - timedelta(days=-offset)).isoformat().replace("+00:00", "Z"),
            }
        )
    return {"events": events}


def test_new_domain_under_7_days_is_malicious():
    # registration 3 days ago → offset -3 from now
    data = _events(created_offset_days=-3)
    r = _parse_result("example.com", data)
    assert r.verdict == Verdict.MALICIOUS


def test_domain_under_30_days_is_suspicious():
    data = _events(created_offset_days=-15)
    assert _parse_result("example.com", data).verdict == Verdict.SUSPICIOUS


def test_older_domain_is_clean():
    data = _events(created_offset_days=-400)
    r = _parse_result("example.com", data)
    assert r.verdict == Verdict.CLEAN
    assert r.details["Registered"]
    assert r.details["Domain age"].startswith("~1 year")


def test_missing_registration_defaults_to_clean():
    r = _parse_result("example.com", {"events": []})
    assert r.verdict == Verdict.CLEAN
    assert r.details["Domain"] == "example.com"


def test_registrar_extracted_from_vcard():
    data = {
        "events": [],
        "entities": [
            {
                "roles": ["registrar"],
                "vcardArray": [
                    "vcard",
                    [
                        ["version", {}, "text", "4.0"],
                        ["fn", {}, "text", "Acme Registrar LLC"],
                    ],
                ],
            },
        ],
    }
    r = _parse_result("example.com", data)
    assert r.details["Registrar"] == "Acme Registrar LLC"


# --- check_rdap integration (HTTP mocked) ---


@respx.mock
async def test_check_rdap_extracts_registrable_domain_from_subdomain():
    # request must go to example.com, not www.example.com
    respx.get(RDAP_BOOTSTRAP.format(domain="example.com")).mock(
        return_value=httpx.Response(200, json={"events": []})
    )
    r = await check_rdap("https://www.example.com/path")
    assert r.verdict == Verdict.CLEAN
    assert r.details["Domain"] == "example.com"


@respx.mock
async def test_check_rdap_404_is_skipped():
    respx.get(RDAP_BOOTSTRAP.format(domain="example.com")).mock(return_value=httpx.Response(404))
    r = await check_rdap("https://example.com")
    assert r.verdict == Verdict.SKIPPED
    assert "No RDAP record" in r.error


@respx.mock
async def test_check_rdap_other_http_error_is_error():
    respx.get(RDAP_BOOTSTRAP.format(domain="example.com")).mock(return_value=httpx.Response(500))
    r = await check_rdap("https://example.com")
    assert r.verdict == Verdict.ERROR

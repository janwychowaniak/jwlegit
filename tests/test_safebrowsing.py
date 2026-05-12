from __future__ import annotations

import httpx
import respx

from jwlegit.models import Verdict
from jwlegit.services.safebrowsing import API_LOOKUP, _parse_result, check_safebrowsing

URL = "https://example.com"


def test_no_matches_is_clean():
    r = _parse_result({})
    assert r.verdict == Verdict.CLEAN
    assert r.details["Threats found"] == "None"


def test_matches_are_malicious_and_deduplicated_and_sorted():
    data = {
        "matches": [
            {"threatType": "MALWARE", "platformType": "WINDOWS"},
            {"threatType": "MALWARE", "platformType": "LINUX"},
            {"threatType": "SOCIAL_ENGINEERING", "platformType": "WINDOWS"},
        ]
    }
    r = _parse_result(data)
    assert r.verdict == Verdict.MALICIOUS
    assert r.details["Threats found"] == "3"
    assert r.details["Threat types"] == "MALWARE, SOCIAL_ENGINEERING"
    assert r.details["Platforms"] == "LINUX, WINDOWS"


def test_missing_fields_become_unknown():
    r = _parse_result({"matches": [{}]})
    assert r.verdict == Verdict.MALICIOUS
    assert r.details["Threat types"] == "UNKNOWN"
    assert r.details["Platforms"] == "UNKNOWN"


# --- check_safebrowsing integration (HTTP mocked) ---


async def test_check_safebrowsing_skipped_without_api_key(monkeypatch):
    monkeypatch.delenv("GOOGLE_SAFEBROWSING_API_KEY", raising=False)
    r = await check_safebrowsing(URL)
    assert r.verdict == Verdict.SKIPPED


@respx.mock
async def test_check_safebrowsing_clean(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "k")
    respx.post(API_LOOKUP).mock(return_value=httpx.Response(200, json={}))
    r = await check_safebrowsing(URL)
    assert r.verdict == Verdict.CLEAN


@respx.mock
async def test_check_safebrowsing_malicious(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "k")
    respx.post(API_LOOKUP).mock(
        return_value=httpx.Response(
            200,
            json={
                "matches": [
                    {"threatType": "MALWARE", "platformType": "ANY_PLATFORM"},
                ]
            },
        )
    )
    r = await check_safebrowsing(URL)
    assert r.verdict == Verdict.MALICIOUS


@respx.mock
async def test_check_safebrowsing_http_error(monkeypatch):
    monkeypatch.setenv("GOOGLE_SAFEBROWSING_API_KEY", "k")
    respx.post(API_LOOKUP).mock(return_value=httpx.Response(403))
    r = await check_safebrowsing(URL)
    assert r.verdict == Verdict.ERROR

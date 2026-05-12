from __future__ import annotations

import httpx
import respx

from jwlegit.models import Verdict
from jwlegit.services.virustotal import (
    API_ANALYSIS,
    API_URLS,
    check_virustotal,
    _gui_link,
    _parse_result,
)


URL = "https://example.com/"
ANALYSIS_ID = "an-1"


def _data(malicious=0, suspicious=0, harmless=0, undetected=0):
    return {"attributes": {"stats": {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
    }}}


def test_any_malicious_is_malicious():
    r = _parse_result(URL, _data(malicious=1, harmless=70, undetected=20))
    assert r.verdict == Verdict.MALICIOUS
    assert r.details["Malicious"] == "1/91"


def test_suspicious_without_malicious():
    r = _parse_result(URL, _data(suspicious=2, harmless=80))
    assert r.verdict == Verdict.SUSPICIOUS


def test_all_harmless_is_clean():
    r = _parse_result(URL, _data(harmless=90))
    assert r.verdict == Verdict.CLEAN
    assert r.details["Harmless"] == "90/90"


def test_gui_link_uses_urlsafe_b64_without_padding():
    link = _gui_link("https://example.com/")
    assert "=" not in link.rsplit("/", 1)[-1]
    assert link.startswith("https://www.virustotal.com/gui/url/")


# --- check_virustotal integration (HTTP mocked) ---


async def test_check_virustotal_skipped_without_api_key(monkeypatch):
    monkeypatch.delenv("VIRUSTOTAL_API_KEY", raising=False)
    r = await check_virustotal(URL)
    assert r.verdict == Verdict.SKIPPED


@respx.mock
async def test_check_virustotal_polls_until_completed(monkeypatch, fast_sleep):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    respx.post(API_URLS).mock(return_value=httpx.Response(200, json={"data": {"id": ANALYSIS_ID}}))
    queued = {"data": {"attributes": {"status": "queued", "stats": {}}}}
    completed = {"data": {"attributes": {"status": "completed", "stats": {
        "malicious": 2, "suspicious": 0, "harmless": 60, "undetected": 8,
    }}}}
    respx.get(API_ANALYSIS.format(id=ANALYSIS_ID)).mock(side_effect=[
        httpx.Response(200, json=queued),
        httpx.Response(200, json=completed),
    ])

    r = await check_virustotal(URL)
    assert r.verdict == Verdict.MALICIOUS
    assert r.details["Malicious"] == "2/70"


@respx.mock
async def test_check_virustotal_times_out(monkeypatch, fast_sleep):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    monkeypatch.setattr("jwlegit.services.virustotal.TIMEOUT", 10)
    monkeypatch.setattr("jwlegit.services.virustotal.POLL_INTERVAL", 5)
    respx.post(API_URLS).mock(return_value=httpx.Response(200, json={"data": {"id": ANALYSIS_ID}}))
    respx.get(API_ANALYSIS.format(id=ANALYSIS_ID)).mock(return_value=httpx.Response(
        200, json={"data": {"attributes": {"status": "queued", "stats": {}}}}
    ))

    r = await check_virustotal(URL)
    assert r.verdict == Verdict.ERROR
    assert "timed out" in r.error


@respx.mock
async def test_check_virustotal_propagates_http_error(monkeypatch):
    monkeypatch.setenv("VIRUSTOTAL_API_KEY", "k")
    respx.post(API_URLS).mock(return_value=httpx.Response(429, json={}))

    r = await check_virustotal(URL)
    assert r.verdict == Verdict.ERROR

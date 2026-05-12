from __future__ import annotations

import httpx
import respx

from jwlegit.models import Verdict
from jwlegit.services.urlscan import (
    API_RESULT,
    API_SUBMIT,
    _parse_result,
    check_urlscan,
)

UUID = "abc-123"
URL = "https://example.com"


def test_malicious_overrides_score():
    data = {"verdicts": {"overall": {"score": 0, "malicious": True, "categories": ["phishing"]}}}
    r = _parse_result(UUID, data)
    assert r.verdict == Verdict.MALICIOUS
    assert r.details["Categories"] == "phishing"
    assert UUID in r.link


def test_positive_score_is_suspicious():
    data = {"verdicts": {"overall": {"score": 50, "malicious": False}}}
    assert _parse_result(UUID, data).verdict == Verdict.SUSPICIOUS


def test_zero_score_clean_no_categories_key():
    data = {"verdicts": {"overall": {"score": 0, "malicious": False}}}
    r = _parse_result(UUID, data)
    assert r.verdict == Verdict.CLEAN
    assert "Categories" not in r.details


def test_community_score_shown_when_nonzero():
    data = {
        "verdicts": {
            "overall": {"score": 0, "malicious": False},
            "community": {"score": -5},
        }
    }
    r = _parse_result(UUID, data)
    assert r.details["Community Score"] == "-5"


def test_missing_verdicts_block_defaults_to_clean():
    r = _parse_result(UUID, {})
    assert r.verdict == Verdict.CLEAN
    assert r.details["Score"] == "0"
    assert r.details["Malicious"] == "False"


# --- check_urlscan integration (HTTP mocked) ---


async def test_check_urlscan_skipped_without_api_key(monkeypatch):
    monkeypatch.delenv("URLSCAN_API_KEY", raising=False)
    r = await check_urlscan(URL)
    assert r.verdict == Verdict.SKIPPED
    assert "URLSCAN_API_KEY" in r.error


@respx.mock
async def test_check_urlscan_polls_until_result_ready(monkeypatch, fast_sleep):
    monkeypatch.setenv("URLSCAN_API_KEY", "k")
    respx.post(API_SUBMIT).mock(return_value=httpx.Response(200, json={"uuid": UUID}))
    respx.get(API_RESULT.format(uuid=UUID)).mock(
        side_effect=[
            httpx.Response(404),
            httpx.Response(404),
            httpx.Response(200, json={"verdicts": {"overall": {"score": 10, "malicious": True}}}),
        ]
    )

    r = await check_urlscan(URL)
    assert r.verdict == Verdict.MALICIOUS
    assert UUID in r.link


@respx.mock
async def test_check_urlscan_times_out(monkeypatch, fast_sleep):
    monkeypatch.setenv("URLSCAN_API_KEY", "k")
    monkeypatch.setattr("jwlegit.services.urlscan.TIMEOUT", 10)
    monkeypatch.setattr("jwlegit.services.urlscan.POLL_INTERVAL", 5)
    respx.post(API_SUBMIT).mock(return_value=httpx.Response(200, json={"uuid": UUID}))
    respx.get(API_RESULT.format(uuid=UUID)).mock(return_value=httpx.Response(404))

    r = await check_urlscan(URL)
    assert r.verdict == Verdict.ERROR
    assert "timed out" in r.error
    assert UUID in r.link


@respx.mock
async def test_check_urlscan_propagates_submit_error(monkeypatch):
    monkeypatch.setenv("URLSCAN_API_KEY", "k")
    respx.post(API_SUBMIT).mock(return_value=httpx.Response(401, json={"message": "bad key"}))

    r = await check_urlscan(URL)
    assert r.verdict == Verdict.ERROR
    assert r.error  # any non-empty error message


@respx.mock
async def test_check_urlscan_unexpected_poll_status_errors(monkeypatch, fast_sleep):
    monkeypatch.setenv("URLSCAN_API_KEY", "k")
    respx.post(API_SUBMIT).mock(return_value=httpx.Response(200, json={"uuid": UUID}))
    respx.get(API_RESULT.format(uuid=UUID)).mock(return_value=httpx.Response(500))

    r = await check_urlscan(URL)
    assert r.verdict == Verdict.ERROR

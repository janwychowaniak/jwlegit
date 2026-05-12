from __future__ import annotations

import socket

import httpx
import respx

from jwlegit.models import Verdict
from jwlegit.services.abuseipdb import API_CHECK, check_abuseipdb, _parse_result


IP = "1.2.3.4"
URL = "https://example.com"


def _data(confidence=0, reports=0, **extra):
    return {
        "abuseConfidencePercentage": confidence,
        "totalReports": reports,
        **extra,
    }


def test_confidence_at_or_above_50_is_malicious():
    assert _parse_result(IP, _data(confidence=50, reports=10)).verdict == Verdict.MALICIOUS
    assert _parse_result(IP, _data(confidence=99, reports=5)).verdict == Verdict.MALICIOUS


def test_confidence_between_1_and_49_is_suspicious():
    assert _parse_result(IP, _data(confidence=1, reports=1)).verdict == Verdict.SUSPICIOUS
    assert _parse_result(IP, _data(confidence=49, reports=1)).verdict == Verdict.SUSPICIOUS


def test_reports_without_confidence_is_caution():
    assert _parse_result(IP, _data(confidence=0, reports=3)).verdict == Verdict.CAUTION


def test_zero_signal_is_clean():
    assert _parse_result(IP, _data(confidence=0, reports=0)).verdict == Verdict.CLEAN


def test_optional_fields_only_present_when_set():
    r = _parse_result(IP, _data(confidence=0, reports=0))
    assert "Country" not in r.details
    assert "ISP" not in r.details
    assert "Domain" not in r.details
    r2 = _parse_result(IP, _data(confidence=0, reports=0, countryCode="US", isp="X", domain="x.test"))
    assert r2.details["Country"] == "US"
    assert r2.details["ISP"] == "X"
    assert r2.details["Domain"] == "x.test"
    assert IP in r2.link


# --- check_abuseipdb integration (HTTP + DNS mocked) ---


async def test_check_abuseipdb_skipped_without_api_key(monkeypatch):
    monkeypatch.delenv("ABUSEIPDB_API_KEY", raising=False)
    r = await check_abuseipdb(URL)
    assert r.verdict == Verdict.SKIPPED


async def test_check_abuseipdb_dns_failure_is_error(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    def fail(host):
        raise socket.gaierror("Name or service not known")
    monkeypatch.setattr("jwlegit.services.abuseipdb.socket.gethostbyname", fail)
    r = await check_abuseipdb(URL)
    assert r.verdict == Verdict.ERROR
    assert "DNS" in r.error


@respx.mock
async def test_check_abuseipdb_high_confidence_is_malicious(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setattr("jwlegit.services.abuseipdb.socket.gethostbyname", lambda h: IP)
    respx.get(API_CHECK).mock(return_value=httpx.Response(200, json={"data": {
        "abuseConfidencePercentage": 88,
        "totalReports": 42,
        "countryCode": "US",
        "isp": "Example ISP",
        "domain": "example.com",
        "isPublic": True,
    }}))

    r = await check_abuseipdb(URL)
    assert r.verdict == Verdict.MALICIOUS
    assert r.details["IP"] == IP


@respx.mock
async def test_check_abuseipdb_http_error_returns_error(monkeypatch):
    monkeypatch.setenv("ABUSEIPDB_API_KEY", "k")
    monkeypatch.setattr("jwlegit.services.abuseipdb.socket.gethostbyname", lambda h: IP)
    respx.get(API_CHECK).mock(return_value=httpx.Response(500))
    r = await check_abuseipdb(URL)
    assert r.verdict == Verdict.ERROR

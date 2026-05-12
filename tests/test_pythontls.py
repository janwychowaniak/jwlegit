from __future__ import annotations

import datetime

from jwlegit.models import Verdict
from jwlegit.services.pythontls import _parse_result


def _cert_date(offset_days: int) -> str:
    d = datetime.datetime.now(datetime.UTC).replace(tzinfo=None) + datetime.timedelta(
        days=offset_days
    )
    return d.strftime("%b %d %H:%M:%S %Y GMT")


def _info(not_after_offset_days: int, **extra):
    cert = {
        "subject": ((("commonName", "example.com"),),),
        "issuer": (
            (("organizationName", "Acme CA"),),
            (("commonName", "Acme Root"),),
        ),
        "notBefore": _cert_date(-365),
        "notAfter": _cert_date(not_after_offset_days),
        "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
    }
    return {
        "cert": cert,
        "protocol": "TLSv1.3",
        "cipher": ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
        **extra,
    }


def test_healthy_cert_is_clean():
    r = _parse_result("example.com", _info(not_after_offset_days=120))
    assert r.verdict == Verdict.CLEAN
    assert r.details["Subject"] == "example.com"
    assert r.details["Issuer"] == "Acme CA — Acme Root"
    assert r.details["Protocol"] == "TLSv1.3"
    assert "TLS_AES_256_GCM_SHA384" in r.details["Cipher"]
    assert "256-bit" in r.details["Cipher"]
    assert "Warning" not in r.details


def test_expiring_soon_is_suspicious():
    r = _parse_result("example.com", _info(not_after_offset_days=7))
    assert r.verdict == Verdict.SUSPICIOUS
    assert "expiring soon" in r.details["Warning"].lower()


def test_expired_cert_is_malicious():
    r = _parse_result("example.com", _info(not_after_offset_days=-5))
    assert r.verdict == Verdict.MALICIOUS
    assert "EXPIRED" in r.details["Warning"]


def test_many_sans_get_truncated():
    info = _info(not_after_offset_days=120)
    info["cert"]["subjectAltName"] = tuple(("DNS", f"h{i}.example.com") for i in range(8))
    r = _parse_result("example.com", info)
    assert "(+3 more)" in r.details["SANs"]


# --- check_tls integration (socket/ssl bypassed) ---


async def test_check_tls_missing_hostname():
    from jwlegit.services.pythontls import check_tls

    r = await check_tls("not-a-url")
    assert r.verdict == Verdict.ERROR


async def test_check_tls_happy_path(monkeypatch):
    from jwlegit.services import pythontls

    monkeypatch.setattr(pythontls, "_get_cert_info", lambda host: _info(120))
    r = await pythontls.check_tls("https://example.com")
    assert r.verdict == Verdict.CLEAN
    assert r.details["Protocol"] == "TLSv1.3"


async def test_check_tls_socket_error_is_caught(monkeypatch):
    from jwlegit.services import pythontls

    def boom(host):
        raise ConnectionRefusedError("nope")

    monkeypatch.setattr(pythontls, "_get_cert_info", boom)
    r = await pythontls.check_tls("https://example.com")
    assert r.verdict == Verdict.ERROR
    assert "nope" in r.error

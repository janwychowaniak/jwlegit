from __future__ import annotations

import asyncio
import datetime
import ssl
import socket
from urllib.parse import urlparse

from jwlegit.models import ServiceResult, Verdict

DEFAULT_PORT = 443


async def check_tls(url: str) -> ServiceResult:
    hostname = urlparse(url).hostname
    if not hostname:
        return ServiceResult(
            service_name="TLS Certificate",
            verdict=Verdict.ERROR,
            error="Could not extract hostname from URL",
        )

    try:
        cert_info = await asyncio.to_thread(_get_cert_info, hostname)
        return _parse_result(hostname, cert_info)
    except Exception as e:
        return ServiceResult(
            service_name="TLS Certificate",
            verdict=Verdict.ERROR,
            error=str(e),
        )


def _get_cert_info(hostname: str) -> dict:
    ctx = ssl.create_default_context()
    with socket.create_connection((hostname, DEFAULT_PORT), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            cert = ssock.getpeercert()
            protocol = ssock.version()
            cipher = ssock.cipher()
            return {
                "cert": cert,
                "protocol": protocol,
                "cipher": cipher,
            }


def _parse_result(hostname: str, info: dict) -> ServiceResult:
    cert = info["cert"]
    details: dict[str, str] = {}
    verdict = Verdict.CLEAN

    # Subject
    subject_parts = []
    for rdn in cert.get("subject", ()):
        for attr_type, attr_value in rdn:
            if attr_type == "commonName":
                subject_parts.append(attr_value)
    if subject_parts:
        details["Subject"] = ", ".join(subject_parts)

    # Issuer
    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for attr_type, attr_value in rdn:
            if attr_type == "organizationName":
                issuer_parts.append(attr_value)
            elif attr_type == "commonName":
                issuer_parts.append(attr_value)
    if issuer_parts:
        details["Issuer"] = " — ".join(issuer_parts)

    # Validity
    not_before = cert.get("notBefore", "")
    not_after = cert.get("notAfter", "")
    if not_after:
        details["Valid until"] = not_after
        try:
            expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
            days_left = (expiry - now).days
            details["Days until expiry"] = str(days_left)
            if days_left < 0:
                verdict = Verdict.MALICIOUS
                details["Warning"] = "Certificate has EXPIRED"
            elif days_left < 14:
                verdict = Verdict.SUSPICIOUS
                details["Warning"] = "Certificate expiring soon"
        except ValueError:
            pass

    # SANs
    sans = [value for type_, value in cert.get("subjectAltName", ()) if type_ == "DNS"]
    if sans:
        details["SANs"] = ", ".join(sans[:5])
        if len(sans) > 5:
            details["SANs"] += f" (+{len(sans) - 5} more)"

    # Protocol & cipher
    if info.get("protocol"):
        details["Protocol"] = info["protocol"]
    if info.get("cipher"):
        cipher_name, _, key_bits = info["cipher"]
        details["Cipher"] = f"{cipher_name} ({key_bits}-bit)"

    return ServiceResult(
        service_name="TLS Certificate",
        verdict=verdict,
        details=details,
    )

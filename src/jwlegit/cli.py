from __future__ import annotations

import argparse
import asyncio
import sys
from urllib.parse import urlparse

from jwlegit.models import ServiceResult
from jwlegit.report import print_report
from jwlegit.services.urlscan import check_urlscan
from jwlegit.services.virustotal import check_virustotal
from jwlegit.services.pythontls import check_tls
from jwlegit.services.abuseipdb import check_abuseipdb
from jwlegit.services.safebrowsing import check_safebrowsing


def _validate_url(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        print(f"Error: Invalid URL scheme '{parsed.scheme}'. Use http:// or https://", file=sys.stderr)
        sys.exit(1)
    if not parsed.hostname:
        print("Error: URL must include a hostname", file=sys.stderr)
        sys.exit(1)
    return url


async def _run(url: str) -> list[ServiceResult]:
    results = await asyncio.gather(
        check_urlscan(url),
        check_virustotal(url),
        check_abuseipdb(url),
        check_safebrowsing(url),
        check_tls(url),
    )
    return list(results)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="jwlegit",
        description="Check URL reputation across urlscan.io, VirusTotal, AbuseIPDB, Google Safe Browsing, and TLS certificate analysis",
    )
    parser.add_argument("url", help="URL to check (e.g. https://example.com)")
    args = parser.parse_args()

    url = _validate_url(args.url)
    results = asyncio.run(_run(url))
    print_report(url, results)


if __name__ == "__main__":
    main()

# jwlegit

URL reputation checker — queries urlscan.io, VirusTotal, AbuseIPDB, Google Safe Browsing, and performs TLS certificate analysis in parallel, presenting a combined report.

## Installation

```bash
uv pip install -e .
```

## Configuration

Set API credentials as environment variables:

```bash
export URLSCAN_API_KEY="your-urlscan-api-key"
export VIRUSTOTAL_API_KEY="your-virustotal-api-key"
export ABUSEIPDB_API_KEY="your-abuseipdb-api-key"
export GOOGLE_SAFEBROWSING_API_KEY="your-google-api-key"
```

Missing credentials will cause that service to be skipped (not crash).
The TLS certificate check requires no API key.

## Usage

```bash
jwlegit https://example.com
```

Or without installing:

```bash
uv run jwlegit https://example.com
```

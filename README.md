# jwlegit

URL reputation checker — queries urlscan.io, VirusTotal, and performs TLS certificate analysis in parallel, presenting a combined report.

## Installation

```bash
uv pip install -e .
```

## Configuration

Set API credentials as environment variables:

```bash
export URLSCAN_API_SECRET="your-urlscan-api-key"
export VIRUSTOTAL_API_SECRET="your-virustotal-api-key"
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

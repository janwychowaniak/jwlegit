# jwlegit

URL reputation checker — queries urlscan.io, VirusTotal, and SSL Labs in parallel and presents a combined report.

## Installation

```bash
uv pip install -e .
```

## Configuration

Set API credentials as environment variables:

```bash
export URLSCAN_API_SECRET="your-urlscan-api-key"
export VIRUSTOTAL_API_SECRET="your-virustotal-api-key"
export QUALYS_API_SECRET="your-email@example.com"   # registered email for SSL Labs
```

Missing credentials will cause that service to be skipped (not crash).

## Usage

```bash
jwlegit https://example.com
```

Or without installing:

```bash
uv run jwlegit https://example.com
```

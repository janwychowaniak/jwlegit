# jwlegit

URL reputation checker — queries urlscan.io, VirusTotal, AbuseIPDB, Google Safe Browsing, RDAP/WHOIS, and TLS certificate analysis in parallel, presenting a combined report.

## Installation

```bash
uv tool install jwlegit
```

Or with [pipx](https://pipx.pypa.io/) if you don't use [uv](https://docs.astral.sh/uv/):

```bash
pipx install jwlegit
```

Both put the `jwlegit` script on your `PATH` inside an isolated environment, which is the right pattern for a CLI tool.

## Configuration

This tool reads the following environment variables:

| Variable                      | Service              | Notes                            |
|-------------------------------|----------------------|----------------------------------|
| `URLSCAN_API_KEY`             | urlscan.io           | Submits a scan and polls         |
| `VIRUSTOTAL_API_KEY`          | VirusTotal           | Submits URL and polls analysis   |
| `ABUSEIPDB_API_KEY`           | AbuseIPDB            | Checks the resolved IP, not URL  |
| `GOOGLE_SAFEBROWSING_API_KEY` | Google Safe Browsing | Single lookup                    |
| —                             | TLS Certificate      | No key required                  |
| —                             | RDAP / WHOIS         | No key required                  |

Set them however you prefer. Missing credentials cause that service to be skipped — the tool won't crash.

## Usage

```bash
jwlegit https://example.com
```

## Development

```bash
git clone https://github.com/janwychowaniak/jwlegit
cd jwlegit
uv sync --group dev
uv run pytest
```

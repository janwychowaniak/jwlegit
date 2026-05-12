# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv pip install -e .              # install (editable)
uv run jwlegit <url>             # run without installing
jwlegit <url>                    # run after install
```

No test suite, linter, or formatter is configured.

## Architecture

`cli.py` is a thin orchestrator: validate URL → `asyncio.gather` every `check_*` coroutine → hand the resulting list to `report.print_report`. All services run concurrently; one slow service doesn't block the others.

### The service contract

Every module in `src/jwlegit/services/` exposes one coroutine `async check_<service>(url) -> ServiceResult` (`models.py`) and **never raises**. Failures must be encoded as a returned `ServiceResult`:

- `Verdict.SKIPPED` — required API key absent (must not count toward the overall verdict)
- `Verdict.ERROR` — network/parse/timeout failure; populate `.error`
- `Verdict.CLEAN | CAUTION | SUSPICIOUS | MALICIOUS` — actual signal from the upstream service

The per-service threshold logic that maps raw API responses → verdict lives in each module's `_parse_result`. Examples currently in use: VirusTotal flips to MALICIOUS on any positive detection; AbuseIPDB uses CAUTION for "reports exist but confidence is 0" vs. SUSPICIOUS/MALICIOUS at higher confidence; RDAP flips on domain age (<7d malicious, <30d suspicious); TLS flips on certificate expiry. When adding a service, decide where its thresholds sit on this scale rather than inventing a new convention.

### Adding a new service

1. Create `src/jwlegit/services/<name>.py` following the contract above. Read the API key from `os.environ` and return `SKIPPED` if absent — don't crash.
2. Wrap the entire body in `try/except Exception` and return `Verdict.ERROR` on any failure.
3. Import and add it to the `asyncio.gather(...)` call in `cli.py`.
4. Update the README's env-var list and the CLI `--help` description string.

### Overall verdict

`report._overall_verdict` picks the worst verdict from the list in this priority order: `MALICIOUS > SUSPICIOUS > CAUTION > ERROR > CLEAN`. `SKIPPED` results are deliberately excluded — a missing API key should not affect the final call. If you add a new `Verdict` member, both `_overall_verdict` and the `_COLORS` map in `report.py` must be updated.

### Output

`report.py` uses ANSI colors only when stdout is a TTY (`sys.stdout.isatty()`), so piped output stays plain. Details are rendered as aligned key/value pairs from `ServiceResult.details: dict[str, str]` — keep values pre-formatted strings, not raw numbers/objects.

## Notes

- Python ≥ 3.11. Sole runtime dependency is `httpx` (used in async mode by every HTTP service); TLS check uses stdlib `ssl`/`socket` via `asyncio.to_thread`.
- RDAP uses a small heuristic in `services/rdap.py` to extract the registrable domain from subdomains without pulling in the Public Suffix List — be aware it may misclassify exotic TLDs.

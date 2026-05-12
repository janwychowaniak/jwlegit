# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
uv sync --group dev              # install runtime + dev deps from uv.lock
uv run jwlegit <url>             # run the CLI from source
uv run pytest                    # full test suite (84 tests, ~1s)
uv run pytest tests/test_rdap.py::test_registrable_domain   # single test
uv run ruff check .              # lint
uv run ruff format .             # format
uv run mypy                      # type-check
uv build                         # produce sdist + wheel in dist/
```

The published CLI for end users installs via `uv tool install jwlegit` or `pipx install jwlegit` — both put `jwlegit` on PATH in an isolated venv (the correct pattern for a CLI). The `uv sync --group dev` workflow above is for development on this repo.

Tests cover both the pure helpers (`_parse_result`, `_overall_verdict`, `_registrable_domain`, `_validate_url`) and the `check_*` coroutines end-to-end via `respx` (httpx route mocking). Polling-loop tests use the `fast_sleep` fixture in `tests/conftest.py` to monkeypatch `asyncio.sleep`. AbuseIPDB tests stub `socket.gethostbyname` and TLS tests stub `_get_cert_info` to avoid real network/SSL traffic.

## How changes reach `main`

A branch ruleset (`protect-main`) rejects direct pushes that don't carry passing CI on the commit. The flow is:

1. Topic branch, push.
2. `gh pr create --base main` — opens a PR, which fires `.github/workflows/ci.yml`.
3. Five required checks must pass: `lint`, `audit`, `test (3.11)`, `test (3.12)`, `test (3.13)`. Lint runs `ruff check`, `ruff format --check`, and `mypy`. Audit runs `pip-audit` against the runtime-only dep export.
4. `gh pr merge <#> --rebase --delete-branch` once green.

`main` cannot be force-pushed or deleted.

## Releases

Published to PyPI as [`jwlegit`](https://pypi.org/project/jwlegit/) via Trusted Publishing — no API tokens involved. `.github/workflows/publish.yml` fires on `release: published` and: validates the tag is strict semver (`vN.N.N`), verifies `pyproject.toml` `version` matches the tag, runs pytest, builds, `twine check`s, then uploads via OIDC in the `pypi` GitHub environment.

Cutting a release:

1. Bump `version` in `pyproject.toml`; land via PR.
2. `gh release create vX.Y.Z --target main --generate-notes --title vX.Y.Z`
3. `gh run watch` to follow.

`v*` tags are protected (no delete, no force-push). The `pypi` environment restricts deploys to `v*` refs. Pre-release tags like `v1.0.0rc1` are rejected by the strict-semver regex in `publish.yml`.

## Dependencies

Dependabot (`.github/dependabot.yml`) tracks `pip` and `github-actions` weekly with conservative cooldown windows (30d major / 14d minor / 7d patch) as a supply-chain defense. CVE-driven security updates bypass cooldown. Dependabot PRs go through the same CI gates as any other PR.

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
4. Update the README's env-var table, the CLI `--help` description string, and the `description` field in `pyproject.toml` (this is what PyPI renders).

### Overall verdict

`report._overall_verdict` picks the worst verdict from the list in this priority order: `MALICIOUS > SUSPICIOUS > CAUTION > ERROR > CLEAN`. `SKIPPED` results are deliberately excluded — a missing API key should not affect the final call. If you add a new `Verdict` member, both `_overall_verdict` and the `_COLORS` map in `report.py` must be updated.

### Output

`report.py` uses ANSI colors only when stdout is a TTY (`sys.stdout.isatty()`), so piped output stays plain. Details are rendered as aligned key/value pairs from `ServiceResult.details: dict[str, str]` — keep values pre-formatted strings, not raw numbers/objects.

## Notes

- Python ≥ 3.11. Sole runtime dependency is `httpx` (used in async mode by every HTTP service); TLS check uses stdlib `ssl`/`socket` via `asyncio.to_thread`.
- RDAP uses a small heuristic in `services/rdap.py` to extract the registrable domain from subdomains without pulling in the Public Suffix List — be aware it may misclassify exotic TLDs.

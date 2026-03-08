from __future__ import annotations

import sys

from jwlegit.models import ServiceResult, Verdict

# ANSI color codes
_COLORS = {
    Verdict.CLEAN: "\033[32m",      # green
    Verdict.CAUTION: "\033[37m",   # white
    Verdict.SUSPICIOUS: "\033[33m", # yellow
    Verdict.MALICIOUS: "\033[31m",  # red
    Verdict.ERROR: "\033[31m",      # red
    Verdict.SKIPPED: "\033[90m",    # gray
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _use_color() -> bool:
    return sys.stdout.isatty()


def _c(text: str, verdict: Verdict) -> str:
    if not _use_color():
        return text
    return f"{_COLORS[verdict]}{text}{_RESET}"


def _bold(text: str) -> str:
    if not _use_color():
        return text
    return f"{_BOLD}{text}{_RESET}"


def print_report(url: str, results: list[ServiceResult]) -> None:
    width = 60

    print()
    print(f"{'═' * width}")
    print(_bold(f"  jwlegit — URL Reputation Report"))
    print(f"  Target: {url}")
    print(f"{'═' * width}")

    for result in results:
        _print_service(result, width)

    # Overall verdict
    overall = _overall_verdict(results)
    print(f"{'═' * width}")
    label = f"  OVERALL: {overall.value.upper()}"
    print(_bold(_c(label, overall)))
    print(f"{'═' * width}")
    print()


def _print_service(result: ServiceResult, width: int) -> None:
    print(f"{'─' * width}")
    verdict_str = result.verdict.value.upper()
    header = f"  {result.service_name}: {verdict_str}"
    print(_c(header, result.verdict))

    # Collect all key-value pairs for aligned output
    pairs: list[tuple[str, str]] = []

    if result.error:
        pairs.append(("Error", result.error))

    for key, value in result.details.items():
        pairs.append((key, value))

    if result.link:
        pairs.append(("Link", result.link))

    if pairs:
        max_key = max(len(k) for k, _ in pairs)
        for key, value in pairs:
            print(f"    {key + ':':<{max_key + 1}} {value}")


def _overall_verdict(results: list[ServiceResult]) -> Verdict:
    priority = [Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.CAUTION, Verdict.ERROR, Verdict.CLEAN]
    verdicts = {r.verdict for r in results if r.verdict != Verdict.SKIPPED}
    for v in priority:
        if v in verdicts:
            return v
    return Verdict.CLEAN

from __future__ import annotations

import pytest

from jwlegit.models import ServiceResult, Verdict
from jwlegit.report import _overall_verdict


def _r(v: Verdict) -> ServiceResult:
    return ServiceResult(service_name="x", verdict=v)


@pytest.mark.parametrize(
    "verdicts, expected",
    [
        ([Verdict.CLEAN, Verdict.CLEAN], Verdict.CLEAN),
        ([Verdict.CLEAN, Verdict.CAUTION], Verdict.CAUTION),
        ([Verdict.CAUTION, Verdict.SUSPICIOUS], Verdict.SUSPICIOUS),
        ([Verdict.SUSPICIOUS, Verdict.MALICIOUS], Verdict.MALICIOUS),
        ([Verdict.ERROR, Verdict.CLEAN], Verdict.ERROR),
        ([Verdict.ERROR, Verdict.SUSPICIOUS], Verdict.SUSPICIOUS),
        ([Verdict.MALICIOUS, Verdict.ERROR, Verdict.CLEAN], Verdict.MALICIOUS),
    ],
)
def test_priority_ordering(verdicts, expected):
    assert _overall_verdict([_r(v) for v in verdicts]) == expected


def test_skipped_is_excluded():
    # SKIPPED on its own falls back to CLEAN (per current behavior).
    assert _overall_verdict([_r(Verdict.SKIPPED)]) == Verdict.CLEAN
    # SKIPPED does not raise the verdict above other signals.
    assert _overall_verdict([_r(Verdict.SKIPPED), _r(Verdict.CLEAN)]) == Verdict.CLEAN
    # SKIPPED does not suppress MALICIOUS.
    assert (
        _overall_verdict([_r(Verdict.SKIPPED), _r(Verdict.MALICIOUS)])
        == Verdict.MALICIOUS
    )


def test_empty_input():
    assert _overall_verdict([]) == Verdict.CLEAN

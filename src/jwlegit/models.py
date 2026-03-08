from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Verdict(Enum):
    CLEAN = "clean"
    CAUTION = "caution"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass
class ServiceResult:
    service_name: str
    verdict: Verdict
    details: dict[str, str] = field(default_factory=dict)
    link: str = ""
    error: str = ""

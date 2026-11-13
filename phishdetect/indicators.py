"""Evidence model shared by every detection component."""
from __future__ import annotations

from dataclasses import asdict, dataclass

# Evidence sources. The UI and the API keep these visibly separate.
THREAT_INTEL = "threat_intel"   # confirmed match in an external threat feed
HEURISTIC = "heuristic"         # deterministic rule about the URL / message
PAGE = "page"                   # observation from safely retrieving the page
ML = "ml"                       # statistical model prediction
REPUTATION = "reputation"       # popularity / registration-age evidence
UNAVAILABLE = "unavailable"     # a check that could not be performed

# Transparent, fixed weights per severity (see docs/METHODOLOGY.md).
SEVERITY_WEIGHTS = {
    "critical": 0.85,
    "high": 0.55,
    "medium": 0.30,
    "low": 0.12,
    "info": 0.0,
    "positive": 0.0,
}


@dataclass
class Indicator:
    id: str
    title: str
    severity: str
    source: str
    evidence: str = ""
    explanation: str = ""
    weight: float | None = None
    group: str = ""   # indicators in the same group do not stack (strongest wins)

    def __post_init__(self) -> None:
        if self.severity not in SEVERITY_WEIGHTS:
            raise ValueError(f"unknown severity {self.severity}")
        if self.weight is None:
            self.weight = SEVERITY_WEIGHTS[self.severity]

    def to_dict(self) -> dict:
        d = asdict(self)
        d["weight"] = round(float(self.weight), 3)
        return d

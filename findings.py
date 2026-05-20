"""Finding data model shared by every scan module."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

# Lower index == more severe. Used to sort and colour reports.
SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

SEVERITY_COLOR = {
    "critical": "#b00020",
    "high": "#d9480f",
    "medium": "#e8a400",
    "low": "#2b8a3e",
    "info": "#1971c2",
}

# How sure we are the finding is real. "confirmed" is only set by the
# verification phase after a successful proof-of-concept.
CONFIDENCE_LEVELS = ("tentative", "firm", "confirmed")

# Plain-English description of what each verifier WILL do, shown in the
# approval rundown so the operator authorises an action they fully understand.
# Every action here is bounded and non-destructive by design.
VERIFY_ACTIONS = {
    "sqli": "Send balanced vs. unbalanced SQL quote payloads and compare the "
            "responses. Proves the injection point exists — extracts no data.",
    "xss": "Re-send a benign, script-free HTML tag and confirm it lands "
           "unescaped in an executable context. Executes no JavaScript.",
    "open_redirect": "Re-send the redirect payload and capture the Location "
                     "header showing the attacker-controlled destination.",
    "exposed_file": "Fetch the exposed file and confirm its content signature. "
                    "A short, value-redacted snippet is recorded as evidence.",
    "unauth_access": "Request the page with NO credentials and confirm it is a "
                     "genuine authenticated area. Stops at confirmation — "
                     "performs no action inside it.",
}


@dataclass
class Finding:
    """A single observation produced by a scan module."""

    title: str
    severity: str  # one of SEVERITY_ORDER keys
    target: str
    description: str
    module: str
    evidence: str = ""
    remediation: str = ""
    references: list[str] = field(default_factory=list)

    # Richer rundown detail (populated by detection modules where known).
    confidence: str = "tentative"  # one of CONFIDENCE_LEVELS
    impact: str = ""
    reproduction: list[str] = field(default_factory=list)
    transcript: str = ""

    # Verification: verify_type names the verifier; "" means not verifiable.
    verify_type: str = ""
    verify_data: dict = field(default_factory=dict)
    verified: bool = False
    verification: str = ""  # human-readable outcome after the verify phase

    def __post_init__(self) -> None:
        sev = self.severity.lower()
        if sev not in SEVERITY_ORDER:
            sev = "info"
        self.severity = sev
        if self.confidence not in CONFIDENCE_LEVELS:
            self.confidence = "tentative"

    @property
    def rank(self) -> int:
        return SEVERITY_ORDER[self.severity]

    def to_dict(self) -> dict:
        return asdict(self)


def rundown_text(finding: Finding) -> str:
    """Render a full operator briefing for a finding (used at approval time)."""
    lines = [
        f"FINDING: {finding.title}",
        f"  severity    : {finding.severity.upper()}",
        f"  confidence  : {finding.confidence}",
        f"  target      : {finding.target}",
        f"  module      : {finding.module}",
        "",
        f"  {finding.description}",
    ]
    if finding.impact:
        lines += ["", f"  impact      : {finding.impact}"]
    if finding.evidence:
        lines += [f"  evidence    : {finding.evidence}"]
    if finding.reproduction:
        lines += ["", "  reproduction:"]
        lines += [f"    {i}. {step}"
                  for i, step in enumerate(finding.reproduction, 1)]
    action = VERIFY_ACTIONS.get(finding.verify_type)
    if action:
        lines += [
            "",
            "  PROPOSED VERIFICATION (requires your approval):",
            f"    {action}",
        ]
    return "\n".join(lines)

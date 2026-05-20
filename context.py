"""Run configuration and shared assessment context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from rich.console import Console

from sentinel.findings import Finding
from sentinel.http import HttpClient
from sentinel.scope import Scope

ALL_PHASES = [
    "osint", "recon", "ports", "crawl", "content", "jsanalysis", "vulns",
    "defense", "verify",
]

# Async callback that shows a finding's rundown and returns the operator's
# approval decision for running its proof-of-concept verification.
ApprovalCallback = Callable[[Finding], Awaitable[bool]]


@dataclass
class Config:
    """Everything the user can tune from the command line."""

    target: str
    out_dir: str = "reports"
    workspace: str | None = None
    rate: float = 10.0
    concurrency: int = 10
    timeout: float = 15.0
    max_pages: int = 200
    max_depth: int = 4
    allow_private: bool = False
    include_subdomains: bool = True
    verify_tls: bool = True
    # When True the verify phase runs every proof-of-concept without pausing
    # for per-finding approval (still gated by the operator setting the flag).
    auto_verify: bool = False
    phases: list[str] = field(default_factory=lambda: list(ALL_PHASES))


class Context:
    """Carries shared state between scan phases for a single assessment.

    Output is delivered through `log()` and `add_finding()`. By default these
    print to the console (CLI mode); the TUI supplies callbacks instead so the
    same engine drives both interfaces unchanged.
    """

    def __init__(
        self,
        config: Config,
        scope: Scope,
        http: HttpClient,
        log_callback: Callable[[str], None] | None = None,
        finding_callback: Callable[[Finding], None] | None = None,
        approval_callback: ApprovalCallback | None = None,
    ) -> None:
        self.config = config
        self.scope = scope
        self.http = http
        self.console = Console()
        self.findings: list[Finding] = []
        self._log_callback = log_callback
        self._finding_callback = finding_callback
        self._approval_callback = approval_callback

        # Populated as phases run; later phases consume earlier output.
        self.recon: dict = {}
        self.open_ports: list[int] = []
        # Discovered URLs mapped to the set of query parameter names seen.
        self.urls: dict[str, set[str]] = {}

    def log(self, message: str) -> None:
        """Emit a progress line (Rich markup) to the console or UI sink."""
        if self._log_callback is not None:
            self._log_callback(message)
        else:
            self.console.print(message)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self.log(
            f"  [{finding.severity.upper()}] {finding.title} "
            f"[dim]({finding.target})[/dim]"
        )
        if self._finding_callback is not None:
            self._finding_callback(finding)

    def record_url(self, url: str, params: set[str] | None = None) -> None:
        existing = self.urls.setdefault(url, set())
        if params:
            existing.update(params)

    async def request_approval(self, finding: Finding) -> bool:
        """Ask the operator whether to run a finding's verification PoC.

        Returns True when pre-approved via config, when the approval callback
        approves, and False otherwise (e.g. non-interactive run with no flag).
        """
        if self.config.auto_verify:
            return True
        if self._approval_callback is not None:
            return await self._approval_callback(finding)
        return False

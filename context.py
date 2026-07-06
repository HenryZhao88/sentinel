"""Run configuration and shared assessment context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Awaitable, Callable

from rich.console import Console

from sentinel.endpoint import AuthProfile, Endpoint
from sentinel.findings import Finding
from sentinel.http import HttpClient
from sentinel.scope import Scope

ALL_PHASES = [
    "osint", "recon", "ports", "crawl", "browsercrawl", "content",
    "jsanalysis", "access", "vulns", "defense", "verify",
]
DEFAULT_PHASES = [phase for phase in ALL_PHASES if phase != "browsercrawl"]

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
    auth_profiles: list[AuthProfile] = field(default_factory=list)
    primary_auth_profile: str | None = None
    browser: bool = False
    browser_max_actions: int = 40
    ssrf_callback_url: str | None = None
    # When True the verify phase runs every proof-of-concept without pausing
    # for per-finding approval (still gated by the operator setting the flag).
    auto_verify: bool = False
    phases: list[str] = field(default_factory=lambda: list(DEFAULT_PHASES))


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
        # Structured request surfaces discovered by crawl/content/JS/browser
        # phases. Existing modules can keep using `urls`; newer modules should
        # prefer endpoints so POST, JSON and auth context are preserved.
        self.endpoints: list[Endpoint] = []
        self._endpoint_index: dict[str, Endpoint] = {}

        self.auth_profiles = {p.name: p for p in config.auth_profiles}
        self.default_auth_profile = (
            config.primary_auth_profile
            or (config.auth_profiles[0].name if config.auth_profiles else None)
        )

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

    def _record_url_only(self, url: str, params: set[str] | None = None) -> None:
        existing = self.urls.setdefault(url, set())
        if params:
            existing.update(params)

    def record_url(self, url: str, params: set[str] | None = None) -> None:
        """Record a URL in the legacy map and mirror it as a GET endpoint."""
        self._record_url_only(url, params)
        self.record_endpoint(
            Endpoint(
                method="GET",
                url=url,
                query_params=params,
                source="legacy",
                auth_profile=self.default_auth_profile,
            ),
            sync_url=False,
        )

    def record_endpoint(
        self, endpoint: Endpoint | None = None, sync_url: bool = True, **kwargs
    ) -> Endpoint:
        """Record or merge a structured request surface.

        Callers may pass an Endpoint instance or Endpoint constructor kwargs.
        The legacy `ctx.urls` map is kept in sync so older phases continue to
        work while endpoint-aware modules get method/body/JSON/auth metadata.
        """
        ep = endpoint or Endpoint(**kwargs)
        if ep.auth_profile is None:
            ep.auth_profile = self.default_auth_profile
        key = ep.signature()
        existing = self._endpoint_index.get(key)
        if existing is None:
            self._endpoint_index[key] = ep
            self.endpoints.append(ep)
            existing = ep
        else:
            existing.merge(ep)

        if sync_url:
            names = set(existing.query_params)
            if existing.method != "GET":
                names.update(existing.body_params)
            self._record_url_only(existing.url, names)
        return existing

    def auth_kwargs(
        self,
        url: str,
        auth_profile: str | None = None,
        use_default_auth: bool = True,
    ) -> dict:
        name = auth_profile
        if name is None and use_default_auth:
            name = self.default_auth_profile
        if not name:
            return {}
        profile = self.auth_profiles.get(name)
        if profile is None:
            return {}
        return profile.request_kwargs(url)

    async def request(
        self,
        method: str,
        url: str,
        auth_profile: str | None = None,
        use_default_auth: bool = True,
        **kwargs,
    ):
        auth = self.auth_kwargs(url, auth_profile, use_default_auth)
        request_headers = kwargs.pop("headers", None) or {}
        request_cookies = kwargs.pop("cookies", None) or {}
        headers = {**auth.pop("headers", {}), **request_headers}
        cookies = {**auth.pop("cookies", {}), **request_cookies}
        if headers:
            kwargs["headers"] = headers
        if cookies:
            kwargs["cookies"] = cookies
        return await self.http.request(method, url, **kwargs)

    async def get(self, url: str, **kwargs):
        return await self.request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs):
        return await self.request("POST", url, **kwargs)

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

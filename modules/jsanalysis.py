"""JavaScript analysis: endpoint extraction and leaked-secret detection.

Fetches in-scope JavaScript files and statically inspects them for hidden API
routes (fed forward to the vulns phase) and accidentally-shipped secrets.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urljoin, urlparse

from sentinel.context import Context
from sentinel.findings import Finding

_MAX_FILES = 60
_MAX_BYTES = 3_000_000

# Patterns for credentials that should never appear in client-side code.
# Severity reflects how directly the match implies a usable secret.
_SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("AWS access key ID", "high", r"AKIA[0-9A-Z]{16}"),
    ("Google API key", "high", r"AIza[0-9A-Za-z\-_]{35}"),
    ("Slack token", "high", r"xox[baprs]-[0-9A-Za-z-]{10,48}"),
    ("Stripe live secret key", "critical", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("GitHub token", "high", r"gh[pousr]_[0-9A-Za-z]{36,}"),
    ("Private key block", "critical",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    ("JSON Web Token", "medium",
     r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("Hardcoded secret assignment", "medium",
     r"(?i)(?:api[_-]?key|secret|password|access[_-]?token)"
     r"\s*[:=]\s*['\"][0-9a-zA-Z\-_/+]{12,}['\"]"),
]
_COMPILED_SECRETS = [
    (name, sev, re.compile(pattern)) for name, sev, pattern in _SECRET_PATTERNS
]

# Quoted absolute paths and full URLs — likely API endpoints.
_PATH_RE = re.compile(r"""['"](/[A-Za-z0-9_./-][A-Za-z0-9_?&=./%~-]{2,120})['"]""")
_URL_RE = re.compile(r"""['"](https?://[A-Za-z0-9._-]+/[A-Za-z0-9_?&=./%~-]{0,120})['"]""")


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» jsanalysis[/bold cyan]")

    js_urls = await _collect_js_urls(ctx)
    if not js_urls:
        ctx.log("  [dim]no in-scope JavaScript files found[/dim]")
        return

    sem = asyncio.Semaphore(ctx.config.concurrency)
    endpoints: set[str] = set()

    async def _analyse(url: str) -> None:
        async with sem:
            resp = await ctx.http.get(url)
        if resp is None or resp.status_code != 200:
            return
        body = resp.text[:_MAX_BYTES]
        _scan_secrets(ctx, url, body)
        endpoints.update(_extract_endpoints(ctx, url, body))

    await asyncio.gather(*(_analyse(u) for u in js_urls))

    ctx.recon["js_files_analysed"] = len(js_urls)
    ctx.recon["js_endpoints"] = sorted(endpoints)
    if endpoints:
        ctx.add_finding(Finding(
            title=f"{len(endpoints)} endpoint(s) extracted from JavaScript",
            severity="info",
            target=ctx.scope.host,
            module="jsanalysis",
            description="Static analysis of client-side JavaScript revealed "
                        "URL paths. In-scope paths were forwarded to the "
                        "vulns phase for testing.",
            evidence=", ".join(sorted(endpoints)[:25])
                     + (" …" if len(endpoints) > 25 else ""),
            remediation="Confirm undocumented or admin endpoints enforce "
                        "authentication and authorization server-side.",
        ))


async def _collect_js_urls(ctx: Context) -> list[str]:
    """Gather in-scope .js URLs from the crawl plus the target's root page."""
    found = {
        u for u in ctx.urls
        if urlparse(u).path.lower().endswith(".js") and ctx.scope.in_scope(u)
    }
    # Even without a prior crawl, parse <script src> from the landing page.
    resp = await ctx.http.get(ctx.scope.root_url)
    if resp is not None and "html" in resp.headers.get("content-type", ""):
        for src in re.findall(
            r"""<script[^>]+src=['"]([^'"]+)['"]""", resp.text, re.IGNORECASE
        ):
            absolute = urljoin(ctx.scope.root_url, src)
            if absolute.lower().split("?")[0].endswith(".js") \
                    and ctx.scope.in_scope(absolute):
                found.add(absolute)
    return sorted(found)[:_MAX_FILES]


def _scan_secrets(ctx: Context, url: str, body: str) -> None:
    for name, severity, pattern in _COMPILED_SECRETS:
        match = pattern.search(body)
        if not match:
            continue
        snippet = match.group(0)
        # Redact the middle of the match so the report doesn't store the secret.
        if len(snippet) > 14:
            snippet = f"{snippet[:8]}…{snippet[-4:]}"
        ctx.add_finding(Finding(
            title=f"Possible {name} exposed in JavaScript",
            severity=severity,
            target=url,
            module="jsanalysis",
            description="A pattern matching a credential or key was found in "
                        "client-side JavaScript, which is fully visible to "
                        "any visitor.",
            evidence=f"matched {name}: {snippet}",
            remediation="Rotate the exposed credential immediately and move "
                        "secrets to server-side configuration.",
            references=["https://owasp.org/www-community/vulnerabilities/"
                        "Use_of_hard-coded_password"],
        ))


def _extract_endpoints(ctx: Context, url: str, body: str) -> set[str]:
    endpoints: set[str] = set()
    base = ctx.scope.root_url
    for match in _PATH_RE.findall(body):
        absolute = urljoin(base, match)
        if ctx.scope.in_scope(absolute):
            endpoints.add(absolute)
            query = urlparse(absolute).query
            params = {p.split("=")[0] for p in query.split("&") if p}
            ctx.record_url(absolute, params)
    for match in _URL_RE.findall(body):
        if ctx.scope.in_scope(match):
            endpoints.add(match)
            ctx.record_url(match)
    return endpoints

"""JavaScript analysis: endpoint extraction and leaked-secret detection.

Fetches in-scope JavaScript files and statically inspects them for hidden API
routes (fed forward to the vulns phase) and accidentally-shipped secrets.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qsl, urljoin, urlparse

from sentinel.context import Context
from sentinel.endpoint import Endpoint
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
_FETCH_URL_RE = re.compile(r"""fetch\(\s*['"`]([^'"`]+)['"`]""")
_AXIOS_RE = re.compile(
    r"""axios\.(get|post|put|patch|delete)\(\s*['"`]([^'"`]+)['"`]([^;]{0,1200})""",
    re.IGNORECASE,
)
_JSON_STRINGIFY_RE = re.compile(r"""JSON\.stringify\(\s*(\{.{0,1000}?\})\s*\)""",
                                re.DOTALL)
_OBJECT_PAIR_RE = re.compile(
    r"""['"]?([A-Za-z_$][\w$-]*)['"]?\s*:\s*("""
    r"""'[^']*'|"[^"]*"|\d+|true|false|null)""",
    re.IGNORECASE,
)
_DOM_SOURCES: list[tuple[str, re.Pattern[str]]] = [
    ("location", re.compile(
        r"\b(?:window\.)?location(?:\.(?:href|hash|search|pathname))?\b",
        re.IGNORECASE,
    )),
    ("document URL/referrer", re.compile(
        r"\bdocument\.(?:URL|documentURI|referrer)\b",
        re.IGNORECASE,
    )),
    ("window.name", re.compile(r"\bwindow\.name\b", re.IGNORECASE)),
    ("web storage", re.compile(
        r"\b(?:localStorage|sessionStorage)\.getItem\s*\(",
        re.IGNORECASE,
    )),
    ("postMessage data", re.compile(
        r"\baddEventListener\s*\(\s*['\"]message['\"]|\bevent\.data\b",
        re.IGNORECASE,
    )),
]
_DOM_SINKS: list[tuple[str, re.Pattern[str]]] = [
    ("HTML assignment", re.compile(
        r"\.(?:innerHTML|outerHTML)\s*=",
        re.IGNORECASE,
    )),
    ("insertAdjacentHTML", re.compile(
        r"\.insertAdjacentHTML\s*\(",
        re.IGNORECASE,
    )),
    ("document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(", re.IGNORECASE)),
    ("eval/function sink", re.compile(
        r"\b(?:eval|Function|setTimeout|setInterval)\s*\(",
        re.IGNORECASE,
    )),
    ("React dangerouslySetInnerHTML", re.compile(
        r"dangerouslySetInnerHTML",
        re.IGNORECASE,
    )),
]
_DIRECT_DOM_XSS = re.compile(
    r"(?:(?:innerHTML|outerHTML)\s*=\s*[^;\n]{0,120}"
    r"(?:location|document\.(?:URL|documentURI|referrer)|window\.name|"
    r"event\.data|localStorage|sessionStorage)|"
    r"(?:document\.write(?:ln)?|insertAdjacentHTML|eval|Function)\s*\("
    r"[^;\n]{0,160}(?:location|document\.(?:URL|documentURI|referrer)|"
    r"window\.name|event\.data|localStorage|sessionStorage))",
    re.IGNORECASE,
)


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» jsanalysis[/bold cyan]")

    js_urls = await _collect_js_urls(ctx)
    if not js_urls:
        ctx.log("  [dim]no in-scope JavaScript files found[/dim]")
        return

    sem = asyncio.Semaphore(ctx.config.concurrency)
    endpoints: set[str] = set()
    dom_findings = 0

    async def _analyse(url: str) -> None:
        nonlocal dom_findings
        async with sem:
            resp = await ctx.get(url)
        if resp is None or resp.status_code != 200:
            return
        body = resp.text[:_MAX_BYTES]
        _scan_secrets(ctx, url, body)
        dom_findings += _scan_dom_xss(ctx, url, body)
        endpoints.update(_extract_endpoints(ctx, url, body))

    await asyncio.gather(*(_analyse(u) for u in js_urls))

    ctx.recon["js_files_analysed"] = len(js_urls)
    ctx.recon["js_endpoints"] = sorted(endpoints)
    ctx.recon["dom_xss_candidates"] = dom_findings
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
    found.update(
        e.url for e in ctx.endpoints
        if urlparse(e.url).path.lower().endswith(".js") and ctx.scope.in_scope(e.url)
    )
    # Even without a prior crawl, parse <script src> from the landing page.
    resp = await ctx.get(ctx.scope.root_url)
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


def _scan_dom_xss(ctx: Context, url: str, body: str) -> int:
    source_hits = [name for name, pattern in _DOM_SOURCES if pattern.search(body)]
    sink_hits = [name for name, pattern in _DOM_SINKS if pattern.search(body)]
    if not source_hits or not sink_hits:
        return 0

    direct = _DIRECT_DOM_XSS.search(body)
    if direct:
        snippet = re.sub(r"\s+", " ", direct.group(0)).strip()[:180]
        ctx.add_finding(Finding(
            title="Likely DOM XSS source-to-sink flow in JavaScript",
            severity="high",
            target=url,
            module="jsanalysis",
            description="Client-side JavaScript appears to move browser-"
                        "controlled data such as location, referrer, message "
                        "data, or storage into a dangerous DOM/eval sink.",
            evidence=f"sources={', '.join(source_hits[:4])}; "
                     f"sinks={', '.join(sink_hits[:4])}; snippet={snippet}",
            remediation="Parse and validate browser-controlled data, write "
                        "text with safe APIs such as textContent, and avoid "
                        "HTML/eval sinks for untrusted values.",
            references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
            confidence="firm",
            impact="An attacker may be able to execute JavaScript in the "
                   "victim's browser by controlling a URL fragment, query "
                   "string, postMessage payload, referrer, or stored browser "
                   "value.",
        ))
        return 1

    ctx.add_finding(Finding(
        title="Potential DOM XSS source and sink in same JavaScript file",
        severity="medium",
        target=url,
        module="jsanalysis",
        description="The file reads browser-controlled data and also contains "
                    "dangerous DOM/eval sinks. Static matching did not prove a "
                    "flow, but this is a strong manual review target.",
        evidence=f"sources={', '.join(source_hits[:5])}; "
                 f"sinks={', '.join(sink_hits[:5])}",
        remediation="Trace data flow from the listed sources to sinks. Encode "
                    "or sanitize before HTML insertion and prefer safe DOM APIs.",
        references=["https://owasp.org/www-community/attacks/DOM_Based_XSS"],
    ))
    return 1


def _extract_endpoints(ctx: Context, url: str, body: str) -> set[str]:
    endpoints: set[str] = set()
    base = ctx.scope.root_url

    for match in _FETCH_URL_RE.finditer(body):
        absolute = _absolute(ctx, base, match.group(1))
        if not absolute:
            continue
        window = body[match.end():match.end() + 1200]
        method = _extract_method(window) or "GET"
        json_body = _extract_json_body(window)
        content_type = "application/json" if json_body is not None else ""
        _record_js_endpoint(
            ctx, url, absolute, method=method, json_body=json_body,
            content_type=content_type,
        )
        endpoints.add(absolute)

    for method, raw_url, tail in _AXIOS_RE.findall(body):
        absolute = _absolute(ctx, base, raw_url)
        if not absolute:
            continue
        json_body = _extract_json_body(tail) or _extract_object_literal(tail)
        content_type = "application/json" if json_body is not None else ""
        _record_js_endpoint(
            ctx, url, absolute, method=method.upper(), json_body=json_body,
            content_type=content_type,
        )
        endpoints.add(absolute)

    for match in _PATH_RE.findall(body):
        absolute = urljoin(base, match)
        if ctx.scope.in_scope(absolute):
            endpoints.add(absolute)
            _record_js_endpoint(ctx, url, absolute, method="GET")
    for match in _URL_RE.findall(body):
        if ctx.scope.in_scope(match):
            endpoints.add(match)
            _record_js_endpoint(ctx, url, match, method="GET")
    return endpoints


def _absolute(ctx: Context, base: str, raw: str) -> str | None:
    if raw.startswith(("ws://", "wss://", "mailto:", "tel:", "data:")):
        return None
    absolute = urljoin(base, raw)
    if not absolute.startswith(("http://", "https://")):
        return None
    if not ctx.scope.in_scope(absolute):
        return None
    return absolute


def _extract_method(window: str) -> str | None:
    match = re.search(r"""method\s*:\s*['"`]([A-Za-z]+)['"`]""", window,
                      re.IGNORECASE)
    return match.group(1).upper() if match else None


def _literal_value(raw: str):
    raw = raw.strip()
    if raw[0:1] in {"'", '"'} and raw[-1:] == raw[0]:
        return raw[1:-1]
    if raw.lower() == "true":
        return True
    if raw.lower() == "false":
        return False
    if raw.lower() == "null":
        return None
    try:
        return int(raw)
    except ValueError:
        return raw


def _extract_object_literal(text: str) -> dict | None:
    start = text.find("{")
    end = text.find("}", start + 1)
    if start == -1 or end == -1:
        return None
    pairs = _OBJECT_PAIR_RE.findall(text[start:end + 1])
    if not pairs:
        return None
    return {name: _literal_value(value) for name, value in pairs}


def _extract_json_body(text: str) -> dict | None:
    match = _JSON_STRINGIFY_RE.search(text)
    if not match:
        return None
    return _extract_object_literal(match.group(1))


def _query_params(url: str) -> dict[str, str]:
    return dict(parse_qsl(urlparse(url).query, keep_blank_values=True))


def _record_js_endpoint(
    ctx: Context,
    source_url: str,
    absolute: str,
    method: str,
    json_body: dict | None = None,
    content_type: str = "",
) -> None:
    query = _query_params(absolute)
    ctx.record_url(absolute, set(query))
    ctx.record_endpoint(Endpoint(
        method=method,
        url=absolute,
        query_params=query,
        json_body=json_body,
        content_type=content_type,
        source="jsanalysis",
        auth_profile=ctx.default_auth_profile,
        evidence_url=source_url,
    ))

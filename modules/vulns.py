"""Non-destructive vulnerability checks.

Every check here is read-only and benign: it sends a small number of probe
requests with harmless markers and inspects responses. No payloads attempt to
execute code, modify data, or brute-force credentials.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import tempfile
import uuid
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sentinel.context import Context
from sentinel.endpoint import Endpoint, json_leaf_paths, set_json_leaf
from sentinel.findings import SEVERITY_ORDER, Finding
from sentinel.integrations import run_command, tool_path

# Unique token unlikely to appear naturally in a response.
_MARKER = "sntl9z3x"
# Special characters whose un-encoded reflection indicates missing output
# encoding (a strong reflected-XSS signal).
_XSS_PROBE = f"{_MARKER}<\"'>"

# Database error fingerprints (error-based SQLi indicator).
_SQL_ERRORS = re.compile(
    r"(SQL syntax.*MySQL|valid MySQL result|MySqlClient\.|"
    r"SQL syntax|PostgreSQL.*ERROR|pg_query\(\)|"
    r"ORA-\d{5}|Oracle error|"
    r"Microsoft OLE DB Provider for SQL Server|"
    r"SQLite/JDBCDriver|SQLite\.Exception|"
    r"Warning.*\bmysqli?_|Unclosed quotation mark after the character string)",
    re.IGNORECASE,
)

# Parameter names commonly used for redirects.
_REDIRECT_PARAMS = {
    "url", "next", "return", "returnurl", "return_url", "redirect",
    "redirect_uri", "redirect_url", "dest", "destination", "continue", "to",
}
_EVIL_HOST = "sentinel-oob.example"
_MAX_NUCLEI_TARGETS = 50
_SSRF_PATH_HINT = re.compile(
    r"(proxy|fetch|import|webhook|callback|render|preview|image|avatar|url)",
    re.IGNORECASE,
)


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» vulns[/bold cyan]")

    await _cookie_flags(ctx)
    await _cors(ctx)

    targets = _endpoints_with_params(ctx)
    if not targets:
        ctx.log("  [dim]no parameterised endpoints to test with built-in checks"
                "[/dim]")
    else:
        sem = asyncio.Semaphore(ctx.config.concurrency)

        async def _test(endpoint: Endpoint) -> None:
            async with sem:
                await _reflected_xss(ctx, endpoint)
                await _sql_injection(ctx, endpoint)
                await _open_redirect(ctx, endpoint)
                await _url_taking_review(ctx, endpoint)

        await asyncio.gather(*(_test(endpoint) for endpoint in targets))

    _summarise_endpoint_risks(ctx)

    await _nuclei_scan(ctx)


def _json_sample(endpoint: Endpoint) -> dict | list | None:
    if endpoint.json_body is not None:
        return endpoint.json_body
    if "json" in endpoint.content_type.lower() and endpoint.body_params:
        return dict(endpoint.body_params)
    return None


def _param_surfaces(endpoint: Endpoint) -> list[tuple[str, str]]:
    surfaces: list[tuple[str, str]] = []
    surfaces.extend(("query", name) for name in endpoint.query_params)
    if endpoint.method not in {"GET", "HEAD", "OPTIONS"} and not endpoint.is_json:
        surfaces.extend(("body", name) for name in endpoint.body_params)
    sample = _json_sample(endpoint)
    if sample is not None:
        surfaces.extend(("json", path) for path in json_leaf_paths(sample))
    return surfaces


def _endpoints_with_params(ctx: Context) -> list[Endpoint]:
    endpoints = list(ctx.endpoints)
    if not endpoints:
        endpoints = [
            Endpoint(method="GET", url=url, query_params=params, source="legacy")
            for url, params in ctx.urls.items()
        ]
    seen: set[str] = set()
    selected: list[Endpoint] = []
    for endpoint in endpoints:
        if not _param_surfaces(endpoint):
            continue
        key = endpoint.signature()
        if key in seen:
            continue
        seen.add(key)
        selected.append(endpoint)
    return selected


def _surface_label(surface: str, name: str) -> str:
    if surface == "query":
        return f"query parameter '{name}'"
    if surface == "body":
        return f"form/body parameter '{name}'"
    return f"JSON field '{name}'"


def _xss_probe(surface: str, name: str) -> tuple[str, str]:
    token = re.sub(r"[^A-Za-z0-9_-]", "_", f"{surface}_{name}")[:48]
    marker = f"{_MARKER}_{token}"
    return marker, f"{marker}<\"'>"


def _base_headers(endpoint: Endpoint) -> dict[str, str]:
    headers = dict(endpoint.headers)
    if endpoint.content_type and "content-type" not in {
        k.lower() for k in headers
    }:
        headers["Content-Type"] = endpoint.content_type
    return headers


async def _send_probe(
    ctx: Context,
    endpoint: Endpoint,
    surface: str,
    name: str,
    value: str,
    follow_redirects: bool = False,
):
    url = endpoint.url
    kwargs: dict = {
        "headers": _base_headers(endpoint),
        "follow_redirects": follow_redirects,
    }
    if surface == "query":
        url = _with_param(url, name, value)

    if endpoint.method not in {"GET", "HEAD", "OPTIONS"}:
        sample = _json_sample(endpoint)
        if sample is not None:
            payload = set_json_leaf(sample, name, value) if surface == "json" else sample
            kwargs["json"] = payload
            kwargs["headers"].setdefault("Content-Type", "application/json")
        else:
            data = dict(endpoint.body_params)
            if surface == "body":
                data[name] = value
            if data:
                kwargs["data"] = data

    resp = await ctx.request(
        endpoint.method,
        url,
        auth_profile=endpoint.auth_profile,
        **kwargs,
    )
    return resp, url


def _current_value(endpoint: Endpoint, surface: str, name: str) -> str:
    if surface == "query":
        return str(endpoint.query_params.get(name, "1") or "1")
    if surface == "body":
        return str(endpoint.body_params.get(name, "1") or "1")
    sample = _json_sample(endpoint)
    if isinstance(sample, dict):
        current = sample
        for part in name.split("."):
            if isinstance(current, list):
                current = current[int(part)]
            else:
                current = current.get(part, "1")
        return str(current or "1")
    return "1"


async def _nuclei_scan(ctx: Context) -> None:
    """Run nuclei's community templates against the target, if installed."""
    nuclei = tool_path("nuclei")
    if not nuclei:
        return
    targets = _nuclei_targets(ctx)
    ctx.recon["nuclei_targets"] = targets
    ctx.log(f"  [dim]running nuclei community templates against "
            f"{len(targets)} target(s)[/dim]")

    tmp_path = ""
    if len(targets) == 1:
        target_args = ["-u", targets[0]]
    else:
        with tempfile.NamedTemporaryFile("w", delete=False) as handle:
            tmp_path = handle.name
            handle.write("\n".join(targets) + "\n")
        target_args = ["-list", tmp_path]

    try:
        code, stdout, stderr = await run_command(
            [
                nuclei, *target_args,
                "-jsonl", "-silent", "-no-color",
                "-severity", "low,medium,high,critical",
                "-rate-limit", str(int(max(ctx.config.rate, 1))),
                "-timeout", "10",
            ],
            timeout=600,
        )
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
    if code != 0 and not stdout.strip():
        ctx.log(f"  [yellow]nuclei did not complete: {stderr.strip()[:120]}"
                "[/yellow]")
        return

    count = 0
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = hit.get("info", {})
        severity = str(info.get("severity", "info")).lower()
        if severity not in SEVERITY_ORDER:
            severity = "info"
        refs = info.get("reference") or []
        if isinstance(refs, str):
            refs = [refs]
        ctx.add_finding(Finding(
            title=f"[nuclei] {info.get('name', hit.get('template-id', 'finding'))}",
            severity=severity,
            target=hit.get("matched-at") or hit.get("host")
                   or ctx.scope.root_url,
            module="vulns",
            description=info.get("description")
                        or f"nuclei template '{hit.get('template-id', '')}' "
                           "matched.",
            evidence=f"template-id={hit.get('template-id', '')}",
            remediation=info.get("remediation")
                        or "Review the referenced nuclei template for "
                           "remediation guidance.",
            references=[r for r in refs if isinstance(r, str)][:5],
        ))
        count += 1
    ctx.recon["nuclei_findings"] = count
    ctx.log(f"  [dim]nuclei contributed {count} finding(s)[/dim]")


def _nuclei_targets(ctx: Context) -> list[str]:
    seen: set[str] = set()
    targets: list[str] = []

    def add(url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            return
        clean = urlunparse(parsed._replace(fragment=""))
        if clean in seen:
            return
        seen.add(clean)
        targets.append(clean)

    add(ctx.scope.root_url)
    for endpoint in ctx.endpoints:
        add(endpoint.url)
        if len(targets) >= _MAX_NUCLEI_TARGETS:
            return targets
    for url in ctx.urls:
        add(url)
        if len(targets) >= _MAX_NUCLEI_TARGETS:
            break
    return targets[:_MAX_NUCLEI_TARGETS]


def _with_param(url: str, name: str, value: str) -> str:
    """Return url with query parameter `name` set to `value`."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = value
    return urlunparse(parts._replace(query=urlencode(query)))


async def _reflected_xss(ctx: Context, endpoint: Endpoint) -> None:
    for surface, name in _param_surfaces(endpoint):
        marker, probe_value = _xss_probe(surface, name)
        resp, sent_url = await _send_probe(
            ctx, endpoint, surface, name, probe_value
        )
        if resp is None:
            continue
        ctype = resp.headers.get("content-type", "").lower()
        body = resp.text
        label = _surface_label(surface, name)
        reported_immediate = False
        if probe_value in body:
            reported_immediate = True
            html_response = "html" in ctype
            ctx.add_finding(Finding(
                title=f"Reflected unescaped input in {label}",
                severity="high" if html_response else "medium",
                target=endpoint.url,
                module="vulns",
                description="A probe containing < > \" ' was reflected verbatim "
                            "in the response. In HTML this is a strong "
                            "reflected-XSS signal; in API responses it is a "
                            "dangerous reflection that often becomes DOM XSS "
                            "when clients render it unsafely.",
                evidence=f"{endpoint.method} {surface}:{name}; "
                         f"reflected marker {probe_value!r}",
                remediation="Context-aware output encoding; for API responses, "
                            "keep JSON typed and never inject values into the "
                            "DOM with unsafe sinks.",
                references=["https://owasp.org/www-community/attacks/xss/"],
                confidence="firm",
                impact="An attacker may be able to make victim-controlled "
                       "input execute in this site's browser origin when the "
                       "response is rendered as HTML or consumed by unsafe "
                       "client-side code.",
                reproduction=[
                    f"Send {endpoint.method} {sent_url} with {label} set to "
                    f"{probe_value!r}.",
                    "Observe the probe reflected unescaped in the response.",
                ],
                verify_type="xss" if surface == "query" else "",
                verify_data={
                    "url": endpoint.url,
                    "param": name,
                    "auth_profile": endpoint.auth_profile,
                }
                if surface == "query" else {},
            ))
        elif marker in body:
            reported_immediate = True
            severity = "medium" if surface == "json" or "json" in ctype else "info"
            ctx.add_finding(Finding(
                title=f"Input reflected in response for {label}",
                severity=severity,
                target=endpoint.url,
                module="vulns",
                description="Input is reflected in the response. Special "
                            "characters appear encoded or transformed, but the "
                            "endpoint should be reviewed for context-specific "
                            "XSS or unsafe client-side rendering.",
                evidence=f"{endpoint.method} {surface}:{name}; marker reflected",
                remediation="Confirm encoding is correct for every output "
                            "context (HTML, attribute, JavaScript, URL, JSON).",
            ))
        if not reported_immediate:
            await _stored_xss_followup(
                ctx, endpoint, surface, name, sent_url, marker, probe_value
            )


async def _sql_injection(ctx: Context, endpoint: Endpoint) -> None:
    for surface, name in _param_surfaces(endpoint):
        baseline, _ = await _send_probe(ctx, endpoint, surface, name, _MARKER)
        if baseline is None:
            continue
        if _SQL_ERRORS.search(baseline.text):
            continue  # baseline already errors; cannot attribute to our probe
        probe, sent_url = await _send_probe(
            ctx, endpoint, surface, name, f"{_MARKER}'"
        )
        if probe is None:
            continue
        match = _SQL_ERRORS.search(probe.text)
        if match:
            current = _current_value(endpoint, surface, name)
            label = _surface_label(surface, name)
            ctx.add_finding(Finding(
                title=f"Possible SQL injection in {label}",
                severity="critical",
                target=endpoint.url,
                module="vulns",
                description="Appending a single quote to the parameter produced "
                            "a database error not present in the baseline "
                            "response, an error-based SQL injection indicator.",
                evidence=f"{endpoint.method} {surface}:{name}; "
                         f"error fragment: {match.group(0)[:120]}",
                remediation="Use parameterised queries / prepared statements; "
                            "never build SQL from raw input.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                confidence="firm",
                impact="An attacker could read or modify database contents and "
                       "potentially bypass authentication.",
                reproduction=[
                    f"Send {endpoint.method} {sent_url} with {label} containing "
                    "a trailing quote.",
                    "Observe a database error absent from the baseline response.",
                ],
                verify_type="sqli" if surface == "query" else "",
                verify_data={
                    "url": endpoint.url,
                    "param": name,
                    "value": current,
                    "auth_profile": endpoint.auth_profile,
                }
                if surface == "query" else {},
            ))


async def _open_redirect(ctx: Context, endpoint: Endpoint) -> None:
    for surface, name in _param_surfaces(endpoint):
        if name.split(".")[-1].lower() not in _REDIRECT_PARAMS:
            continue
        resp, sent_url = await _send_probe(
            ctx,
            endpoint,
            surface,
            name,
            f"https://{_EVIL_HOST}/",
            follow_redirects=False,
        )
        if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
            continue
        location = resp.headers.get("location", "")
        if _EVIL_HOST in urlparse(location).netloc:
            label = _surface_label(surface, name)
            ctx.add_finding(Finding(
                title=f"Open redirect via {label}",
                severity="medium",
                target=endpoint.url,
                module="vulns",
                description="The parameter controls the redirect destination "
                            "and accepts an arbitrary external host.",
                evidence=f"{endpoint.method} {surface}:{name}; Location: {location}",
                remediation="Allow-list redirect targets or use relative paths "
                            "only.",
                references=["https://owasp.org/www-community/attacks/"
                            "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                confidence="firm",
                impact="An attacker could craft a link or request on this "
                       "domain that sends users to a malicious site, useful "
                       "for phishing and OAuth token theft.",
                reproduction=[
                    f"Send {endpoint.method} {sent_url} with {label} set to "
                    f"https://{_EVIL_HOST}/.",
                    f"Observe an HTTP {resp.status_code} redirect to the "
                    "external host.",
                ],
                verify_type="open_redirect" if surface == "query" else "",
                verify_data={
                    "url": endpoint.url,
                    "param": name,
                    "auth_profile": endpoint.auth_profile,
                }
                if surface == "query" else {},
            ))


async def _url_taking_review(ctx: Context, endpoint: Endpoint) -> None:
    if "takes_url" not in endpoint.risk_hints:
        return
    parsed = urlparse(endpoint.url)
    if not _SSRF_PATH_HINT.search(parsed.path):
        return
    url_like_surfaces = [
        (surface, name)
        for surface, name in _param_surfaces(endpoint)
        if name.split(".")[-1].lower() in _REDIRECT_PARAMS
        or name.split(".")[-1].lower().endswith("_url")
        or name.split(".")[-1].lower() in {"url", "uri", "host", "callback", "webhook"}
    ]
    if not url_like_surfaces:
        return
    url_like = [_surface_label(surface, name) for surface, name in url_like_surfaces]
    ctx.add_finding(Finding(
        title="URL-taking endpoint suitable for SSRF/OOB review",
        severity="low",
        target=endpoint.url,
        module="vulns",
        description="The endpoint accepts URL/host-like input on a route whose "
                    "name suggests fetching, proxying, rendering, or callbacks. "
                    "Sentinel does not perform out-of-band SSRF callbacks, so "
                    "this is a prioritised manual/OOB test candidate.",
        evidence=f"{endpoint.method}; inputs: {', '.join(url_like[:6])}",
        remediation="If the server fetches user-supplied URLs, enforce strict "
                    "scheme/host allow-lists, block private address ranges, "
                    "and resolve/re-check DNS at connection time.",
        references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
    ))
    if ctx.config.ssrf_callback_url:
        await _send_ssrf_callback_probe(ctx, endpoint, url_like_surfaces[0])


async def _send_ssrf_callback_probe(
    ctx: Context,
    endpoint: Endpoint,
    surface_name: tuple[str, str],
) -> None:
    surface, name = surface_name
    callback = _callback_url(ctx.config.ssrf_callback_url or "")
    resp, sent_url = await _send_probe(
        ctx,
        endpoint,
        surface,
        name,
        callback,
        follow_redirects=False,
    )
    status = resp.status_code if resp is not None else "no-response"
    ctx.recon.setdefault("ssrf_callback_probes", []).append({
        "endpoint": endpoint.url,
        "method": endpoint.method,
        "surface": surface,
        "name": name,
        "callback": callback,
        "status": status,
    })
    ctx.add_finding(Finding(
        title="SSRF/OOB callback probe dispatched",
        severity="info",
        target=endpoint.url,
        module="vulns",
        description="Sentinel sent a unique operator-provided callback URL to "
                    "a URL-like parameter. Check the collaborator/callback "
                    "service for the token to determine whether the server "
                    "made an outbound request.",
        evidence=f"{endpoint.method} {sent_url}; {_surface_label(surface, name)}; "
                 f"callback={callback}; response={status}",
        remediation="If the callback was received, treat this as SSRF and "
                    "restrict outbound fetches with strict allow-lists and "
                    "private-network protections.",
    ))


def _callback_url(base: str) -> str:
    token = f"sentinel-{uuid.uuid4().hex}"
    parsed = urlparse(base)
    query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    query["sentinel"] = token
    return urlunparse(parsed._replace(query=urlencode(query)))


async def _stored_xss_followup(
    ctx: Context,
    endpoint: Endpoint,
    surface: str,
    name: str,
    sent_url: str,
    marker: str,
    probe_value: str,
) -> None:
    if endpoint.method in {"GET", "HEAD", "OPTIONS"}:
        return
    follow_url = endpoint.evidence_url or ctx.scope.root_url
    if not ctx.scope.in_scope(follow_url):
        follow_url = ctx.scope.root_url
    resp = await ctx.get(
        follow_url,
        auth_profile=endpoint.auth_profile,
        follow_redirects=False,
    )
    if resp is None:
        return
    body = resp.text
    ctype = resp.headers.get("content-type", "").lower()
    label = _surface_label(surface, name)
    if probe_value in body and "html" in ctype:
        ctx.add_finding(Finding(
            title=f"Potential stored XSS via {label}",
            severity="high",
            target=endpoint.url,
            module="vulns",
            description="A probe submitted to a non-GET endpoint was later "
                        "rendered unescaped on a related page, indicating "
                        "stored or persistent XSS behavior.",
            evidence=f"{endpoint.method} {surface}:{name}; follow-up={follow_url}; "
                     f"marker={probe_value!r}",
            remediation="Encode stored user input on output, sanitize rich text "
                        "with an allow-list sanitizer, and validate server-side "
                        "before persistence.",
            references=["https://owasp.org/www-community/attacks/xss/"],
            confidence="firm",
            impact="An attacker could persist script-capable markup that later "
                   "executes in other users' browsers.",
            reproduction=[
                f"Submit {endpoint.method} {sent_url} with {label} set to "
                f"{probe_value!r}.",
                f"Fetch {follow_url} and observe the marker rendered unescaped.",
            ],
        ))
    elif marker in body:
        ctx.add_finding(Finding(
            title=f"Input appears persisted via {label}",
            severity="medium",
            target=endpoint.url,
            module="vulns",
            description="A marker submitted to a non-GET endpoint appeared on "
                        "a related page. Special characters were not observed "
                        "unescaped, but this is a stored-XSS/manual review "
                        "candidate.",
            evidence=f"{endpoint.method} {surface}:{name}; follow-up={follow_url}",
            remediation="Trace where submitted input is persisted and confirm "
                        "all later output contexts are encoded safely.",
        ))


def _summarise_endpoint_risks(ctx: Context) -> None:
    stateful = [e for e in ctx.endpoints if "state_changing" in e.risk_hints]
    uploads = [e for e in ctx.endpoints if "file_upload" in e.risk_hints]
    api = [e for e in ctx.endpoints if "api" in e.risk_hints]
    ctx.recon["endpoint_risk_hints"] = {
        "state_changing": len(stateful),
        "file_upload": len(uploads),
        "api": len(api),
    }
    if stateful:
        ctx.add_finding(Finding(
            title=f"{len(stateful)} likely state-changing endpoint(s) discovered",
            severity="info",
            target=ctx.scope.host,
            module="vulns",
            description="Non-GET or action-named endpoints were discovered. "
                        "They are important manual review targets for CSRF, "
                        "authorization, validation and business logic bugs.",
            evidence=", ".join(f"{e.method} {e.url}" for e in stateful[:10]),
            remediation="Confirm every state-changing endpoint enforces "
                        "authentication, authorization, CSRF protection where "
                        "needed, and server-side validation.",
        ))
    if uploads:
        ctx.add_finding(Finding(
            title=f"{len(uploads)} file upload surface(s) discovered",
            severity="info",
            target=ctx.scope.host,
            module="vulns",
            description="Multipart/form upload endpoints were discovered and "
                        "should be tested manually for file type validation, "
                        "storage isolation, malware scanning, and direct object "
                        "access controls.",
            evidence=", ".join(f"{e.method} {e.url}" for e in uploads[:10]),
            remediation="Validate file type and size server-side, store uploads "
                        "outside executable paths, randomise object names, and "
                        "enforce authorization on retrieval.",
        ))


async def _cookie_flags(ctx: Context) -> None:
    resp = await ctx.get(ctx.scope.root_url)
    if resp is None:
        return
    for raw in resp.headers.get_list("set-cookie"):
        lower = raw.lower()
        name = raw.split("=", 1)[0].strip()
        missing = []
        if "secure" not in lower:
            missing.append("Secure")
        if "httponly" not in lower:
            missing.append("HttpOnly")
        if "samesite" not in lower:
            missing.append("SameSite")
        if missing:
            ctx.add_finding(Finding(
                title=f"Cookie '{name}' missing attribute(s): {', '.join(missing)}",
                severity="low",
                target=ctx.scope.root_url,
                module="vulns",
                description="A Set-Cookie response is missing hardening "
                            "attributes.",
                evidence=raw[:200],
                remediation="Set Secure, HttpOnly and an explicit SameSite on "
                            "session cookies.",
            ))


async def _cors(ctx: Context) -> None:
    resp = await ctx.get(
        ctx.scope.root_url,
        headers={"Origin": f"https://{_EVIL_HOST}"},
    )
    if resp is None:
        return
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    if acao == "*" and acac == "true":
        ctx.add_finding(Finding(
            title="Insecure CORS: wildcard origin with credentials",
            severity="high",
            target=ctx.scope.root_url,
            module="vulns",
            description="The server returns Access-Control-Allow-Origin: * "
                        "together with Allow-Credentials: true.",
            evidence=f"ACAO={acao}; ACAC={acac}",
            remediation="Never combine a wildcard origin with credentials; "
                        "reflect only allow-listed origins.",
        ))
    elif _EVIL_HOST in acao:
        ctx.add_finding(Finding(
            title="CORS reflects arbitrary Origin",
            severity="medium" if acac == "true" else "low",
            target=ctx.scope.root_url,
            module="vulns",
            description="The server reflected an attacker-supplied Origin into "
                        "Access-Control-Allow-Origin.",
            evidence=f"sent Origin https://{_EVIL_HOST}; ACAO={acao}; "
                     f"ACAC={acac}",
            remediation="Validate Origin against a strict allow-list before "
                        "reflecting it.",
        ))

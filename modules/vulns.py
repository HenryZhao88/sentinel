"""Non-destructive vulnerability checks.

Every check here is read-only and benign: it sends a small number of probe
requests with harmless markers and inspects responses. No payloads attempt to
execute code, modify data, or brute-force credentials.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sentinel.context import Context
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
    r"PostgreSQL.*ERROR|pg_query\(\)|"
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


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» vulns[/bold cyan]")

    await _cookie_flags(ctx)
    await _cors(ctx)

    targets = [(u, p) for u, p in ctx.urls.items() if p]
    if not targets:
        ctx.log("  [dim]no parameterised URLs to test with built-in checks"
                "[/dim]")
    else:
        sem = asyncio.Semaphore(ctx.config.concurrency)

        async def _test(url: str, params: set[str]) -> None:
            async with sem:
                await _reflected_xss(ctx, url, params)
                await _sql_injection(ctx, url, params)
                await _open_redirect(ctx, url, params)

        await asyncio.gather(*(_test(u, p) for u, p in targets))

    await _nuclei_scan(ctx)


async def _nuclei_scan(ctx: Context) -> None:
    """Run nuclei's community templates against the target, if installed."""
    nuclei = tool_path("nuclei")
    if not nuclei:
        return
    ctx.log("  [dim]running nuclei community templates[/dim]")
    code, stdout, stderr = await run_command(
        [
            nuclei, "-u", ctx.scope.root_url,
            "-jsonl", "-silent", "-no-color",
            "-severity", "low,medium,high,critical",
            "-rate-limit", str(int(max(ctx.config.rate, 1))),
            "-timeout", "10",
        ],
        timeout=600,
    )
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


def _with_param(url: str, name: str, value: str) -> str:
    """Return url with query parameter `name` set to `value`."""
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = value
    return urlunparse(parts._replace(query=urlencode(query)))


async def _reflected_xss(ctx: Context, url: str, params: set[str]) -> None:
    for name in params:
        probe_url = _with_param(url, name, _XSS_PROBE)
        resp = await ctx.http.get(probe_url)
        if resp is None or "html" not in resp.headers.get("content-type", ""):
            continue
        body = resp.text
        if _XSS_PROBE in body:
            ctx.add_finding(Finding(
                title=f"Reflected unescaped input in '{name}'",
                severity="high",
                target=url,
                module="vulns",
                description="A probe containing < > \" ' was reflected verbatim "
                            "in an HTML response, indicating missing output "
                            "encoding and likely reflected XSS.",
                evidence=f"param={name}; reflected marker {_XSS_PROBE!r}",
                remediation="Context-aware output encoding; apply a strict "
                            "Content-Security-Policy.",
                references=["https://owasp.org/www-community/attacks/xss/"],
                confidence="firm",
                impact="An attacker could run script in a victim's browser in "
                       "this site's origin — session theft, UI spoofing, "
                       "action forgery.",
                reproduction=[
                    f"Request {probe_url}",
                    f"Observe the probe {_XSS_PROBE!r} reflected unescaped in "
                    "the HTML response.",
                ],
                verify_type="xss",
                verify_data={"url": url, "param": name},
            ))
        elif _MARKER in body:
            ctx.add_finding(Finding(
                title=f"Input reflected in response for '{name}'",
                severity="info",
                target=url,
                module="vulns",
                description="Input is reflected but special characters appear "
                            "encoded. Worth manual review for context-specific "
                            "XSS.",
                evidence=f"param={name}",
                remediation="Confirm encoding is correct for every output "
                            "context (HTML, attribute, JS, URL).",
            ))


async def _sql_injection(ctx: Context, url: str, params: set[str]) -> None:
    for name in params:
        baseline = await ctx.http.get(_with_param(url, name, _MARKER))
        if baseline is None:
            continue
        if _SQL_ERRORS.search(baseline.text):
            continue  # baseline already errors — can't attribute to our probe
        probe = await ctx.http.get(_with_param(url, name, f"{_MARKER}'"))
        if probe is None:
            continue
        match = _SQL_ERRORS.search(probe.text)
        if match:
            current = dict(parse_qsl(urlparse(url).query)).get(name, "1")
            ctx.add_finding(Finding(
                title=f"Possible SQL injection in '{name}'",
                severity="critical",
                target=url,
                module="vulns",
                description="Appending a single quote to the parameter produced "
                            "a database error not present in the baseline "
                            "response — a classic error-based SQLi indicator.",
                evidence=f"param={name}; error fragment: {match.group(0)[:120]}",
                remediation="Use parameterised queries / prepared statements; "
                            "never build SQL from raw input.",
                references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                confidence="firm",
                impact="An attacker could read or modify database contents and "
                       "potentially bypass authentication.",
                reproduction=[
                    f"Request the parameter with a trailing quote: "
                    f"{_with_param(url, name, current + chr(39))}",
                    "Observe a database error absent from the baseline "
                    "response.",
                ],
                verify_type="sqli",
                verify_data={"url": url, "param": name, "value": current},
            ))


async def _open_redirect(ctx: Context, url: str, params: set[str]) -> None:
    for name in params:
        if name.lower() not in _REDIRECT_PARAMS:
            continue
        probe_url = _with_param(url, name, f"https://{_EVIL_HOST}/")
        resp = await ctx.http.get(probe_url, follow_redirects=False)
        if resp is None or resp.status_code not in (301, 302, 303, 307, 308):
            continue
        location = resp.headers.get("location", "")
        if _EVIL_HOST in urlparse(location).netloc:
            ctx.add_finding(Finding(
                title=f"Open redirect via '{name}'",
                severity="medium",
                target=url,
                module="vulns",
                description="The parameter controls the redirect destination "
                            "and accepts an arbitrary external host.",
                evidence=f"param={name}; Location: {location}",
                remediation="Allow-list redirect targets or use relative paths "
                            "only.",
                references=["https://owasp.org/www-community/attacks/"
                            "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"],
                confidence="firm",
                impact="An attacker could craft a link on this domain that "
                       "silently sends users to a malicious site — useful for "
                       "phishing and OAuth token theft.",
                reproduction=[
                    f"Request {probe_url}",
                    f"Observe an HTTP {resp.status_code} redirect to the "
                    "external host.",
                ],
                verify_type="open_redirect",
                verify_data={"url": url, "param": name},
            ))


async def _cookie_flags(ctx: Context) -> None:
    resp = await ctx.http.get(ctx.scope.root_url)
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
    resp = await ctx.http.get(
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

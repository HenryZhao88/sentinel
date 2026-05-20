"""Defense testing: how well does the app / WAF withstand attack payloads?

For each parameterised URL, Sentinel sends a battery of well-known *detection*
payloads and classifies each response: blocked, reflected, error, or passed.
This is observational — it measures filtering coverage, it does not exploit.
Payloads are benign (e.g. `id`, `{{7*7}}`); only their handling is of interest.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from sentinel.context import Context
from sentinel.findings import Finding

# How many parameterised URLs to exercise (keeps request volume bounded).
_MAX_URLS = 12

# Categorised attack payloads. Each is a standard, non-destructive detection
# probe — the same kind every scanner uses to fingerprint input filtering.
_PAYLOADS: dict[str, list[str]] = {
    "SQL injection": [
        "' OR '1'='1", "1' OR '1'='1' -- ", "' UNION SELECT NULL-- ",
        "admin'-- ", "\" OR \"\"=\"", "') OR ('1'='1",
    ],
    "Cross-site scripting": [
        "<script>alert(1)</script>", "<svg/onload=alert(1)>",
        "\"><img src=x onerror=alert(1)>", "javascript:alert(1)",
        "<body onload=alert(1)>",
    ],
    "Path traversal": [
        "../../../../etc/passwd", "..%2f..%2f..%2fetc%2fpasswd",
        "....//....//etc/passwd", "..\\..\\..\\windows\\win.ini",
    ],
    "Command injection": [";id", "| id", "$(id)", "`id`", "& whoami"],
    "Template injection": ["{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}"],
}

# Response signals.
_BLOCK_STATUS = {403, 406, 419, 429, 501, 503}
_WAF_SIGNATURES = re.compile(
    r"(access denied|request blocked|web application firewall|"
    r"forbidden|not acceptable|cloudflare|incapsula|mod_security|"
    r"your request looks suspicious|attention required)",
    re.IGNORECASE,
)
_SQL_ERRORS = re.compile(
    r"(SQL syntax|mysqli?_|ORA-\d{5}|PostgreSQL.*ERROR|"
    r"Unclosed quotation mark|SQLite)", re.IGNORECASE,
)
# Markers that a payload was not just passed through but actually evaluated.
_EXECUTED = {
    "Command injection": re.compile(r"uid=\d+\(", re.IGNORECASE),
    "Template injection": re.compile(r"(^|[^0-9])49([^0-9]|$)"),
    "Path traversal": re.compile(r"root:.*:0:0:|\[(extensions|fonts)\]",
                                 re.IGNORECASE),
}
# A stable literal each category's evaluation produces, for the repro script.
_PROOF = {
    "Command injection": "uid=",
    "Template injection": "49",
    "Path traversal": "root:",
}


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = value
    return urlunparse(parts._replace(query=urlencode(query)))


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» defense[/bold cyan]")
    targets = [(u, sorted(p)[0]) for u, p in ctx.urls.items() if p][:_MAX_URLS]
    if not targets:
        ctx.log("  [dim]no parameterised URLs to test defenses against[/dim]")
        return

    # tally[category] = {"blocked": n, "reflected": n, "error": n,
    #                     "passed": n, "executed": n, "total": n}
    tally: dict[str, dict[str, int]] = {
        cat: {k: 0 for k in
              ("blocked", "reflected", "error", "passed", "executed", "total")}
        for cat in _PAYLOADS
    }
    sem = asyncio.Semaphore(ctx.config.concurrency)

    async def _probe(url: str, param: str, category: str, payload: str) -> None:
        async with sem:
            # Never chase a payload-controlled redirect target.
            resp = await ctx.http.get(
                _with_param(url, param, payload), follow_redirects=False
            )
        bucket = tally[category]
        bucket["total"] += 1
        if resp is None:
            bucket["error"] += 1
            return
        body = resp.text if resp.content else ""
        executed = _EXECUTED.get(category)
        if executed is not None and executed.search(body):
            bucket["executed"] += 1
            ctx.add_finding(Finding(
                title=f"{category} payload executed by the server",
                severity="critical" if category != "Path traversal" else "high",
                target=url,
                module="defense",
                description=f"A {category.lower()} payload sent in parameter "
                            f"'{param}' was not just reflected but evaluated "
                            "by the server.",
                evidence=f"param={param}; payload={payload}",
                remediation="Treat all input as untrusted; never pass it to "
                            "interpreters, shells, or template engines.",
                confidence="firm",
                impact="An attacker can run code or read files on the server.",
                reproduction=[
                    f"Request {_with_param(url, param, payload)}",
                    "Observe the payload being evaluated in the response.",
                ],
                verify_type="payload_exec",
                verify_data={
                    "url": url, "param": param, "payload": payload,
                    "proof": _PROOF.get(category, ""),
                },
            ))
            return
        if resp.status_code in _BLOCK_STATUS or _WAF_SIGNATURES.search(body):
            bucket["blocked"] += 1
        elif resp.status_code >= 500 or _SQL_ERRORS.search(body):
            bucket["error"] += 1
        elif payload in body:
            bucket["reflected"] += 1
        else:
            bucket["passed"] += 1

    jobs = [
        _probe(url, param, category, payload)
        for url, param in targets
        for category, payloads in _PAYLOADS.items()
        for payload in payloads
    ]
    await asyncio.gather(*jobs)

    ctx.recon["defense"] = tally
    _summarise(ctx, tally)


def _summarise(ctx: Context, tally: dict[str, dict[str, int]]) -> None:
    lines = []
    weak: list[str] = []
    for category, b in tally.items():
        total = b["total"]
        if not total:
            continue
        rate = round(100 * b["blocked"] / total)
        lines.append(f"{category}: {rate}% blocked "
                     f"({b['blocked']}/{total})")
        # 0% blocked, with payloads getting through, is a filtering gap.
        if b["blocked"] == 0 and (b["reflected"] or b["passed"]):
            weak.append(category)

    ctx.add_finding(Finding(
        title="Defense posture summary",
        severity="info",
        target=ctx.scope.host,
        module="defense",
        description="Share of attack payloads blocked by the application or "
                    "an upstream WAF, per category.",
        evidence="; ".join(lines) or "no parameters tested",
        remediation="Low block rates indicate missing input filtering. A WAF "
                    "is defence-in-depth, not a substitute for fixing the "
                    "underlying input handling.",
    ))

    for category in weak:
        ctx.add_finding(Finding(
            title=f"No filtering observed for {category} payloads",
            severity="low",
            target=ctx.scope.host,
            module="defense",
            description=f"None of the {category.lower()} payloads were "
                        "blocked. The application accepted them all — there is "
                        "no WAF or input filtering for this attack class.",
            evidence=f"0/{tally[category]['total']} payloads blocked",
            remediation="Add server-side input validation for this attack "
                        "class and consider a WAF ruleset as defence-in-depth.",
        ))

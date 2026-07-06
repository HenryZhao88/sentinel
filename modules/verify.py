"""Human-gated proof-of-concept verification.

For each finding a detection module flagged as verifiable, Sentinel presents
the operator with a full rundown and asks for approval. On approval it runs a
*bounded, non-destructive* proof that confirms the vulnerability is real — and
nothing more. The principle: prove the door is unlocked; never walk through it.
"""

from __future__ import annotations

import random
import re
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from sentinel.context import Context
from sentinel.findings import Finding
from sentinel.modules.vulns import _SQL_ERRORS

# Benign, script-free probe used for the XSS proof — contains no executable
# payload, only a structurally-distinctive tag.
_XSS_PROBE = 'sntlvrfy"><svg data-sentinel></svg>'
_XSS_MARKER = "<svg data-sentinel></svg>"
_REDIRECT_HOST = "sentinel-oob.example"
# Signs a page is a genuine authenticated area rather than a login form.
_AUTH_MARKERS = ("log out", "logout", "sign out", "signout")
_ADMIN_MARKERS = ("dashboard", "admin panel", "manage users", "settings",
                   "administration")


def _with_param(url: str, name: str, value: str) -> str:
    parts = urlparse(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query[name] = value
    return urlunparse(parts._replace(query=urlencode(query)))


def _line(label: str, resp: httpx.Response | None, sent: str) -> str:
    if resp is None:
        return f"{label}: GET {sent}\n    -> no response"
    location = resp.headers.get("location", "")
    extra = f", Location: {location}" if location else ""
    return (f"{label}: GET {sent}\n"
            f"    -> HTTP {resp.status_code}, {len(resp.content)} bytes{extra}")


def _auth_kwargs(finding: Finding) -> dict:
    auth_profile = finding.verify_data.get("auth_profile")
    if not auth_profile:
        return {"use_default_auth": False}
    return {"auth_profile": auth_profile}


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» verify[/bold cyan]")
    pending = [f for f in ctx.findings if f.verify_type]
    if not pending:
        ctx.log("  [dim]no findings eligible for verification[/dim]")
        return

    for finding in pending:
        verifier = _VERIFIERS.get(finding.verify_type)
        if verifier is None:
            continue
        approved = await ctx.request_approval(finding)
        if not approved:
            finding.verification = "skipped — operator did not approve"
            ctx.log(f"  [dim]skipped (not approved): {finding.title}[/dim]")
            continue
        try:
            confirmed, detail, transcript = await verifier(ctx, finding)
        except Exception as exc:  # noqa: BLE001 — never abort the phase
            finding.verification = f"verification error: {exc!r}"
            ctx.log(f"  [yellow]verification error: {finding.title}[/yellow]")
            continue

        finding.verified = confirmed
        finding.verification = detail
        if transcript:
            finding.transcript = transcript
        if confirmed:
            finding.confidence = "confirmed"
            ctx.log(f"  [bold green]CONFIRMED[/bold green] {finding.title}")
        else:
            ctx.log(f"  [yellow]not confirmed[/yellow] {finding.title}")


async def _verify_sqli(
    ctx: Context, finding: Finding
) -> tuple[bool, str, str]:
    url = finding.verify_data["url"]
    param = finding.verify_data["param"]
    base = str(finding.verify_data.get("value", "1"))

    unbalanced_url = _with_param(url, param, base + "'")
    true_url = _with_param(url, param, base + "' AND '1'='1")
    false_url = _with_param(url, param, base + "' AND '1'='2")

    auth = _auth_kwargs(finding)
    unbalanced = await ctx.get(unbalanced_url, **auth)
    true_resp = await ctx.get(true_url, **auth)
    false_resp = await ctx.get(false_url, **auth)

    transcript = "\n".join([
        _line("unbalanced quote", unbalanced, unbalanced_url),
        _line("balanced TRUE   ", true_resp, true_url),
        _line("balanced FALSE  ", false_resp, false_url),
    ])

    unbalanced_errors = (
        unbalanced is not None and bool(_SQL_ERRORS.search(unbalanced.text))
    )
    true_clean = (
        true_resp is not None and not _SQL_ERRORS.search(true_resp.text)
    )
    if unbalanced_errors and true_clean:
        return (
            True,
            "Confirmed: an unbalanced quote produced a SQL error while the "
            "syntactically-balanced payload did not — the parameter is "
            "injected into a SQL statement. No data was extracted.",
            transcript,
        )
    return (
        False,
        "Not confirmed: the balanced/unbalanced responses did not show the "
        "expected SQL-error differential.",
        transcript,
    )


async def _verify_xss(
    ctx: Context, finding: Finding
) -> tuple[bool, str, str]:
    url = finding.verify_data["url"]
    param = finding.verify_data["param"]
    probe_url = _with_param(url, param, _XSS_PROBE)
    resp = await ctx.get(probe_url, **_auth_kwargs(finding))
    transcript = _line("script-free tag probe", resp, probe_url)

    if resp is not None and _XSS_MARKER in resp.text:
        return (
            True,
            "Confirmed: a script-free HTML tag was reflected unescaped into "
            "the page, proving input breaks out into an executable HTML "
            "context. No JavaScript was executed.",
            transcript,
        )
    return (
        False,
        "Not confirmed: the injected tag was encoded or absent — reflection "
        "may not reach an executable context.",
        transcript,
    )


async def _verify_open_redirect(
    ctx: Context, finding: Finding
) -> tuple[bool, str, str]:
    url = finding.verify_data["url"]
    param = finding.verify_data["param"]
    probe_url = _with_param(url, param, f"https://{_REDIRECT_HOST}/")
    resp = await ctx.get(
        probe_url, follow_redirects=False, **_auth_kwargs(finding)
    )
    transcript = _line("redirect probe", resp, probe_url)

    if resp is not None and resp.status_code in (301, 302, 303, 307, 308):
        location = resp.headers.get("location", "")
        if _REDIRECT_HOST in urlparse(location).netloc:
            return (
                True,
                f"Confirmed: the server issued an HTTP {resp.status_code} "
                f"redirect to the attacker-controlled host in Location.",
                transcript,
            )
    return (False, "Not confirmed: no off-site redirect was issued.",
            transcript)


async def _verify_exposed_file(
    ctx: Context, finding: Finding
) -> tuple[bool, str, str]:
    url = finding.verify_data["url"]
    resp = await ctx.http.get(url)
    transcript = _line("exposed file", resp, url)
    if resp is None or resp.status_code != 200 or not resp.content:
        return (False, "Not confirmed: the file was not retrievable.",
                transcript)

    body = resp.text
    path = urlparse(url).path.lower()
    signatures = {
        ".git/config": "[core]",
        ".git/head": "ref:",
        ".env": "=",
        ".svn/entries": "",
    }
    expected = next((v for k, v in signatures.items() if path.endswith(k)), "")
    if expected and expected not in body.lower():
        return (False, "Not confirmed: file content did not match the "
                       "expected signature.", transcript)
    # Record only that content exists and its size — never the secret values.
    return (
        True,
        f"Confirmed: the file is publicly retrievable ({len(resp.content)} "
        "bytes) and matches the expected format. Contents are NOT stored in "
        "this report.",
        transcript,
    )


async def _verify_unauth_access(
    ctx: Context, finding: Finding
) -> tuple[bool, str, str]:
    url = finding.verify_data["url"]
    # Sentinel's client carries no session cookies — this request is anonymous.
    resp = await ctx.http.get(url)
    transcript = _line("anonymous request (no credentials)", resp, url)
    if resp is None or resp.status_code != 200:
        return (False, "Not confirmed: the page was not served anonymously.",
                transcript)

    lowered = resp.text.lower()
    has_auth_marker = any(m in lowered for m in _AUTH_MARKERS)
    has_admin_marker = any(m in lowered for m in _ADMIN_MARKERS)
    if has_auth_marker and has_admin_marker:
        return (
            True,
            "Confirmed: an authenticated admin area was reached with NO "
            "credentials (broken access control). Verification stops here — "
            "Sentinel performed no action inside the area.",
            transcript,
        )
    return (
        False,
        "Not confirmed: the page lacks authenticated-area markers — it may be "
        "a public page or a login form rather than an admin area.",
        transcript,
    )


_ARITH = re.compile(r"\d+\s*\*\s*\d+")


def _evaluated(resp: httpx.Response | None, payload: str, product: str) -> bool:
    """True if `product` appears as a standalone number AND the payload was not
    merely echoed verbatim — i.e. the server returned the *result* of the
    arithmetic, not the expression."""
    if resp is None or not product:
        return False
    body = resp.text
    if payload in body:  # reflected literally, not evaluated
        return False
    return re.search(rf"(?<!\d){re.escape(product)}(?!\d)", body) is not None


async def _verify_payload_exec(
    ctx: Context, finding: Finding
) -> tuple[bool, str, str]:
    """Confirm template/expression injection with two independent identities.

    The detector flagged one random product. Here we re-send that payload and,
    crucially, a *second* payload built from the same template syntax but
    different random factors. A server that genuinely evaluates the expression
    returns both products; a page that merely happened to contain the first
    number cannot also contain the second. This rules out the one-in-millions
    coincidence that a single arithmetic check leaves open.
    """
    url = finding.verify_data["url"]
    param = finding.verify_data["param"]
    payload = str(finding.verify_data.get("payload", ""))
    proof = str(finding.verify_data.get("proof", ""))

    primary_url = _with_param(url, param, payload)
    primary = await ctx.http.get(primary_url, follow_redirects=False)

    # Rebuild the same template wrapper with a fresh, unrelated identity.
    match = _ARITH.search(payload)
    control_url = control_payload = control_proof = ""
    control = None
    if match:
        c, d = random.randint(1000, 9999), random.randint(1000, 9999)
        control_proof = str(c * d)
        control_payload = f"{payload[:match.start()]}{c}*{d}{payload[match.end():]}"
        control_url = _with_param(url, param, control_payload)
        control = await ctx.http.get(control_url, follow_redirects=False)

    transcript = "\n".join(filter(None, [
        _line(f"identity #1 (expect {proof})", primary, primary_url),
        _line(f"identity #2 (expect {control_proof})", control, control_url)
        if match else "",
    ]))

    primary_ok = _evaluated(primary, payload, proof)
    control_ok = bool(match) and _evaluated(control, control_payload, control_proof)
    if primary_ok and control_ok:
        return (
            True,
            f"Confirmed: the server evaluated two independent expressions, "
            f"returning {proof} and {control_proof} respectively — proof it "
            "executes input supplied in the URL. No further action was taken.",
            transcript,
        )
    return (
        False,
        "Not confirmed: the server did not return the evaluated result of both "
        "arithmetic identities, so this is not reliable server-side execution.",
        transcript,
    )


_VERIFIERS = {
    "sqli": _verify_sqli,
    "xss": _verify_xss,
    "open_redirect": _verify_open_redirect,
    "exposed_file": _verify_exposed_file,
    "unauth_access": _verify_unauth_access,
    "payload_exec": _verify_payload_exec,
}

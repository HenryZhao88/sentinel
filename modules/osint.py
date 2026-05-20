"""Passive OSINT recon: certificate transparency and the Wayback Machine.

These checks query third-party datasets (crt.sh, web.archive.org) rather than
the target itself, so they generate no traffic to the assessed host. Historical
URLs that fall inside scope are fed forward so later phases can test them.
"""

from __future__ import annotations

import asyncio
import json
import re
from urllib.parse import urlparse

from sentinel.context import Context
from sentinel.findings import Finding

# A syntactically valid DNS hostname (labels of letters/digits/hyphens).
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}$"
)

_CRTSH = "https://crt.sh/?q=%25.{domain}&output=json"
_WAYBACK = (
    "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
    "&output=json&fl=original&collapse=urlkey&limit={limit}"
)
_WAYBACK_LIMIT = 600
# Cap how many historical parameterised URLs we forward for active testing.
_FORWARD_CAP = 300
# crt.sh and the Wayback CDX API are slow public services; give them headroom
# beyond the per-request timeout used for the target itself.
_OSINT_TIMEOUT = 45.0


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» osint[/bold cyan]")
    await asyncio.gather(_crtsh(ctx), _wayback(ctx))


async def _crtsh(ctx: Context) -> None:
    domain = ctx.scope.base_domain
    resp = await ctx.http.get(
        _CRTSH.format(domain=domain),
        headers={"Accept": "application/json"},
        timeout=_OSINT_TIMEOUT,
    )
    if resp is None:
        ctx.recon["crtsh"] = {"error": "crt.sh did not respond (timeout)"}
        return
    if resp.status_code != 200:
        ctx.recon["crtsh"] = {"error": f"crt.sh returned HTTP {resp.status_code}"}
        return
    try:
        records = json.loads(resp.text)
    except json.JSONDecodeError:
        ctx.recon["crtsh"] = {"error": "crt.sh returned unparseable data"}
        return

    names: set[str] = set()
    suffix = f".{domain}"
    for record in records:
        value = record.get("name_value", "")
        for name in value.splitlines():
            name = name.strip().lower().lstrip("*.")
            # Keep only real hostnames genuinely within the target domain —
            # crt.sh also returns organisation fields and unrelated SANs.
            if not _HOSTNAME_RE.match(name):
                continue
            if name == domain or name.endswith(suffix):
                names.add(name)

    ctx.recon["crtsh"] = sorted(names)
    existing = set(ctx.recon.get("subdomains", []))
    merged = sorted(existing | names)
    ctx.recon["subdomains"] = merged

    if names:
        ctx.add_finding(Finding(
            title=f"{len(names)} subdomain(s) from certificate transparency",
            severity="info",
            target=domain,
            module="osint",
            description="Certificate transparency logs (crt.sh) disclosed "
                        "hostnames issued certificates under this domain.",
            evidence=", ".join(sorted(names)[:30])
                     + (" …" if len(names) > 30 else ""),
            remediation="Review each host: decommission anything unintended "
                        "and confirm it is covered by your engagement scope.",
            references=["https://crt.sh/"],
        ))


async def _wayback(ctx: Context) -> None:
    domain = ctx.scope.base_domain
    resp = await ctx.http.get(
        _WAYBACK.format(domain=domain, limit=_WAYBACK_LIMIT),
        timeout=_OSINT_TIMEOUT,
    )
    if resp is None:
        ctx.recon["wayback"] = {
            "error": "web.archive.org did not respond (timeout)"
        }
        return
    if resp.status_code != 200:
        # The CDX API rate-limits / blocks automated access from some networks.
        ctx.recon["wayback"] = {
            "error": f"web.archive.org returned HTTP {resp.status_code} "
                     "(rate-limited or blocked — not a Sentinel error)"
        }
        return
    try:
        rows = json.loads(resp.text)
    except json.JSONDecodeError:
        ctx.recon["wayback"] = {"error": "Wayback returned unparseable data"}
        return

    # First row is the CDX column header; the rest are [original_url].
    urls = {row[0] for row in rows[1:] if row}
    in_scope = sorted(u for u in urls if ctx.scope.in_scope(u))
    ctx.recon["wayback"] = {
        "total": len(urls),
        "in_scope": len(in_scope),
    }

    # Forward in-scope URLs (especially parameterised ones) to later phases.
    forwarded = 0
    parameterised = 0
    for url in in_scope:
        if forwarded >= _FORWARD_CAP:
            break
        params = set(urlparse(url).query.split("&")) if urlparse(url).query else set()
        param_names = {p.split("=")[0] for p in params if p}
        ctx.record_url(url, param_names)
        forwarded += 1
        if param_names:
            parameterised += 1

    if in_scope:
        ctx.add_finding(Finding(
            title=f"{len(in_scope)} historical URL(s) from the Wayback Machine",
            severity="info",
            target=domain,
            module="osint",
            description="The Internet Archive holds previously-crawled URLs "
                        "for this domain. Old endpoints often outlive their "
                        "documentation and may still be live.",
            evidence=f"{forwarded} URL(s) forwarded for testing; "
                     f"{parameterised} carry query parameters.",
            remediation="Retire endpoints that should no longer exist and "
                        "confirm legacy routes are still access-controlled.",
            references=["https://web.archive.org/"],
        ))

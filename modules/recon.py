"""Reconnaissance: DNS, TLS, HTTP headers, tech fingerprinting, subdomains."""

from __future__ import annotations

import asyncio
import datetime as dt
import socket
import ssl
from pathlib import Path

import dns.resolver

from sentinel.context import Context
from sentinel.findings import Finding

_WORDLIST = Path(__file__).parent.parent / "wordlists" / "subdomains.txt"

# Header / body signatures -> human-readable technology name.
_TECH_SIGNATURES = {
    "x-powered-by": lambda v: v,
    "server": lambda v: v,
    "x-aspnet-version": lambda v: f"ASP.NET {v}",
    "x-generator": lambda v: v,
    "x-drupal-cache": lambda v: "Drupal",
}

_BODY_SIGNATURES = {
    "wp-content": "WordPress",
    "/_next/": "Next.js",
    "__NUXT__": "Nuxt.js",
    "ng-version": "Angular",
    "data-reactroot": "React",
    "csrf-param": "Ruby on Rails",
}

# Headers whose absence is worth reporting, with severity + advice.
_SECURITY_HEADERS = {
    "strict-transport-security": (
        "medium",
        "Add HSTS to force HTTPS and prevent protocol downgrade.",
    ),
    "content-security-policy": (
        "medium",
        "Define a Content-Security-Policy to mitigate XSS and injection.",
    ),
    "x-frame-options": (
        "low",
        "Set X-Frame-Options or CSP frame-ancestors to prevent clickjacking.",
    ),
    "x-content-type-options": (
        "low",
        "Set X-Content-Type-Options: nosniff to stop MIME sniffing.",
    ),
    "referrer-policy": (
        "info",
        "Set a Referrer-Policy to limit information leakage.",
    ),
}


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» recon[/bold cyan]")
    host = ctx.scope.host

    await asyncio.gather(
        _dns_records(ctx, host),
        _tls_inspection(ctx, host),
        _http_headers(ctx),
        _subdomains(ctx),
    )


async def _dns_records(ctx: Context, host: str) -> None:
    records: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    def _query(rtype: str) -> list[str]:
        try:
            answers = resolver.resolve(host, rtype)
            return [r.to_text() for r in answers]
        except Exception:  # noqa: BLE001 — any DNS failure -> "no records"
            return []

    for rtype in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"):
        values = await asyncio.to_thread(_query, rtype)
        if values:
            records[rtype] = values

    ctx.recon["dns"] = records
    ctx.recon["resolved_ips"] = ctx.scope.resolved_ips

    spf = [t for t in records.get("TXT", []) if "v=spf1" in t]
    if not spf:
        ctx.add_finding(Finding(
            title="No SPF record published",
            severity="info",
            target=host,
            module="recon",
            description="No SPF TXT record was found for the domain.",
            remediation="Publish an SPF record to reduce email spoofing risk.",
        ))


async def _tls_inspection(ctx: Context, host: str) -> None:
    port = ctx.scope.port or 443
    if ctx.scope.scheme != "https" and ctx.scope.port not in (443, None):
        return

    def _probe() -> dict | None:
        context = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    return {
                        "protocol": tls.version(),
                        "cipher": tls.cipher(),
                        "cert": tls.getpeercert(),
                    }
        except (OSError, ssl.SSLError):
            return None

    info = await asyncio.to_thread(_probe)
    if not info:
        ctx.recon["tls"] = {"error": "TLS handshake failed"}
        return

    cert = info["cert"] or {}
    not_after = cert.get("notAfter")
    days_left = None
    if not_after:
        try:
            expiry = dt.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - dt.datetime.utcnow()).days
        except ValueError:
            pass

    ctx.recon["tls"] = {
        "protocol": info["protocol"],
        "cipher": info["cipher"][0] if info["cipher"] else None,
        "issuer": _name_field(cert.get("issuer")),
        "subject": _name_field(cert.get("subject")),
        "expires": not_after,
        "days_left": days_left,
    }

    if info["protocol"] in ("TLSv1", "TLSv1.1", "SSLv3"):
        ctx.add_finding(Finding(
            title=f"Obsolete TLS protocol negotiated ({info['protocol']})",
            severity="medium",
            target=f"{host}:{port}",
            module="recon",
            description="The server negotiated a deprecated TLS/SSL version.",
            evidence=info["protocol"],
            remediation="Disable TLS 1.1 and below; require TLS 1.2+.",
        ))
    if days_left is not None and days_left < 0:
        ctx.add_finding(Finding(
            title="TLS certificate expired",
            severity="high",
            target=f"{host}:{port}",
            module="recon",
            description="The server's TLS certificate is past its expiry date.",
            evidence=f"notAfter={not_after}",
            remediation="Renew the certificate immediately.",
        ))
    elif days_left is not None and days_left < 14:
        ctx.add_finding(Finding(
            title=f"TLS certificate expiring soon ({days_left} days)",
            severity="low",
            target=f"{host}:{port}",
            module="recon",
            description="The certificate will expire within two weeks.",
            evidence=f"notAfter={not_after}",
            remediation="Renew the certificate before it expires.",
        ))


def _name_field(name) -> str:
    if not name:
        return ""
    parts = []
    for rdn in name:
        for key, value in rdn:
            parts.append(f"{key}={value}")
    return ", ".join(parts)


async def _http_headers(ctx: Context) -> None:
    resp = await ctx.http.get(ctx.scope.root_url)
    if resp is None:
        ctx.recon["http"] = {"error": "no response"}
        return

    headers = {k.lower(): v for k, v in resp.headers.items()}
    ctx.recon["http"] = {
        "status": resp.status_code,
        "headers": dict(resp.headers),
    }

    # Technology fingerprinting from headers and body.
    tech: set[str] = set()
    for sig, render in _TECH_SIGNATURES.items():
        if sig in headers:
            tech.add(render(headers[sig]))
    body = resp.text[:200_000] if resp.content else ""
    for sig, name in _BODY_SIGNATURES.items():
        if sig in body:
            tech.add(name)
    ctx.recon["technologies"] = sorted(tech)

    # Missing security headers.
    for header, (severity, advice) in _SECURITY_HEADERS.items():
        if header not in headers:
            ctx.add_finding(Finding(
                title=f"Missing security header: {header}",
                severity=severity,
                target=ctx.scope.root_url,
                module="recon",
                description=f"The response did not include the {header} header.",
                remediation=advice,
                references=["https://owasp.org/www-project-secure-headers/"],
            ))

    if "server" in headers and any(c.isdigit() for c in headers["server"]):
        ctx.add_finding(Finding(
            title="Server version disclosed",
            severity="info",
            target=ctx.scope.root_url,
            module="recon",
            description="The Server header reveals software and version detail.",
            evidence=f"Server: {headers['server']}",
            remediation="Suppress or genericise the Server header.",
        ))


async def _subdomains(ctx: Context) -> None:
    if not _WORDLIST.exists():
        return
    candidates = [
        line.strip() for line in _WORDLIST.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    base = ctx.scope.base_domain
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    found: list[str] = []

    def _resolve(fqdn: str) -> bool:
        try:
            resolver.resolve(fqdn, "A")
            return True
        except Exception:  # noqa: BLE001
            return False

    sem = asyncio.Semaphore(20)

    async def _check(label: str) -> None:
        fqdn = f"{label}.{base}"
        async with sem:
            if await asyncio.to_thread(_resolve, fqdn):
                found.append(fqdn)

    await asyncio.gather(*(_check(c) for c in candidates))
    ctx.recon["subdomains"] = sorted(found)
    if found:
        ctx.add_finding(Finding(
            title=f"{len(found)} subdomain(s) discovered",
            severity="info",
            target=base,
            module="recon",
            description="Wordlist-based DNS resolution found live subdomains.",
            evidence=", ".join(sorted(found)[:25]),
            remediation="Confirm each subdomain is intended to be exposed and "
                        "is covered by your assessment scope.",
        ))

"""Wordlist-based discovery of interesting paths and exposed files."""

from __future__ import annotations

import asyncio
from pathlib import Path
from urllib.parse import urljoin

from sentinel.context import Context
from sentinel.findings import Finding

_WORDLIST = Path(__file__).parent.parent / "wordlists" / "paths.txt"

# Paths that, if reachable, are findings in their own right.
_SENSITIVE = {
    ".git/config": ("high", "Exposed Git repository metadata."),
    ".git/HEAD": ("high", "Exposed Git repository metadata."),
    ".env": ("critical", "Environment file may leak secrets/credentials."),
    ".env.local": ("critical", "Environment file may leak secrets/credentials."),
    "wp-config.php.bak": ("critical", "Backup of WordPress config may leak DB creds."),
    "config.php.bak": ("critical", "Backup config file may leak credentials."),
    ".DS_Store": ("low", "Reveals directory contents."),
    "phpinfo.php": ("medium", "Exposes server configuration detail."),
    "server-status": ("medium", "Apache status page may leak request data."),
    ".svn/entries": ("high", "Exposed Subversion metadata."),
    "backup.zip": ("high", "Downloadable backup archive."),
    "backup.sql": ("critical", "Downloadable database dump."),
    "dump.sql": ("critical", "Downloadable database dump."),
}

# First path segment hints that suggest a privileged/admin route.
_ADMIN_HINTS = {
    "admin", "administrator", "wp-admin", "dashboard", "manage", "console",
    "cpanel", "backend", "controlpanel",
}
# Text that distinguishes a logged-in area from a public page or login form.
_AUTH_MARKERS = ("log out", "logout", "sign out", "signout")


def _looks_like_admin(path: str) -> bool:
    first = path.strip("/").split("/", 1)[0].lower()
    return first in _ADMIN_HINTS


def _has_auth_markers(body: str) -> bool:
    lowered = body.lower()
    return any(marker in lowered for marker in _AUTH_MARKERS)


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» content[/bold cyan]")
    if not _WORDLIST.exists():
        return
    paths = [
        line.strip() for line in _WORDLIST.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    base = ctx.scope.root_url.rstrip("/") + "/"

    # Detect soft-404s: a random path that "shouldn't" exist.
    baseline = await ctx.http.get(urljoin(base, "sentinel-nonexistent-a8f3e1"))
    baseline_len = len(baseline.content) if baseline is not None else -1
    baseline_status = baseline.status_code if baseline is not None else 404

    sem = asyncio.Semaphore(ctx.config.concurrency)

    async def _check(path: str) -> None:
        url = urljoin(base, path)
        async with sem:
            resp = await ctx.http.get(url)
        if resp is None:
            return
        status = resp.status_code
        if status in (404, 400) or status >= 500:
            return
        # Skip soft-404s that mirror the baseline page.
        if (status == baseline_status
                and abs(len(resp.content) - baseline_len) < 64):
            return

        if status in (301, 302, 307, 308):
            ctx.record_url(url)
            return

        if status in (401, 403):
            ctx.add_finding(Finding(
                title=f"Protected path exists: /{path}",
                severity="info",
                target=url,
                module="content",
                description=f"Path returned HTTP {status} (exists but access "
                            "controlled).",
                evidence=f"HTTP {status}",
                remediation="Confirm the access control is intentional.",
            ))
            return

        # 200-class hit.
        ctx.record_url(url)
        if path in _SENSITIVE:
            severity, note = _SENSITIVE[path]
            ctx.add_finding(Finding(
                title=f"Sensitive resource exposed: /{path}",
                severity=severity,
                target=url,
                module="content",
                description=note,
                evidence=f"HTTP {status}, {len(resp.content)} bytes",
                remediation="Remove the file from the web root or block access.",
                confidence="firm",
                impact="The file is publicly downloadable and may leak source "
                       "code, credentials, or internal configuration.",
                verify_type="exposed_file",
                verify_data={"url": url},
            ))
        elif _looks_like_admin(path) and _has_auth_markers(resp.text):
            ctx.add_finding(Finding(
                title=f"Authenticated area reachable without login: /{path}",
                severity="high",
                target=url,
                module="content",
                description="An admin/authenticated-looking page was served "
                            "with HTTP 200 and contains markers of a logged-in "
                            "area — a possible broken access control.",
                evidence=f"HTTP {status}; admin markers present in response",
                remediation="Require authentication and authorization on every "
                            "privileged route, enforced server-side.",
                confidence="firm",
                impact="Anyone may be able to reach privileged functionality "
                       "without credentials.",
                verify_type="unauth_access",
                verify_data={"url": url},
            ))
        else:
            ctx.add_finding(Finding(
                title=f"Discovered path: /{path}",
                severity="info",
                target=url,
                module="content",
                description=f"Path is reachable (HTTP {status}).",
                evidence=f"HTTP {status}, {len(resp.content)} bytes",
                remediation="Verify the resource is meant to be public.",
            ))

    await asyncio.gather(*(_check(p) for p in paths))

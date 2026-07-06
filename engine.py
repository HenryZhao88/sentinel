"""Assessment orchestrator: wires phases together in order."""

from __future__ import annotations

import time
from typing import Callable

from sentinel import report
from sentinel.context import ALL_PHASES, ApprovalCallback, Config, Context
from sentinel.findings import Finding
from sentinel.http_client import HttpClient
from sentinel.modules import (
    content, crawler, defense, jsanalysis, osint, ports, recon, verify, vulns,
)
from sentinel.scope import Scope

_PHASE_FUNCS = {
    "osint": osint.run,
    "recon": recon.run,
    "ports": ports.run,
    "crawl": crawler.run,
    "content": content.run,
    "jsanalysis": jsanalysis.run,
    "vulns": vulns.run,
    "defense": defense.run,
    "verify": verify.run,
}


async def run_assessment(
    config: Config,
    log_callback: Callable[[str], None] | None = None,
    finding_callback: Callable[[Finding], None] | None = None,
    approval_callback: ApprovalCallback | None = None,
) -> dict[str, str]:
    """Execute the selected phases against the target and write reports.

    When `log_callback`/`finding_callback` are supplied (e.g. by the TUI),
    progress and findings are streamed to them instead of the console.
    `approval_callback` gates per-finding proof-of-concept verification.
    """
    scope = Scope(
        config.target,
        allow_private=config.allow_private,
        include_subdomains=config.include_subdomains,
    )
    http = HttpClient(
        rate=config.rate,
        concurrency=config.concurrency,
        timeout=config.timeout,
        verify_tls=config.verify_tls,
    )
    ctx = Context(
        config, scope, http,
        log_callback, finding_callback, approval_callback,
    )

    ctx.log(
        f"[bold]Sentinel[/bold] assessing [cyan]{scope.root_url}[/cyan] "
        f"([dim]{', '.join(scope.resolved_ips)}[/dim])\n"
    )
    started = time.monotonic()
    # Always run phases in canonical order so later phases see earlier output,
    # regardless of the order the caller listed them.
    ordered = [p for p in ALL_PHASES if p in config.phases]
    try:
        for phase in ordered:
            await _PHASE_FUNCS[phase](ctx)
    finally:
        await http.aclose()

    elapsed = time.monotonic() - started
    paths = report.write(ctx)

    ctx.log(
        f"\n[bold green]Done[/bold green] in {elapsed:.1f}s · "
        f"{http.request_count} requests · {len(ctx.findings)} finding(s)"
    )
    ctx.log(f"  HTML:      {paths['html']}")
    ctx.log(f"  JSON:      {paths['json']}")
    ctx.log(f"  CSV:       {paths['csv']}")
    ctx.log(f"  reproduce: {paths['reproduce']}")
    return paths

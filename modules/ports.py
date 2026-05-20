"""Port scanning: uses nmap for service/version detection when available,
otherwise falls back to a built-in polite TCP-connect scan.
"""

from __future__ import annotations

import asyncio
import xml.etree.ElementTree as ET

from sentinel.context import Context
from sentinel.findings import Finding
from sentinel.integrations import run_command, tool_path

# port -> (service name, severity if exposed, note)
_COMMON_PORTS = {
    21: ("FTP", "medium", "FTP is often unencrypted; prefer SFTP/FTPS."),
    22: ("SSH", "info", "Ensure key-based auth and current OpenSSH."),
    23: ("Telnet", "high", "Telnet is plaintext; disable it."),
    25: ("SMTP", "info", "Verify the mail service is intended to be public."),
    80: ("HTTP", "info", "Plain HTTP — ensure it redirects to HTTPS."),
    110: ("POP3", "low", "Prefer POP3S."),
    143: ("IMAP", "low", "Prefer IMAPS."),
    443: ("HTTPS", "info", "Expected for a web target."),
    445: ("SMB", "high", "SMB should not be internet-exposed."),
    3306: ("MySQL", "high", "Databases should not be internet-exposed."),
    3389: ("RDP", "high", "RDP should not be internet-exposed."),
    5432: ("PostgreSQL", "high", "Databases should not be internet-exposed."),
    6379: ("Redis", "high", "Redis should not be internet-exposed."),
    8080: ("HTTP-alt", "info", "Often a dev/admin service — verify intent."),
    8443: ("HTTPS-alt", "info", "Often a dev/admin service — verify intent."),
    9200: ("Elasticsearch", "high", "Elasticsearch should not be public."),
    27017: ("MongoDB", "high", "MongoDB should not be internet-exposed."),
}

# Service names nmap may report that warrant a non-info severity.
_RISKY_SERVICES = {
    "telnet": "high", "microsoft-ds": "high", "ms-wbt-server": "high",
    "mysql": "high", "postgresql": "high", "redis": "high",
    "mongodb": "high", "elasticsearch": "high", "ftp": "medium",
    "vnc": "high", "rdp": "high",
}


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» ports[/bold cyan]")
    nmap = tool_path("nmap")
    if nmap:
        ctx.log("  [dim]using nmap for service/version detection[/dim]")
        if await _nmap_scan(ctx, nmap):
            return
        ctx.log("  [yellow]nmap run failed — falling back to built-in scan"
                "[/yellow]")
    await _builtin_scan(ctx)


async def _nmap_scan(ctx: Context, nmap: str) -> bool:
    """Run an nmap connect scan; return True on success."""
    code, stdout, stderr = await run_command(
        [
            nmap, "-sT", "-sV", "-Pn", "-T4",
            "--top-ports", "200", "-oX", "-", ctx.scope.host,
        ],
        timeout=400,
    )
    if code != 0 or not stdout.strip():
        return False
    try:
        root = ET.fromstring(stdout)
    except ET.ParseError:
        return False

    for port_el in root.findall(".//host/ports/port"):
        state_el = port_el.find("state")
        if state_el is None or state_el.get("state") != "open":
            continue
        portid = int(port_el.get("portid", "0"))
        ctx.open_ports.append(portid)

        svc = port_el.find("service")
        name = (svc.get("name") if svc is not None else "") or "unknown"
        product = (svc.get("product") if svc is not None else "") or ""
        version = (svc.get("version") if svc is not None else "") or ""
        banner = " ".join(p for p in (product, version) if p).strip()

        severity = _RISKY_SERVICES.get(name.lower(), "info")
        note = _COMMON_PORTS.get(portid, ("", "", ""))[2] or \
            "Confirm this service is intended to be reachable."
        ctx.add_finding(Finding(
            title=f"Open port {portid}/tcp ({name})"
                  + (f" — {banner}" if banner else ""),
            severity=severity,
            target=f"{ctx.scope.host}:{portid}",
            module="ports",
            description=f"nmap reports port {portid} open running '{name}'.",
            evidence=f"service={name}; {banner or 'version not identified'}",
            remediation=note,
        ))
    ctx.open_ports.sort()
    ctx.recon["port_scanner"] = "nmap"
    return True


async def _builtin_scan(ctx: Context) -> None:
    host = ctx.scope.host
    sem = asyncio.Semaphore(min(ctx.config.concurrency, 50))

    async def _probe(port: int) -> None:
        async with sem:
            try:
                fut = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(fut, timeout=4.0)
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass
            except (OSError, asyncio.TimeoutError):
                return
            ctx.open_ports.append(port)

    await asyncio.gather(*(_probe(p) for p in _COMMON_PORTS))
    ctx.open_ports.sort()
    ctx.recon["port_scanner"] = "built-in"

    for port in ctx.open_ports:
        service, severity, note = _COMMON_PORTS[port]
        ctx.add_finding(Finding(
            title=f"Open port {port}/tcp ({service})",
            severity=severity,
            target=f"{host}:{port}",
            module="ports",
            description=f"TCP connect succeeded on port {port} ({service}).",
            evidence=f"{host}:{port} accepts connections",
            remediation=note,
        ))

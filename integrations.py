"""Detection and invocation of optional external tools.

Sentinel works fully standalone, but if `nmap` or `nuclei` are installed it
will use them for deeper coverage. Nothing here is required; every caller has a
built-in fallback.
"""

from __future__ import annotations

import asyncio
import shutil
from asyncio.subprocess import PIPE

# tool name -> metadata used for detection, install hints and UI messages.
KNOWN_TOOLS: dict[str, dict] = {
    "nmap": {
        "purpose": "service and version detection during the ports phase",
        "brew": "nmap",
        "apt": "nmap",
        "go": None,
    },
    "nuclei": {
        "purpose": "community template-based vulnerability checks in the "
                   "vulns phase",
        "brew": "nuclei",
        "apt": None,
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    },
}


def tool_path(name: str) -> str | None:
    """Return the absolute path to a tool, or None if it is not installed."""
    return shutil.which(name)


def detect() -> dict[str, str | None]:
    """Return {tool_name: path-or-None} for every known optional tool."""
    return {name: shutil.which(name) for name in KNOWN_TOOLS}


def install_command(name: str) -> list[str] | None:
    """Return the best available install command for a tool, or None.

    The user must explicitly approve running this — Sentinel never installs
    software on its own.
    """
    spec = KNOWN_TOOLS.get(name)
    if spec is None:
        return None
    if shutil.which("brew") and spec.get("brew"):
        return ["brew", "install", spec["brew"]]
    if shutil.which("apt-get") and spec.get("apt"):
        return ["sudo", "apt-get", "install", "-y", spec["apt"]]
    if shutil.which("go") and spec.get("go"):
        return ["go", "install", spec["go"]]
    return None


async def run_command(
    args: list[str], timeout: float = 300.0
) -> tuple[int, str, str]:
    """Run a command, returning (returncode, stdout, stderr).

    A non-zero return code is reported, never raised, so callers can fall back
    to built-in behaviour.
    """
    try:
        proc = await asyncio.create_subprocess_exec(
            *args, stdout=PIPE, stderr=PIPE
        )
    except (OSError, ValueError) as exc:
        return -1, "", f"could not launch {args[0]}: {exc}"
    try:
        out, err = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, "", f"{args[0]} timed out after {timeout:.0f}s"
    return (
        proc.returncode or 0,
        out.decode(errors="replace"),
        err.decode(errors="replace"),
    )

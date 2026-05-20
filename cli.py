"""Command-line entry point for Sentinel."""

from __future__ import annotations

import argparse
import asyncio
import subprocess
import sys

from sentinel import __version__
from sentinel.context import ALL_PHASES, Config
from sentinel.engine import run_assessment
from sentinel.scope import Scope, ScopeError

_AUTH_NOTICE = """\
╭─ AUTHORIZATION REQUIRED ───────────────────────────────────────────────╮
│ Sentinel actively probes the target. Run it ONLY against systems you   │
│ own or are explicitly authorized to test (signed engagement or a       │
│ published bug-bounty scope). Unauthorized scanning is illegal.         │
╰────────────────────────────────────────────────────────────────────────╯"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Automated, scope-aware website pentesting toolkit "
                    "for authorized assessments.",
    )
    parser.add_argument("--version", action="version",
                        version=f"Sentinel {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Run an automated assessment.")
    scan.add_argument("target", help="Target URL or host, e.g. https://example.com")
    scan.add_argument("--out", default="reports",
                      help="Base directory for reports; each scan lands in "
                           "<out>/<host>/<timestamp>/ (default: reports)")
    scan.add_argument("--workspace", default=None,
                      help="Group this scan under a named workspace "
                           "(reports go to sentinel-workspaces/<name>/)")
    scan.add_argument("--rate", type=float, default=10.0,
                      help="Max requests per second (default: 10)")
    scan.add_argument("--concurrency", type=int, default=10,
                      help="Max concurrent requests (default: 10)")
    scan.add_argument("--timeout", type=float, default=15.0,
                      help="Per-request timeout in seconds (default: 15)")
    scan.add_argument("--max-pages", type=int, default=200,
                      help="Max pages to crawl (default: 200)")
    scan.add_argument("--max-depth", type=int, default=4,
                      help="Max crawl depth (default: 4)")
    scan.add_argument("--only", default="",
                      help=f"Comma-separated phases to run "
                           f"(of: {','.join(ALL_PHASES)})")
    scan.add_argument("--no-subdomains", action="store_true",
                      help="Restrict scope to the exact host only")
    scan.add_argument("--allow-private", action="store_true",
                      help="Permit targets on private/loopback IPs (lab use)")
    scan.add_argument("--insecure", action="store_true",
                      help="Do not verify TLS certificates")
    scan.add_argument("--i-am-authorized", action="store_true",
                      help="Confirm you are authorized to test the target "
                           "(skips the interactive prompt)")
    scan.add_argument("--verify-findings", action="store_true",
                      help="Pre-approve proof-of-concept verification for "
                           "every finding (otherwise each is approved "
                           "interactively during the verify phase)")

    sub.add_parser("ui", help="Launch the interactive, button-driven terminal UI.")
    sub.add_parser("doctor", help="Check for optional external tools "
                                  "(nmap, nuclei) and offer to install them.")
    return parser


def _confirm_authorization(target: str, authorized_flag: bool) -> bool:
    print(_AUTH_NOTICE)
    if authorized_flag:
        print(f"\n[authorization acknowledged via --i-am-authorized]\n")
        return True
    if not sys.stdin.isatty():
        print("\nRefusing to run: no TTY for confirmation. Re-run with "
              "--i-am-authorized only if you are authorized.\n", file=sys.stderr)
        return False
    answer = input(
        f"\nType the target host to confirm you are authorized to test it\n"
        f"  target: {target}\n  confirm > "
    ).strip()
    return answer != "" and answer in target


def _run_doctor() -> int:
    """Report optional-tool status and offer to install anything missing."""
    from sentinel.integrations import KNOWN_TOOLS, detect, install_command

    print("Sentinel optional tool check\n")
    found = detect()
    for name, path in found.items():
        purpose = KNOWN_TOOLS[name]["purpose"]
        if path:
            print(f"  ✓ {name:<8} found at {path}")
            print(f"    used for {purpose}")
            continue

        print(f"  ✗ {name:<8} not installed — used for {purpose}")
        cmd = install_command(name)
        if cmd is None:
            print(f"    No automatic installer available. See the {name} "
                  "project docs to install it manually.")
            continue
        if not sys.stdin.isatty():
            print(f"    Install it with: {' '.join(cmd)}")
            continue
        answer = input(f"    Install now with `{' '.join(cmd)}`? [y/N] ").strip()
        if answer.lower() in ("y", "yes"):
            print(f"    Running: {' '.join(cmd)}")
            completed = subprocess.run(cmd)
            if completed.returncode == 0:
                print(f"    ✓ {name} installed.")
            else:
                print(f"    Install command exited with "
                      f"{completed.returncode}; install {name} manually.")
        else:
            print(f"    Skipped. Install later with: {' '.join(cmd)}")
    print("\nSentinel runs fully without these — they only add extra coverage.")
    return 0


def _integration_notice() -> None:
    from sentinel.integrations import detect

    found = detect()
    active = [name for name, path in found.items() if path]
    missing = [name for name, path in found.items() if not path]
    if active:
        print(f"Optional tools detected: {', '.join(active)} — will be used.")
    if missing:
        print(f"Optional tools not found: {', '.join(missing)}. "
              "Run `sentinel doctor` to install them for deeper coverage.")


def _make_approval_callback():
    """Build the interactive per-finding verification approval prompt."""
    from sentinel.findings import rundown_text

    interactive = sys.stdin.isatty()

    async def approve(finding) -> bool:
        print("\n" + "=" * 72)
        print(rundown_text(finding))
        print("=" * 72)
        if not interactive:
            print("  [non-interactive run — skipping verification. Use "
                  "--verify-findings to pre-approve.]")
            return False
        answer = await asyncio.to_thread(
            input, "  Approve this proof-of-concept?  [y]es / [N]o > "
        )
        approved = answer.strip().lower() in ("y", "yes")
        print("  → approved" if approved else "  → skipped")
        return approved

    return approve


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.command == "ui":
        from sentinel.tui import run as run_tui
        run_tui()
        return 0

    if args.command == "doctor":
        return _run_doctor()

    if args.command != "scan":
        return 1

    phases = list(ALL_PHASES)
    if args.only:
        requested = [p.strip() for p in args.only.split(",") if p.strip()]
        unknown = [p for p in requested if p not in ALL_PHASES]
        if unknown:
            print(f"Unknown phase(s): {', '.join(unknown)}", file=sys.stderr)
            return 2
        phases = [p for p in ALL_PHASES if p in requested]

    # Validate scope (DNS + private-IP guard) before asking for confirmation.
    try:
        Scope(
            args.target,
            allow_private=args.allow_private,
            include_subdomains=not args.no_subdomains,
        )
    except ScopeError as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 3

    if not _confirm_authorization(args.target, args.i_am_authorized):
        print("Aborted: authorization not confirmed.", file=sys.stderr)
        return 4

    _integration_notice()

    config = Config(
        target=args.target,
        out_dir=args.out,
        workspace=args.workspace,
        rate=args.rate,
        concurrency=args.concurrency,
        timeout=args.timeout,
        max_pages=args.max_pages,
        max_depth=args.max_depth,
        allow_private=args.allow_private,
        include_subdomains=not args.no_subdomains,
        verify_tls=not args.insecure,
        auto_verify=args.verify_findings,
        phases=phases,
    )
    # With --verify-findings every PoC is pre-approved, so no prompt is needed.
    approval = None if args.verify_findings else _make_approval_callback()

    try:
        asyncio.run(run_assessment(config, approval_callback=approval))
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except ScopeError as exc:
        print(f"Scope error: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())

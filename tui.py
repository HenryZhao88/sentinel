"""Button-driven terminal UI for Sentinel, built on Textual.

Run with `sentinel ui`. Everything is point-and-click: fill the target field,
toggle phases, tick the authorization box, and press Start Scan. Progress and
findings stream into the panes below in real time.
"""

from __future__ import annotations

import webbrowser
from pathlib import Path

from rich.text import Text
from textual import on, work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    Footer,
    Header,
    Input,
    Label,
    RichLog,
    Rule,
    Static,
)

from sentinel.context import ALL_PHASES, DEFAULT_PHASES, Config
from sentinel.engine import run_assessment
from sentinel.findings import (
    SEVERITY_COLOR, SEVERITY_ORDER, Finding, rundown_text,
)
from sentinel.scope import Scope, ScopeError


class ApprovalScreen(ModalScreen[bool]):
    """Modal shown during the verify phase: a finding rundown + approve/skip.

    This is the human-in-the-loop gate — no proof-of-concept runs until the
    operator presses Approve here.
    """

    def __init__(self, finding: Finding) -> None:
        super().__init__()
        self._finding = finding

    def compose(self) -> ComposeResult:
        with Vertical(id="approve-box"):
            yield Static(
                "⚠  Proof-of-concept verification — your approval is required",
                id="approve-title",
            )
            yield Static(rundown_text(self._finding), id="approve-body")
            with Horizontal(id="approve-actions"):
                yield Button("✓  Approve PoC", variant="success",
                             id="approve-yes")
                yield Button("✗  Skip", variant="error", id="approve-no")

    @on(Button.Pressed, "#approve-yes")
    def _approve(self) -> None:
        self.dismiss(True)

    @on(Button.Pressed, "#approve-no")
    def _skip(self) -> None:
        self.dismiss(False)


class SentinelApp(App):
    """Sentinel's interactive control panel."""

    TITLE = "Sentinel"
    SUB_TITLE = "authorized website pentesting"

    CSS = """
    Screen { layout: vertical; }
    #config {
        height: auto; max-height: 60%;
        border: round $primary; padding: 0 1; margin: 0 1;
    }
    #config > Label { margin-top: 1; color: $text-muted; }
    #target, #workspace { width: 1fr; }
    #phases {
        height: auto; margin-top: 1;
        layout: grid; grid-size: 4; grid-rows: auto;
    }
    #tuning { height: auto; margin-top: 1; }
    .num { width: 16; }
    .num-label { width: 14; content-align: left middle; }
    #actions { height: auto; margin: 1 1 0 1; }
    #actions Button { margin-right: 2; }
    #panes { height: 1fr; margin: 1 1 0 1; }
    #log { width: 2fr; border: round $accent; }
    #findings-pane { width: 3fr; }
    #findings { height: 1fr; border: round $accent; }
    #summary { height: auto; padding: 0 1; }
    .auth { color: $warning; text-style: bold; }
    ApprovalScreen { align: center middle; }
    #approve-box {
        width: 86; height: auto; max-height: 90%;
        background: $surface; border: thick $warning; padding: 1 2;
    }
    #approve-title { text-style: bold; color: $warning; margin-bottom: 1; }
    #approve-body { height: auto; }
    #approve-actions { height: auto; margin-top: 1; }
    #approve-actions Button { margin-right: 2; }
    """

    BINDINGS = [("q", "quit", "Quit"), ("ctrl+c", "quit", "Quit")]

    def __init__(self) -> None:
        super().__init__()
        self._report_paths: dict[str, str] | None = None
        self._scan_worker = None
        self._counts: dict[str, int] = {s: 0 for s in SEVERITY_ORDER}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with VerticalScroll(id="config"):
            yield Label("Target URL")
            yield Input(
                placeholder="https://example.com  (only sites you may test)",
                id="target",
            )
            yield Label("Workspace (optional — groups related scans)")
            yield Input(placeholder="e.g. acme-engagement", id="workspace")
            yield Label("Phases to run")
            with Horizontal(id="phases"):
                for phase in ALL_PHASES:
                    yield Checkbox(
                        phase,
                        value=phase in DEFAULT_PHASES,
                        id=f"phase-{phase}",
                    )
            yield Label("Tuning")
            with Horizontal(id="tuning"):
                yield Label("Rate /sec", classes="num-label")
                yield Input("10", type="integer", id="rate", classes="num")
                yield Label("Concurrency", classes="num-label")
                yield Input("10", type="integer", id="concurrency", classes="num")
                yield Label("Max pages", classes="num-label")
                yield Input("200", type="integer", id="maxpages", classes="num")
            yield Checkbox(
                "Allow private / loopback IPs (lab targets you control)",
                id="allowpriv",
            )
            yield Checkbox(
                "Pre-approve all PoC verifications (unattended — skips the "
                "per-finding prompt)",
                id="autoverify",
            )
            yield Checkbox(
                "I confirm I am AUTHORIZED to test this target",
                id="authorized",
                classes="auth",
            )
        # Action bar lives outside the scroll area so buttons are always visible.
        with Horizontal(id="actions"):
            yield Button("▶  Start Scan", variant="success", id="start")
            yield Button("■  Stop", variant="error", id="stop", disabled=True)
            yield Button(
                "📄  Open HTML Report",
                variant="primary",
                id="report",
                disabled=True,
            )
        with Horizontal(id="panes"):
            yield RichLog(id="log", markup=True, wrap=True, highlight=True)
            with Vertical(id="findings-pane"):
                yield Static("No findings yet.", id="summary")
                yield Rule()
                yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_columns("Severity", "Title", "Module", "Target")
        log = self.query_one("#log", RichLog)
        log.write("[bold]Sentinel ready.[/bold] Fill in a target and press "
                  "[green]Start Scan[/green].")
        log.write("[dim]Only scan systems you own or are authorized to test."
                  "[/dim]")

    # ----------------------------------------------------------------- events

    @on(Button.Pressed, "#start")
    def _on_start(self) -> None:
        self._start_scan()

    @on(Button.Pressed, "#stop")
    def _on_stop(self) -> None:
        if self._scan_worker is not None:
            self._scan_worker.cancel()
            self.query_one("#log", RichLog).write(
                "[yellow]Stop requested — cancelling scan…[/yellow]"
            )

    @on(Button.Pressed, "#report")
    def _on_report(self) -> None:
        if not self._report_paths:
            return
        uri = Path(self._report_paths["html"]).resolve().as_uri()
        try:
            webbrowser.open(uri)
            self.notify(f"Opened report: {uri}")
        except Exception as exc:  # noqa: BLE001
            self.notify(f"Could not open browser: {exc}", severity="warning")

    # ------------------------------------------------------------- scan logic

    def _start_scan(self) -> None:
        log = self.query_one("#log", RichLog)

        target = self.query_one("#target", Input).value.strip()
        if not target:
            self.notify("Enter a target URL first.", severity="error")
            return
        if not self.query_one("#authorized", Checkbox).value:
            self.notify(
                "Tick the authorization box to confirm you may test this "
                "target.",
                severity="error",
                title="Authorization required",
            )
            return

        phases = [
            p for p in ALL_PHASES
            if self.query_one(f"#phase-{p}", Checkbox).value
        ]
        if not phases:
            self.notify("Select at least one phase.", severity="error")
            return

        allow_private = self.query_one("#allowpriv", Checkbox).value

        # Validate scope up front so bad targets fail fast with a clear message.
        try:
            Scope(target, allow_private=allow_private)
        except ScopeError as exc:
            self.notify(str(exc), severity="error", title="Scope rejected")
            log.write(f"[bold red]Scope rejected:[/bold red] {exc}")
            return

        workspace = self.query_one("#workspace", Input).value.strip() or None
        auto_verify = self.query_one("#autoverify", Checkbox).value

        config = Config(
            target=target,
            workspace=workspace,
            rate=_to_int(self, "rate", 10),
            concurrency=_to_int(self, "concurrency", 10),
            max_pages=_to_int(self, "maxpages", 200),
            allow_private=allow_private,
            browser="browsercrawl" in phases,
            auto_verify=auto_verify,
            phases=phases,
        )

        # Reset UI state for a fresh run.
        log.clear()
        self.query_one("#findings", DataTable).clear()
        self._counts = {s: 0 for s in SEVERITY_ORDER}
        self._update_summary()
        self._report_paths = None
        self.query_one("#report", Button).disabled = True
        self.query_one("#start", Button).disabled = True
        self.query_one("#stop", Button).disabled = False

        self._scan_worker = self._run_scan(config)

    @work(exclusive=True, group="scan")
    async def _run_scan(self, config: Config) -> None:
        log = self.query_one("#log", RichLog)
        try:
            paths = await run_assessment(
                config,
                log_callback=self._on_log,
                finding_callback=self._on_finding,
                approval_callback=self._on_approval,
            )
            self._report_paths = paths
            self.query_one("#report", Button).disabled = False
            self.notify("Scan complete — report ready.", title="Sentinel")
        except ScopeError as exc:
            log.write(f"[bold red]Scope error:[/bold red] {exc}")
            self.notify(str(exc), severity="error")
        except Exception as exc:  # noqa: BLE001 — surface, don't crash the UI
            log.write(f"[bold red]Scan failed:[/bold red] {exc!r}")
            self.notify(f"Scan failed: {exc}", severity="error")
        finally:
            self.query_one("#start", Button).disabled = False
            self.query_one("#stop", Button).disabled = True
            self._scan_worker = None

    # --------------------------------------------------------------- callbacks

    async def _on_approval(self, finding: Finding) -> bool:
        """Pause the scan and ask the operator to approve a verification PoC."""
        return await self.push_screen_wait(ApprovalScreen(finding))

    def _on_log(self, message: str) -> None:
        self.query_one("#log", RichLog).write(message)

    def _on_finding(self, finding: Finding) -> None:
        color = SEVERITY_COLOR[finding.severity]
        sev = Text(finding.severity.upper(), style=f"bold {color}")
        self.query_one("#findings", DataTable).add_row(
            sev, finding.title, finding.module, finding.target
        )
        self._counts[finding.severity] += 1
        self._update_summary()

    def _update_summary(self) -> None:
        total = sum(self._counts.values())
        if total == 0:
            self.query_one("#summary", Static).update("No findings yet.")
            return
        parts = []
        for sev in SEVERITY_ORDER:
            count = self._counts[sev]
            if count:
                parts.append(
                    f"[{SEVERITY_COLOR[sev]}]{sev}: {count}[/]"
                )
        summary = Text.from_markup(
            f"[bold]{total} finding(s)[/bold]   " + "   ".join(parts)
        )
        self.query_one("#summary", Static).update(summary)


def _to_int(app: App, widget_id: str, default: int) -> int:
    raw = app.query_one(f"#{widget_id}", Input).value.strip()
    try:
        value = int(raw)
        return value if value > 0 else default
    except (ValueError, TypeError):
        return default


def run() -> None:
    """Launch the Sentinel TUI."""
    SentinelApp().run()


if __name__ == "__main__":
    run()

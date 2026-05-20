"""Report generation: JSON for tooling, HTML for humans, CSV for spreadsheets,
plus a standalone reproduce.py script.

Output is organised per site: each scan goes to
`reports/<host>/<timestamp>/`. With a workspace it instead goes to
`sentinel-workspaces/<name>/<host>_<timestamp>/` and a workspace index is kept
up to date so multiple scans can be compared over time.
"""

from __future__ import annotations

import csv
import datetime as dt
import html
import json
import stat
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

from sentinel import reproducer
from sentinel.context import Context
from sentinel.findings import SEVERITY_COLOR, SEVERITY_ORDER

WORKSPACE_ROOT = Path("sentinel-workspaces")


def _output_dir(ctx: Context, timestamp: dt.datetime) -> Path:
    """Resolve the directory for this run's reports.

    Default layout groups every scan by site:
        <out_dir>/<host>/<timestamp>/
    so a tester working across several companies/sites keeps them separate.
    """
    stamp = timestamp.strftime("%Y%m%d-%H%M%S")
    if ctx.config.workspace:
        return WORKSPACE_ROOT / ctx.config.workspace / f"{ctx.scope.host}_{stamp}"
    return Path(ctx.config.out_dir) / ctx.scope.host / stamp


def _host_of(target: str) -> str:
    """Best-effort hostname extraction from a finding's target string."""
    parsed = urlparse(target if "://" in target else f"//{target}")
    return (parsed.hostname or target.split(":")[0] or target).lower()


def write(ctx: Context) -> dict[str, str]:
    """Write JSON + HTML + CSV reports; return a map of {format: path}."""
    now = dt.datetime.now(dt.timezone.utc)
    out = _output_dir(ctx, now)
    out.mkdir(parents=True, exist_ok=True)

    findings = sorted(ctx.findings, key=lambda f: (f.rank, f.module, f.title))
    summary = {sev: 0 for sev in SEVERITY_ORDER}
    by_host: dict[str, dict[str, int]] = defaultdict(
        lambda: {sev: 0 for sev in SEVERITY_ORDER}
    )
    for f in findings:
        summary[f.severity] += 1
        by_host[_host_of(f.target)][f.severity] += 1

    payload = {
        "tool": "Sentinel",
        "generated": now.isoformat(timespec="seconds"),
        "workspace": ctx.config.workspace,
        "target": ctx.scope.root_url,
        "scope": {
            "host": ctx.scope.host,
            "base_domain": ctx.scope.base_domain,
            "resolved_ips": ctx.scope.resolved_ips,
            "include_subdomains": ctx.scope.include_subdomains,
        },
        "stats": {
            "requests_sent": ctx.http.request_count,
            "transport_errors": ctx.http.error_count,
            "urls_discovered": len(ctx.urls),
            "open_ports": ctx.open_ports,
        },
        "summary": summary,
        "by_host": {h: dict(c) for h, c in by_host.items()},
        "recon": ctx.recon,
        "findings": [f.to_dict() for f in findings],
    }

    json_path = out / "report.json"
    json_path.write_text(json.dumps(payload, indent=2, default=str))

    csv_path = out / "report.csv"
    _write_csv(csv_path, findings)

    html_path = out / "report.html"
    html_path.write_text(_render_html(payload, findings, dict(by_host)))

    # A standalone, runnable script that reproduces this scan's findings.
    repro_path = out / "reproduce.py"
    repro_path.write_text(
        reproducer.generate(ctx, payload["generated"])
    )
    repro_path.chmod(repro_path.stat().st_mode | stat.S_IXUSR)

    paths = {
        "json": str(json_path),
        "csv": str(csv_path),
        "html": str(html_path),
        "reproduce": str(repro_path),
        "dir": str(out),
    }
    if ctx.config.workspace:
        _update_workspace_index(ctx, payload, paths, now)
    return paths


def _write_csv(path: Path, findings: list) -> None:
    with path.open("w", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            ["severity", "module", "title", "target", "evidence",
             "remediation", "references"]
        )
        for f in findings:
            writer.writerow([
                f.severity, f.module, f.title, f.target,
                f.evidence, f.remediation, " ".join(f.references),
            ])


def _update_workspace_index(
    ctx: Context, payload: dict, paths: dict, now: dt.datetime
) -> None:
    """Append this run to the workspace's index.json."""
    index_path = WORKSPACE_ROOT / ctx.config.workspace / "index.json"
    if index_path.exists():
        try:
            index = json.loads(index_path.read_text())
        except json.JSONDecodeError:
            index = {"workspace": ctx.config.workspace, "scans": []}
    else:
        index = {"workspace": ctx.config.workspace, "scans": []}

    index["scans"].append({
        "target": payload["target"],
        "host": ctx.scope.host,
        "generated": now.isoformat(timespec="seconds"),
        "summary": payload["summary"],
        "total_findings": len(payload["findings"]),
        "report_dir": paths["dir"],
    })
    index_path.write_text(json.dumps(index, indent=2))


def _render_defense(defense: dict | None) -> str:
    """Render the defense-testing posture table, or '' if not run."""
    if not defense:
        return ""
    rows = []
    for category, b in defense.items():
        total = b.get("total", 0)
        if not total:
            continue
        blocked = b.get("blocked", 0)
        rate = round(100 * blocked / total)
        rows.append(
            f"<tr><td>{html.escape(category)}</td>"
            f"<td><span class='bar' style='width:{rate}px'></span> {rate}%</td>"
            f"<td>{blocked}/{total}</td>"
            f"<td>{b.get('reflected', 0)} reflected · "
            f"{b.get('passed', 0)} passed · {b.get('executed', 0)} executed"
            "</td></tr>"
        )
    if not rows:
        return ""
    return (
        "<h2>Defense posture (WAF / input filtering)</h2>"
        "<table><tr><th>Attack class</th><th>Block rate</th>"
        "<th>Blocked</th><th>Other outcomes</th></tr>"
        + "".join(rows) + "</table>"
    )


def _render_html(payload: dict, findings: list, by_host: dict) -> str:
    def esc(value) -> str:
        return html.escape(str(value))

    summary = payload["summary"]
    chips = "".join(
        f'<span class="chip" style="background:{SEVERITY_COLOR[sev]}">'
        f'{esc(sev)}: {count}</span>'
        for sev, count in summary.items() if count
    ) or '<span class="chip" style="background:#2b8a3e">no findings</span>'

    host_rows = "".join(
        f"<tr><td><code>{esc(host)}</code></td>"
        + "".join(
            f'<td style="color:{SEVERITY_COLOR[sev]}">{counts[sev] or ""}</td>'
            for sev in SEVERITY_ORDER
        )
        + "</tr>"
        for host, counts in sorted(by_host.items())
    )

    rows = []
    for f in findings:
        refs = "".join(
            f'<a href="{esc(r)}">{esc(r)}</a><br>' for r in f.references
        )
        repro = ""
        if f.reproduction:
            steps = "".join(f"<li>{esc(s)}</li>" for s in f.reproduction)
            repro = f"<p><b>Reproduction:</b></p><ol>{steps}</ol>"
        if f.verified:
            badge = '<span class="vbadge ok">✓ VERIFIED</span>'
        elif f.verification:
            badge = '<span class="vbadge no">unverified</span>'
        else:
            badge = ""
        verification = (
            f'<p><b>Verification:</b> {esc(f.verification)}</p>'
            if f.verification else ""
        )
        transcript = (
            f"<p><b>Proof transcript:</b></p><pre>{esc(f.transcript)}</pre>"
            if f.transcript else ""
        )
        rows.append(f"""
        <details class="finding">
          <summary>
            <span class="sev" style="background:{SEVERITY_COLOR[f.severity]}">
              {esc(f.severity.upper())}</span>
            <span class="ftitle">{esc(f.title)}</span>
            {badge}
            <span class="fmod">{esc(f.confidence)} · {esc(f.module)}</span>
          </summary>
          <div class="fbody">
            <p><b>Target:</b> <code>{esc(f.target)}</code></p>
            <p>{esc(f.description)}</p>
            {f'<p><b>Impact:</b> {esc(f.impact)}</p>' if f.impact else ''}
            {f'<p><b>Evidence:</b> <code>{esc(f.evidence)}</code></p>' if f.evidence else ''}
            {repro}
            {verification}
            {transcript}
            {f'<p><b>Remediation:</b> {esc(f.remediation)}</p>' if f.remediation else ''}
            {f'<p><b>References:</b><br>{refs}</p>' if refs else ''}
          </div>
        </details>""")

    defense_html = _render_defense(payload.get("recon", {}).get("defense"))

    stats = payload["stats"]
    workspace = payload.get("workspace")
    ws_line = (f' · workspace <b>{esc(workspace)}</b>' if workspace else "")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sentinel report — {esc(payload['target'])}</title>
<style>
  body{{font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;margin:0;
       background:#0f1115;color:#e6e6e6}}
  header{{background:#171a21;padding:24px 32px;border-bottom:1px solid #2a2f3a}}
  h1{{margin:0 0 4px;font-size:20px}} h2{{font-size:16px;margin-top:28px}}
  main{{max-width:980px;margin:0 auto;padding:24px 32px}}
  .chip{{display:inline-block;color:#fff;border-radius:12px;padding:3px 10px;
        margin:3px 6px 3px 0;font-size:12px;font-weight:600}}
  .meta{{color:#9aa4b2;font-size:13px}}
  .finding{{background:#171a21;border:1px solid #2a2f3a;border-radius:8px;
           margin:10px 0}}
  summary{{cursor:pointer;padding:12px 14px;display:flex;align-items:center;
          gap:10px;list-style:none}}
  summary::-webkit-details-marker{{display:none}}
  .sev{{color:#fff;font-size:11px;font-weight:700;border-radius:4px;
       padding:2px 7px}}
  .ftitle{{flex:1;font-weight:600}}
  .fmod{{color:#9aa4b2;font-size:12px;font-family:monospace}}
  .fbody{{padding:0 16px 14px;border-top:1px solid #2a2f3a}}
  code{{background:#0f1115;padding:1px 5px;border-radius:4px;
       word-break:break-all}}
  pre{{background:#0f1115;padding:10px 12px;border-radius:6px;
      overflow-x:auto;font-size:12px;border:1px solid #2a2f3a}}
  a{{color:#4dabf7}}
  table{{border-collapse:collapse;margin:8px 0;width:100%}}
  td,th{{padding:4px 14px 4px 0;text-align:left;font-size:13px}}
  th{{color:#9aa4b2;border-bottom:1px solid #2a2f3a}}
  .vbadge{{font-size:10px;font-weight:700;border-radius:4px;padding:2px 6px}}
  .vbadge.ok{{background:#2b8a3e;color:#fff}}
  .vbadge.no{{background:#3a3f4a;color:#9aa4b2}}
  .bar{{display:inline-block;height:10px;border-radius:3px;
       background:#2b8a3e;vertical-align:middle}}
</style></head><body>
<header>
  <h1>🛡 Sentinel assessment report</h1>
  <div class="meta">Target <b>{esc(payload['target'])}</b>{ws_line} ·
    generated {esc(payload['generated'])}</div>
</header>
<main>
  <div>{chips}</div>
  <table>
    <tr><td>Resolved IPs</td><td>{esc(', '.join(payload['scope']['resolved_ips']))}</td></tr>
    <tr><td>Requests sent</td><td>{stats['requests_sent']}</td></tr>
    <tr><td>URLs discovered</td><td>{stats['urls_discovered']}</td></tr>
    <tr><td>Open ports</td><td>{esc(stats['open_ports']) or 'none'}</td></tr>
  </table>
  <h2>Findings by host</h2>
  <table>
    <tr><th>Host</th>
      {''.join(f'<th>{esc(s)}</th>' for s in SEVERITY_ORDER)}</tr>
    {host_rows or '<tr><td colspan="6">No findings.</td></tr>'}
  </table>
  {defense_html}
  <h2>All findings ({len(findings)})</h2>
  {''.join(rows) if rows else '<p>No findings recorded.</p>'}
  <p class="meta">Sentinel performs non-destructive checks only. Verify every
     finding manually before reporting. Authorized testing use only.</p>
</main></body></html>"""

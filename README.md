# Sentinel

**An automated, scope-aware website penetration testing toolkit for authorized
security assessments and bug-bounty work.**

Sentinel chains reconnaissance, crawling, content discovery, JavaScript
analysis, access-control replay, vulnerability checks, defense testing, and human-gated
proof-of-concept verification into a single workflow — then produces a ranked
HTML / JSON / CSV report.

It runs from the command line or a button-driven terminal UI. It is built to be
the tool you can point at an authorized target without it doing anything
reckless: every check is non-destructive, every request is rate-limited, and
exploitation is gated behind your explicit approval.

---

## Table of contents

1. [Authorization — read this first](#1-authorization--read-this-first)
2. [Install](#2-install)
3. [Quick start](#3-quick-start)
4. [How a scan works: the 11 phases](#4-how-a-scan-works-the-11-phases)
5. [Proof-of-concept verification](#5-proof-of-concept-verification)
6. [The terminal UI](#6-the-terminal-ui)
7. [The command line](#7-the-command-line)
8. [Workspaces](#8-workspaces)
9. [Optional external tools](#9-optional-external-tools)
10. [Reading the report](#10-reading-the-report)
11. [Walkthroughs](#11-walkthroughs)
12. [Troubleshooting](#12-troubleshooting)
13. [How Sentinel stays safe](#13-how-sentinel-stays-safe)

---

## 1. Authorization — read this first

Run Sentinel **only** against systems you own or have **explicit written
permission** to test — a signed engagement, or a target inside a published
bug-bounty program's scope. Unauthorized scanning is illegal in most
jurisdictions, regardless of intent.

Sentinel will not let you skip this:

- Every scan requires an authorization acknowledgement (a prompt, the
  `--i-am-authorized` flag, or a checkbox in the UI).
- Targets that resolve to private / loopback / reserved IPs are refused unless
  you pass `--allow-private` (intended for lab environments you control).
- It performs **no** destructive actions, denial-of-service, mass multi-target
  scanning, or credential brute-forcing.

If you are not sure you are authorized to test a target, you are not.

---

## 2. Install

Requirements: **Python 3.10+**.

```bash
# from the project root
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

This installs the `sentinel` command. Verify it:

```bash
sentinel --version
```

**Optional but recommended** — install `nmap` and `nuclei` for deeper coverage
(see [section 9](#9-optional-external-tools)):

```bash
sentinel doctor
```

On macOS, the optional `--browser` discovery mode can use local Node.js as a
fallback without installing Playwright. For full rendered Chromium crawling,
install the browser extra:

```bash
pip install -e '.[browser]'
playwright install chromium
```

---

## 3. Quick start

### The easy way — the terminal UI

```bash
sentinel ui
```

This opens a control panel. Type a target, tick the boxes, press **Start Scan**.
No commands to memorize. See [section 6](#6-the-terminal-ui).

### The command line

```bash
# A full assessment of a site you are authorized to test
sentinel scan https://example.com --i-am-authorized
```

Sentinel runs all phases, streams progress to your terminal, and writes the
report to `reports/<host>/<timestamp>/`. Open the `report.html` inside it when
it finishes.

That's it. The rest of this README explains what happened and how to control it.

---

## 4. How a scan works: the 11 phases

A scan runs up to eleven phases in order. Each feeds the next — discovery phases
build structured endpoints, the access/vuln checks test them, and the verifier
confirms eligible findings.

| # | Phase        | What it does |
|---|--------------|--------------|
| 1 | `osint`      | **Passive recon.** Subdomains from certificate-transparency logs (crt.sh) and historical URLs from the Wayback Machine. Sends no traffic to the target. |
| 2 | `recon`      | DNS records, TLS/certificate inspection, HTTP headers, technology fingerprinting, missing security headers, wordlist subdomain discovery. |
| 3 | `ports`      | Port scan. Uses `nmap` for service/version detection if installed; otherwise a built-in polite TCP-connect scan of common ports. |
| 4 | `crawl`      | Same-scope spider. Discovers pages, links, scripts, forms, methods, query/body parameters, enctype, and upload surfaces. |
| 5 | `browsercrawl` | Optional browser/runtime discovery enabled with `--browser`; uses Playwright/Chromium when present, otherwise falls back to a Node.js sandbox that captures runtime-constructed fetch/XHR/beacon/WebSocket endpoints. |
| 6 | `content`    | Wordlist discovery of interesting paths and exposed files (`.git`, `.env`, backups, admin panels). |
| 7 | `jsanalysis` | Fetches in-scope JavaScript, extracts hidden API endpoints, fetch/axios routes, JSON body hints, flags leaked secrets, and reports DOM-XSS source/sink candidates. |
| 8 | `access`     | Replays ID-bearing resource endpoints across auth profiles and anonymous access to catch likely IDOR / broken object-level authorization. |
| 9 | `vulns`      | Non-destructive vulnerability checks over query, form body, and JSON parameters: reflected/stored XSS indicators, error-based SQLi, open redirect, CORS, cookie flags, SSRF/OOB candidates, plus `nuclei` against discovered URLs if installed. |
| 10 | `defense`   | **Defense testing.** Sends categorized attack payloads per parameter and reports what the app / WAF blocks, reflects, errors on, or passes. Observational — it measures filtering, it does not exploit. |
| 11 | `verify`    | **Human-gated proof-of-concept verification.** See [section 5](#5-proof-of-concept-verification). |

Run a subset with `--only`:

```bash
sentinel scan https://example.com --only osint,recon,vulns --i-am-authorized
```

### Endpoint and API scanning

Sentinel keeps the legacy URL map for compatibility, but discovery phases now
also record structured endpoints: method, URL, query params, body params, JSON
sample/shape, content type, source module, auth profile, evidence URL, and risk
hints such as `api`, `takes_id`, `takes_url`, `state_changing`, `file_upload`,
and `graphql`.

The built-in vuln checks use those endpoints, so POST forms and JSON API
parameters are tested for reflected input/XSS indicators, stored/persistent
reflection, error-based SQLi, and open redirect issues. URL-taking routes are
flagged for manual/OOB SSRF review by default. If you provide
`--ssrf-callback`, Sentinel sends unique callback URLs to URL-like inputs and
records the tokens for your collaborator/callback service.

Browser-aware crawling is optional. On macOS, Sentinel uses Node.js as a
dependency-free fallback when Playwright/Chromium is not installed. The fallback
runs scripts in a sandbox with browser network APIs stubbed, so target
JavaScript cannot make real outbound requests but runtime-constructed API URLs
still get captured. For full rendered crawling, install `pip install -e
'.[browser]'` and `playwright install chromium`, then run with `--browser`. The
browser phase does not submit forms or generic buttons.

---

## 5. Proof-of-concept verification

Detection phases produce findings like *"possible SQL injection."* The `verify`
phase upgrades the strong ones to *"confirmed — here is the proof."*

For each verifiable finding, Sentinel shows you a full rundown — severity,
impact, evidence, reproduction steps — and asks you to **approve**. Only then
does it run a **bounded, non-destructive proof**:

| Finding | What the approved verification does |
|---|---|
| **SQL injection** | Sends balanced vs. unbalanced quote payloads and compares responses. Proves the injection point exists. Extracts no data. |
| **Reflected XSS** | Re-sends a benign, script-free HTML tag and confirms it lands unescaped in an executable context. Executes no JavaScript. |
| **Open redirect** | Re-sends the payload and captures the off-site `Location` header. |
| **Exposed file** | Confirms the file's content signature. A size and format check only — secret values are **not** stored in the report. |
| **Auth bypass** | Requests the page with **no credentials** and confirms it is a genuine authenticated area — then **stops**. Performs no action inside it. |

**The principle: prove the door is unlocked; never walk through it.** Sentinel
confirms vulnerabilities and documents them with a request/response transcript.
It does not exploit them, dump data, or open shells — that remains a deliberate
manual decision for you, when it is explicitly within your engagement's scope.

### Approving verifications

Two modes, usable together:

- **Interactive (default)** — Sentinel pauses on each finding and asks. In the
  CLI it's a `[y/N]` prompt; in the UI it's a modal with Approve / Skip buttons.
- **Pre-approved** — for an unattended run, pass `--verify-findings` (CLI) or
  tick *"Pre-approve all PoC verifications"* (UI). Every PoC runs without
  pausing.

A confirmed finding is marked `confirmed` confidence and carries a proof
transcript in the report.

---

## 6. The terminal UI

```bash
sentinel ui
```

The control panel, top to bottom:

- **Target URL** — the site to assess.
- **Workspace** *(optional)* — a name to group related scans (see
  [section 8](#8-workspaces)).
- **Phases** — checkboxes for all 11 phases; untick any you want to skip.
  `browsercrawl` is off by default; enable it for rendered/runtime SPA
  discovery. On macOS it can use Node.js as a fallback when Playwright is not
  installed.
- **Tuning** — requests/second, concurrency, max pages to crawl.
- **Pre-approve all PoC verifications** — unattended verification (off = you're
  asked per finding).
- **I confirm I am AUTHORIZED to test this target** — the scan button stays
  disabled until this is ticked.
- **▶ Start Scan / ■ Stop / 📄 Open HTML Report**.

While a scan runs, the left pane streams activity and the right pane fills with
findings, colour-coded by severity, with a live count summary. If a verification
needs approval, a modal appears with the full rundown — press **Approve** or
**Skip**.

Mouse and keyboard both work. Press **q** to quit.

> A TUI needs a real interactive terminal. If `sentinel ui` looks wrong, run it
> in a normal terminal tab rather than a constrained or piped environment.

---

## 7. The command line

### Synopsis

```
sentinel scan <target> [options]
sentinel ui
sentinel doctor
sentinel --version
```

### `scan` options

| Option | Default | Description |
|---|---|---|
| `<target>` | — | Target URL or host, e.g. `https://example.com`. |
| `--i-am-authorized` | — | Confirm authorization without the interactive prompt. |
| `--only <phases>` | default phases | Comma-separated phases to run, e.g. `recon,vulns`. Include `browsercrawl` explicitly or pass `--browser` for rendered crawling. |
| `--workspace <name>` | — | Group this scan under a named workspace. |
| `--out <dir>` | `reports` | Output directory (ignored when `--workspace` is set). |
| `--rate <n>` | `10` | Maximum requests per second. |
| `--concurrency <n>` | `10` | Maximum concurrent requests. |
| `--timeout <s>` | `15` | Per-request timeout in seconds. |
| `--max-pages <n>` | `200` | Maximum pages to crawl. |
| `--max-depth <n>` | `4` | Maximum crawl depth. |
| `--browser` | — | Enable optional browser/runtime discovery. Uses Playwright/Chromium when available, otherwise Node.js fallback. |
| `--verify-findings` | — | Pre-approve every proof-of-concept verification. |
| `--header "Name: value"` | — | Add an authenticated scan header. May repeat. |
| `--cookie "name=value"` | — | Add an authenticated scan cookie. May repeat. |
| `--auth-profile NAME:PATH` | — | Load a JSON auth profile. May repeat; multiple profiles enable access-control/IDOR replay. |
| `--ssrf-callback <url>` | — | Send unique callback URLs to URL-like parameters and record tokens for external SSRF/OOB verification. |
| `--no-subdomains` | — | Restrict scope to the exact host only. |
| `--allow-private` | — | Permit targets on private / loopback IPs (lab use). |
| `--insecure` | — | Do not verify TLS certificates. |

### Examples

```bash
# Gentle scan — 5 req/s, low concurrency (good for fragile or production sites)
sentinel scan https://example.com --rate 5 --concurrency 4 --i-am-authorized

# Recon only, no active probing
sentinel scan https://example.com --only osint,recon --i-am-authorized

# Full scan with unattended verification, grouped in a workspace
sentinel scan https://example.com --workspace acme-2026 \
  --verify-findings --i-am-authorized

# A lab target on your own machine
sentinel scan http://localhost:3000 --allow-private --i-am-authorized

# Authenticated scan with a bearer token
sentinel scan https://app.example.com \
  --header "Authorization: Bearer $TOKEN" \
  --i-am-authorized

# IDOR/access-control replay with two users
sentinel scan https://app.example.com \
  --auth-profile user_a:profiles/user-a.json \
  --auth-profile user_b:profiles/user-b.json \
  --i-am-authorized

# Browser/runtime SPA/API discovery. On macOS this works with Node.js fallback.
sentinel scan https://app.example.com --browser --i-am-authorized

# Optional full Chromium rendering
pip install -e '.[browser]'
playwright install chromium
sentinel scan https://app.example.com --browser --i-am-authorized

# Opt-in SSRF/OOB collaborator probing
sentinel scan https://app.example.com \
  --ssrf-callback https://collaborator.example/collect \
  --i-am-authorized
```

Auth profile JSON files can contain:

```json
{
  "name": "user_a",
  "headers": {"Authorization": "Bearer ey..."},
  "cookies": {"session": "abc123"},
  "base_urls": ["https://app.example.com"]
}
```

The first auth profile is used for normal crawling and vulnerability checks.
The `access` phase replays ID-bearing resource requests as the other profiles
and anonymously, then reports likely broken access control when the alternate
identity receives a successful, similar response.

### Exit codes

`0` success · `2` bad phase name · `3` scope error (DNS / private IP) ·
`4` authorization not confirmed · `130` interrupted.

---

## 8. Workspaces

A workspace groups related scans — useful across an engagement or when
re-testing the same target over time.

```bash
sentinel scan https://app.example.com --workspace acme-2026 --i-am-authorized
sentinel scan https://api.example.com --workspace acme-2026 --i-am-authorized
```

Output layout:

```
sentinel-workspaces/
└── acme-2026/
    ├── index.json                          ← every scan in this workspace
    ├── app.example.com_20260519-141500/
    │   ├── report.html
    │   ├── report.json
    │   └── report.csv
    └── api.example.com_20260519-142230/
        └── ...
```

`index.json` records each run's target, timestamp, severity summary, and report
location — so you can track findings across scans.

Without `--workspace`, reports go to a single directory (`--out`, default
`reports/`).

---

## 9. Optional external tools

Sentinel is fully standalone, but uses optional tools for deeper coverage when
they are installed:

- **`nmap`** — service and version detection in the `ports` phase.
- **`nuclei`** — community template-based vulnerability checks in the `vulns`
  phase. Sentinel now feeds nuclei a capped, de-duplicated list of discovered
  live URLs/endpoints, not only the root URL.
- **Node.js** — dependency-free runtime endpoint discovery fallback for the
  optional `browsercrawl` phase. macOS developer machines commonly already have
  it through Homebrew.
- **Playwright/Chromium** — full rendered SPA crawling in the optional
  `browsercrawl` phase (`pip install -e .[browser]` and
  `playwright install chromium`).

Check what's available and install what's missing:

```bash
sentinel doctor
```

`doctor` detects `nmap` and `nuclei`, explains what each adds, and offers to
install anything missing (via `brew`, `apt`, or `go` — whichever fits your
system). Node.js and Playwright are documented above for `browsercrawl`. When a
tool is absent, Sentinel falls back where it can — built-in scanners still run,
and `browsercrawl` uses Node.js when Playwright/Chromium is unavailable.

---

## 10. Reading the report

### Where reports go

Every scan creates its own folder, grouped by site:

```
reports/
├── app.acme.com/
│   ├── 20260519-141500/
│   │   ├── report.html
│   │   ├── report.json
│   │   ├── report.csv
│   │   └── reproduce.py
│   └── 20260519-160000/        ← a later re-scan; nothing is overwritten
│       └── ...
└── shop.othercorp.com/
    └── 20260519-150000/
        └── ...
```

One folder per site keeps work for different clients/companies cleanly
separated. Each scan gets its own timestamped sub-folder, so re-scanning a site
never overwrites earlier evidence. Change the base directory with `--out`.

(With `--workspace`, output instead goes under `sentinel-workspaces/<name>/` —
see [section 8](#8-workspaces).)

### The four files

- **`report.html`** — the human report. Open it in a browser.
- **`report.json`** — full structured data for tooling and diffing.
- **`report.csv`** — findings as a spreadsheet row per finding.
- **`reproduce.py`** — a standalone script that reproduces the findings.

### reproduce.py

`reproduce.py` is a self-contained Python script (standard library only — no
install needed) with one `reproduce_*` function per reproducible finding. Run
it to re-demonstrate the vulnerabilities:

```bash
python3 reports/app.acme.com/20260519-141500/reproduce.py
```

Each function re-issues the request(s) that prove one finding and prints a
clear CONFIRMED / not-reproduced verdict. Like the rest of Sentinel it is
**non-destructive** — it proves each issue and stops. It is handy for
re-checking after a fix, for attaching to a report, or as a starting point you
can edit by hand. The script exits `1` if anything reproduced, `0` if not.

### The HTML report contains

- A **severity summary** — counts of critical / high / medium / low / info.
- **Endpoint statistics** — total endpoint count, method breakdown, API
  endpoint count, auth profiles used, and access-control finding count.
- **Findings by host** — a per-host severity breakdown.
- **Defense posture** — block rates per attack class, if the `defense` phase ran.
- **All findings** — each expandable to show target, impact, evidence,
  reproduction steps, verification result, and (if verified) a proof
  transcript.

**Severity** is the potential impact. **Confidence** is how sure Sentinel is:
`tentative` → `firm` → `confirmed` (only the `verify` phase sets `confirmed`).
Always review findings manually before reporting them — Sentinel flags;
you judge.

---

## 11. Walkthroughs

### A. First scan against a practice target

Use a target you are explicitly allowed to scan — your own machine, or a
sanctioned practice site.

```bash
sentinel scan http://localhost:8080 --allow-private --i-am-authorized
```

Open the generated `reports/<host>/<timestamp>/report.html` and read the
findings top-down: critical and high first.

### B. Reviewing and confirming a finding

Run a scan without pre-approval so you control verification:

```bash
sentinel scan https://staging.example.com --i-am-authorized
```

When the `verify` phase reaches a finding, Sentinel prints the full rundown and
asks `Approve this proof-of-concept? [y/N]`. Read the rundown — it tells you
exactly what the verification will do — then approve or skip. Confirmed findings
appear in the report with a proof transcript.

### C. Light-touch scan of a production site

Production systems deserve a gentle hand. Lower the rate, skip the noisier
phases:

```bash
sentinel scan https://www.example.com \
  --rate 3 --concurrency 3 \
  --only osint,recon,vulns \
  --i-am-authorized
```

### D. Tracking an engagement over time

Put every scan in one workspace and re-run as you go:

```bash
sentinel scan https://example.com --workspace example-q2 --i-am-authorized
# ... later, after fixes ...
sentinel scan https://example.com --workspace example-q2 --i-am-authorized
```

Compare runs via `sentinel-workspaces/example-q2/index.json`.

---

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Scope error: ... resolves to non-public address` | Target is on a private/loopback IP. Add `--allow-private` if it's a lab target you control. |
| `Aborted: authorization not confirmed` | You didn't confirm authorization. Type the host at the prompt, or pass `--i-am-authorized`. |
| All requests fail / `transport_errors` high | The target is slow, down, or blocking automated clients. Try a higher `--timeout`, or check the site is reachable. |
| `crt.sh` / Wayback show errors in `osint` | Those public services are slow or rate-limit some networks. It's a remote-side block, not a Sentinel fault — the rest of the scan is unaffected. |
| `nuclei`/`nmap` "not found" | Optional. Run `sentinel doctor` to install them, or ignore — built-in scanners cover the basics. |
| The TUI renders oddly | Run `sentinel ui` in a real, full-size terminal window. |
| Verification all "skipped" on a CLI run | Non-interactive shell with no `--verify-findings`. Run interactively, or pass the flag. |

---

## 13. How Sentinel stays safe

Sentinel is deliberately scoped. It does **not**:

- exploit vulnerabilities, dump data, or open shells (verification proves a
  bug, then stops);
- scan multiple targets in bulk or sweep IP ranges;
- brute-force credentials.

It **does**:

- require authorization for every run;
- refuse private/reserved IP targets unless you opt in;
- rate-limit and concurrency-cap every request across all phases;
- keep exploitation behind explicit, per-finding human approval.

This is what makes Sentinel safe to point at an authorized target: it gathers
evidence and hands you confirmed, well-documented findings — the deeper,
irreversible decisions stay with you.

---

## Disclaimer

Sentinel is provided for lawful, authorized security testing and education
only. The authors accept no liability for misuse. You are responsible for
ensuring you have permission to test any target.

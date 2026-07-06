# Sentinel

Sentinel is an automated, scope-aware website security assessment toolkit for
authorized testing. It runs passive OSINT, recon, port checks, crawling,
content discovery, JavaScript analysis, vulnerability checks, defense probing,
and optional human-approved proof-of-concept verification.

Only run Sentinel against systems you own or are explicitly authorized to test.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Optional tools add coverage when installed:

```bash
sentinel doctor
```

## Run

```bash
sentinel scan https://example.com --i-am-authorized
```

For lab targets on private or loopback IPs:

```bash
sentinel scan http://127.0.0.1:8000 --allow-private --i-am-authorized
```

Interactive terminal UI:

```bash
sentinel ui
```

Reports are written under `reports/<host>/<timestamp>/` by default, with HTML,
JSON, CSV, and a standalone `reproduce.py` script.

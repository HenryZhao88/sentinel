"""Optional Playwright-backed browser discovery.

This phase is intentionally dependency-light for normal installs: Playwright is
loaded only when the phase is selected. It captures network requests from a
rendered page so SPA/XHR/API surfaces can flow into the endpoint model.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from collections import deque
from urllib.parse import parse_qsl, urldefrag, urljoin, urlparse

from sentinel.context import Context
from sentinel.endpoint import Endpoint
from sentinel.findings import Finding
from sentinel.integrations import run_command

_NETWORK_TYPES = {"document", "fetch", "xhr"}
_NODE_MAX_SCRIPTS = 40
_NODE_MAX_SCRIPT_BYTES = 1_000_000
_NODE_TIMEOUT = 8.0


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» browsercrawl[/bold cyan]")
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        if await _node_runtime_discovery(ctx):
            return
        ctx.log("  [dim]Playwright is not installed and Node.js fallback is "
                "unavailable; install with `pip install -e .[browser]` and "
                "`playwright install chromium`[/dim]")
        ctx.recon["browsercrawl"] = {"enabled": False, "reason": "no_runtime"}
        return

    discovered_before = len(ctx.endpoints)
    visited: set[str] = set()
    queued: deque[str] = deque([ctx.scope.root_url])
    pages_opened = 0
    max_actions = max(1, ctx.config.browser_max_actions)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                ignore_https_errors=not ctx.config.verify_tls,
                extra_http_headers=_browser_headers(ctx),
            )
            await _add_cookies(ctx, context)
            page = await context.new_page()
            page.on("request", lambda request: _record_request(ctx, request))

            while queued and pages_opened < max_actions:
                url = queued.popleft()
                if url in visited:
                    continue
                visited.add(url)
                try:
                    await page.goto(
                        url,
                        wait_until="domcontentloaded",
                        timeout=int(ctx.config.timeout * 1000),
                    )
                    await page.wait_for_load_state("networkidle", timeout=2500)
                except Exception:
                    pass
                pages_opened += 1
                for link in await _page_links(ctx, page, url):
                    if link not in visited and len(queued) + len(visited) < max_actions:
                        queued.append(link)
            await context.close()
            await browser.close()
    except Exception as exc:  # noqa: BLE001
        if await _node_runtime_discovery(ctx):
            ctx.recon["browsercrawl"]["playwright_error"] = str(exc)[:240]
            return
        ctx.log("  [yellow]browser crawl skipped/aborted: "
                f"{str(exc)[:180]}[/yellow]")
        ctx.recon["browsercrawl"] = {
            "enabled": False,
            "reason": str(exc)[:240],
            "pages_opened": pages_opened,
        }
        return

    new_count = len(ctx.endpoints) - discovered_before
    ctx.recon["browsercrawl"] = {
        "enabled": True,
        "pages_opened": pages_opened,
        "endpoints_discovered": max(0, new_count),
    }
    ctx.add_finding(Finding(
        title=f"Browser crawl complete: {max(0, new_count)} endpoint(s) added",
        severity="info",
        target=ctx.scope.host,
        module="browsercrawl",
        description="Rendered same-scope pages in Chromium and captured "
                    "document, XHR, and fetch requests into the endpoint model.",
        evidence=f"pages_opened={pages_opened}; max_actions={max_actions}",
        remediation="Review browser-discovered XHR/fetch endpoints for "
                    "authorization, validation, and API-specific issues.",
    ))


class _HTMLAssets(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.script_srcs: list[str] = []
        self.inline_scripts: list[str] = []
        self._in_script = False
        self._script_chunks: list[str] = []

    def handle_starttag(self, tag: str, attrs: list) -> None:
        attr = dict(attrs)
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"])
        elif tag == "script":
            src = attr.get("src")
            script_type = (attr.get("type") or "").lower()
            if src:
                self.script_srcs.append(src)
            elif script_type in {"", "text/javascript", "application/javascript",
                                 "module"}:
                self._in_script = True
                self._script_chunks = []

    def handle_data(self, data: str) -> None:
        if self._in_script:
            self._script_chunks.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._in_script:
            self.inline_scripts.append("".join(self._script_chunks))
            self._in_script = False
            self._script_chunks = []


async def _node_runtime_discovery(ctx: Context) -> bool:
    node = shutil.which("node")
    if not node:
        return False

    ctx.log("  [dim]Playwright unavailable; using Node.js runtime discovery "
            "fallback[/dim]")
    discovered_before = len(ctx.endpoints)
    queue: deque[str] = deque([ctx.scope.root_url])
    visited: set[str] = set()
    scripts_seen: set[str] = set()
    pages_opened = 0
    max_actions = max(1, ctx.config.browser_max_actions)

    while queue and pages_opened < max_actions:
        page_url = queue.popleft()
        if page_url in visited:
            continue
        visited.add(page_url)
        resp = await ctx.get(page_url, follow_redirects=False)
        if resp is None or "html" not in resp.headers.get("content-type", ""):
            continue
        pages_opened += 1
        ctx.record_endpoint(Endpoint(
            method="GET",
            url=page_url,
            source="browsercrawl-node",
            auth_profile=ctx.default_auth_profile,
            status_code=resp.status_code,
        ))

        parser = _HTMLAssets()
        try:
            parser.feed(resp.text)
        except Exception:
            pass

        for raw in parser.links:
            link, _ = urldefrag(urljoin(page_url, raw))
            if ctx.scope.in_scope(link) and link not in visited:
                if len(queue) + len(visited) < max_actions:
                    queue.append(link)

        scripts = list(parser.inline_scripts)
        for raw_src in parser.script_srcs:
            src, _ = urldefrag(urljoin(page_url, raw_src))
            if src in scripts_seen or not ctx.scope.in_scope(src):
                continue
            scripts_seen.add(src)
            if len(scripts_seen) > _NODE_MAX_SCRIPTS:
                break
            script_resp = await ctx.get(src)
            if script_resp is None or script_resp.status_code != 200:
                continue
            scripts.append(script_resp.text[:_NODE_MAX_SCRIPT_BYTES])

        captured = await _run_node_harness(ctx, page_url, scripts)
        for item in captured:
            _record_node_capture(ctx, item, page_url)

    new_count = len(ctx.endpoints) - discovered_before
    ctx.recon["browsercrawl"] = {
        "enabled": True,
        "runtime": "node",
        "pages_opened": pages_opened,
        "endpoints_discovered": max(0, new_count),
    }
    ctx.add_finding(Finding(
        title=f"Node browser fallback complete: {max(0, new_count)} endpoint(s) added",
        severity="info",
        target=ctx.scope.host,
        module="browsercrawl",
        description="Playwright was unavailable, so Sentinel used a Node.js "
                    "sandbox with browser/network APIs stubbed to capture "
                    "runtime-constructed fetch, XHR, beacon, WebSocket, and "
                    "EventSource endpoints without making JavaScript network "
                    "requests.",
        evidence=f"pages_opened={pages_opened}; scripts_seen={len(scripts_seen)}",
        remediation="Install Playwright/Chromium for full rendered crawling. "
                    "Review Node-discovered endpoints as API/manual testing "
                    "targets.",
    ))
    return True


async def _run_node_harness(
    ctx: Context, page_url: str, scripts: list[str]
) -> list[dict]:
    if not scripts:
        return []
    payload = {
        "baseUrl": page_url,
        "scripts": scripts,
        "timeoutMs": int(max(100, ctx.config.timeout * 250)),
    }
    harness = _NODE_HARNESS
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        payload_path = tmp_path / "payload.json"
        harness_path = tmp_path / "harness.js"
        payload_path.write_text(json.dumps(payload))
        harness_path.write_text(harness)
        code, stdout, _stderr = await run_command(
            [shutil.which("node") or "node", str(harness_path), str(payload_path)],
            timeout=_NODE_TIMEOUT,
        )
    if code != 0 or not stdout.strip():
        return []
    try:
        decoded = json.loads(stdout.strip().splitlines()[-1])
    except json.JSONDecodeError:
        return []
    return decoded if isinstance(decoded, list) else []


def _record_node_capture(ctx: Context, item: dict, evidence_url: str) -> None:
    url = str(item.get("url") or "")
    if not url.startswith(("http://", "https://")) or not ctx.scope.in_scope(url):
        return
    method = str(item.get("method") or "GET").upper()
    headers = item.get("headers") if isinstance(item.get("headers"), dict) else {}
    content_type = str(headers.get("content-type") or headers.get("Content-Type") or "")
    body = item.get("body")
    body_params: dict[str, str] = {}
    json_body = None
    if isinstance(body, str) and body:
        if "json" in content_type:
            try:
                json_body = json.loads(body)
            except json.JSONDecodeError:
                json_body = None
        elif "application/x-www-form-urlencoded" in content_type:
            body_params = dict(parse_qsl(body, keep_blank_values=True))
    query = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
    ctx.record_url(url, set(query))
    ctx.record_endpoint(Endpoint(
        method=method,
        url=url,
        query_params=query,
        body_params=body_params,
        json_body=json_body,
        content_type=content_type,
        source="browsercrawl-node",
        auth_profile=ctx.default_auth_profile,
        evidence_url=evidence_url,
        risk_hints={"api"} if item.get("kind") in {"fetch", "xhr", "beacon"} else set(),
    ))


def _browser_headers(ctx: Context) -> dict[str, str]:
    return dict(ctx.auth_kwargs(ctx.scope.root_url).get("headers", {}))


async def _add_cookies(ctx: Context, browser_context) -> None:
    cookies = ctx.auth_kwargs(ctx.scope.root_url).get("cookies", {})
    if not cookies:
        return
    parsed = urlparse(ctx.scope.root_url)
    cookie_items = [
        {
            "name": name,
            "value": value,
            "domain": parsed.hostname or ctx.scope.host,
            "path": "/",
            "secure": parsed.scheme == "https",
        }
        for name, value in cookies.items()
    ]
    await browser_context.add_cookies(cookie_items)


def _record_request(ctx: Context, request) -> None:
    try:
        url = request.url
        if not ctx.scope.in_scope(url):
            return
        if request.resource_type not in _NETWORK_TYPES:
            return
        method = request.method.upper()
        headers = request.headers or {}
        content_type = headers.get("content-type", "")
        query = dict(parse_qsl(urlparse(url).query, keep_blank_values=True))
        body_params: dict[str, str] = {}
        json_body = None
        post_data = request.post_data
        if post_data:
            if "json" in content_type:
                try:
                    json_body = json.loads(post_data)
                except json.JSONDecodeError:
                    json_body = None
            elif "application/x-www-form-urlencoded" in content_type:
                body_params = dict(parse_qsl(post_data, keep_blank_values=True))
        ctx.record_url(url, set(query))
        ctx.record_endpoint(Endpoint(
            method=method,
            url=url,
            query_params=query,
            body_params=body_params,
            json_body=json_body,
            content_type=content_type,
            source="browsercrawl",
            auth_profile=ctx.default_auth_profile,
            evidence_url=request.frame.url if request.frame else ctx.scope.root_url,
        ))
    except Exception:
        return


async def _page_links(ctx: Context, page, base_url: str) -> list[str]:
    try:
        raw_links = await page.eval_on_selector_all(
            "a[href]",
            "els => els.map(a => a.href).filter(Boolean)",
        )
    except Exception:
        raw_links = []
    links: list[str] = []
    for raw in raw_links:
        link, _ = urldefrag(urljoin(base_url, str(raw)))
        if not link.startswith(("http://", "https://")):
            continue
        if not ctx.scope.in_scope(link):
            continue
        links.append(link)
    return links


_NODE_HARNESS = r"""
const fs = require("fs");
const vm = require("vm");

const payload = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const captured = [];

function absUrl(value) {
  try {
    const raw = value && value.url ? value.url : value;
    return new URL(String(raw || ""), payload.baseUrl).href;
  } catch (_err) {
    return String(value || "");
  }
}

function headersToObject(headers) {
  const out = {};
  if (!headers) return out;
  if (Array.isArray(headers)) {
    for (const pair of headers) {
      if (Array.isArray(pair) && pair.length >= 2) out[String(pair[0]).toLowerCase()] = String(pair[1]);
    }
    return out;
  }
  if (typeof headers.forEach === "function") {
    try {
      headers.forEach((value, key) => { out[String(key).toLowerCase()] = String(value); });
      return out;
    } catch (_err) {}
  }
  if (typeof headers === "object") {
    for (const [key, value] of Object.entries(headers)) out[String(key).toLowerCase()] = String(value);
  }
  return out;
}

function record(kind, method, url, body, headers) {
  captured.push({
    kind,
    method: String(method || "GET").toUpperCase(),
    url: absUrl(url),
    body: typeof body === "string" ? body : "",
    headers: headersToObject(headers),
  });
}

function fakeElement() {
  return {
    value: "1",
    checked: false,
    dataset: {},
    style: {},
    classList: { add() {}, remove() {}, contains() { return false; } },
    getAttribute() { return ""; },
    setAttribute() {},
    appendChild() {},
    removeChild() {},
    addEventListener(event, cb) { if (event === "click" && typeof cb === "function") cb({ preventDefault() {} }); },
    removeEventListener() {},
    querySelector() { return fakeElement(); },
    querySelectorAll() { return []; },
    innerHTML: "",
    textContent: "",
  };
}

function fakeFetch(input, init = {}) {
  const method = init.method || (input && input.method) || "GET";
  const headers = init.headers || (input && input.headers) || {};
  const body = init.body || "";
  record("fetch", method, input, body, headers);
  return Promise.resolve({
    ok: true,
    status: 200,
    headers: { get() { return null; } },
    json: async () => ({}),
    text: async () => "",
    blob: async () => ({}),
  });
}

class FakeXMLHttpRequest {
  constructor() { this.headers = {}; this.readyState = 0; this.status = 200; this.responseText = ""; }
  open(method, url) { this.method = method || "GET"; this.url = url; }
  setRequestHeader(key, value) { this.headers[String(key).toLowerCase()] = String(value); }
  send(body = "") {
    record("xhr", this.method || "GET", this.url || payload.baseUrl, body, this.headers);
    this.readyState = 4;
    if (typeof this.onreadystatechange === "function") this.onreadystatechange();
    if (typeof this.onload === "function") this.onload();
  }
  addEventListener(event, cb) { if (event === "load" && typeof cb === "function") this.onload = cb; }
  getResponseHeader() { return null; }
}

class FakeWebSocket {
  constructor(url) { record("websocket", "GET", url, "", {}); }
  send() {}
  close() {}
  addEventListener() {}
}

class FakeEventSource {
  constructor(url) { record("eventsource", "GET", url, "", {}); }
  close() {}
  addEventListener() {}
}

const document = {
  cookie: "",
  body: fakeElement(),
  head: fakeElement(),
  documentElement: fakeElement(),
  createElement() { return fakeElement(); },
  getElementById() { return fakeElement(); },
  getElementsByClassName() { return []; },
  getElementsByTagName() { return []; },
  querySelector() { return fakeElement(); },
  querySelectorAll() { return []; },
  addEventListener(event, cb) { if (event === "DOMContentLoaded" && typeof cb === "function") cb(); },
  removeEventListener() {},
  write() {},
  writeln() {},
};

const storage = {
  getItem() { return ""; },
  setItem() {},
  removeItem() {},
};

const sandbox = {
  console: { log() {}, warn() {}, error() {}, debug() {} },
  URL,
  URLSearchParams,
  Buffer,
  JSON,
  Math,
  Date,
  RegExp,
  Promise,
  document,
  location: new URL(payload.baseUrl),
  navigator: {
    userAgent: "Sentinel Node browsercrawl fallback",
    sendBeacon(url, data) { record("beacon", "POST", url, typeof data === "string" ? data : "", {}); return true; },
  },
  localStorage: storage,
  sessionStorage: storage,
  fetch: fakeFetch,
  XMLHttpRequest: FakeXMLHttpRequest,
  WebSocket: FakeWebSocket,
  EventSource: FakeEventSource,
  setTimeout(fn) { if (typeof fn === "function") { try { fn(); } catch (_err) {} } return 0; },
  clearTimeout() {},
  setInterval() { return 0; },
  clearInterval() {},
  atob(value) { return Buffer.from(String(value), "base64").toString("binary"); },
  btoa(value) { return Buffer.from(String(value), "binary").toString("base64"); },
  addEventListener(event, cb) { if (event === "load" && typeof cb === "function") cb(); },
  removeEventListener() {},
};
sandbox.window = sandbox;
sandbox.self = sandbox;
sandbox.globalThis = sandbox;

for (const code of payload.scripts || []) {
  try {
    vm.runInNewContext(String(code), sandbox, { timeout: payload.timeoutMs || 1000 });
  } catch (_err) {}
}

Promise.resolve().then(() => {
  console.log(JSON.stringify(captured));
});
"""

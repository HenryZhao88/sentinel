"""Same-scope spider that discovers pages, endpoints and parameters."""

from __future__ import annotations

import asyncio
import re
from collections import deque
from html.parser import HTMLParser
from urllib.parse import parse_qs, urldefrag, urljoin, urlparse

from sentinel.context import Context
from sentinel.findings import Finding

# File extensions not worth fetching during a crawl.
_SKIP_EXT = re.compile(
    r"\.(png|jpe?g|gif|svg|webp|ico|css|woff2?|ttf|eot|mp4|webm|"
    r"pdf|zip|gz|tar|mp3|avi)(\?|$)",
    re.IGNORECASE,
)


class _LinkExtractor(HTMLParser):
    """Collects href/src/action URLs and form parameter names."""

    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []
        self.forms: list[dict] = []
        self._current_form: dict | None = None

    def handle_starttag(self, tag: str, attrs: list) -> None:
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("script", "img", "iframe") and a.get("src"):
            self.links.append(a["src"])
        elif tag == "form":
            self._current_form = {
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "params": [],
            }
            self.forms.append(self._current_form)
        elif tag in ("input", "textarea", "select") and self._current_form:
            name = a.get("name")
            if name:
                self._current_form["params"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self._current_form = None


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» crawl[/bold cyan]")
    start = ctx.scope.root_url
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    seen: set[str] = {start}
    pages_fetched = 0

    while queue and pages_fetched < ctx.config.max_pages:
        url, depth = queue.popleft()
        resp = await ctx.http.get(url, follow_redirects=False)
        if resp is None:
            continue
        pages_fetched += 1

        # Follow same-scope redirects.
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("location")
            if location:
                target = urljoin(url, location)
                if ctx.scope.in_scope(target) and target not in seen:
                    seen.add(target)
                    queue.append((target, depth))
            continue

        params = set(parse_qs(urlparse(url).query).keys())
        ctx.record_url(url, params)

        ctype = resp.headers.get("content-type", "")
        if "html" not in ctype or depth >= ctx.config.max_depth:
            continue

        parser = _LinkExtractor()
        try:
            parser.feed(resp.text)
        except Exception:  # noqa: BLE001 — malformed HTML shouldn't abort
            pass

        for raw in parser.links:
            link, _ = urldefrag(urljoin(url, raw))
            if not link.startswith(("http://", "https://")):
                continue
            if not ctx.scope.in_scope(link) or _SKIP_EXT.search(link):
                continue
            link_params = set(parse_qs(urlparse(link).query).keys())
            ctx.record_url(link, link_params)
            if link not in seen and len(seen) < ctx.config.max_pages * 2:
                seen.add(link)
                queue.append((link, depth + 1))

        for form in parser.forms:
            action = urljoin(url, form["action"]) if form["action"] else url
            if ctx.scope.in_scope(action):
                ctx.record_url(action, set(form["params"]))

    ctx.recon["crawl"] = {
        "pages_fetched": pages_fetched,
        "urls_discovered": len(ctx.urls),
        "parameterised_urls": sum(1 for p in ctx.urls.values() if p),
    }
    ctx.add_finding(Finding(
        title=f"Crawl complete: {len(ctx.urls)} URL(s) mapped",
        severity="info",
        target=ctx.scope.host,
        module="crawl",
        description=f"Spidered {pages_fetched} page(s) within scope.",
        evidence=f"{sum(1 for p in ctx.urls.values() if p)} URL(s) carry "
                 f"query parameters and will be tested by the vulns phase.",
        remediation="",
    ))

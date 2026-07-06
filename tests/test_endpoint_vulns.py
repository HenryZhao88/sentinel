from __future__ import annotations

import asyncio
import unittest

from sentinel.context import Config, Context
from sentinel.endpoint import AuthProfile
from sentinel.http import HttpClient
from sentinel.modules import access, browsercrawl, crawler, jsanalysis, vulns
from sentinel.scope import Scope
from tests.fixtures.vuln_app import run_vuln_app


async def _context(base_url: str, profiles: list[AuthProfile] | None = None) -> Context:
    config = Config(
        target=base_url,
        rate=0,
        concurrency=8,
        timeout=5,
        max_pages=20,
        allow_private=True,
        auth_profiles=profiles or [],
        primary_auth_profile=profiles[0].name if profiles else None,
    )
    scope = Scope(base_url, allow_private=True)
    http = HttpClient(rate=0, concurrency=8, timeout=5)
    return Context(config, scope, http, log_callback=lambda _: None)


class EndpointVulnTests(unittest.TestCase):
    def test_browsercrawl_node_fallback_discovers_runtime_fetch(self) -> None:
        async def scenario(base_url: str):
            ctx = await _context(base_url)
            try:
                await browsercrawl.run(ctx)
                return ctx
            finally:
                await ctx.http.aclose()

        with run_vuln_app() as base_url:
            ctx = asyncio.run(scenario(base_url))

        self.assertEqual(ctx.recon["browsercrawl"].get("runtime"), "node")
        self.assertTrue(
            any("/runtime/dynamic?rid=1" in e.url for e in ctx.endpoints)
        )

    def test_crawl_js_and_vulns_cover_query_form_and_json(self) -> None:
        async def scenario(base_url: str):
            ctx = await _context(base_url)
            original_tool_path = vulns.tool_path
            vulns.tool_path = lambda _name: None
            try:
                await crawler.run(ctx)
                await jsanalysis.run(ctx)
                await vulns.run(ctx)
                return ctx
            finally:
                vulns.tool_path = original_tool_path
                await ctx.http.aclose()

        with run_vuln_app() as base_url:
            ctx = asyncio.run(scenario(base_url))

        self.assertTrue(
            any(e.method == "POST" and e.url.endswith("/post-xss")
                for e in ctx.endpoints)
        )
        self.assertTrue(
            any(e.method == "POST" and e.url.endswith("/api/echo") and e.json_body
                for e in ctx.endpoints)
        )
        titles = [finding.title for finding in ctx.findings]
        self.assertTrue(any("query parameter 'q'" in title for title in titles))
        self.assertTrue(any("form/body parameter 'comment'" in title for title in titles))
        self.assertTrue(any("Possible SQL injection" in title for title in titles))
        self.assertTrue(any("Open redirect" in title for title in titles))
        self.assertTrue(any("JSON field 'name'" in title for title in titles))
        self.assertTrue(any("DOM XSS" in title for title in titles))
        self.assertTrue(any("stored XSS" in title for title in titles))

    def test_access_phase_flags_cross_user_idor(self) -> None:
        profiles = [
            AuthProfile(
                name="user_a",
                headers={"Authorization": "Bearer user-a"},
            ),
            AuthProfile(
                name="user_b",
                headers={"Authorization": "Bearer user-b"},
            ),
        ]

        async def scenario(base_url: str):
            ctx = await _context(base_url, profiles)
            try:
                await crawler.run(ctx)
                await jsanalysis.run(ctx)
                await access.run(ctx)
                return ctx
            finally:
                await ctx.http.aclose()

        with run_vuln_app() as base_url:
            ctx = asyncio.run(scenario(base_url))

        self.assertTrue(
            any(e.url.endswith("/api/users/1") for e in ctx.endpoints)
        )
        self.assertTrue(
            any(f.module == "access" and "IDOR" in f.title for f in ctx.findings)
        )


if __name__ == "__main__":
    unittest.main()

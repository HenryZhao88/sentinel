"""Target scope parsing and enforcement.

The Scope object is the safety boundary for an assessment: every URL the
toolkit touches is checked against it, and targets resolving to private or
reserved address space are rejected unless explicitly allowed.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class ScopeError(Exception):
    """Raised when a target cannot be parsed or violates safety rules."""


# Multi-label public suffixes we want to treat as a single registrable unit so
# that "example.co.uk" is the base domain rather than "co.uk". This is a small
# pragmatic list, not the full Public Suffix List.
_MULTI_LABEL_SUFFIXES = {
    "co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au",
    "co.nz", "co.jp", "com.br", "co.in", "co.za",
}


class Scope:
    """Defines and enforces which hosts an assessment is allowed to touch."""

    def __init__(
        self,
        root_url: str,
        allow_private: bool = False,
        include_subdomains: bool = True,
    ) -> None:
        raw = root_url if "://" in root_url else f"https://{root_url}"
        parsed = urlparse(raw)
        if not parsed.hostname:
            raise ScopeError(f"Could not parse a hostname from {root_url!r}")

        self.scheme = parsed.scheme or "https"
        self.host = parsed.hostname.lower()
        self.port = parsed.port
        self.allow_private = allow_private
        self.include_subdomains = include_subdomains
        self.base_domain = self._registrable_domain(self.host)
        self.root_url = f"{self.scheme}://{parsed.netloc or self.host}"
        self.resolved_ips: list[str] = []

        self._resolve_and_check()

    @staticmethod
    def _registrable_domain(host: str) -> str:
        parts = host.split(".")
        if len(parts) <= 2:
            return host
        last_two = ".".join(parts[-2:])
        if last_two in _MULTI_LABEL_SUFFIXES and len(parts) >= 3:
            return ".".join(parts[-3:])
        return last_two

    def _resolve_and_check(self) -> None:
        try:
            infos = socket.getaddrinfo(self.host, None)
        except socket.gaierror as exc:
            raise ScopeError(f"DNS resolution failed for {self.host}: {exc}")

        seen: set[str] = set()
        for info in infos:
            addr = info[4][0]
            if addr in seen:
                continue
            seen.add(addr)
            self.resolved_ips.append(addr)
            ip = ipaddress.ip_address(addr)
            unsafe = (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            )
            if unsafe and not self.allow_private:
                raise ScopeError(
                    f"{self.host} resolves to non-public address {addr}. "
                    "If this is a lab target you control, re-run with "
                    "--allow-private."
                )

    def in_scope(self, url: str) -> bool:
        """Return True if a URL's host falls within the assessment scope."""
        try:
            host = (urlparse(url).hostname or "").lower()
        except ValueError:
            return False
        if not host:
            return False
        if host == self.host:
            return True
        if self.include_subdomains and host.endswith(f".{self.base_domain}"):
            return True
        return False

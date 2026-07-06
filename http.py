"""Backward-compatible HTTP client import path."""

from sentinel.http_client import DEFAULT_UA, HttpClient, RateLimiter

__all__ = ["DEFAULT_UA", "HttpClient", "RateLimiter"]

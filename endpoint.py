"""Structured request surfaces discovered during an assessment."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse


_URL_PARAM_HINTS = {
    "url", "uri", "link", "next", "return", "returnurl", "return_url",
    "redirect", "redirect_uri", "redirect_url", "dest", "destination",
    "continue", "callback", "callback_url", "webhook", "host", "domain",
    "image", "avatar", "feed", "proxy",
}
_ID_NAME_RE = re.compile(
    r"(^id$|_id$|uuid|guid|user|account|tenant|org|order|invoice|file)",
    re.IGNORECASE,
)
_ID_VALUE_RE = re.compile(
    r"(^\d{1,12}$|^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12}$)",
    re.IGNORECASE,
)
_STATE_PATH_RE = re.compile(
    r"/(create|update|delete|remove|save|submit|checkout|purchase|pay|"
    r"password|reset|invite|upload|admin)\b",
    re.IGNORECASE,
)
_API_PATH_RE = re.compile(
    r"(^|/)(api|graphql|v\d+|rest|rpc)(/|$)|\.(json|graphql)$",
    re.IGNORECASE,
)


def _clean_url(url: str) -> str:
    parsed = urlparse(url)
    return urlunparse(parsed._replace(fragment=""))


def _coerce_param_map(value: dict[str, Any] | set[str] | list[str] | None) -> dict[str, str]:
    if not value:
        return {}
    if isinstance(value, dict):
        return {str(k): "" if v is None else str(v) for k, v in value.items()}
    return {str(k): "" for k in value}


def _json_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): _json_shape(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_shape(value[0])] if value else []
    return type(value).__name__


def json_leaf_paths(value: Any, prefix: str = "") -> list[str]:
    """Return dotted paths to scalar JSON leaves suitable for probing."""
    if isinstance(value, dict):
        paths: list[str] = []
        for key, child in value.items():
            child_prefix = f"{prefix}.{key}" if prefix else str(key)
            paths.extend(json_leaf_paths(child, child_prefix))
        return paths
    if isinstance(value, list) and value:
        return json_leaf_paths(value[0], f"{prefix}.0" if prefix else "0")
    return [prefix] if prefix else []


def set_json_leaf(value: Any, dotted_path: str, replacement: str) -> Any:
    """Return a copy of JSON-like data with one scalar leaf replaced."""
    if not dotted_path:
        return replacement
    root = json.loads(json.dumps(value))
    current = root
    parts = dotted_path.split(".")
    for part in parts[:-1]:
        if isinstance(current, list):
            current = current[int(part)]
        else:
            current = current[part]
    last = parts[-1]
    if isinstance(current, list):
        current[int(last)] = replacement
    else:
        current[last] = replacement
    return root


@dataclass
class AuthProfile:
    """Headers/cookies used to make requests as one application identity."""

    name: str
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    base_urls: list[str] = field(default_factory=list)

    def applies_to(self, url: str) -> bool:
        if not self.base_urls:
            return True
        clean = _clean_url(url)
        return any(clean.startswith(base.rstrip("/") + "/") or clean == base.rstrip("/")
                   for base in self.base_urls)

    def request_kwargs(self, url: str) -> dict[str, dict[str, str]]:
        if not self.applies_to(url):
            return {}
        kwargs: dict[str, dict[str, str]] = {}
        if self.headers:
            kwargs["headers"] = dict(self.headers)
        if self.cookies:
            kwargs["cookies"] = dict(self.cookies)
        return kwargs


@dataclass
class Endpoint:
    """One discovered way to call the application."""

    method: str
    url: str
    query_params: dict[str, str] | set[str] | list[str] | None = None
    body_params: dict[str, str] | set[str] | list[str] | None = None
    json_shape: Any | None = None
    json_body: Any | None = None
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    source: str = ""
    auth_profile: str | None = None
    evidence_url: str = ""
    risk_hints: set[str] = field(default_factory=set)
    status_code: int | None = None

    def __post_init__(self) -> None:
        self.method = self.method.upper()
        self.url = _clean_url(self.url)
        self.query_params = _coerce_param_map(self.query_params)
        self.body_params = _coerce_param_map(self.body_params)
        parsed_query = {
            key: value for key, value in parse_qsl(
                urlparse(self.url).query, keep_blank_values=True
            )
        }
        parsed_query.update(self.query_params)
        self.query_params = parsed_query
        if not self.content_type:
            self.content_type = self.headers.get("content-type", "")
        if self.json_body is not None and self.json_shape is None:
            self.json_shape = _json_shape(self.json_body)
        self.risk_hints = set(self.risk_hints)
        self.risk_hints.update(infer_risk_hints(self))

    @property
    def is_json(self) -> bool:
        return "json" in self.content_type.lower() or self.json_body is not None

    @property
    def is_api(self) -> bool:
        return "api" in self.risk_hints

    def signature(self) -> str:
        json_paths = ",".join(sorted(json_leaf_paths(self.json_body)))
        return "|".join([
            self.method,
            self.url,
            self.content_type.lower(),
            ",".join(sorted(self.query_params)),
            ",".join(sorted(self.body_params)),
            json_paths,
            self.auth_profile or "",
        ])

    def merge(self, other: "Endpoint") -> None:
        self.query_params.update(other.query_params)
        self.body_params.update(other.body_params)
        self.headers.update(other.headers)
        if other.content_type and not self.content_type:
            self.content_type = other.content_type
        if other.json_body is not None and self.json_body is None:
            self.json_body = other.json_body
            self.json_shape = other.json_shape or _json_shape(other.json_body)
        if other.source and other.source not in self.source.split(","):
            self.source = ",".join(filter(None, [self.source, other.source]))
        if other.evidence_url and not self.evidence_url:
            self.evidence_url = other.evidence_url
        if other.status_code is not None:
            self.status_code = other.status_code
        self.risk_hints.update(other.risk_hints)
        self.risk_hints.update(infer_risk_hints(self))


def infer_risk_hints(endpoint: Endpoint) -> set[str]:
    hints: set[str] = set()
    parsed = urlparse(endpoint.url)
    path = parsed.path.lower()
    names = set(endpoint.query_params) | set(endpoint.body_params)
    if endpoint.json_body is not None:
        names.update(path.split(".")[-1] for path in json_leaf_paths(endpoint.json_body))

    if endpoint.method not in {"GET", "HEAD", "OPTIONS"} or _STATE_PATH_RE.search(path):
        hints.add("state_changing")
    if _API_PATH_RE.search(path) or endpoint.is_json:
        hints.add("api")
    if "graphql" in path or (
        isinstance(endpoint.json_body, dict) and "query" in endpoint.json_body
    ):
        hints.add("graphql")
    if "multipart/form-data" in endpoint.content_type.lower():
        hints.add("file_upload")
    for name in names:
        lowered = name.lower()
        if lowered in _URL_PARAM_HINTS or lowered.endswith("_url"):
            hints.add("takes_url")
        if _ID_NAME_RE.search(lowered):
            hints.add("takes_id")
    for value in list(endpoint.query_params.values()) + list(endpoint.body_params.values()):
        if _ID_VALUE_RE.search(str(value)):
            hints.add("takes_id")
    if re.search(r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f-]{27,36})(/|$)", path):
        hints.add("takes_id")
    return hints


def parse_cookie_pairs(values: list[str] | tuple[str, ...] | None) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for raw in values or []:
        for part in raw.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            if name:
                cookies[name] = value.strip()
    return cookies


def load_auth_profile(path: str, fallback_name: str | None = None) -> AuthProfile:
    data = json.loads(Path(path).read_text())
    name = fallback_name or str(data.get("name") or Path(path).stem)
    headers = {
        str(k): str(v) for k, v in dict(data.get("headers") or {}).items()
    }
    raw_cookies = data.get("cookies") or {}
    if isinstance(raw_cookies, dict):
        cookies = {str(k): str(v) for k, v in raw_cookies.items()}
    elif isinstance(raw_cookies, list):
        cookies = parse_cookie_pairs([str(v) for v in raw_cookies])
    else:
        cookies = parse_cookie_pairs([str(raw_cookies)])
    base_urls: list[str] = []
    if data.get("base_url"):
        base_urls.append(str(data["base_url"]).rstrip("/"))
    base_urls.extend(str(v).rstrip("/") for v in data.get("base_urls") or [])
    return AuthProfile(name=name, headers=headers, cookies=cookies, base_urls=base_urls)

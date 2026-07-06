"""Access-control and IDOR-oriented replay checks."""

from __future__ import annotations

import difflib
import re
from urllib.parse import parse_qsl, urlparse

import httpx

from sentinel.context import Context
from sentinel.endpoint import Endpoint, json_leaf_paths
from sentinel.findings import Finding

_ID_SEGMENT_RE = re.compile(
    r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-"
    r"[89ab][0-9a-f]{3}-[0-9a-f]{12})(/|$)",
    re.IGNORECASE,
)
_ID_NAME_RE = re.compile(
    r"(^id$|_id$|uuid|guid|user|account|tenant|org|order|invoice|file)",
    re.IGNORECASE,
)
_DANGEROUS_ACTION_RE = re.compile(
    r"/(create|update|delete|remove|save|submit|checkout|purchase|pay|"
    r"password|reset|invite|upload)\b",
    re.IGNORECASE,
)
_PROTECTED_HINT_RE = re.compile(
    r"(api|admin|user|account|tenant|org|order|invoice|profile|me|file|"
    r"document|private)",
    re.IGNORECASE,
)
_DENY_MARKERS = re.compile(
    r"(login|log in|sign in|unauthorized|forbidden|access denied|"
    r"permission denied|not allowed|csrf|session expired)",
    re.IGNORECASE,
)


async def run(ctx: Context) -> None:
    ctx.log("[bold cyan]» access[/bold cyan]")
    profile_names = list(ctx.auth_profiles)
    if not profile_names:
        ctx.log("  [dim]no auth profiles supplied; skipping IDOR replay[/dim]")
        ctx.recon["access"] = {
            "profiles": [],
            "candidates": 0,
            "findings": 0,
        }
        return

    candidates = [e for e in ctx.endpoints if _is_candidate(e)]
    if not candidates:
        ctx.log("  [dim]no ID-bearing endpoints found for access replay[/dim]")
        ctx.recon["access"] = {
            "profiles": profile_names,
            "candidates": 0,
            "findings": 0,
        }
        return

    findings_before = len(ctx.findings)
    for endpoint in candidates:
        await _check_endpoint(ctx, endpoint)

    added = len(ctx.findings) - findings_before
    ctx.recon["access"] = {
        "profiles": profile_names,
        "candidates": len(candidates),
        "findings": added,
    }
    ctx.log(f"  [dim]access replay checked {len(candidates)} endpoint(s), "
            f"{added} finding(s)[/dim]")


def _is_candidate(endpoint: Endpoint) -> bool:
    if not _is_replay_safe(endpoint):
        return False
    return bool(_id_evidence(endpoint))


def _is_replay_safe(endpoint: Endpoint) -> bool:
    if endpoint.method in {"GET", "HEAD"}:
        return True
    if endpoint.method == "POST" and (
        "api" in endpoint.risk_hints or "graphql" in endpoint.risk_hints
    ):
        return not _DANGEROUS_ACTION_RE.search(urlparse(endpoint.url).path)
    return False


def _id_evidence(endpoint: Endpoint) -> list[str]:
    evidence: list[str] = []
    path = urlparse(endpoint.url).path
    if _ID_SEGMENT_RE.search(path):
        evidence.append("ID-like path segment")
    for name, value in parse_qsl(urlparse(endpoint.url).query, keep_blank_values=True):
        if _ID_NAME_RE.search(name) or value.isdigit():
            evidence.append(f"query:{name}")
    for name, value in endpoint.query_params.items():
        if _ID_NAME_RE.search(name) or str(value).isdigit():
            evidence.append(f"query:{name}")
    for name, value in endpoint.body_params.items():
        if _ID_NAME_RE.search(name) or str(value).isdigit():
            evidence.append(f"body:{name}")
    if isinstance(endpoint.json_body, dict):
        for path_name in json_leaf_paths(endpoint.json_body):
            leaf = path_name.split(".")[-1]
            if _ID_NAME_RE.search(leaf):
                evidence.append(f"json:{path_name}")
    return sorted(set(evidence))


async def _check_endpoint(ctx: Context, endpoint: Endpoint) -> None:
    owner = endpoint.auth_profile or ctx.default_auth_profile
    if owner is None:
        owner = next(iter(ctx.auth_profiles), None)
    if owner is None:
        return

    baseline = await _send_endpoint(ctx, endpoint, auth_profile=owner)
    if not _successful_content(baseline) or _looks_denied(baseline):
        return

    anonymous = await _send_endpoint(
        ctx, endpoint, auth_profile=None, use_default_auth=False
    )
    anonymous_public = (
        _successful_content(anonymous)
        and not _looks_denied(anonymous)
        and _similarity(baseline, anonymous) >= 0.62
    )
    if anonymous_public and not _protected_hint(endpoint):
        return
    if anonymous_public:
        _report(ctx, endpoint, owner, "anonymous", baseline, anonymous, _similarity(baseline, anonymous))

    comparisons = [name for name in ctx.auth_profiles if name != owner]
    for name in comparisons:
        other = await _send_endpoint(ctx, endpoint, auth_profile=name)
        if not _successful_content(other) or _looks_denied(other):
            continue
        score = _similarity(baseline, other)
        if score < 0.62:
            continue
        _report(ctx, endpoint, owner, name, baseline, other, score)


def _protected_hint(endpoint: Endpoint) -> bool:
    parsed = urlparse(endpoint.url)
    if _PROTECTED_HINT_RE.search(parsed.path):
        return True
    names = set(endpoint.query_params) | set(endpoint.body_params)
    if isinstance(endpoint.json_body, dict):
        names.update(path.split(".")[-1] for path in json_leaf_paths(endpoint.json_body))
    return any(_PROTECTED_HINT_RE.search(name) for name in names)


async def _send_endpoint(
    ctx: Context,
    endpoint: Endpoint,
    auth_profile: str | None,
    use_default_auth: bool = True,
) -> httpx.Response | None:
    headers = dict(endpoint.headers)
    if endpoint.content_type and "content-type" not in {
        key.lower() for key in headers
    }:
        headers["Content-Type"] = endpoint.content_type
    kwargs: dict = {"headers": headers, "follow_redirects": False}
    if endpoint.method not in {"GET", "HEAD", "OPTIONS"}:
        if endpoint.json_body is not None:
            kwargs["json"] = endpoint.json_body
            kwargs["headers"].setdefault("Content-Type", "application/json")
        elif endpoint.body_params:
            kwargs["data"] = dict(endpoint.body_params)
    return await ctx.request(
        endpoint.method,
        endpoint.url,
        auth_profile=auth_profile,
        use_default_auth=use_default_auth,
        **kwargs,
    )


def _successful_content(resp: httpx.Response | None) -> bool:
    return resp is not None and 200 <= resp.status_code < 300 and len(resp.content) > 0


def _looks_denied(resp: httpx.Response | None) -> bool:
    if resp is None:
        return True
    if resp.status_code in {401, 403, 419}:
        return True
    return bool(_DENY_MARKERS.search(resp.text[:5000]))


def _normalised_body(resp: httpx.Response) -> str:
    return re.sub(r"\s+", " ", resp.text).strip().lower()[:20000]


def _similarity(a: httpx.Response, b: httpx.Response) -> float:
    left = _normalised_body(a)
    right = _normalised_body(b)
    if not left or not right:
        return 0.0
    length_ratio = min(len(left), len(right)) / max(len(left), len(right))
    body_ratio = difflib.SequenceMatcher(None, left, right).quick_ratio()
    return min(length_ratio, body_ratio)


def _title(resp: httpx.Response) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip()[:80]


def _report(
    ctx: Context,
    endpoint: Endpoint,
    owner: str,
    other: str,
    baseline: httpx.Response,
    replay: httpx.Response,
    score: float,
) -> None:
    anonymous = other == "anonymous"
    ctx.add_finding(Finding(
        title="Possible broken access control / IDOR",
        severity="high" if anonymous else "medium",
        target=endpoint.url,
        module="access",
        description="A resource request discovered under one identity was "
                    "replayed as another identity and still returned a "
                    "successful, similar response rather than a deny or login "
                    "page.",
        evidence=(
            f"{endpoint.method}; owner={owner}; replay_as={other}; "
            f"status={baseline.status_code}->{replay.status_code}; "
            f"bytes={len(baseline.content)}->{len(replay.content)}; "
            f"similarity={score:.2f}; id_evidence={', '.join(_id_evidence(endpoint))}; "
            f"title={_title(replay) or 'n/a'}"
        ),
        remediation="Enforce object-level authorization server-side for every "
                    "resource lookup. Do not rely on hidden fields, client-side "
                    "routes, or obscurity of object identifiers.",
        references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
        confidence="firm",
        impact="Another user may be able to read or act on resources they do "
               "not own by replaying or changing object identifiers.",
    ))

"""Secure native website-login tool.

The model may request a site by origin, but it never receives a credential
field, browser profile, cookie, storage state, or page bridge.  The host must
install ``website_login_callback``; without that native credential boundary the
tool fails closed.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urlsplit, urlunsplit

from tools.registry import registry, tool_error


_TERMINAL_RESULTS = frozenset({"completed", "cancelled", "failed"})
_OPAQUE_REQUEST_ID = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_SENSITIVE_SITE_NAME = re.compile(
    r"\b(?:password|passwd|passcode|otp|one[- ]time|token|secret|cookie|"
    r"credential|bearer|api[- ]?key|access[- ]?key|form[- ]?(?:field|value)|"
    r"username|user[- ]?name)\b",
    re.IGNORECASE,
)


WEBSITE_LOGIN_SCHEMA = {
    "name": "website_login",
    "description": (
        "Ask the user's native Work Mode client to open one HTTPS site "
        "so the user can log in directly in the site UI. Any exact HTTPS "
        "origin is eligible, including standard OIDC/SSO redirect flows; "
        "the user-controlled sign-in is the security gate. The model only "
        "requests the handoff; it never fills or observes credential form "
        "fields. The model must never enter or request passwords, OTPs, "
        "payment data, cookies, tokens, form values, browser profiles, or "
        "storage state."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "origin": {
                "type": "string",
                "description": "Exact HTTPS origin, such as https://example.com (no path, query, fragment, or userinfo).",
            },
            "site_name": {
                "type": "string",
                "description": "Optional short human-readable site label; never put credentials or form contents here.",
                "maxLength": 120,
            },
        },
        "required": ["origin"],
        "additionalProperties": False,
    },
}


def _normalize_origin(origin: object) -> str | None:
    if not isinstance(origin, str):
        return None
    value = origin.strip()
    if len(value) > 2048:
        return None
    try:
        parsed = urlsplit(value)
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return None
        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname or any(ch.isspace() for ch in hostname):
            return None
        if ":" in hostname:
            hostname = f"[{hostname}]"
        else:
            try:
                hostname = hostname.encode("idna").decode("ascii")
            except UnicodeError:
                return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65_535:
            return None
        if port == 443:
            netloc = hostname
        elif port is None:
            netloc = hostname
        else:
            netloc = f"{hostname}:{port}"
        return urlunsplit(("https", netloc, "", "", ""))
    except (TypeError, ValueError):
        return None


def _normalize_site_name(site_name: object) -> str | None:
    if site_name is None:
        return None
    if not isinstance(site_name, str):
        raise ValueError("website login site label is invalid")
    value = site_name.strip()
    if not value:
        return None
    if len(value) > 120:
        raise ValueError("website login site label is invalid")
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("website login site label is invalid")
    if any(char in value for char in "=<>[]{}\"'`;"):
        raise ValueError("website login site label is invalid")
    if _SENSITIVE_SITE_NAME.search(value):
        raise ValueError("website login site label is invalid")
    return value


def website_login(origin: str, site_name: str | None = None, *, callback=None) -> str:
    """Request an explicit user-directed native login and return safe metadata."""
    normalized_origin = _normalize_origin(origin)
    if normalized_origin is None:
        return tool_error("website login requires an exact HTTPS origin")
    try:
        site_name = _normalize_site_name(site_name)
    except ValueError as exc:
        return tool_error(str(exc))
    if not callable(callback):
        return tool_error("website login is unavailable without a native credential boundary")

    try:
        raw_result = callback(normalized_origin, site_name)
        payload = json.loads(raw_result) if isinstance(raw_result, str) else raw_result
    except Exception:
        return tool_error("website login boundary failed")
    if not isinstance(payload, dict):
        return tool_error("website login boundary returned an invalid result")
    request_id = payload.get("requestID")
    result = payload.get("result")
    if (
        not isinstance(request_id, str)
        or not _OPAQUE_REQUEST_ID.fullmatch(request_id)
        or result not in _TERMINAL_RESULTS
    ):
        return tool_error("website login boundary returned an invalid result")
    return json.dumps({"requestID": request_id, "result": result}, ensure_ascii=False)


def _website_login_handler(args: dict, **kwargs) -> str:
    """Registry adapter that rejects fields before any callback is reached."""
    if not isinstance(args, dict):
        return tool_error("website login accepts metadata only")
    if set(args) - {"origin", "site_name"}:
        return tool_error("website login accepts metadata only")
    return website_login(
        origin=args.get("origin", ""),
        site_name=args.get("site_name"),
        callback=kwargs.get("callback"),
    )


registry.register(
    name="website_login",
    toolset="work_mode",
    schema=WEBSITE_LOGIN_SCHEMA,
    handler=_website_login_handler,
    emoji="🔐",
)

"""Detect browser auth walls from bounded accessibility metadata.

The detector deliberately works on roles, labels, URL origin/path, and browser
refs only. It never reads input values or returns a raw DOM/snapshot as part of
an auth context.
"""

from __future__ import annotations

import re
import secrets
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from tools.native_auth_runtime import NativeAuthRuntime, NativeAuthSecurityError


_REF_RE = re.compile(r"(?:\[ref\s*[=:]\s*)?(@?e[0-9]{1,8})\]?", re.IGNORECASE)
_QUOTED_RE = re.compile(r"[\"']([^\"']{1,240})[\"']")
_ROLE_RE = re.compile(
    r"\b(textbox|searchbox|spinbutton|combobox|input|button|link|checkbox|radio|generic)\b",
    re.IGNORECASE,
)
_INPUT_ROLES = frozenset({"textbox", "searchbox", "spinbutton", "combobox", "input"})
_ACTION_ROLES = frozenset({"button", "link"})


def _browser_target(ref: str, *, browser_backend: str) -> dict[str, str]:
    """Attach a fresh opaque browser target ID to snapshot refs.

    Browser Use contexts require a target identity in addition to the visible
    harness ref. The ID is deliberately unrelated to page values or DOM
    content; descriptor-based probes may replace the ref with a page-issued
    CSS target later in the same browser context.
    """
    target: dict[str, str] = {"strategy": "ref", "value": ref}
    if str(browser_backend or "").strip().lower() == "browser-use":
        target["target_id"] = "ref_" + secrets.token_urlsafe(18)
    return target
_LOGIN_WORDS = (
    "sign in",
    "signin",
    "log in",
    "login",
    "authenticate",
    "authentication",
    "verify your",
    "verification",
    "two-factor",
    "2fa",
    "one-time",
    "one time",
    "password",
    "passkey",
    "security key",
    "captcha",
    "continue with",
)


def _origin_and_path(url: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(str(url or "").strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = parsed.hostname.rstrip(".").lower()
        host = host.encode("idna").decode("ascii")
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        netloc = host if port in (None, 443) else f"{host}:{port}"
        origin = urlunsplit(("https", netloc, "", "", ""))
        path = parsed.path or "/"
        if not path.startswith("/") or "\\" in path or ".." in path.split("/"):
            return None
        return origin, path[:512]
    except (TypeError, ValueError, UnicodeError):
        return None


def _line_metadata(line: str) -> tuple[str, str, str] | None:
    role_match = _ROLE_RE.search(line or "")
    ref_match = _REF_RE.search(line or "")
    if not role_match or not ref_match:
        return None
    role = role_match.group(1).lower()
    ref = ref_match.group(1).lower()
    if not ref.startswith("@"):
        ref = "@" + ref
    quoted = _QUOTED_RE.findall(line or "")
    label = next((item.strip() for item in quoted if item.strip()), "")
    if not label:
        # Accessibility snapshots sometimes expose an unquoted name after the
        # role; retain only a tiny bounded token, never the full line.
        tail = (line or "").split("[ref", 1)[0]
        label = re.sub(r"^[\s\-•*]+", "", tail)
        label = re.sub(r"\b(?:textbox|searchbox|spinbutton|combobox|input|button|link|checkbox|radio|generic)\b", "", label, flags=re.I)
        label = " ".join(label.split())[:120]
    return role, label, ref


def _kind_for_field(label: str, line: str) -> str:
    text = f"{label} {line}".lower()
    if "password" in text:
        return "password"
    if re.search(r"\b(?:passcode|pass code|access code)\b", text):
        return "passcode" if "access" not in text else "access_code"
    if re.search(r"\bpin\b", text):
        return "pin"
    if "secret" in text:
        return "secret"
    if "authenticator" in text or "totp" in text or "time-based" in text:
        return "totp_code"
    if "sms" in text or "text message" in text:
        return "sms_code"
    if "email" in text and re.search(r"\b(?:code|verification)\b", text):
        return "email_code"
    if "recovery" in text:
        return "recovery_code"
    if "backup" in text and "code" in text:
        return "backup_code"
    if "security question" in text or "security answer" in text:
        return "security_answer"
    if "date of birth" in text or "birth date" in text or "birthday" in text:
        return "date_of_birth"
    if "phone" in text or "mobile number" in text or "telephone" in text:
        return "phone"
    if "organization" in text or "company" in text:
        return "organization"
    if "tenant" in text or "workspace" in text:
        return "tenant"
    if "invite" in text or "access code" in text:
        return "access_code"
    if "one-time" in text or "one time" in text or "otp" in text:
        return "one_time_code"
    if "verification code" in text or "verification" in text:
        return "verification_code"
    if "username" in text or "user name" in text:
        return "username"
    if "email" in text:
        return "email"
    if "numeric" in text or "number" in text:
        return "numeric"
    return "identifier" if any(word in text for word in ("login", "account", "identifier")) else "text"


def _action_kind(label: str) -> str | None:
    text = (label or "").lower()
    if "passkey" in text:
        return "passkey"
    if "security key" in text or "hardware key" in text:
        return "security_key"
    if "captcha" in text or "verification challenge" in text:
        return "captcha"
    if "push" in text and ("approve" in text or "approval" in text):
        return "push_approval"
    if "device" in text and "approv" in text:
        return "device_approval"
    if "continue with" in text or any(provider in text for provider in ("google", "microsoft", "okta", "sso")):
        return "sso_continue"
    if "magic link" in text:
        return "email_magic_link"
    if "phone verification" in text:
        return "phone_verification"
    if text in {"cancel", "close"} or text.startswith("cancel"):
        return "cancel"
    if any(word in text for word in ("sign in", "signin", "log in", "login", "continue", "next", "verify", "submit", "authenticate")):
        return "submit"
    return None


def detect_auth_context(
    *,
    runtime: NativeAuthRuntime,
    task_id: str,
    browser_session_key: str,
    browser_session_id: str,
    provider_origin: str,
    path: str,
    title: str,
    snapshot: str,
    refs: dict[str, Any] | None,
    browser_backend: str = "",
    browser_session_name: str | None = None,
) -> dict[str, Any] | None:
    """Return a sanitized auth context, or ``None`` for an ordinary page."""
    origin_path = _origin_and_path(provider_origin)
    if origin_path is None:
        # Callers may pass a full URL in provider_origin for convenience.
        origin_path = _origin_and_path(str(provider_origin))
    if origin_path is None:
        return None
    origin, url_path = origin_path
    if path:
        raw_path = str(path).strip()
        parsed_path = urlsplit(raw_path)
        url_path = parsed_path.path or "/"
        if not url_path.startswith("/") or "\\" in url_path or ".." in url_path.split("/"):
            return None
        url_path = url_path[:512]
    bounded_title = " ".join(str(title or "").split())[:160]
    bounded_snapshot = str(snapshot or "")[:256 * 1024]
    lower_page = f"{origin} {url_path} {bounded_title} {bounded_snapshot}".lower()

    fields: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    seen_refs: set[str] = set()
    for line in bounded_snapshot.splitlines():
        metadata = _line_metadata(line)
        if metadata is None:
            continue
        role, label, ref = metadata
        if ref in seen_refs:
            continue
        seen_refs.add(ref)
        if role in _INPUT_ROLES:
            kind = _kind_for_field(label, line)
            fields.append(
                {
                    "field_id": f"field_{len(fields) + 1}",
                    "kind": kind,
                    "label": label or kind.replace("_", " ").title(),
                    "required": True,
                    "target": _browser_target(ref, browser_backend=browser_backend),
                }
            )
        elif role in _ACTION_ROLES or _action_kind(label) in {
            "sso_continue", "passkey", "security_key", "captcha", "push_approval", "device_approval", "email_magic_link", "phone_verification"
        }:
            kind = _action_kind(label)
            if kind is not None:
                actions.append(
                    {
                        "action_id": f"action_{len(actions) + 1}",
                        "kind": kind,
                        "label": label or kind.replace("_", " ").title(),
                        "target": _browser_target(ref, browser_backend=browser_backend),
                    }
                )

    login_signal = any(word in lower_page for word in _LOGIN_WORDS)
    browser_owned_signal = any(
        phrase in lower_page
        for phrase in ("passkey", "security key", "captcha", "push approval", "device approval", "magic link")
    )
    if not fields and not actions:
        return None
    if not login_signal and not browser_owned_signal and not any(field["kind"] in {"password", "passcode", "totp_code", "one_time_code", "verification_code", "recovery_code"} for field in fields):
        return None
    try:
        return runtime.create_context(
            task_id=task_id,
            browser_session_key=browser_session_key,
            browser_session_id=browser_session_id,
            provider_origin=origin,
            path=url_path,
            flow=("browser_owned" if browser_owned_signal and not fields else "password"),
            fields=fields,
            actions=actions,
            browser_backend=browser_backend,
            browser_session_name=browser_session_name,
        )
    except NativeAuthSecurityError:
        return None


def detect_auth_context_from_descriptors(
    *,
    runtime: NativeAuthRuntime,
    task_id: str,
    browser_session_key: str,
    browser_session_id: str,
    provider_origin: str,
    path: str,
    title: str,
    fields: list[dict[str, Any]],
    actions: list[dict[str, Any]],
    signals: str = "",
    browser_backend: str = "",
    browser_session_name: str | None = None,
    document_generation: str | None = None,
    tab_handle: str | None = None,
    frame_handle: str | None = None,
) -> dict[str, Any] | None:
    """Mint a context from browser-generated descriptor metadata.

    This is used by the Browser Use harness, which can generate stable CSS
    targets in the page process but does not expose an accessibility snapshot
    to the parent tool. The descriptors are still validated by
    ``NativeAuthRuntime.create_context`` before they become capabilities.
    """
    origin_path = _origin_and_path(provider_origin)
    if origin_path is None:
        return None
    origin, fallback_path = origin_path
    raw_path = str(path or fallback_path).strip()
    parsed_path = urlsplit(raw_path)
    url_path = parsed_path.path or "/"
    lower = f"{origin} {url_path} {title or ''} {signals or ''}".lower()
    login_signal = any(word in lower for word in _LOGIN_WORDS)
    browser_owned_signal = any(
        phrase in lower
        for phrase in ("passkey", "security key", "captcha", "push approval", "device approval", "magic link")
    )
    if not isinstance(fields, list) or not isinstance(actions, list) or not fields and not actions:
        return None
    if not login_signal and not browser_owned_signal:
        return None
    try:
        return runtime.create_context(
            task_id=task_id,
            browser_session_key=browser_session_key,
            browser_session_id=browser_session_id,
            provider_origin=origin,
            path=url_path,
            flow=("browser_owned" if browser_owned_signal and not fields else "password"),
            fields=fields,
            actions=actions,
            browser_backend=browser_backend,
            browser_session_name=browser_session_name,
            document_generation=document_generation,
            tab_handle=tab_handle,
            frame_handle=frame_handle,
        )
    except NativeAuthSecurityError:
        return None


__all__ = ["detect_auth_context", "detect_auth_context_from_descriptors"]

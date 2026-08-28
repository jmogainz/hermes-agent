"""In-process native-auth runtime for Semreh browser sessions.

This module deliberately is *not* a model-facing tool.  It owns the short-lived
native-auth contexts created by the browser runtime, accepts ciphertext from the
WebUI control plane, and performs the final target validation/decryption/fill
inside the existing Hermes process.

The model can see component metadata and opaque capability handles.  It never
receives a plaintext field value, a decryption primitive, or an envelope body.
"""

from __future__ import annotations

import base64
import json
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import urlsplit, urlunsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


AUTH_CONTEXT_SCHEMA = "hermes.auth-context.v1"
NATIVE_COMPONENT_SCHEMA = "semreh.native-component.v1"
NATIVE_COMPONENT_STATE_SCHEMA = "semreh.native-component-state.v1"
NATIVE_SECRET_ENVELOPE_SCHEMA = "semreh.native-secret-envelope.v1"

_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_FIELD_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_REF_RE = re.compile(r"^@e[0-9]{1,8}$")
_TARGET_STRATEGIES = frozenset({"css", "xpath", "role", "label", "ref", "cdp"})

# The taxonomy is intentionally broad, but it is still a closed allowlist.  A
# page/model cannot turn this protocol into arbitrary HTML or JavaScript.
FIELD_KINDS = frozenset(
    {
        "email",
        "username",
        "identifier",
        "phone",
        "organization",
        "tenant",
        "access_code",
        "password",
        "passcode",
        "pin",
        "secret",
        "totp_code",
        "sms_code",
        "email_code",
        "one_time_code",
        "verification_code",
        "recovery_code",
        "backup_code",
        "security_answer",
        "date_of_birth",
        "numeric",
        "text",
        "select",
        "radio",
        "checkbox",
        "consent",
        "submit",
        "sso_continue",
        "email_magic_link",
        "phone_verification",
        "passkey",
        "security_key",
        "captcha",
        "push_approval",
        "device_approval",
        "cancel",
    }
)

ACTION_KINDS = frozenset(
    {
        "submit",
        "select",
        "radio",
        "checkbox",
        "consent",
        "sso_continue",
        "email_magic_link",
        "phone_verification",
        "passkey",
        "security_key",
        "captcha",
        "push_approval",
        "device_approval",
        "cancel",
    }
)

BROWSER_OWNED_KINDS = frozenset(
    {
        "sso_continue",
        "email_magic_link",
        "phone_verification",
        "passkey",
        "security_key",
        "captcha",
        "push_approval",
        "device_approval",
    }
)

VALUE_FIELD_KINDS = FIELD_KINDS - BROWSER_OWNED_KINDS - {"submit", "cancel"}

_ENVELOPE_KEYS = frozenset(
    {
        "schema",
        "component_id",
        "sequence",
        "key_id",
        "client_public_key",
        "nonce",
        "ciphertext",
        "tag",
    }
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _decode_b64(value: Any, *, name: str, max_bytes: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > max_bytes * 2:
        raise NativeAuthSecurityError(f"invalid {name}")
    try:
        raw = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(raw + b"=" * ((4 - len(raw) % 4) % 4))
    except (ValueError, TypeError, UnicodeError):
        raise NativeAuthSecurityError(f"invalid {name}") from None
    if not decoded or len(decoded) > max_bytes:
        raise NativeAuthSecurityError(f"invalid {name}")
    return decoded


def _opaque(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not _OPAQUE_RE.fullmatch(value):
        raise NativeAuthSecurityError(f"invalid {name}")
    return value


def _new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(18)}"


def _canonical_origin(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 2048:
        raise NativeAuthSecurityError("invalid provider origin")
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() != "https" or not parsed.hostname:
            raise NativeAuthSecurityError("provider origin must be HTTPS")
        if parsed.username is not None or parsed.password is not None:
            raise NativeAuthSecurityError("provider origin contains userinfo")
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            raise NativeAuthSecurityError("provider origin must not contain a path or query")
        hostname = parsed.hostname.rstrip(".").lower()
        if not hostname or any(char.isspace() for char in hostname):
            raise NativeAuthSecurityError("invalid provider origin")
        if ":" in hostname:
            hostname = f"[{hostname}]"
        else:
            hostname = hostname.encode("idna").decode("ascii")
        port = parsed.port
    except (TypeError, ValueError, UnicodeError):
        raise NativeAuthSecurityError("invalid provider origin") from None
    if port is not None and not 1 <= port <= 65535:
        raise NativeAuthSecurityError("invalid provider origin port")
    netloc = hostname if port in (None, 443) else f"{hostname}:{port}"
    return urlunsplit(("https", netloc, "", "", ""))


def _safe_path(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 512:
        raise NativeAuthSecurityError("invalid auth path")
    path = value.strip() or "/"
    if not path.startswith("/") or "?" in path or "#" in path or "\\" in path:
        raise NativeAuthSecurityError("auth path must be a query-free path")
    if ".." in path.split("/"):
        raise NativeAuthSecurityError("auth path traversal")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in path):
        raise NativeAuthSecurityError("auth path contains control characters")
    return path


def _safe_label(value: Any, *, fallback: str = "") -> str:
    if value is None:
        value = fallback
    if not isinstance(value, str) or len(value) > 120:
        raise NativeAuthSecurityError("auth label is invalid")
    value = value.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise NativeAuthSecurityError("auth label contains control characters")
    return value


def _safe_instruction(value: Any, *, max_length: int = 320) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > max_length:
        raise NativeAuthSecurityError("native component text is invalid")
    value = value.strip()
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise NativeAuthSecurityError("native component text contains control characters")
    return value


def _validate_target(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise NativeAuthSecurityError("browser target is required")
    allowed = {"strategy", "value", "frame_path", "target_id"}
    if set(value) - allowed:
        raise NativeAuthSecurityError("browser target contains unsupported metadata")
    strategy = value.get("strategy")
    target_value = value.get("value")
    if strategy not in _TARGET_STRATEGIES or not isinstance(target_value, str):
        raise NativeAuthSecurityError("browser target is invalid")
    target_value = target_value.strip()
    if not target_value or len(target_value) > 2048:
        raise NativeAuthSecurityError("browser target is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in target_value):
        raise NativeAuthSecurityError("browser target contains control characters")
    lowered = target_value.lower()
    if "javascript:" in lowered or "<script" in lowered or "innerhtml" in lowered:
        raise NativeAuthSecurityError("browser target contains executable content")
    if strategy == "ref" and not _REF_RE.fullmatch(target_value):
        raise NativeAuthSecurityError("browser ref target is invalid")
    frame_path = value.get("frame_path", [])
    if frame_path is None:
        frame_path = []
    if not isinstance(frame_path, list) or len(frame_path) > 8:
        raise NativeAuthSecurityError("browser frame path is invalid")
    normalized_frames: list[str] = []
    for frame in frame_path:
        if not isinstance(frame, str) or not frame or len(frame) > 160:
            raise NativeAuthSecurityError("browser frame path is invalid")
        normalized_frames.append(frame)
    target_id = value.get("target_id")
    if target_id is not None:
        _opaque(target_id, name="browser target id")
    result: dict[str, Any] = {"strategy": strategy, "value": target_value}
    if normalized_frames:
        result["frame_path"] = normalized_frames
    if target_id is not None:
        result["target_id"] = target_id
    return result


def derive_envelope_key(
    *,
    private_key: X25519PrivateKey,
    peer_public_key: bytes | X25519PublicKey,
    key_id: str,
) -> bytes:
    """Derive the AES-GCM key shared by Semreh and this runtime."""
    if isinstance(peer_public_key, bytes):
        peer = X25519PublicKey.from_public_bytes(peer_public_key)
    else:
        peer = peer_public_key
    shared = private_key.exchange(peer)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"semreh.native-auth.v1:" + str(key_id).encode("ascii"),
    ).derive(shared)


class NativeAuthSecurityError(ValueError):
    """Safe, non-secret error for a rejected native-auth operation."""


@dataclass
class _AuthContext:
    public: dict[str, Any]
    task_id: str
    browser_session_key: str
    browser_backend: str
    browser_session_name: str | None
    private_key: X25519PrivateKey
    key_id: str
    event: threading.Event = field(default_factory=threading.Event)
    result: dict[str, Any] | None = None
    consumed: bool = False
    status_callback: Optional[Callable[[dict[str, Any]], None]] = None


class NativeAuthRuntime:
    """Thread-safe in-process registry and secure-fill coordinator."""

    def __init__(
        self,
        *,
        timeout_seconds: float = 900.0,
        fill_executor: Optional[Callable[..., dict[str, Any]]] = None,
        action_executor: Optional[Callable[..., dict[str, Any]]] = None,
        target_validator: Optional[Callable[..., None]] = None,
    ) -> None:
        self.timeout_seconds = max(5.0, min(float(timeout_seconds), 3600.0))
        self._lock = threading.RLock()
        self._contexts: dict[str, _AuthContext] = {}
        # Terminal ownership is metadata-only and lets stale envelopes return
        # the precise safe error (expired/cancelled/replay/other session) after
        # the live context has been removed.
        self._closed: dict[str, str] = {}
        self._closed_owners: dict[str, str] = {}
        self._wire_consumed_envelopes: set[str] = set()
        self._wire_submit_lock = threading.Lock()
        self._private_key = X25519PrivateKey.generate()
        self._key_id = _new_id("rt")
        self._fill_executor = fill_executor or self._default_fill_executor
        self._action_executor = action_executor or self._default_action_executor
        self._target_validator = target_validator or self._default_target_validator

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def public_key(self) -> str:
        raw = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        return _b64(raw)

    def set_fill_executor(self, executor: Callable[..., dict[str, Any]]) -> None:
        self._fill_executor = executor

    def set_action_executor(self, executor: Callable[..., dict[str, Any]]) -> None:
        self._action_executor = executor

    def set_target_validator(self, validator: Callable[..., None]) -> None:
        self._target_validator = validator

    def create_context(
        self,
        *,
        task_id: str,
        browser_session_id: str,
        provider_origin: str,
        path: str,
        flow: str,
        fields: list[dict[str, Any]],
        actions: list[dict[str, Any]],
        browser_session_key: str | None = None,
        browser_backend: str = "",
        browser_session_name: str | None = None,
        document_generation: str | None = None,
        tab_handle: str | None = None,
        frame_handle: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(task_id, str) or not task_id.strip():
            raise NativeAuthSecurityError("auth task is required")
        origin = _canonical_origin(provider_origin)
        normalized_path = _safe_path(path)
        if not isinstance(flow, str) or len(flow.strip()) > 64:
            raise NativeAuthSecurityError("invalid auth flow")
        flow = flow.strip() or "unknown"
        if not isinstance(fields, list) or len(fields) > 32:
            raise NativeAuthSecurityError("invalid auth fields")
        if not isinstance(actions, list) or len(actions) > 16:
            raise NativeAuthSecurityError("invalid auth actions")

        backend = str(browser_backend or "").strip().lower()
        require_browser_target_id = backend == "browser-use"
        normalized_fields: list[dict[str, Any]] = []
        seen_ids: set[str] = set()
        for raw in fields:
            normalized = self._normalize_field(
                raw,
                seen_ids,
                require_target=True,
                require_browser_target_id=require_browser_target_id,
            )
            normalized_fields.append(normalized)
        normalized_actions: list[dict[str, Any]] = []
        seen_action_ids: set[str] = set()
        for raw in actions:
            normalized_actions.append(
                self._normalize_action(
                    raw,
                    seen_action_ids,
                    require_browser_target_id=require_browser_target_id,
                )
            )
        if not any(action["kind"] == "cancel" for action in normalized_actions):
            normalized_actions.append({"id": "cancel", "kind": "cancel", "label": "Cancel"})

        context_id = _new_id("ctx")
        component_id = _new_id("cmp")
        public_browser_id = (
            browser_session_id
            if isinstance(browser_session_id, str) and _OPAQUE_RE.fullmatch(browser_session_id)
            else _new_id("bs")
        )
        if document_generation is not None:
            _opaque(document_generation, name="document generation")
        if tab_handle is not None:
            _opaque(tab_handle, name="tab handle")
        if frame_handle is not None:
            _opaque(frame_handle, name="frame handle")
        document_handle = document_generation or _new_id("doc")
        tab_handle = tab_handle or _new_id("tab")
        frame_handle = frame_handle or _new_id("frame")
        with self._lock:
            context_private_key = self._private_key
            context_key_id = self._key_id
            self._private_key = X25519PrivateKey.generate()
            self._key_id = _new_id("rt")
        context_public_key = _b64(
            context_private_key.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        )
        public = {
            "schema": AUTH_CONTEXT_SCHEMA,
            "context_id": context_id,
            "component_id": component_id,
            "browser_session_id": public_browser_id,
            "provider_origin": origin,
            "path": normalized_path,
            "flow": flow,
            "fields": normalized_fields,
            "actions": normalized_actions,
            "runtime_public_key": context_public_key,
            "key_id": context_key_id,
            "expires_at": time.time() + self.timeout_seconds,
            "tab_handle": tab_handle,
            "frame_handle": frame_handle,
            "document_generation": document_handle,
        }
        context = _AuthContext(
            public=public,
            task_id=task_id,
            browser_session_key=browser_session_key or browser_session_id,
            browser_backend=str(browser_backend or "").strip().lower(),
            browser_session_name=(str(browser_session_name).strip() if browser_session_name else None),
            private_key=context_private_key,
            key_id=context_key_id,
        )
        with self._lock:
            self._contexts[context_id] = context
            self._contexts[component_id] = context
        return self._public_copy(public)

    def model_action_guard(self, task_id: str, target: str, *, action: str) -> str | None:
        """Return a safe error when model browser input hits an auth target."""
        if not isinstance(task_id, str) or not task_id or not isinstance(target, str):
            return None
        target = target.strip()
        with self._lock:
            contexts = list({id(context): context for context in self._contexts.values()}.values())
        for context in contexts:
            if context.task_id != task_id or context.result is not None:
                continue
            if time.time() >= float(context.public.get("expires_at", 0)):
                continue
            reserved = []
            for field in context.public.get("fields", []):
                raw_target = field.get("target") or {}
                reserved.extend([str(raw_target.get("value") or ""), str(raw_target.get("target_id") or "")])
            for action_descriptor in context.public.get("actions", []):
                raw_target = action_descriptor.get("target") or {}
                reserved.extend([str(raw_target.get("value") or ""), str(raw_target.get("target_id") or "")])
            if target in {value for value in reserved if value}:
                return "auth_boundary_required: use the pending native Semreh authentication component"
        return None

    def _pending_for_task(self, task_id: str) -> bool:
        if not isinstance(task_id, str) or not task_id:
            return False
        now = time.time()
        with self._lock:
            contexts = {id(context): context for context in self._contexts.values()}.values()
            return any(
                context.task_id == task_id
                and context.result is None
                and now < float(context.public.get("expires_at", 0))
                for context in contexts
            )

    def model_browser_mutation_guard(self, task_id: str, *, action: str) -> str | None:
        """Reject model-driven browser mutation while native auth is pending."""
        if self._pending_for_task(task_id):
            safe_action = str(action or "browser mutation").strip()[:64] or "browser mutation"
            return f"auth_boundary_required: browser {safe_action} is paused until the native Semreh authentication component completes"
        return None

    def model_code_guard(self, task_id: str, code: str) -> str | None:
        """Reject model browser code while native auth is pending."""
        if not isinstance(code, str):
            return None
        if self._pending_for_task(task_id):
            return "auth_boundary_required: browser code is paused until the native Semreh authentication component completes"
        return None

    def _remove_context(self, context: _AuthContext) -> None:
        """Drop every registry alias for a terminal context after notification."""
        with self._lock:
            self._closed_owners[context.public["context_id"]] = context.task_id
            stale_keys = [key for key, value in self._contexts.items() if value is context]
            for key in stale_keys:
                self._contexts.pop(key, None)

    def public_auth_context(self, context_id: str) -> dict[str, Any]:
        """Return the strict model-facing auth-context projection."""
        context_id = _opaque(context_id, name="auth context")
        with self._lock:
            context = self._contexts.get(context_id)
        if context is None:
            raise NativeAuthSecurityError("auth context is no longer active")
        public = context.public
        field_components = [
            str(field.get("component_id") or "")
            for field in public.get("fields", [])
            if field.get("component_id")
        ]
        action_components = [
            str(action.get("component_id") or "")
            for action in public.get("actions", [])
            if action.get("component_id")
        ]
        component_ids = field_components + action_components
        if not component_ids:
            component_ids = [public["component_id"]]
        handles = [
            str(field["browser_field_handle"])
            for field in public.get("fields", [])
            if field.get("browser_field_handle")
        ] + [
            str(action["browser_action_handle"])
            for action in public.get("actions", [])
            if action.get("browser_action_handle")
        ]
        return self._public_copy({
            "type": "hermes.auth-context.v1",
            "issued_by": "browser",
            "immutable": True,
            "context_id": public["context_id"],
            "browser_session_id": public["browser_session_id"],
            "provider_origin": public["provider_origin"],
            "path": public["path"],
            "label": _safe_label(public.get("title"), fallback="Sign in"),
            "component_ids": component_ids[:32],
            "action_handles": handles[:32] or [public["component_id"]],
            "runtime_public_key": public["runtime_public_key"],
            "key_id": public["key_id"],
            "expires_at": _iso_timestamp(public["expires_at"]),
        })

    def public_components(self, component_id: str) -> list[dict[str, Any]]:
        """Return browser-issued strict component messages for one context."""
        component_id = _opaque(component_id, name="component")
        with self._lock:
            context = self._contexts.get(component_id)
        if context is None:
            raise NativeAuthSecurityError("auth context is no longer active")
        public = context.public
        messages: list[dict[str, Any]] = []
        for field in public.get("fields", []):
            messages.append(self._wire_component_for_field(context, field))
        for action in public.get("actions", []):
            if action.get("kind") == "cancel":
                continue
            if not action.get("target"):
                continue
            messages.append(self._wire_component_for_action(context, action))
        return self._public_copy(messages)

    def public_state(
        self,
        component_id: str,
        *,
        state: str,
        field_ids: list[str] | None = None,
        action_id: str | None = None,
        cancel_reason: str | None = None,
    ) -> dict[str, Any]:
        """Return strict metadata-only native-component state."""
        component_id = _opaque(component_id, name="component")
        with self._lock:
            context = self._contexts.get(component_id)
        if context is None:
            raise NativeAuthSecurityError("auth context is no longer active")
        allowed = {"available", "focused", "awaiting_browser", "completed", "cancelled", "blocked", "unavailable"}
        if state not in allowed:
            raise NativeAuthSecurityError("native auth state is invalid")
        field_ids = field_ids or []
        if len(field_ids) > 32 or not all(isinstance(value, str) and _FIELD_ID_RE.fullmatch(value) for value in field_ids):
            raise NativeAuthSecurityError("native auth field ids are invalid")
        result = {
            "type": "semreh.native-component-state.v1",
            "issued_by": "browser",
            "immutable": True,
            "context_id": context.public["context_id"],
            "browser_session_id": context.public["browser_session_id"],
            "component_id": component_id,
            "action_handle": self._action_handle_for_context(context, action_id),
            "kind": self._kind_for_action_or_component(context, component_id, action_id),
            "provider_origin": context.public["provider_origin"],
            "path": context.public["path"],
            "status": state,
        }
        if field_ids:
            result["field_ids"] = field_ids
        if action_id:
            result["action_id"] = action_id
        if cancel_reason is None and state == "cancelled":
            cancel_reason = "user_cancelled"
        if cancel_reason:
            if state != "cancelled" or cancel_reason not in {"user_cancelled", "browser_cancelled", "expired", "navigation_cancelled"}:
                raise NativeAuthSecurityError("native auth cancellation reason is invalid")
            result["cancel_reason"] = cancel_reason
        return self._public_copy(result)

    def _wire_component_for_field(self, context: _AuthContext, field: dict[str, Any]) -> dict[str, Any]:
        kind_map = {
            "identifier": "identifier",
            "email": "identifier",
            "username": "identifier",
            "password": "secret",
            "secret": "secret",
            "passcode": "secret",
            "pin": "secret",
            "one_time_code": "one_time_code",
            "totp_code": "one_time_code",
            "sms_code": "one_time_code",
            "email_code": "one_time_code",
            "verification_code": "one_time_code",
            "recovery_code": "recovery_code",
            "backup_code": "recovery_code",
        }
        kind = kind_map.get(field["kind"])
        if kind is None:
            raise NativeAuthSecurityError("field kind is not supported by the wire contract")
        return self._wire_component(
            context,
            component_id=field.get("component_id") or _new_id("cmp"),
            field=field["browser_field_handle"],
            action_handle=field["browser_field_handle"],
            kind=kind,
            label=field["label"],
            binding=self._wire_binding(context, field.get("target"), editable=True),
        )

    def _wire_component_for_action(self, context: _AuthContext, action: dict[str, Any]) -> dict[str, Any]:
        kind = action.get("kind")
        if kind not in {"submit", *BROWSER_OWNED_KINDS, "cancel"}:
            raise NativeAuthSecurityError("action kind is not supported by the wire contract")
        return self._wire_component(
            context,
            component_id=action.get("component_id") or _new_id("cmp"),
            field=action.get("field_handle") or action.get("browser_action_handle") or _new_id("fld"),
            action_handle=action.get("browser_action_handle") or _new_id("act"),
            kind=kind,
            label=action["label"],
            binding=self._wire_binding(context, action.get("target"), editable=False) if action.get("target") else None,
        )

    def _wire_component(self, context: _AuthContext, *, component_id: str, field: str, action_handle: str, kind: str, label: str, binding: dict[str, Any] | None) -> dict[str, Any]:
        result = {
            "type": NATIVE_COMPONENT_SCHEMA,
            "issued_by": "browser",
            "immutable": True,
            "context_id": context.public["context_id"],
            "browser_session_id": context.public["browser_session_id"],
            "component_id": component_id,
            "field": field,
            "action_handle": action_handle,
            "kind": kind,
            "label": _safe_label(label, fallback=kind.replace("_", " ").title()),
            "provider_origin": context.public["provider_origin"],
            "path": context.public["path"],
            "runtime_public_key": context.public["runtime_public_key"],
            "key_id": context.public["key_id"],
            "expires_at": _iso_timestamp(context.public["expires_at"]),
        }
        if binding is not None:
            result["binding"] = binding
        return result

    def _wire_binding(self, context: _AuthContext, target: dict[str, Any] | None, *, editable: bool) -> dict[str, Any]:
        if target is None:
            raise NativeAuthSecurityError("browser target is required")
        return {
            "issued_by": "browser",
            "immutable": True,
            "tab_handle": context.public["tab_handle"],
            "frame_handle": context.public["frame_handle"],
            "document_generation": context.public["document_generation"],
            "visibility": "visible",
            "editability": "editable" if editable else "not_editable",
            "match_count": 1,
            "target_ref": self._wire_target(target),
        }

    @staticmethod
    def _wire_target(target: dict[str, Any]) -> dict[str, Any]:
        strategy = target.get("strategy")
        value = str(target.get("value") or "")
        ref_id = target.get("target_id") or _new_id("ref")
        base = {"issued_by": "browser", "immutable": True, "ref_id": ref_id}
        if strategy == "css":
            return {**base, "strategy": "css", "selector": value[:160]}
        if strategy == "xpath":
            return {**base, "strategy": "xpath", "selector": value[:160]}
        if strategy == "role":
            role, _, label = value.partition(":")
            return {**base, "strategy": "role", "role": role if role in {"textbox", "button", "link", "combobox", "checkbox", "radio", "image", "option", "menuitem", "switch"} else "textbox", "label": label[:80] or "Authentication control"}
        if strategy == "label":
            return {**base, "strategy": "label", "label": value[:80]}
        # The current agent-browser adapter's ref is an exact opaque harness
        # reference; represent it as a CDP handle in the public wire contract.
        return {**base, "strategy": "cdp", "cdp_handle": value[:128]}

    @staticmethod
    def _action_handle_for_context(context: _AuthContext, action_id: str | None) -> str:
        for action in context.public.get("actions", []):
            if action_id and action.get("id") == action_id:
                return action.get("browser_action_handle") or _new_id("act")
        return (context.public.get("actions") or [{}])[0].get("browser_action_handle") or _new_id("act")

    @staticmethod
    def _kind_for_action_or_component(context: _AuthContext, component_id: str, action_id: str | None) -> str:
        for action in context.public.get("actions", []):
            if action_id and action.get("id") == action_id:
                return action.get("kind", "submit")
        for field in context.public.get("fields", []):
            if field.get("component_id") == component_id:
                return {"password": "secret", "one_time_code": "one_time_code", "recovery_code": "recovery_code"}.get(field.get("kind"), "identifier")
        return "submit"

    def prepare_component(self, candidate: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        if not isinstance(candidate, dict):
            raise NativeAuthSecurityError("native component must be an object")
        if candidate.get("schema") != NATIVE_COMPONENT_SCHEMA:
            raise NativeAuthSecurityError("unsupported native component schema")
        context_id = _opaque(candidate.get("context_id"), name="auth context")
        with self._lock:
            context = self._contexts.get(context_id)
        if context is None:
            raise NativeAuthSecurityError("auth context is no longer active")
        self._check_context(context, task_id=task_id)

        requested_fields = candidate.get("fields")
        if requested_fields is None:
            requested_fields = []
        if not isinstance(requested_fields, list) or len(requested_fields) > 32:
            raise NativeAuthSecurityError("native component fields are invalid")
        requested_actions = candidate.get("actions")
        if requested_actions is None:
            requested_actions = []
        if not isinstance(requested_actions, list) or len(requested_actions) > 16:
            raise NativeAuthSecurityError("native component actions are invalid")

        trusted_fields = {field["field_id"]: field for field in context.public["fields"]}
        trusted_actions = {action["id"]: action for action in context.public["actions"]}
        field_ids = self._requested_ids(requested_fields, key="id", fallback_key="field_id")
        action_ids = self._requested_ids(requested_actions, key="id", fallback_key="action_id")
        if not field_ids:
            field_ids = list(trusted_fields)
        if not action_ids:
            action_ids = [action_id for action_id in trusted_actions if action_id != "cancel"]
            if not action_ids and "cancel" in trusted_actions:
                action_ids = ["cancel"]
        if any(field_id not in trusted_fields for field_id in field_ids):
            raise NativeAuthSecurityError("native component references an unknown field")
        if any(action_id not in trusted_actions for action_id in action_ids):
            raise NativeAuthSecurityError("native component references an unknown action")

        # Only presentation fields are model-controlled. Targets, handles,
        # requiredness, semantic kinds, origin, and expiration come from the
        # browser context stored above.
        hostname = urlsplit(context.public["provider_origin"]).hostname or "the site"
        title = _safe_instruction(candidate.get("title"), max_length=160) or f"Sign in to {hostname}"
        instruction = _safe_instruction(candidate.get("instruction"), max_length=320) or (
            "Enter the requested information in this secure Semreh form."
        )
        component = {
            "schema": NATIVE_COMPONENT_SCHEMA,
            "component_id": context.public["component_id"],
            "context_id": context.public["context_id"],
            "browser_session_id": context.public["browser_session_id"],
            "provider_origin": context.public["provider_origin"],
            "path": context.public["path"],
            "flow": context.public["flow"],
            "title": title,
            "instruction": instruction,
            "fields": [self._component_field(trusted_fields[field_id]) for field_id in field_ids],
            "actions": [self._component_action(trusted_actions[action_id]) for action_id in action_ids],
            "runtime_public_key": context.public["runtime_public_key"],
            "key_id": context.public["key_id"],
            "expires_at": context.public["expires_at"],
        }
        with self._lock:
            self._contexts[component["component_id"]] = context
        return self._public_copy(component)

    def set_status_callback(
        self,
        component_id: str,
        callback: Optional[Callable[[dict[str, Any]], None]],
    ) -> None:
        with self._lock:
            context = self._contexts.get(component_id)
            if context is not None:
                context.status_callback = callback

    def wait_for_component(self, component_id: str, *, task_id: str, timeout: float | None = None) -> dict[str, Any]:
        component_id = _opaque(component_id, name="component")
        with self._lock:
            context = self._contexts.get(component_id)
        if context is None:
            return {"schema": NATIVE_COMPONENT_STATE_SCHEMA, "component_id": component_id, "state": "expired"}
        self._check_context(context, task_id=task_id, allow_expired=True)
        deadline = time.monotonic() + (self.timeout_seconds if timeout is None else max(1.0, float(timeout)))
        try:
            from tools.interrupt import is_interrupted
        except Exception:
            is_interrupted = lambda: False
        while not context.event.wait(timeout=min(5.0, max(0.1, deadline - time.monotonic()))):
            if is_interrupted():
                self.cancel_context(context.public["component_id"], task_id=task_id)
                break
            if time.monotonic() >= deadline:
                self.expire_context(component_id)
                break
            self._touch_browser_session(context)
        result = context.result or {
            "schema": NATIVE_COMPONENT_STATE_SCHEMA,
            "component_id": component_id,
            "state": "expired",
        }
        return self._public_copy(result)

    def expire_context(self, context_id_or_component_id: str) -> None:
        with self._lock:
            context = self._contexts.get(context_id_or_component_id)
            if context is None:
                return
            if context.result is None:
                context.result = self._state(context, "expired")
                self._closed[context.public["context_id"]] = "expired"
                self._closed[context.public["component_id"]] = "expired"
                context.event.set()
        self._notify(context, context.result)
        self._remove_context(context)

    def cancel_context(self, component_id: str, *, task_id: str) -> dict[str, Any]:
        component_id = _opaque(component_id, name="component")
        with self._lock:
            context = self._contexts.get(component_id)
        if context is None:
            raise NativeAuthSecurityError("auth component is no longer active")
        self._check_context(context, task_id=task_id, allow_expired=True)
        with self._lock:
            if context.result is None:
                context.result = self._state(context, "cancelled")
                self._closed[context.public["context_id"]] = "cancelled"
                self._closed[component_id] = "cancelled"
                context.event.set()
            result = context.result
        self._notify(context, result)
        safe_result = self._public_copy(result or {})
        self._remove_context(context)
        return safe_result

    def _submit_wire_envelope(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        """Serialize wire submissions so duplicate requests cannot double-fill."""
        with self._wire_submit_lock:
            return self._submit_wire_envelope_unlocked(envelope, task_id=task_id)

    def _submit_wire_envelope_unlocked(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        allowed = {
            "type", "issued_by", "immutable", "context_id", "browser_session_id",
            "envelope_id", "provider_origin", "path", "cipher_suite", "key_id",
            "client_public_key", "nonce", "ciphertext", "tag", "journal_policy", "expires_at",
        }
        if set(envelope) != allowed:
            raise NativeAuthSecurityError("native auth envelope has an invalid shape")
        if envelope.get("type") != NATIVE_SECRET_ENVELOPE_SCHEMA or envelope.get("issued_by") != "semreh-native" or envelope.get("immutable") is not True:
            raise NativeAuthSecurityError("unsupported native auth envelope")
        context_id = _opaque(envelope.get("context_id"), name="auth context")
        browser_session_id = _opaque(envelope.get("browser_session_id"), name="browser session")
        envelope_id = _opaque(envelope.get("envelope_id"), name="envelope")
        key_id = _opaque(envelope.get("key_id"), name="runtime key")
        if envelope.get("cipher_suite") != "AES-256-GCM" or envelope.get("journal_policy") != "never":
            raise NativeAuthSecurityError("native auth envelope policy is invalid")
        with self._lock:
            context = self._contexts.get(context_id)
            already_consumed = envelope_id in self._wire_consumed_envelopes
            closed_reason = self._closed.get(context_id)
        if already_consumed:
            raise NativeAuthSecurityError("native auth envelope replay")
        if context is None:
            owner = self._closed_owners.get(context_id)
            if owner is not None and owner != task_id:
                raise NativeAuthSecurityError("auth component belongs to another session")
            if closed_reason == "expired":
                raise NativeAuthSecurityError("auth component expired")
            if closed_reason == "cancelled":
                raise NativeAuthSecurityError("auth component cancelled")
            raise NativeAuthSecurityError("auth context is no longer active")
        self._check_context(context, task_id=task_id)
        if browser_session_id != context.public["browser_session_id"]:
            raise NativeAuthSecurityError("native auth browser session mismatch")
        if key_id != context.public["key_id"]:
            raise NativeAuthSecurityError("native auth runtime key mismatch")
        if _canonical_origin(envelope.get("provider_origin")) != context.public["provider_origin"]:
            raise NativeAuthSecurityError("native auth provider origin mismatch")
        if _safe_path(envelope.get("path")) != context.public["path"]:
            raise NativeAuthSecurityError("native auth path mismatch")
        try:
            expires_at = datetime.strptime(
                str(envelope.get("expires_at")),
                "%Y-%m-%dT%H:%M:%SZ",
            ).replace(tzinfo=timezone.utc).timestamp()
            if expires_at <= time.time():
                raise NativeAuthSecurityError("native auth envelope expired")
        except NativeAuthSecurityError:
            raise
        except (TypeError, ValueError, OverflowError):
            raise NativeAuthSecurityError("native auth envelope expiry is invalid") from None

        for field in context.public["fields"]:
            if field["kind"] in VALUE_FIELD_KINDS:
                self._target_validator(context=context.public, field=field)
        for action in context.public["actions"]:
            if action.get("target"):
                self._target_validator(context=context.public, action=action)

        plaintext_bytes = bytearray()
        field_values: dict[str, str] = {}
        try:
            client_public = _decode_b64(envelope.get("client_public_key"), name="client public key", max_bytes=32)
            if len(client_public) != 32:
                raise NativeAuthSecurityError("invalid client public key")
            nonce = _decode_b64(envelope.get("nonce"), name="nonce", max_bytes=12)
            if len(nonce) != 12:
                raise NativeAuthSecurityError("invalid nonce")
            ciphertext = _decode_b64(envelope.get("ciphertext"), name="ciphertext", max_bytes=64 * 1024)
            tag = _decode_b64(envelope.get("tag"), name="tag", max_bytes=16)
            if len(tag) != 16:
                raise NativeAuthSecurityError("invalid tag")
            key = derive_envelope_key(private_key=context.private_key, peer_public_key=client_public, key_id=key_id)
            aad = f"{context_id}:{envelope_id}:{key_id}".encode("ascii")
            plaintext_bytes = bytearray(AESGCM(key).decrypt(nonce, ciphertext + tag, aad))
            decoded = json.loads(bytes(plaintext_bytes).decode("utf-8"))
            if not isinstance(decoded, dict) or set(decoded) != {"fields", "action_handle"}:
                raise NativeAuthSecurityError("native auth plaintext has an invalid shape")
            raw_fields = decoded.get("fields")
            action_handle = decoded.get("action_handle")
            if not isinstance(raw_fields, dict) or not isinstance(action_handle, str):
                raise NativeAuthSecurityError("native auth plaintext has an invalid shape")
            trusted_fields = {field["browser_field_handle"]: field for field in context.public["fields"]}
            if set(raw_fields) - set(trusted_fields):
                raise NativeAuthSecurityError("native auth references an unknown field")
            for field_handle, value in raw_fields.items():
                field = trusted_fields[field_handle]
                if field["kind"] in BROWSER_OWNED_KINDS or field["kind"] in {"submit", "cancel"}:
                    raise NativeAuthSecurityError("native auth supplied a browser-owned field value")
                if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                    raise NativeAuthSecurityError("native auth field value is invalid")
                field_values[field["field_id"]] = value
            missing = [
                field["browser_field_handle"]
                for field in context.public["fields"]
                if field.get("required") and field["browser_field_handle"] not in raw_fields
            ]
            if missing:
                raise NativeAuthSecurityError("native auth required field is missing")
            actions = {action.get("browser_action_handle"): action for action in context.public["actions"]}
            action = actions.get(action_handle)
            if action is None:
                raise NativeAuthSecurityError("native auth action is invalid")

            self._notify(context, self._state(context, "accepted", field_ids=list(field_values), action_id=action.get("id")))
            for field in context.public["fields"]:
                value = field_values.get(field["field_id"])
                if value is None:
                    continue
                try:
                    self._fill_executor(context=context.public, field=field, plaintext=value)
                except NativeAuthSecurityError:
                    raise
                except Exception:
                    raise NativeAuthSecurityError("secure browser fill failed") from None
            self._notify(context, self._state(context, "filled", field_ids=list(field_values), action_id=action.get("id")))
            if action.get("kind") not in {"cancel", *BROWSER_OWNED_KINDS}:
                try:
                    self._action_executor(context=context.public, action=action)
                except NativeAuthSecurityError:
                    raise
                except Exception:
                    raise NativeAuthSecurityError("secure browser action failed") from None
            result = self._state(context, "submitted", field_ids=list(field_values), action_id=action.get("id"))
            with self._lock:
                self._wire_consumed_envelopes.add(envelope_id)
                context.result = result
                self._closed[context.public["context_id"]] = "submitted"
                self._closed[context.public["component_id"]] = "submitted"
                self._closed_owners[context.public["context_id"]] = task_id
                self._closed_owners[context.public["component_id"]] = task_id
                context.event.set()
            self._notify(context, result)
            safe_result = self._public_copy(result)
            self._remove_context(context)
            return safe_result
        except NativeAuthSecurityError as exc:
            result = self._state(context, "failed")
            with self._lock:
                self._wire_consumed_envelopes.add(envelope_id)
                context.result = result
                self._closed[context.public["context_id"]] = "failed"
                self._closed[context.public["component_id"]] = "failed"
                context.event.set()
            self._notify(context, result)
            self._remove_context(context)
            raise exc
        finally:
            for index in range(len(plaintext_bytes)):
                plaintext_bytes[index] = 0
            plaintext_bytes.clear()
            field_values.clear()

    def submit_envelope(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        if isinstance(envelope, dict) and envelope.get("type") == NATIVE_SECRET_ENVELOPE_SCHEMA:
            return self._submit_wire_envelope(envelope, task_id=task_id)

        if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
            raise NativeAuthSecurityError("native auth envelope has an invalid shape")
        if envelope.get("schema") != NATIVE_SECRET_ENVELOPE_SCHEMA:
            raise NativeAuthSecurityError("unsupported native auth envelope schema")
        component_id = _opaque(envelope.get("component_id"), name="component")
        sequence = envelope.get("sequence")
        if not isinstance(sequence, int) or sequence < 1 or sequence > 1_000_000:
            raise NativeAuthSecurityError("invalid native auth sequence")
        key_id = _opaque(envelope.get("key_id"), name="runtime key")
        with self._lock:
            context = self._contexts.get(component_id)
            closed_reason = self._closed.get(component_id)
        if context is None:
            if closed_reason == "submitted":
                raise NativeAuthSecurityError("native auth envelope replay")
            if closed_reason == "expired":
                raise NativeAuthSecurityError("auth component expired")
            if closed_reason == "cancelled":
                raise NativeAuthSecurityError("auth component cancelled")
            if closed_reason == "failed":
                raise NativeAuthSecurityError("auth component already failed")
            raise NativeAuthSecurityError("auth component is no longer active")
        self._check_context(context, task_id=task_id)
        if key_id != context.public["key_id"]:
            raise NativeAuthSecurityError("native auth runtime key mismatch")
        with self._lock:
            if context.consumed:
                raise NativeAuthSecurityError("native auth envelope replay")
            if sequence != 1:
                raise NativeAuthSecurityError("native auth sequence is invalid")
            context.consumed = True

        # Validate browser-issued targets before touching ciphertext/plaintext.
        for field in context.public["fields"]:
            if field["kind"] in VALUE_FIELD_KINDS:
                self._target_validator(context=context.public, field=field)
        for action in context.public["actions"]:
            if action.get("target"):
                self._target_validator(context=context.public, action=action)

        plaintext_bytes = bytearray()
        field_values: dict[str, Any] = {}
        try:
            client_public = _decode_b64(
                envelope.get("client_public_key"),
                name="client public key",
                max_bytes=32,
            )
            if len(client_public) != 32:
                raise NativeAuthSecurityError("invalid client public key")
            nonce = _decode_b64(envelope.get("nonce"), name="nonce", max_bytes=12)
            if len(nonce) != 12:
                raise NativeAuthSecurityError("invalid nonce")
            ciphertext = _decode_b64(envelope.get("ciphertext"), name="ciphertext", max_bytes=64 * 1024)
            tag = _decode_b64(envelope.get("tag"), name="tag", max_bytes=16)
            if len(tag) != 16:
                raise NativeAuthSecurityError("invalid tag")
            key = derive_envelope_key(
                private_key=context.private_key,
                peer_public_key=client_public,
                key_id=key_id,
            )
            aad = f"{component_id}:{sequence}:{key_id}".encode("ascii")
            plaintext_bytes = bytearray(AESGCM(key).decrypt(nonce, ciphertext + tag, aad))
            decoded = json.loads(bytes(plaintext_bytes).decode("utf-8"))
            if not isinstance(decoded, dict) or set(decoded) != {"fields", "action_id"}:
                raise NativeAuthSecurityError("native auth plaintext has an invalid shape")
            raw_fields = decoded.get("fields")
            if not isinstance(raw_fields, dict) or len(raw_fields) > 32:
                raise NativeAuthSecurityError("native auth fields are invalid")
            action_id = decoded.get("action_id")
            if not isinstance(action_id, str) or action_id not in {
                action["id"] for action in context.public["actions"]
            }:
                raise NativeAuthSecurityError("native auth action is invalid")
            trusted_fields = {field["field_id"]: field for field in context.public["fields"]}
            if set(raw_fields) - set(trusted_fields):
                raise NativeAuthSecurityError("native auth references an unknown field")
            for field_id, value in raw_fields.items():
                field = trusted_fields[field_id]
                if field["kind"] not in VALUE_FIELD_KINDS:
                    raise NativeAuthSecurityError("native auth supplied a browser-owned field value")
                if isinstance(value, bool):
                    field_values[field_id] = value
                elif isinstance(value, str) and len(value) <= 4096 and "\x00" not in value:
                    field_values[field_id] = value
                else:
                    raise NativeAuthSecurityError("native auth field value is invalid")
            missing = [
                field["field_id"]
                for field in context.public["fields"]
                if field.get("required") and field["kind"] in VALUE_FIELD_KINDS and field["field_id"] not in field_values
            ]
            if missing:
                raise NativeAuthSecurityError("native auth required field is missing")

            self._notify(context, self._state(context, "accepted", field_ids=list(field_values), action_id=action_id))
            for field in context.public["fields"]:
                if field["field_id"] not in field_values:
                    continue
                value = field_values[field["field_id"]]
                try:
                    self._fill_executor(context=context.public, field=field, plaintext=value)
                except NativeAuthSecurityError:
                    raise
                except Exception:
                    raise NativeAuthSecurityError("secure browser fill failed") from None
            self._notify(context, self._state(context, "filled", field_ids=list(field_values), action_id=action_id))
            action = next(action for action in context.public["actions"] if action["id"] == action_id)
            if action["kind"] not in {"cancel", *BROWSER_OWNED_KINDS}:
                try:
                    self._action_executor(context=context.public, action=action)
                except NativeAuthSecurityError:
                    raise
                except Exception:
                    raise NativeAuthSecurityError("secure browser action failed") from None
            result = self._state(context, "submitted", field_ids=list(field_values), action_id=action_id)
            with self._lock:
                context.result = result
                self._closed[component_id] = "submitted"
                context.event.set()
            self._notify(context, result)
            return self._public_copy(result)
        except NativeAuthSecurityError as exc:
            result = self._state(context, "failed")
            with self._lock:
                context.result = result
                self._closed[component_id] = "failed"
                context.event.set()
            self._notify(context, result)
            raise exc
        except Exception:
            result = self._state(context, "failed")
            with self._lock:
                context.result = result
                self._closed[component_id] = "failed"
                context.event.set()
            self._notify(context, result)
            raise NativeAuthSecurityError("native auth submission failed") from None
        finally:
            # Python strings cannot be guaranteed to be zeroed, but keeping the
            # lifetime narrow and clearing all references is still meaningful.
            for index in range(len(plaintext_bytes)):
                plaintext_bytes[index] = 0
            plaintext_bytes.clear()
            field_values.clear()

    def _normalize_field(
        self,
        raw: Any,
        seen_ids: set[str],
        *,
        require_target: bool,
        require_browser_target_id: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise NativeAuthSecurityError("auth field is invalid")
        field_id = raw.get("field_id", raw.get("id"))
        if not isinstance(field_id, str) or not _FIELD_ID_RE.fullmatch(field_id) or field_id in seen_ids:
            raise NativeAuthSecurityError("auth field id is invalid")
        seen_ids.add(field_id)
        kind = raw.get("kind")
        if kind not in FIELD_KINDS:
            raise NativeAuthSecurityError("auth field kind is unsupported")
        label = _safe_label(raw.get("label"), fallback=field_id.replace("_", " ").title())
        required = raw.get("required", False)
        if not isinstance(required, bool):
            raise NativeAuthSecurityError("auth field required flag is invalid")
        target = raw.get("target")
        if require_target and kind in VALUE_FIELD_KINDS:
            target = _validate_target(target)
        elif target is not None:
            target = _validate_target(target)
        if target is not None and "target_id" not in target:
            if require_browser_target_id:
                raise NativeAuthSecurityError("browser target id is required")
            target["target_id"] = _new_id("ref")
        result = {
            "field_id": field_id,
            "component_id": raw.get("component_id") or _new_id("cmp"),
            "kind": kind,
            "label": label,
            "required": required,
            "browser_field_handle": raw.get("browser_field_handle") or _new_id("fld"),
        }
        _opaque(result["component_id"], name="native component id")
        _opaque(result["browser_field_handle"], name="browser field handle")
        if target is not None:
            result["target"] = target
        for key in ("keyboard", "format", "placeholder"):
            if key in raw:
                result[key] = _safe_label(raw[key])
        options = raw.get("options")
        if options is not None:
            if not isinstance(options, list) or len(options) > 64:
                raise NativeAuthSecurityError("auth field options are invalid")
            normalized_options = []
            for option in options:
                if not isinstance(option, dict):
                    raise NativeAuthSecurityError("auth field option is invalid")
                option_id = option.get("id")
                option_label = option.get("label")
                if not isinstance(option_id, str) or not _FIELD_ID_RE.fullmatch(option_id):
                    raise NativeAuthSecurityError("auth option id is invalid")
                normalized_options.append({"id": option_id, "label": _safe_label(option_label)})
            result["options"] = normalized_options
        return result

    def _normalize_action(
        self,
        raw: Any,
        seen_ids: set[str],
        *,
        require_browser_target_id: bool = False,
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise NativeAuthSecurityError("auth action is invalid")
        action_id = raw.get("action_id", raw.get("id"))
        if not isinstance(action_id, str) or not _FIELD_ID_RE.fullmatch(action_id) or action_id in seen_ids:
            raise NativeAuthSecurityError("auth action id is invalid")
        seen_ids.add(action_id)
        kind = raw.get("kind")
        if kind not in ACTION_KINDS:
            raise NativeAuthSecurityError("auth action kind is unsupported")
        result = {
            "id": action_id,
            "component_id": raw.get("component_id") or _new_id("cmp"),
            "field_handle": raw.get("field_handle") or _new_id("fld"),
            "browser_action_handle": raw.get("browser_action_handle") or _new_id("act"),
            "kind": kind,
            "label": _safe_label(raw.get("label"), fallback=action_id.replace("_", " ").title()),
        }
        _opaque(result["component_id"], name="native component id")
        _opaque(result["field_handle"], name="native action field handle")
        _opaque(result["browser_action_handle"], name="browser action handle")
        if raw.get("target") is not None:
            target = _validate_target(raw["target"])
            if "target_id" not in target:
                if require_browser_target_id:
                    raise NativeAuthSecurityError("browser target id is required")
                target["target_id"] = _new_id("ref")
            result["target"] = target
        elif kind not in BROWSER_OWNED_KINDS and kind != "cancel":
            raise NativeAuthSecurityError("auth action target is required")
        return result

    @staticmethod
    def _requested_ids(items: list[Any], *, key: str, fallback_key: str) -> list[str]:
        ids: list[str] = []
        for item in items:
            if not isinstance(item, dict):
                raise NativeAuthSecurityError("native component item is invalid")
            value = item.get(key, item.get(fallback_key))
            if not isinstance(value, str) or not _FIELD_ID_RE.fullmatch(value) or value in ids:
                raise NativeAuthSecurityError("native component item id is invalid")
            ids.append(value)
        return ids

    @staticmethod
    def _component_field(field: dict[str, Any]) -> dict[str, Any]:
        result = {
            "id": field["field_id"],
            "kind": field["kind"],
            "label": field["label"],
            "required": field["required"],
            "secure": field["kind"] in {
                "password", "passcode", "pin", "secret", "recovery_code", "backup_code", "security_answer"
            },
            "browser_field_handle": field["browser_field_handle"],
        }
        if field.get("target") is not None:
            result["target"] = field["target"]
        for key in ("keyboard", "format", "placeholder", "options"):
            if key in field:
                result[key] = field[key]
        return result

    @staticmethod
    def _component_action(action: dict[str, Any]) -> dict[str, Any]:
        result = {"id": action["id"], "kind": action["kind"], "label": action["label"]}
        if action.get("target") is not None:
            result["target"] = action["target"]
        return result

    def _check_context(self, context: _AuthContext, *, task_id: str, allow_expired: bool = False) -> None:
        if context.task_id != task_id:
            raise NativeAuthSecurityError("auth component belongs to another session")
        if context.result is not None and not allow_expired:
            state = str(context.result.get("state") or "")
            if state == "expired":
                raise NativeAuthSecurityError("auth component expired")
            if state == "cancelled":
                raise NativeAuthSecurityError("auth component cancelled")
            if state == "submitted":
                raise NativeAuthSecurityError("native auth envelope replay")
            if state == "failed":
                raise NativeAuthSecurityError("auth component already failed")
        if not allow_expired and time.time() >= float(context.public["expires_at"]):
            self.expire_context(context.public["context_id"])
            raise NativeAuthSecurityError("auth component expired")

    def _state(self, context: _AuthContext, state: str, **extra: Any) -> dict[str, Any]:
        result = {
            "schema": NATIVE_COMPONENT_STATE_SCHEMA,
            "component_id": context.public["component_id"],
            "state": state,
        }
        result.update({key: value for key, value in extra.items() if key in {"field_ids", "action_id"}})
        return result

    @staticmethod
    def _public_copy(value: Any) -> Any:
        # The runtime never returns private registry objects; JSON round-trip
        # also prevents callers from mutating the stored context dictionaries.
        return json.loads(json.dumps(value, ensure_ascii=False))

    @staticmethod
    def _notify(context: _AuthContext, result: dict[str, Any] | None) -> None:
        callback = context.status_callback
        if callback is None or result is None:
            return
        try:
            callback(NativeAuthRuntime._public_copy(result))
        except Exception:
            pass

    @staticmethod
    def _touch_browser_session(context: _AuthContext) -> None:
        try:
            from tools.browser_tool import _update_session_activity

            _update_session_activity(context.browser_session_key)
        except Exception:
            pass

    def _private_context_for_public(self, public: dict[str, Any]) -> _AuthContext:
        if not isinstance(public, dict):
            raise NativeAuthSecurityError("native auth runtime context is invalid")
        context_id = public.get("context_id")
        with self._lock:
            context = self._contexts.get(context_id)
        if context is None:
            raise NativeAuthSecurityError("auth context is no longer active")
        return context

    def _default_target_validator(
        self,
        *,
        context: dict[str, Any],
        field: dict[str, Any] | None = None,
        action: dict[str, Any] | None = None,
    ) -> None:
        target = (field or action or {}).get("target")
        if not target:
            return
        internal = self._private_context_for_public(context)
        if internal.browser_backend != "browser-use":
            raise NativeAuthSecurityError("secure browser target adapter unavailable")
        try:
            from tools.browser_use_cli import secure_native_preflight

            secure_native_preflight(
                session=internal.browser_session_name or internal.browser_session_key,
                target=target,
                expected_origin=context["provider_origin"],
                expected_path=context["path"],
                expected_tab_handle=context["tab_handle"],
                expected_frame_handle=context["frame_handle"],
                expected_document_generation=context["document_generation"],
            )
        except NativeAuthSecurityError:
            raise
        except Exception:
            raise NativeAuthSecurityError("secure browser target validation unavailable") from None

    def _default_fill_executor(
        self,
        *,
        context: dict[str, Any],
        field: dict[str, Any],
        plaintext: Any,
    ) -> dict[str, Any]:
        internal = self._private_context_for_public(context)
        if internal.browser_backend != "browser-use":
            raise NativeAuthSecurityError("secure browser fill adapter unavailable")
        try:
            from tools.browser_use_cli import secure_native_fill

            return secure_native_fill(
                session=internal.browser_session_name or internal.browser_session_key,
                target=field["target"],
                plaintext=plaintext,
                expected_origin=context["provider_origin"],
                expected_path=context["path"],
                expected_tab_handle=context["tab_handle"],
                expected_frame_handle=context["frame_handle"],
                expected_document_generation=context["document_generation"],
            )
        except NativeAuthSecurityError:
            raise
        except Exception:
            raise NativeAuthSecurityError("secure browser fill failed") from None

    def _default_action_executor(
        self,
        *,
        context: dict[str, Any],
        action: dict[str, Any],
    ) -> dict[str, Any]:
        internal = self._private_context_for_public(context)
        if internal.browser_backend != "browser-use":
            raise NativeAuthSecurityError("secure browser action adapter unavailable")
        try:
            from tools.browser_use_cli import secure_native_action

            return secure_native_action(
                session=internal.browser_session_name or internal.browser_session_key,
                target=action.get("target"),
                expected_origin=context["provider_origin"],
                expected_path=context["path"],
                expected_tab_handle=context["tab_handle"],
                expected_frame_handle=context["frame_handle"],
                expected_document_generation=context["document_generation"],
            )
        except NativeAuthSecurityError:
            raise
        except Exception:
            raise NativeAuthSecurityError("secure browser action failed") from None


def _iso_timestamp(value: float) -> str:
    from datetime import datetime, timezone

    return datetime.fromtimestamp(float(value), timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# One in-process runtime is shared by browser tools, the WebUI route, and the
# AIAgent instance in a WebUI worker. It is deliberately not registered as a
# model-visible tool.
native_auth_runtime = NativeAuthRuntime()


__all__ = [
    "AUTH_CONTEXT_SCHEMA",
    "NATIVE_COMPONENT_SCHEMA",
    "NATIVE_COMPONENT_STATE_SCHEMA",
    "NATIVE_SECRET_ENVELOPE_SCHEMA",
    "FIELD_KINDS",
    "NativeAuthRuntime",
    "NativeAuthSecurityError",
    "derive_envelope_key",
    "native_auth_runtime",
]

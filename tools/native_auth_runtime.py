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
import hashlib
import json
import math
import re
import secrets
import threading
import time
from collections import OrderedDict
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
NATIVE_SECRET_ENVELOPE_V2_SCHEMA = "semreh.native-secret-envelope.v2"
NATIVE_AUTH_V2_SNAPSHOT_SCHEMA = "hermes.native-auth-snapshot.v2"
NATIVE_COMPONENT_V2_SCHEMA = "semreh.native-component.v2"

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

_V2_ROLES = frozenset({"button", "checkbox", "combobox", "link", "radio", "searchbox", "switch", "textbox"})
_V2_INPUT_ROLES = frozenset({"combobox", "searchbox", "textbox"})
_V2_ACTION_ROLES = frozenset({"button", "checkbox", "link", "radio", "switch"})
_V2_NODE_TYPES = frozenset({"action", "input", "stack", "text"})
_V2_STYLE_VALUES = frozenset({"danger", "primary", "secondary"})
_V2_MAX_PRIVATE_TARGET_BYTES = 8 * 1024
_V2_MAX_PRIVATE_TARGET_DEPTH = 8
_V2_MAX_SNAPSHOTS_PER_TASK = 8
_V2_MAX_SNAPSHOTS = 64
_V2_MAX_COMPONENTS_PER_TASK = 8
_V2_MAX_COMPONENTS = 64
_V2_FORBIDDEN_KEYS = frozenset(
    {
        "browser_session_id",
        "cdp",
        "cdp_handle",
        "component_id",
        "context_id",
        "document_generation",
        "document_id",
        "frame_handle",
        "frame_id",
        "javascript",
        "private_target",
        "selector",
        "target",
        "target_id",
        "tab_handle",
        "url",
        "value",
        "xpath",
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


def _v2_binding_id(ref: str, node_type: str) -> str:
    """Return the stable wire name for a trusted snapshot binding.

    Binding ids are namespaced by node type and are not capabilities; the
    component id and its fresh private key remain the authorization boundary.
    Stability lets clients retry the same generic surface across runtime
    adapters while the private binding record still stays component-local.
    """
    digest = hashlib.sha256(f"semreh.native-auth.v2:{node_type}:{ref}".encode("ascii")).digest()
    return f"bind_{_b64(digest[:18])}"


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


class _NativeAuthEnvelopeExpired(Exception):
    """Internal control flow for expiry discovered during a submit."""


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
    operation_lock: threading.RLock = field(default_factory=threading.RLock)
    expiry_timer: threading.Timer | None = None
    browser_hold_token: str | None = None
    mutation_may_have_begun: bool = False
    quarantine_in_progress: bool = False


@dataclass(frozen=True)
class _TerminalOutcome:
    fingerprint: str
    task_id: str
    result: dict[str, Any]
    failed: bool
    created_at: float
    aliases: tuple[str, ...]


@dataclass
class _V2Snapshot:
    task_id: str
    browser_session: str
    origin: str
    path: str
    targets: dict[str, dict[str, Any]]
    expires_at: float
    used_refs: set[str] = field(default_factory=set)


@dataclass
class _V2Component:
    public: dict[str, Any]
    task_id: str
    bindings: dict[str, dict[str, Any]]
    private_key: X25519PrivateKey
    key_id: str
    browser_session: str
    operation_lock: threading.RLock = field(default_factory=threading.RLock)
    event: threading.Event = field(default_factory=threading.Event)
    result: dict[str, Any] | None = None
    status: str = "available"
    expires_at: float = 0.0
    prepared: bool = False
    prepare_completed: bool = False
    prepare_lease: Any = None
    envelope_id: str | None = None
    envelope_fingerprint: str | None = None
    terminal_at: float | None = None
    quarantine_started: bool = False
    expiry_timer: threading.Timer | None = None
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
        quarantine_executor: Optional[Callable[..., None]] = None,
        terminal_ttl_seconds: float = 300.0,
        max_terminal_entries: int = 1024,
        inspect_resolver: Optional[Callable[..., dict[str, Any]]] = None,
        component_publisher: Optional[Callable[[dict[str, Any]], None]] = None,
        v2_inspect_resolver: Optional[Callable[..., dict[str, Any]]] = None,
        v2_component_publisher: Optional[Callable[[dict[str, Any]], None]] = None,
        v2_ref_ttl_seconds: float | None = None,
        v2_prepare_executor: Optional[Callable[..., Any]] = None,
        v2_apply_executor: Optional[Callable[..., Any]] = None,
    ) -> None:
        self.timeout_seconds = max(0.01, min(float(timeout_seconds), 3600.0))
        self._lock = threading.RLock()
        self._contexts: dict[str, _AuthContext] = {}
        # Terminal ownership is metadata-only and lets stale envelopes return
        # the precise safe error (expired/cancelled/replay/other session) after
        # the live context has been removed.
        self._terminal_ttl_seconds = max(0.01, min(float(terminal_ttl_seconds), 3600.0))
        self._max_terminal_entries = max(1, min(int(max_terminal_entries), 100_000))
        self._closed: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._closed_owners: OrderedDict[str, tuple[str, float]] = OrderedDict()
        self._component_callbacks: dict[
            str, tuple[int, Callable[[dict[str, Any]], None]]
        ] = {}
        self._callback_generations: OrderedDict[str, tuple[int, float]] = OrderedDict()
        self._notified_contexts: dict[str, int] = {}
        self._notification_inflight: dict[str, int] = {}
        self._wire_consumed_envelopes: OrderedDict[str, float] = OrderedDict()
        self._terminal_outcomes: OrderedDict[tuple[str, str], _TerminalOutcome] = OrderedDict()
        self._v2_snapshots: dict[str, _V2Snapshot] = {}
        self._v2_closed: OrderedDict[str, tuple[str, str, float]] = OrderedDict()
        self._v2_components: dict[str, _V2Component] = {}
        self._v2_lost_outcomes: OrderedDict[str, float] = OrderedDict()
        requested_v2_ttl = self.timeout_seconds if v2_ref_ttl_seconds is None else float(v2_ref_ttl_seconds)
        self._v2_ref_ttl_seconds = max(0.01, min(requested_v2_ttl, 300.0))
        self._private_key = X25519PrivateKey.generate()
        self._key_id = _new_id("rt")
        self._inspect_resolver = inspect_resolver
        self._fill_executor = fill_executor or self._default_fill_executor
        self._action_executor = action_executor or self._default_action_executor
        self._target_validator = target_validator or self._default_target_validator
        self._quarantine_executor = quarantine_executor or self._default_quarantine_executor
        self._owned_browser_orphans_reaped = False
        if v2_inspect_resolver is not None:
            self._v2_inspect_resolver = v2_inspect_resolver
        elif inspect_resolver is None:
            self._v2_inspect_resolver = self._default_v2_inspect_resolver
        else:
            self._v2_inspect_resolver = self._unavailable_v2_inspect_resolver
        self._v2_component_publisher = v2_component_publisher or component_publisher
        self._v2_lifecycle_configured = v2_prepare_executor is not None and v2_apply_executor is not None
        self._v2_prepare_executor = v2_prepare_executor or self._default_v2_prepare_executor
        self._v2_apply_executor = v2_apply_executor or self._default_v2_apply_executor

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

    def set_v2_inspect_resolver(self, resolver: Callable[..., dict[str, Any]]) -> None:
        self._v2_inspect_resolver = resolver

    def set_v2_component_publisher(
        self,
        publisher: Callable[[dict[str, Any]], None] | None,
    ) -> None:
        self._v2_component_publisher = publisher

    def set_v2_prepare_executor(self, executor: Callable[..., Any]) -> None:
        self._v2_prepare_executor = executor

    def set_v2_apply_executor(self, executor: Callable[..., Any]) -> None:
        self._v2_apply_executor = executor

    @staticmethod
    def _v2_task_id(task_id: Any) -> str:
        if not isinstance(task_id, str) or not task_id.strip() or len(task_id) > 256:
            raise NativeAuthSecurityError("native auth task is required")
        task_id = task_id.strip()
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in task_id):
            raise NativeAuthSecurityError("native auth task is invalid")
        return task_id

    @staticmethod
    def _v2_browser_session(value: Any) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > 128:
            raise NativeAuthSecurityError("browser session is invalid")
        value = value.strip()
        if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
            raise NativeAuthSecurityError("browser session is invalid")
        if "://" in value or any(char in value for char in "/?#"):
            raise NativeAuthSecurityError("browser session is invalid")
        return value

    def _prune_v2_locked(self, *, now: float | None = None) -> None:
        current = time.time() if now is None else now
        for snapshot_id, snapshot in list(self._v2_snapshots.items()):
            if snapshot.expires_at <= current:
                self._v2_snapshots.pop(snapshot_id, None)
                self._v2_closed[snapshot_id] = (snapshot.task_id, "expired", current)
                self._v2_closed.move_to_end(snapshot_id)
        cutoff = current - self._terminal_ttl_seconds
        for snapshot_id, (_, _, created_at) in list(self._v2_closed.items()):
            if created_at < cutoff:
                self._v2_closed.pop(snapshot_id, None)
        while len(self._v2_closed) > self._max_terminal_entries:
            self._v2_closed.popitem(last=False)
        for component_id, component in list(self._v2_components.items()):
            if component.result is not None and component.terminal_at is not None:
                if component.terminal_at < cutoff:
                    self._v2_components.pop(component_id, None)
                    self._v2_lost_outcomes[component_id] = current
        for component_id, created_at in list(self._v2_lost_outcomes.items()):
            if created_at < cutoff:
                self._v2_lost_outcomes.pop(component_id, None)
        while len(self._v2_lost_outcomes) > self._max_terminal_entries:
            self._v2_lost_outcomes.popitem(last=False)

    @staticmethod
    def _bounded_v2_private_target(value: Any) -> Any:
        if type(value) is str:
            if not value:
                raise NativeAuthSecurityError("secure browser inspect unavailable")
        elif type(value) is dict:
            if not value:
                raise NativeAuthSecurityError("secure browser inspect unavailable")
        else:
            raise NativeAuthSecurityError("secure browser inspect unavailable")

        active_containers: set[int] = set()

        def copy_json_like(current: Any, depth: int = 0) -> Any:
            current_type = type(current)
            if current is None or current_type is bool or current_type is str:
                return current
            if current_type is int:
                return current
            if current_type is float:
                if not math.isfinite(current):
                    raise NativeAuthSecurityError("secure browser inspect unavailable")
                return current
            if current_type is dict:
                if depth > _V2_MAX_PRIVATE_TARGET_DEPTH:
                    raise NativeAuthSecurityError("secure browser inspect unavailable")
                current_id = id(current)
                if current_id in active_containers:
                    raise NativeAuthSecurityError("secure browser inspect unavailable")
                active_containers.add(current_id)
                try:
                    copied: dict[str, Any] = {}
                    for key, child in current.items():
                        if type(key) is not str:
                            raise NativeAuthSecurityError("secure browser inspect unavailable")
                        copied[key] = copy_json_like(child, depth + 1)
                    return copied
                finally:
                    active_containers.remove(current_id)
            if current_type is list:
                if depth > _V2_MAX_PRIVATE_TARGET_DEPTH:
                    raise NativeAuthSecurityError("secure browser inspect unavailable")
                current_id = id(current)
                if current_id in active_containers:
                    raise NativeAuthSecurityError("secure browser inspect unavailable")
                active_containers.add(current_id)
                try:
                    return [copy_json_like(child, depth + 1) for child in current]
                finally:
                    active_containers.remove(current_id)
            raise NativeAuthSecurityError("secure browser inspect unavailable")

        copied = copy_json_like(value)
        try:
            canonical = json.dumps(
                copied,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
                allow_nan=False,
            ).encode("utf-8")
        except Exception:
            raise NativeAuthSecurityError("secure browser inspect unavailable") from None
        if len(canonical) > _V2_MAX_PRIVATE_TARGET_BYTES:
            raise NativeAuthSecurityError("secure browser inspect unavailable")
        return copied

    @staticmethod
    def _normalize_v2_resolver_result(result: Any) -> tuple[str, str, dict[str, dict[str, Any]]]:
        if not isinstance(result, dict):
            raise NativeAuthSecurityError("secure browser inspect unavailable")
        allowed = {"origin", "path", "targets"}
        if set(result) - allowed:
            raise NativeAuthSecurityError("secure browser inspect returned unsupported metadata")
        origin = _canonical_origin(result.get("origin"))
        path = _safe_path(result.get("path", "/"))
        raw_targets = result.get("targets")
        if not isinstance(raw_targets, list) or not 1 <= len(raw_targets) <= 32:
            raise NativeAuthSecurityError("secure browser inspect returned invalid targets")
        targets: dict[str, dict[str, Any]] = {}
        for raw_target in raw_targets:
            if not isinstance(raw_target, dict):
                raise NativeAuthSecurityError("secure browser inspect returned invalid targets")
            if set(raw_target) - {"ref", "role", "label", "hints", "target"}:
                raise NativeAuthSecurityError("secure browser inspect returned unsupported metadata")
            ref = raw_target.get("ref")
            if not isinstance(ref, str) or not _REF_RE.fullmatch(ref) or ref in targets:
                raise NativeAuthSecurityError("secure browser inspect returned invalid refs")
            role = raw_target.get("role")
            if role not in _V2_ROLES:
                raise NativeAuthSecurityError("secure browser inspect returned invalid roles")
            hints = raw_target.get("hints", {})
            if not isinstance(hints, dict) or set(hints) - {"masked", "required", "keyboard"}:
                raise NativeAuthSecurityError("secure browser inspect returned invalid hints")
            if any(not isinstance(hints.get(key), bool) for key in ("masked", "required") if key in hints):
                raise NativeAuthSecurityError("secure browser inspect returned invalid hints")
            if "keyboard" in hints and (not isinstance(hints["keyboard"], str) or hints["keyboard"] not in {"text", "email", "tel", "url", "number", "search"}):
                raise NativeAuthSecurityError("secure browser inspect returned invalid hints")
            trusted_label = _safe_label(
                raw_target.get("label"),
                fallback=str(role).replace("_", " ").title(),
            )
            private_target = raw_target.get("target")
            if "target" not in raw_target:
                raise NativeAuthSecurityError("secure browser inspect returned invalid targets")
            private_target = NativeAuthRuntime._bounded_v2_private_target(private_target)
            targets[ref] = {
                "ref": ref,
                "role": role,
                "trusted_label": trusted_label,
                "hints": NativeAuthRuntime._public_copy(hints),
                "target": private_target,
            }
        return origin, path, targets

    def inspect_v2(self, *, task_id: str, browser_session: str) -> dict[str, Any]:
        task_key = self._v2_task_id(task_id)
        session = self._v2_browser_session(browser_session)
        try:
            result = self._v2_inspect_resolver(browser_session=session, task_id=task_key)
        except Exception:
            raise NativeAuthSecurityError("secure browser inspect unavailable") from None
        try:
            origin, path, targets = self._normalize_v2_resolver_result(result)
        except NativeAuthSecurityError:
            raise
        except Exception:
            raise NativeAuthSecurityError("secure browser inspect unavailable") from None

        snapshot_id = _new_id("snap")
        expires_at = time.time() + self._v2_ref_ttl_seconds
        with self._lock:
            self._prune_v2_locked()
            task_snapshot_count = sum(
                snapshot.task_id == task_key for snapshot in self._v2_snapshots.values()
            )
            if (
                task_snapshot_count >= _V2_MAX_SNAPSHOTS_PER_TASK
                or len(self._v2_snapshots) >= _V2_MAX_SNAPSHOTS
            ):
                raise NativeAuthSecurityError("native auth snapshot capacity exceeded")
            snapshot = _V2Snapshot(
                task_id=task_key,
                browser_session=session,
                origin=origin,
                path=path,
                targets=targets,
                expires_at=expires_at,
            )
            self._v2_snapshots[snapshot_id] = snapshot
        return self._public_copy({
            "schema": NATIVE_AUTH_V2_SNAPSHOT_SCHEMA,
            "snapshot_id": snapshot_id,
            "origin": origin,
            "path": path,
            "targets": [
                {
                    "ref": target["ref"],
                    "role": target["role"],
                    "trusted_label": target["trusted_label"],
                    "hints": target["hints"],
                }
                for target in targets.values()
            ],
            "expires_at": _iso_timestamp(expires_at),
        })

    @staticmethod
    def _v2_text(value: Any, *, max_length: int = 320) -> str:
        return _safe_instruction(value, max_length=max_length)

    @staticmethod
    def _v2_node_keys(node: dict[str, Any], allowed: set[str]) -> None:
        if set(node) & _V2_FORBIDDEN_KEYS or set(node) - allowed:
            raise NativeAuthSecurityError("native auth surface contains unsupported metadata")

    @staticmethod
    def _v2_ref(
        value: Any,
        *,
        snapshot: _V2Snapshot,
        used_refs: set[str],
    ) -> dict[str, Any]:
        if not isinstance(value, str) or not _REF_RE.fullmatch(value):
            raise NativeAuthSecurityError("native auth inspect ref is invalid")
        target = snapshot.targets.get(value)
        if target is None:
            raise NativeAuthSecurityError("native auth inspect ref is unknown")
        if value in used_refs or value in snapshot.used_refs:
            raise NativeAuthSecurityError("native auth inspect ref was already used")
        used_refs.add(value)
        return target

    def _validate_v2_surface(
        self,
        surface: Any,
        *,
        snapshot: _V2Snapshot,
    ) -> tuple[dict[str, Any], dict[str, dict[str, Any]], set[str]]:
        if not isinstance(surface, dict):
            raise NativeAuthSecurityError("native auth surface must be an object")
        seen_node_ids: set[str] = set()
        used_refs: set[str] = set()
        bindings: dict[str, dict[str, Any]] = {}
        node_count = 0
        text_count = 0

        def visit(node: Any, depth: int) -> dict[str, Any]:
            nonlocal node_count, text_count
            if not isinstance(node, dict):
                raise NativeAuthSecurityError("native auth surface node is invalid")
            node_count += 1
            if node_count > 64 or depth > 8:
                raise NativeAuthSecurityError("native auth surface is too large")
            node_type = node.get("type")
            node_id = node.get("id")
            if not isinstance(node_type, str) or node_type not in _V2_NODE_TYPES:
                raise NativeAuthSecurityError("native auth surface node type is invalid")
            if not isinstance(node_id, str) or not _FIELD_ID_RE.fullmatch(node_id) or node_id in seen_node_ids:
                raise NativeAuthSecurityError("native auth surface node id is invalid")
            seen_node_ids.add(node_id)

            if node_type == "stack":
                self._v2_node_keys(node, {"type", "id", "children", "direction", "gap"})
                children = node.get("children")
                if not isinstance(children, list) or len(children) > 32:
                    raise NativeAuthSecurityError("native auth surface children are invalid")
                direction = node.get("direction", "vertical")
                if not isinstance(direction, str) or direction not in {"horizontal", "vertical"}:
                    raise NativeAuthSecurityError("native auth surface direction is invalid")
                gap = node.get("gap", 0)
                if isinstance(gap, bool) or not isinstance(gap, int) or not 0 <= gap <= 64:
                    raise NativeAuthSecurityError("native auth surface gap is invalid")
                return {
                    "type": "stack",
                    "id": node_id,
                    "direction": direction,
                    "gap": gap,
                    "children": [visit(child, depth + 1) for child in children],
                }

            if node_type == "text":
                self._v2_node_keys(node, {"type", "id", "text"})
                text = self._v2_text(node.get("text"))
                text_count += len(text)
                if text_count > 4096:
                    raise NativeAuthSecurityError("native auth surface text is too large")
                return {"type": "text", "id": node_id, "text": text}

            if node_type == "input":
                self._v2_node_keys(
                    node,
                    {"type", "id", "label", "help", "keyboard", "masked", "required", "ref"},
                )
                target = self._v2_ref(node.get("ref"), snapshot=snapshot, used_refs=used_refs)
                if target["role"] not in _V2_INPUT_ROLES:
                    raise NativeAuthSecurityError("native auth inspect ref has the wrong role")
                label = _safe_label(node.get("label"), fallback="Input")
                help_text = self._v2_text(node.get("help")) if "help" in node else None
                keyboard = _safe_label(node.get("keyboard")) if "keyboard" in node else None
                masked = node.get("masked", False)
                required = node.get("required", False)
                if not isinstance(masked, bool) or not isinstance(required, bool):
                    raise NativeAuthSecurityError("native auth input flags are invalid")
                trusted_hints = target.get("hints", {})
                masked = masked or trusted_hints.get("masked", False)
                required = required or trusted_hints.get("required", False)
                if "keyboard" in trusted_hints:
                    keyboard = trusted_hints["keyboard"]
                binding_id = _v2_binding_id(target["ref"], "input")
                bindings[binding_id] = {
                    "binding_id": binding_id,
                    "node_type": "input",
                    "required": required,
                    "role": target["role"],
                    "snapshot_id": None,
                    "task_id": snapshot.task_id,
                    "browser_session": snapshot.browser_session,
                    "ref": target["ref"],
                    "target": target["target"],
                }
                result = {
                    "type": "input",
                    "id": node_id,
                    "label": label,
                    "masked": masked,
                    "required": required,
                    "binding_id": binding_id,
                    "trusted_label": target["trusted_label"],
                    "role": target["role"],
                }
                if help_text is not None:
                    result["help"] = help_text
                if keyboard is not None:
                    result["keyboard"] = keyboard
                return result

            self._v2_node_keys(node, {"type", "id", "label", "style", "ref", "cancel"})
            label = _safe_label(node.get("label"), fallback="Continue")
            style = node.get("style", "primary")
            if not isinstance(style, str) or style not in _V2_STYLE_VALUES:
                raise NativeAuthSecurityError("native auth action style is invalid")
            cancel = node.get("cancel", False)
            if not isinstance(cancel, bool) or (cancel and "ref" in node) or (not cancel and "ref" not in node):
                raise NativeAuthSecurityError("native auth action binding is invalid")
            result = {"type": "action", "id": node_id, "label": label, "style": style}
            if cancel:
                result["cancel"] = True
                return result
            target = self._v2_ref(node.get("ref"), snapshot=snapshot, used_refs=used_refs)
            if target["role"] not in _V2_ACTION_ROLES:
                raise NativeAuthSecurityError("native auth inspect ref has the wrong role")
            binding_id = _v2_binding_id(target["ref"], "action")
            bindings[binding_id] = {
                "binding_id": binding_id,
                "node_type": "action",
                "required": False,
                "role": target["role"],
                "snapshot_id": None,
                "task_id": snapshot.task_id,
                "browser_session": snapshot.browser_session,
                "ref": target["ref"],
                "target": target["target"],
            }
            result.update({
                "binding_id": binding_id,
                "trusted_label": target["trusted_label"],
                "role": target["role"],
            })
            return result

        public_surface = visit(surface, 0)
        if not bindings:
            raise NativeAuthSecurityError("native auth surface has no browser bindings")
        return public_surface, bindings, used_refs

    def present_v2(
        self,
        *,
        task_id: str,
        snapshot_id: str,
        surface: dict[str, Any],
    ) -> dict[str, Any]:
        task_key = self._v2_task_id(task_id)
        snapshot_key = _opaque(snapshot_id, name="native auth snapshot")
        used_refs: set[str] = set()
        with self._lock:
            self._prune_v2_locked()
            active_components = [
                component
                for component in self._v2_components.values()
                if component.result is None
            ]
            task_component_count = sum(
                component.task_id == task_key for component in active_components
            )
            if (
                task_component_count >= _V2_MAX_COMPONENTS_PER_TASK
                or len(active_components) >= _V2_MAX_COMPONENTS
            ):
                raise NativeAuthSecurityError("native auth component capacity exceeded")
            snapshot = self._v2_snapshots.get(snapshot_key)
            if snapshot is None:
                closed = self._v2_closed.get(snapshot_key)
                if closed is not None and closed[0] != task_key:
                    raise NativeAuthSecurityError("native auth snapshot belongs to another session")
                if closed is not None and closed[1] == "expired":
                    raise NativeAuthSecurityError("native auth snapshot expired")
                if closed is not None and closed[1] == "used":
                    raise NativeAuthSecurityError("native auth snapshot was already used")
                raise NativeAuthSecurityError("native auth snapshot is no longer active")
            if snapshot.task_id != task_key:
                raise NativeAuthSecurityError("native auth snapshot belongs to another session")
            publisher = self._v2_component_publisher
            if publisher is None:
                raise NativeAuthSecurityError("native auth publisher unavailable")
            public_surface, bindings, used_refs = self._validate_v2_surface(surface, snapshot=snapshot)
            component_id = _new_id("cmp")
            component_private_key = X25519PrivateKey.generate()
            component_key_id = _new_id("rt")
            component_expires_at = snapshot.expires_at
            for binding in bindings.values():
                binding["snapshot_id"] = snapshot_key
            component = {
                "schema": NATIVE_COMPONENT_V2_SCHEMA,
                "issued_by": "hermes",
                "immutable": True,
                "component_id": component_id,
                "surface": public_surface,
                "origin": snapshot.origin,
                "path": snapshot.path,
                "runtime_public_key": _b64(component_private_key.public_key().public_bytes(
                    serialization.Encoding.Raw,
                    serialization.PublicFormat.Raw,
                )),
                "key_id": component_key_id,
                "expires_at": _iso_timestamp(component_expires_at),
                "state": "available",
            }
            snapshot.used_refs.update(used_refs)
            if len(snapshot.used_refs) == len(snapshot.targets):
                self._v2_snapshots.pop(snapshot_key, None)
                self._v2_closed[snapshot_key] = (snapshot.task_id, "used", time.time())
                self._v2_closed.move_to_end(snapshot_key)
            self._v2_components[component_id] = _V2Component(
                public=self._public_copy(component),
                task_id=task_key,
                bindings=bindings,
                private_key=component_private_key,
                key_id=component_key_id,
                browser_session=snapshot.browser_session,
                expires_at=component_expires_at,
            )
            component_record = self._v2_components[component_id]
            expiry_timer = threading.Timer(
                max(0.0, component_expires_at - time.time()),
                self.expire_v2_component,
                args=(component_id,),
            )
            expiry_timer.daemon = True
            component_record.expiry_timer = expiry_timer
            expiry_timer.start()
            self._prune_v2_locked()
        try:
            publisher(self._public_copy(component))
        except Exception:
            with self._lock:
                failed_component = self._v2_components.pop(component_id, None)
                if failed_component is not None and failed_component.expiry_timer is not None:
                    failed_component.expiry_timer.cancel()
                    failed_component.expiry_timer = None
                snapshot.used_refs.difference_update(used_refs)
                closed = self._v2_closed.get(snapshot_key)
                if closed is not None and closed[0] == snapshot.task_id and closed[1] == "used":
                    self._v2_snapshots[snapshot_key] = snapshot
                    self._v2_closed.pop(snapshot_key, None)
            raise NativeAuthSecurityError("native auth publisher unavailable") from None
        return self._public_copy(component)

    @staticmethod
    def _unavailable_v2_inspect_resolver(**kwargs: Any) -> dict[str, Any]:
        raise NativeAuthSecurityError("secure browser inspect unavailable")

    @staticmethod
    def _default_v2_prepare_executor(**kwargs: Any) -> Any:
        raise NativeAuthSecurityError("secure browser prepare unavailable")

    @staticmethod
    def _default_v2_apply_executor(**kwargs: Any) -> Any:
        raise NativeAuthSecurityError("secure browser apply unavailable")

    @staticmethod
    def _v2_duplicate_key_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise NativeAuthSecurityError("native auth plaintext has duplicate keys")
            result[key] = value
        return result

    @staticmethod
    def _v2_safe_state(component: _V2Component, state: str, **extra: Any) -> dict[str, Any]:
        result = {
            "schema": NATIVE_COMPONENT_V2_SCHEMA.replace("component", "component-state"),
            "component_id": component.public["component_id"],
            "state": state,
        }
        result.update({key: value for key, value in extra.items() if key in {"outcome", "reason"}})
        return result

    @staticmethod
    def _v2_context_lost_result(component_id: str) -> dict[str, Any]:
        return {
            "schema": "semreh.native-component-state.v2",
            "component_id": component_id,
            "state": "context_lost",
            "outcome": "remint_required",
        }

    def _v2_finish_locked(
        self,
        component: _V2Component,
        result: dict[str, Any],
        *,
        envelope_id: str | None = None,
        fingerprint: str | None = None,
    ) -> dict[str, Any]:
        component.result = self._public_copy(result)
        component.status = str(result["state"])
        component.terminal_at = time.time()
        if envelope_id is not None:
            component.envelope_id = envelope_id
            component.envelope_fingerprint = fingerprint
        if component.expiry_timer is not None:
            component.expiry_timer.cancel()
            component.expiry_timer = None
        component.prepare_lease = None
        component.event.set()
        return component.result

    def _notify_v2(self, component: _V2Component, result: dict[str, Any]) -> None:
        callback = getattr(component, "status_callback", None)
        if callback is None:
            return
        try:
            callback(self._public_copy(result))
        except Exception:
            pass

    def set_v2_status_callback(
        self,
        component_id: str,
        callback: Optional[Callable[[dict[str, Any]], None]],
    ) -> None:
        component_id = _opaque(component_id, name="component")
        with self._lock:
            component = self._v2_components.get(component_id)
            if component is None:
                raise NativeAuthSecurityError("native auth component is no longer active")
            component.status_callback = callback

    def _v2_quarantine(self, component: _V2Component) -> None:
        with self._lock:
            if component.quarantine_started:
                return
            component.quarantine_started = True
        try:
            self._quarantine_executor(
                task_id=component.task_id,
                browser_session_name=component.browser_session,
                tab_handle="",
            )
        except Exception:
            pass

    def _v2_terminal_failure(
        self,
        component: _V2Component,
        *,
        envelope_id: str,
        fingerprint: str,
        post_mutation: bool,
    ) -> dict[str, Any]:
        extra = (
            {"outcome": "remint_required", "reason": "browser_state_ambiguous"}
            if post_mutation
            else {}
        )
        with self._lock:
            result = self._v2_finish_locked(
                component,
                self._v2_safe_state(component, "failed", **extra),
                envelope_id=envelope_id,
                fingerprint=fingerprint,
            )
        if post_mutation:
            self._v2_quarantine(component)
        self._notify_v2(component, result)
        return result

    def _submit_v2_envelope(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        allowed = {
            "type", "issued_by", "immutable", "component_id", "envelope_id", "sequence",
            "cipher_suite", "key_id", "client_public_key", "nonce", "ciphertext", "tag",
            "journal_policy",
        }
        if set(envelope) != allowed:
            raise NativeAuthSecurityError("native auth envelope has an invalid shape")
        if envelope.get("type") != NATIVE_SECRET_ENVELOPE_V2_SCHEMA:
            raise NativeAuthSecurityError("unsupported native auth envelope")
        if envelope.get("issued_by") != "semreh-native" or envelope.get("immutable") is not True:
            raise NativeAuthSecurityError("unsupported native auth envelope")
        if envelope.get("cipher_suite") != "AES-256-GCM" or envelope.get("journal_policy") != "never":
            raise NativeAuthSecurityError("native auth envelope policy is invalid")
        component_id = _opaque(envelope.get("component_id"), name="component")
        envelope_id = _opaque(envelope.get("envelope_id"), name="envelope")
        key_id = _opaque(envelope.get("key_id"), name="runtime key")
        sequence = envelope.get("sequence")
        if isinstance(sequence, bool) or sequence != 1:
            raise NativeAuthSecurityError("native auth sequence is invalid")
        task_key = self._v2_task_id(task_id)
        fingerprint = self._envelope_fingerprint(envelope)
        with self._lock:
            self._prune_v2_locked()
            component = self._v2_components.get(component_id)
            if component is None:
                # A process restart loses the private key and all private targets.
                # This result is deliberately independent of the envelope body.
                return self._v2_context_lost_result(component_id)
            if component.task_id != task_key:
                raise NativeAuthSecurityError("auth component belongs to another session")
            if component.result is not None:
                if component.status == "expired":
                    raise NativeAuthSecurityError("native auth envelope expired")
                if component.status == "cancelled":
                    raise NativeAuthSecurityError("auth component cancelled")
                if component.envelope_id == envelope_id and component.envelope_fingerprint == fingerprint:
                    if component.status == "failed":
                        raise NativeAuthSecurityError("native auth submission failed")
                    return self._public_copy(component.result)
                raise NativeAuthSecurityError("native auth envelope replay")
            if component.envelope_id is not None:
                raise NativeAuthSecurityError("native auth envelope replay")
            if key_id != component.key_id:
                raise NativeAuthSecurityError("native auth runtime key mismatch")
            if time.time() >= component.expires_at:
                result = self._v2_finish_locked(component, self._v2_safe_state(component, "expired"))
                notify = True
            else:
                notify = False
        if notify:
            self._notify_v2(component, result)
            raise NativeAuthSecurityError("native auth envelope expired")

        plaintext_bytes = bytearray()
        decoded: Any = None
        raw_values: Any = None
        values: dict[str, str] = {}
        lease: Any = None
        client_public = nonce = ciphertext = tag = key = None
        try:
            def raise_if_expired() -> None:
                with self._lock:
                    if component.result is not None or time.time() < component.expires_at:
                        return
                    expired_result = self._v2_finish_locked(
                        component,
                        self._v2_safe_state(component, "expired"),
                    )
                self._notify_v2(component, expired_result)
                raise _NativeAuthEnvelopeExpired

            # This is the only pre-decrypt browser operation. It receives every
            # binding, including unused actions, and never sees envelope data.
            with self._lock:
                if not component.prepared:
                    component.prepared = True
                    bindings = [self._public_copy(binding) for binding in component.bindings.values()]
                    private_component = self._public_copy(component.public)
                else:
                    bindings = []
                    private_component = self._public_copy(component.public)
                already_prepared = component.prepare_completed
            if not already_prepared:
                lease = self._v2_prepare_executor(component=private_component, bindings=bindings)
                with self._lock:
                    component.prepare_lease = lease
                    component.prepare_completed = True
            else:
                with self._lock:
                    lease = component.prepare_lease
            raise_if_expired()

            client_public = _decode_b64(envelope.get("client_public_key"), name="client public key", max_bytes=32)
            nonce = _decode_b64(envelope.get("nonce"), name="nonce", max_bytes=12)
            ciphertext = _decode_b64(envelope.get("ciphertext"), name="ciphertext", max_bytes=64 * 1024)
            tag = _decode_b64(envelope.get("tag"), name="tag", max_bytes=16)
            if len(client_public) != 32 or len(nonce) != 12 or len(tag) != 16:
                raise NativeAuthSecurityError("native auth submission failed")
            key = derive_envelope_key(
                private_key=component.private_key,
                peer_public_key=client_public,
                key_id=component.key_id,
            )
            aad = f"{component_id}:{envelope_id}:{component.key_id}".encode("ascii")
            plaintext_bytes.extend(AESGCM(key).decrypt(nonce, ciphertext + tag, aad))
            decoded = json.loads(plaintext_bytes, object_pairs_hook=self._v2_duplicate_key_object)
            if not isinstance(decoded, dict) or set(decoded) != {"values", "action_binding_id"}:
                raise NativeAuthSecurityError("native auth submission failed")
            raw_values = decoded["values"]
            action_binding_id = decoded["action_binding_id"]
            if not isinstance(raw_values, dict) or not isinstance(action_binding_id, str):
                raise NativeAuthSecurityError("native auth submission failed")
            input_bindings = {
                binding_id: binding
                for binding_id, binding in component.bindings.items()
                if binding["node_type"] == "input"
            }
            action_bindings = {
                binding_id: binding
                for binding_id, binding in component.bindings.items()
                if binding["node_type"] == "action"
            }
            if action_binding_id not in action_bindings or len(raw_values) > len(input_bindings):
                raise NativeAuthSecurityError("native auth submission failed")
            if set(raw_values) - set(input_bindings):
                raise NativeAuthSecurityError("native auth submission failed")
            for binding_id, value in raw_values.items():
                if not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                    raise NativeAuthSecurityError("native auth submission failed")
                values[binding_id] = value
            missing = [
                binding_id
                for binding_id, binding in input_bindings.items()
                if binding["required"] and binding_id not in values
            ]
            if missing:
                raise NativeAuthSecurityError("native auth submission failed")

            # The operation lock held by submit_envelope linearizes this final
            # mutation-boundary check with cancel/expiry. Keep it after all
            # plaintext validation, but before any accepted notification or
            # reservation that could authorize the browser mutation.
            raise_if_expired()

            self._notify_v2(component, self._v2_safe_state(component, "accepted"))
            # The apply seam owns all browser mutations and is called exactly once.
            with self._lock:
                component.envelope_id = envelope_id
                component.envelope_fingerprint = fingerprint
                mutation_started = True
            apply_result = self._v2_apply_executor(
                lease=lease,
                values=values,
                action_binding_id=action_binding_id,
            )
            del apply_result
            with self._lock:
                result = self._v2_finish_locked(
                    component,
                    self._v2_safe_state(component, "submitted"),
                    envelope_id=envelope_id,
                    fingerprint=fingerprint,
                )
            self._notify_v2(component, result)
            return self._public_copy(result)
        except _NativeAuthEnvelopeExpired:
            raise NativeAuthSecurityError("native auth envelope expired") from None
        except Exception:
            post_mutation = bool(locals().get("mutation_started", False))
            result = self._v2_terminal_failure(
                component,
                envelope_id=envelope_id,
                fingerprint=fingerprint,
                post_mutation=post_mutation,
            )
            del result
            raise NativeAuthSecurityError("native auth submission failed") from None
        finally:
            if isinstance(raw_values, dict):
                raw_values.clear()
            if isinstance(decoded, dict):
                decoded.clear()
            decoded = raw_values = lease = None
            client_public = nonce = ciphertext = tag = key = None
            for index in range(len(plaintext_bytes)):
                plaintext_bytes[index] = 0
            plaintext_bytes.clear()
            values.clear()

    def wait_for_v2_component(
        self,
        component_id: str,
        *,
        task_id: str,
        timeout: float | None = None,
    ) -> dict[str, Any]:
        component_id = _opaque(component_id, name="component")
        task_key = self._v2_task_id(task_id)
        with self._lock:
            component = self._v2_components.get(component_id)
            if component is None:
                return self._v2_context_lost_result(component_id)
            if component.task_id != task_key:
                raise NativeAuthSecurityError("auth component belongs to another session")
            event = component.event
        wait_seconds = self.timeout_seconds if timeout is None else max(0.0, float(timeout))
        if not event.wait(wait_seconds):
            self.expire_v2_component(component_id)
        with self._lock:
            result = component.result
        return self._public_copy(result or self._v2_safe_state(component, "expired"))

    def cancel_v2_component(self, component_id: str, *, task_id: str) -> dict[str, Any]:
        component_id = _opaque(component_id, name="component")
        task_key = self._v2_task_id(task_id)
        with self._lock:
            component = self._v2_components.get(component_id)
            if component is None:
                return self._v2_context_lost_result(component_id)
        with component.operation_lock:
            with self._lock:
                if component.task_id != task_key:
                    raise NativeAuthSecurityError("auth component belongs to another session")
                if component.result is not None:
                    return self._public_copy(component.result)
                result = self._v2_finish_locked(component, self._v2_safe_state(component, "cancelled"))
            self._notify_v2(component, result)
            return self._public_copy(result)

    def expire_v2_component(self, component_id: str) -> None:
        component_id = _opaque(component_id, name="component")
        with self._lock:
            component = self._v2_components.get(component_id)
        if component is None:
            return
        with component.operation_lock:
            with self._lock:
                if component.result is not None:
                    return
                result = self._v2_finish_locked(component, self._v2_safe_state(component, "expired"))
            self._notify_v2(component, result)

    @staticmethod
    def _default_v2_inspect_resolver(**kwargs: Any) -> dict[str, Any]:
        from tools.browser_use_cli import resolve_native_auth_v2
        return resolve_native_auth_v2(**kwargs)

    def _prune_state_locked(self, *, now: float | None = None) -> None:
        current = time.time() if now is None else now
        cutoff = current - self._terminal_ttl_seconds
        timestamped = (
            (self._closed, lambda value: value[1]),
            (self._closed_owners, lambda value: value[1]),
            (self._callback_generations, lambda value: value[1]),
            (self._wire_consumed_envelopes, lambda value: value),
            (self._terminal_outcomes, lambda value: value.created_at),
        )
        for mapping, timestamp in timestamped:
            for key in list(mapping):
                if timestamp(mapping[key]) < cutoff:
                    mapping.pop(key, None)
            while len(mapping) > self._max_terminal_entries:
                mapping.popitem(last=False)

    def _record_closed_locked(self, context: _AuthContext, reason: str) -> tuple[str, ...]:
        now = time.time()
        aliases = tuple(dict.fromkeys(self._context_aliases_locked(context)))
        for alias in aliases:
            self._closed[alias] = (reason, now)
            self._closed.move_to_end(alias)
            self._closed_owners[alias] = (context.task_id, now)
            self._closed_owners.move_to_end(alias)
        self._prune_state_locked(now=now)
        return aliases

    def _closed_reason_locked(self, alias: str) -> str | None:
        value = self._closed.get(alias)
        return value[0] if value is not None else None

    def _closed_owner_locked(self, alias: str) -> str | None:
        value = self._closed_owners.get(alias)
        return value[0] if value is not None else None

    @staticmethod
    def _envelope_fingerprint(envelope: dict[str, Any]) -> str:
        try:
            encoded = json.dumps(
                envelope,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeError):
            raise NativeAuthSecurityError("native auth envelope has an invalid shape") from None
        return hashlib.sha256(encoded).hexdigest()

    def _cached_outcome_locked(
        self,
        identity: tuple[str, str],
        *,
        fingerprint: str,
        task_id: str,
    ) -> dict[str, Any] | None:
        self._prune_state_locked()
        outcome = self._terminal_outcomes.get(identity)
        if outcome is None:
            return None
        if outcome.task_id != task_id:
            raise NativeAuthSecurityError("auth component belongs to another session")
        if outcome.fingerprint != fingerprint:
            raise NativeAuthSecurityError("native auth envelope replay")
        if outcome.failed:
            raise NativeAuthSecurityError("native auth submission failed")
        return self._public_copy(outcome.result)

    def _cache_outcome_locked(
        self,
        identity: tuple[str, str],
        *,
        fingerprint: str,
        context: _AuthContext,
        result: dict[str, Any],
        failed: bool,
    ) -> None:
        now = time.time()
        aliases = self._record_closed_locked(context, str(result.get("state") or "failed"))
        self._terminal_outcomes[identity] = _TerminalOutcome(
            fingerprint=fingerprint,
            task_id=context.task_id,
            result=self._public_copy(result),
            failed=failed,
            created_at=now,
            aliases=aliases,
        )
        self._terminal_outcomes.move_to_end(identity)
        self._prune_state_locked(now=now)

    def _terminal_result_for_alias_locked(self, alias: str, *, task_id: str) -> dict[str, Any] | None:
        self._prune_state_locked()
        for outcome in reversed(self._terminal_outcomes.values()):
            if alias in outcome.aliases:
                if outcome.task_id != task_id:
                    raise NativeAuthSecurityError("auth component belongs to another session")
                return self._public_copy(outcome.result)
        return None

    def _context_aliases_locked(self, context: _AuthContext) -> list[str]:
        aliases = [key for key, value in self._contexts.items() if value is context]
        aliases.extend(
            str(value)
            for value in (context.public.get("context_id"), context.public.get("component_id"))
            if value
        )
        aliases.extend(
            str(item.get("component_id"))
            for group in (context.public.get("fields", []), context.public.get("actions", []))
            for item in group
            if item.get("component_id")
        )
        return aliases

    @staticmethod
    def _release_browser_hold(context: _AuthContext) -> None:
        token = context.browser_hold_token
        context.browser_hold_token = None
        if token is None:
            return
        try:
            from tools.browser_tool import release_browser_session_hold

            release_browser_session_hold(token)
        except Exception:
            pass

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
        if backend == "browser-use":
            self._reap_owned_browser_artifacts_once()
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
        if (
            context.browser_backend == "browser-use"
            and context.browser_session_name
            and context.browser_session_name.startswith("ha1-")
        ):
            try:
                from tools.browser_tool import acquire_browser_session_hold

                context.browser_hold_token = acquire_browser_session_hold(
                    "bu-named-" + context.browser_session_name,
                    expires_at=public["expires_at"],
                )
            except Exception:
                raise NativeAuthSecurityError("secure browser session hold unavailable") from None
        with self._lock:
            replaced = list(
                {
                    id(existing): existing
                    for existing in self._contexts.values()
                    if existing.task_id == task_id
                    and existing.browser_backend == "browser-use"
                    and existing.browser_session_name == context.browser_session_name
                }.values()
            )
            self._contexts[context_id] = context
            self._contexts[component_id] = context
            expiry_timer = threading.Timer(
                self.timeout_seconds,
                self.expire_context,
                args=(context_id,),
            )
            expiry_timer.daemon = True
            context.expiry_timer = expiry_timer
            expiry_timer.start()
        for existing in replaced:
            with existing.operation_lock:
                with self._lock:
                    if existing.result is None:
                        existing.result = self._state(existing, "cancelled")
                        self._record_closed_locked(existing, "cancelled")
                        existing.event.set()
                    result = existing.result
                self._notify(existing, result)
                self._remove_context(existing)
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
                and (
                    context.quarantine_in_progress
                    or (
                        context.result is None
                        and now < float(context.public.get("expires_at", 0))
                    )
                )
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

    def register_component_callback(
        self,
        task_id: str,
        callback: Callable[[dict[str, Any]], None] | None,
    ) -> None:
        """Bind one trusted native-component publisher to an agent task."""
        if not isinstance(task_id, str) or not task_id.strip():
            return
        task_key = task_id.strip()
        with self._lock:
            self._prune_state_locked()
            cached = self._callback_generations.get(task_key)
            registered = self._component_callbacks.get(task_key)
            generation = max(cached[0] if cached else 0, registered[0] if registered else 0) + 1
            self._callback_generations[task_key] = (generation, time.time())
            self._callback_generations.move_to_end(task_key)
            self._prune_state_locked()
            if callback is None:
                self._component_callbacks.pop(task_key, None)
            else:
                self._component_callbacks[task_key] = (generation, callback)

    def close_task(self, task_id: str) -> int:
        """Detach one task and deterministically terminate its active contexts."""
        task_key = str(task_id or "").strip()
        if not task_key:
            return 0
        v2_components: list[_V2Component] = []
        with self._lock:
            self._component_callbacks.pop(task_key, None)
            cached = self._callback_generations.get(task_key)
            self._callback_generations[task_key] = ((cached[0] if cached else 0) + 1, time.time())
            self._callback_generations.move_to_end(task_key)
            self._prune_state_locked()
            now = time.time()
            self._prune_v2_locked(now=now)
            for snapshot_id, snapshot in list(self._v2_snapshots.items()):
                if snapshot.task_id == task_key:
                    self._v2_snapshots.pop(snapshot_id, None)
                    self._v2_closed[snapshot_id] = (task_key, "cancelled", now)
                    self._v2_closed.move_to_end(snapshot_id)
            for component_id, component in list(self._v2_components.items()):
                if component.task_id == task_key:
                    v2_components.append(component)
            self._prune_v2_locked(now=now)
            contexts = list(
                {
                    id(context): context
                    for context in self._contexts.values()
                    if context.task_id == task_key
                }.values()
            )
        for component in v2_components:
            with component.operation_lock:
                with self._lock:
                    if component.result is None:
                        result = self._v2_finish_locked(
                            component,
                            self._v2_safe_state(component, "cancelled"),
                        )
                    else:
                        result = component.result
                if result is not None:
                    self._notify_v2(component, result)
        cleaned = 0
        for context in contexts:
            with context.operation_lock:
                with self._lock:
                    if context.result is None:
                        context.result = self._state(context, "cancelled")
                        self._record_closed_locked(context, "cancelled")
                        context.event.set()
                    result = context.result
                self._notify(context, result)
                self._remove_context(context)
                cleaned += 1
        return cleaned

    def notify_component(self, context_id: str, *, task_id: str) -> bool:
        """Promote a browser-created context to the registered native surface."""
        context_id = _opaque(context_id, name="auth context")
        task_key = str(task_id or "").strip()
        with self._lock:
            context = self._contexts.get(context_id)
            if context is None or context.task_id != task_key:
                return False
            registration = self._component_callbacks.get(task_key)
            if registration is None:
                return False
            generation, callback = registration
            if self._notified_contexts.get(context_id) == generation:
                return True
            if self._notification_inflight.get(context_id) == generation:
                return True
            self._notification_inflight[context_id] = generation
        try:
            # Deliberately pass only the opaque registry key. The callback reads
            # the rest from this runtime's private context registry.
            callback({"component_id": context.public["context_id"]})
        except Exception:
            with self._lock:
                if self._notification_inflight.get(context_id) == generation:
                    self._notification_inflight.pop(context_id, None)
            return False
        with self._lock:
            if self._notification_inflight.get(context_id) == generation:
                self._notification_inflight.pop(context_id, None)
            current = self._component_callbacks.get(task_key)
            is_current = current is not None and current[0] == generation
            is_active = self._contexts.get(context_id) is context
            if not is_current or not is_active:
                return False
            self._notified_contexts[context_id] = generation
        return True

    def _remove_context(self, context: _AuthContext) -> None:
        """Drop every registry alias for a terminal context after notification."""
        with self._lock:
            stale_keys = self._context_aliases_locked(context)
            for key in stale_keys:
                self._contexts.pop(key, None)
                self._notified_contexts.pop(key, None)
                self._notification_inflight.pop(key, None)
            expiry_timer = context.expiry_timer
            context.expiry_timer = None
            context.status_callback = None
        if expiry_timer is not None:
            expiry_timer.cancel()
        self._release_browser_hold(context)

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
        with context.operation_lock:
            with self._lock:
                if context.result is None:
                    context.result = self._state(context, "expired")
                    self._record_closed_locked(context, "expired")
                    context.event.set()
                result = context.result
            self._notify(context, result)
            self._remove_context(context)

    def cancel_context(self, component_id: str, *, task_id: str) -> dict[str, Any]:
        component_id = _opaque(component_id, name="component")
        with self._lock:
            context = self._contexts.get(component_id)
        if context is None:
            with self._lock:
                terminal = self._terminal_result_for_alias_locked(component_id, task_id=task_id)
                owner = self._closed_owner_locked(component_id)
            if terminal is not None:
                return terminal
            if owner is not None and owner != task_id:
                raise NativeAuthSecurityError("auth component belongs to another session")
            raise NativeAuthSecurityError("auth component is no longer active")
        with context.operation_lock:
            self._check_context(context, task_id=task_id, allow_expired=True)
            with self._lock:
                if context.result is None:
                    context.result = self._state(context, "cancelled")
                    self._record_closed_locked(context, "cancelled")
                    context.event.set()
                result = context.result
            self._notify(context, result)
            safe_result = self._public_copy(result or {})
            self._remove_context(context)
            return safe_result

    def _submit_wire_envelope(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        """Linearize submit against cancel/expiry for the owning context."""
        context_id = _opaque(envelope.get("context_id"), name="auth context")
        with self._lock:
            context = self._contexts.get(context_id)
        if context is None:
            return self._submit_wire_envelope_unlocked(envelope, task_id=task_id)
        with context.operation_lock:
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
        fingerprint = self._envelope_fingerprint(envelope)
        identity = ("wire", f"{context_id}:{envelope_id}")
        if envelope.get("cipher_suite") != "AES-256-GCM" or envelope.get("journal_policy") != "never":
            raise NativeAuthSecurityError("native auth envelope policy is invalid")
        with self._lock:
            cached = self._cached_outcome_locked(identity, fingerprint=fingerprint, task_id=task_id)
            if cached is not None:
                return cached
            context = self._contexts.get(context_id)
            already_consumed = envelope_id in self._wire_consumed_envelopes
            closed_reason = self._closed_reason_locked(context_id)
            owner = self._closed_owner_locked(context_id)
        if already_consumed:
            raise NativeAuthSecurityError("native auth envelope replay")
        if context is None:
            if owner is not None and owner != task_id:
                raise NativeAuthSecurityError("auth component belongs to another session")
            if closed_reason == "expired":
                raise NativeAuthSecurityError("auth component expired")
            if closed_reason == "cancelled":
                raise NativeAuthSecurityError("auth component cancelled")
            if closed_reason is None and owner is None:
                return self._context_lost_result(context_id)
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
            expires_at = datetime.strptime(str(envelope.get("expires_at")), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            if expires_at <= time.time():
                raise NativeAuthSecurityError("native auth envelope expired")
        except NativeAuthSecurityError:
            raise
        except (TypeError, ValueError, OverflowError):
            raise NativeAuthSecurityError("native auth envelope expiry is invalid") from None

        plaintext_bytes = bytearray()
        field_values: dict[str, str] = {}
        decoded = raw_fields = action = value = None
        client_public = nonce = ciphertext = tag = key = None
        try:
            for field in context.public["fields"]:
                if field["kind"] in VALUE_FIELD_KINDS:
                    self._run_target_validator(context=context.public, field=field)
            for candidate_action in context.public["actions"]:
                if candidate_action.get("target"):
                    self._run_target_validator(context=context.public, action=candidate_action)
            client_public = _decode_b64(envelope.get("client_public_key"), name="client public key", max_bytes=32)
            nonce = _decode_b64(envelope.get("nonce"), name="nonce", max_bytes=12)
            ciphertext = _decode_b64(envelope.get("ciphertext"), name="ciphertext", max_bytes=64 * 1024)
            tag = _decode_b64(envelope.get("tag"), name="tag", max_bytes=16)
            if len(client_public) != 32 or len(nonce) != 12 or len(tag) != 16:
                raise NativeAuthSecurityError("native auth submission failed")
            key = derive_envelope_key(private_key=context.private_key, peer_public_key=client_public, key_id=key_id)
            aad = f"{context_id}:{envelope_id}:{key_id}".encode("ascii")
            plaintext_bytes = bytearray(AESGCM(key).decrypt(nonce, ciphertext + tag, aad))
            decoded = json.loads(plaintext_bytes)
            if not isinstance(decoded, dict) or set(decoded) != {"fields", "action_handle"}:
                raise NativeAuthSecurityError("native auth submission failed")
            raw_fields = decoded.get("fields")
            action_handle = decoded.get("action_handle")
            trusted_fields = {field["browser_field_handle"]: field for field in context.public["fields"]}
            if not isinstance(raw_fields, dict) or not isinstance(action_handle, str) or set(raw_fields) - set(trusted_fields):
                raise NativeAuthSecurityError("native auth submission failed")
            for field_handle, value in raw_fields.items():
                field = trusted_fields[field_handle]
                if field["kind"] not in VALUE_FIELD_KINDS or not isinstance(value, str) or len(value) > 4096 or "\x00" in value:
                    raise NativeAuthSecurityError("native auth submission failed")
                field_values[field["field_id"]] = value
                value = None
            if any(field.get("required") and field["browser_field_handle"] not in raw_fields for field in context.public["fields"]):
                raise NativeAuthSecurityError("native auth submission failed")
            actions = {candidate.get("browser_action_handle"): candidate for candidate in context.public["actions"]}
            action = actions.get(action_handle)
            if action is None:
                raise NativeAuthSecurityError("native auth submission failed")
            self._notify(context, self._state(context, "accepted", field_ids=list(field_values), action_id=action.get("id")))
            for field in context.public["fields"]:
                value = field_values.get(field["field_id"])
                if value is not None:
                    self._mark_mutation_may_have_begun(context)
                    self._run_fill_executor(context=context.public, field=field, plaintext=value)
                    value = None
            self._notify(context, self._state(context, "filled", field_ids=list(field_values), action_id=action.get("id")))
            if action.get("kind") not in {"cancel", *BROWSER_OWNED_KINDS}:
                self._mark_mutation_may_have_begun(context)
                self._run_action_executor(context=context.public, action=action)
            result = self._state(context, "submitted", field_ids=list(field_values), action_id=action.get("id"))
            with self._lock:
                self._wire_consumed_envelopes[envelope_id] = time.time()
                self._wire_consumed_envelopes.move_to_end(envelope_id)
                context.result = result
                self._cache_outcome_locked(identity, fingerprint=fingerprint, context=context, result=result, failed=False)
                context.event.set()
            self._notify(context, result)
            safe_result = self._public_copy(result)
            self._remove_context(context)
            return safe_result
        except Exception:
            post_mutation = context.mutation_may_have_begun
            result = self._state(
                context,
                "failed",
                **(
                    {
                        "outcome": "remint_required",
                        "reason": "browser_state_ambiguous",
                    }
                    if post_mutation
                    else {}
                ),
            )
            with self._lock:
                context.quarantine_in_progress = post_mutation
                self._wire_consumed_envelopes[envelope_id] = time.time()
                self._wire_consumed_envelopes.move_to_end(envelope_id)
                context.result = result
                self._cache_outcome_locked(identity, fingerprint=fingerprint, context=context, result=result, failed=True)
                context.event.set()
            self._notify(context, result)
            if post_mutation:
                self._quarantine_context(context)
                with self._lock:
                    context.quarantine_in_progress = False
            self._remove_context(context)
            raise NativeAuthSecurityError("native auth submission failed") from None
        finally:
            if isinstance(raw_fields, dict):
                raw_fields.clear()
            if isinstance(decoded, dict):
                decoded.clear()
            decoded = raw_fields = action = value = None
            client_public = nonce = ciphertext = tag = key = None
            for index in range(len(plaintext_bytes)):
                plaintext_bytes[index] = 0
            plaintext_bytes.clear()
            field_values.clear()

    def submit_envelope(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        if isinstance(envelope, dict) and envelope.get("type") == NATIVE_SECRET_ENVELOPE_V2_SCHEMA:
            with self._lock:
                component_id = envelope.get("component_id")
                component = self._v2_components.get(component_id) if isinstance(component_id, str) else None
            if component is None:
                return self._submit_v2_envelope(envelope, task_id=task_id)
            with component.operation_lock:
                return self._submit_v2_envelope(envelope, task_id=task_id)
        if isinstance(envelope, dict) and envelope.get("type") == NATIVE_SECRET_ENVELOPE_SCHEMA:
            return self._submit_wire_envelope(envelope, task_id=task_id)
        if not isinstance(envelope, dict):
            return self._submit_legacy_envelope_unlocked(envelope, task_id=task_id)
        component_id = _opaque(envelope.get("component_id"), name="component")
        with self._lock:
            context = self._contexts.get(component_id)
        if context is None:
            return self._submit_legacy_envelope_unlocked(envelope, task_id=task_id)
        with context.operation_lock:
            return self._submit_legacy_envelope_unlocked(envelope, task_id=task_id)

    def _submit_legacy_envelope_unlocked(self, envelope: dict[str, Any], *, task_id: str) -> dict[str, Any]:
        if not isinstance(envelope, dict) or set(envelope) != _ENVELOPE_KEYS:
            raise NativeAuthSecurityError("native auth envelope has an invalid shape")
        if envelope.get("schema") != NATIVE_SECRET_ENVELOPE_SCHEMA:
            raise NativeAuthSecurityError("unsupported native auth envelope schema")
        component_id = _opaque(envelope.get("component_id"), name="component")
        sequence = envelope.get("sequence")
        if not isinstance(sequence, int) or sequence < 1 or sequence > 1_000_000:
            raise NativeAuthSecurityError("invalid native auth sequence")
        key_id = _opaque(envelope.get("key_id"), name="runtime key")
        fingerprint = self._envelope_fingerprint(envelope)
        identity = ("legacy", f"{component_id}:{sequence}")
        with self._lock:
            cached = self._cached_outcome_locked(identity, fingerprint=fingerprint, task_id=task_id)
            if cached is not None:
                return cached
            context = self._contexts.get(component_id)
            closed_reason = self._closed_reason_locked(component_id)
            owner = self._closed_owner_locked(component_id)
        if context is None:
            if owner is not None and owner != task_id:
                raise NativeAuthSecurityError("auth component belongs to another session")
            if closed_reason == "submitted":
                raise NativeAuthSecurityError("native auth envelope replay")
            if closed_reason == "expired":
                raise NativeAuthSecurityError("auth component expired")
            if closed_reason == "cancelled":
                raise NativeAuthSecurityError("auth component cancelled")
            if closed_reason == "failed":
                raise NativeAuthSecurityError("auth component already failed")
            if closed_reason is None and owner is None:
                return self._context_lost_result(component_id)
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

        plaintext_bytes = bytearray()
        field_values: dict[str, Any] = {}
        decoded = raw_fields = action = value = None
        client_public = nonce = ciphertext = tag = key = None
        try:
            # Validate browser-issued targets before touching ciphertext/plaintext.
            for field in context.public["fields"]:
                if field["kind"] in VALUE_FIELD_KINDS:
                    self._run_target_validator(context=context.public, field=field)
            for candidate_action in context.public["actions"]:
                if candidate_action.get("target"):
                    self._run_target_validator(context=context.public, action=candidate_action)
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
            decoded = json.loads(plaintext_bytes)
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
                self._mark_mutation_may_have_begun(context)
                self._run_fill_executor(context=context.public, field=field, plaintext=value)
                value = None
            self._notify(context, self._state(context, "filled", field_ids=list(field_values), action_id=action_id))
            action = next(action for action in context.public["actions"] if action["id"] == action_id)
            if action["kind"] not in {"cancel", *BROWSER_OWNED_KINDS}:
                self._mark_mutation_may_have_begun(context)
                self._run_action_executor(context=context.public, action=action)
            result = self._state(context, "submitted", field_ids=list(field_values), action_id=action_id)
            with self._lock:
                context.result = result
                self._cache_outcome_locked(identity, fingerprint=fingerprint, context=context, result=result, failed=False)
                context.event.set()
            self._notify(context, result)
            safe_result = self._public_copy(result)
            self._remove_context(context)
            return safe_result
        except Exception:
            post_mutation = context.mutation_may_have_begun
            result = self._state(
                context,
                "failed",
                **(
                    {
                        "outcome": "remint_required",
                        "reason": "browser_state_ambiguous",
                    }
                    if post_mutation
                    else {}
                ),
            )
            with self._lock:
                context.quarantine_in_progress = post_mutation
                context.result = result
                self._cache_outcome_locked(identity, fingerprint=fingerprint, context=context, result=result, failed=True)
                context.event.set()
            self._notify(context, result)
            if post_mutation:
                self._quarantine_context(context)
                with self._lock:
                    context.quarantine_in_progress = False
            self._remove_context(context)
            raise NativeAuthSecurityError("native auth submission failed") from None
        finally:
            # Python strings cannot be guaranteed to be zeroed, but keeping the
            # lifetime narrow and clearing all references is still meaningful.
            if isinstance(raw_fields, dict):
                raw_fields.clear()
            if isinstance(decoded, dict):
                decoded.clear()
            decoded = raw_fields = action = value = None
            client_public = nonce = ciphertext = tag = key = None
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
        result.update({
            key: value
            for key, value in extra.items()
            if key in {"field_ids", "action_id", "outcome", "reason"}
        })
        return result

    @staticmethod
    def _context_lost_result(component_id: str) -> dict[str, Any]:
        return {
            "schema": NATIVE_COMPONENT_STATE_SCHEMA,
            "component_id": component_id,
            "state": "context_lost",
            "outcome": "remint_required",
        }

    def _mark_mutation_may_have_begun(self, context: _AuthContext) -> None:
        with self._lock:
            context.mutation_may_have_begun = True

    def _reap_owned_browser_artifacts_once(self) -> None:
        with self._lock:
            if self._owned_browser_orphans_reaped:
                return
            self._owned_browser_orphans_reaped = True
        try:
            from tools.browser_use_cli import reap_owned_browser_use_orphans

            reap_owned_browser_use_orphans(limit=64)
        except Exception:
            pass

    def _quarantine_context(self, context: _AuthContext) -> None:
        if context.browser_backend != "browser-use":
            return
        session = context.browser_session_name
        if not session or not session.startswith("ha1-"):
            return
        try:
            self._quarantine_executor(
                task_id=context.task_id,
                browser_session_name=session,
                tab_handle=context.public["tab_handle"],
            )
        except Exception:
            pass

    @staticmethod
    def _default_quarantine_executor(
        *,
        task_id: str,
        browser_session_name: str,
        tab_handle: str,
    ) -> None:
        del browser_session_name, tab_handle
        from tools.browser_use_cli import cleanup_browser_use_task

        cleanup_browser_use_task(task_id)

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

    def _run_target_validator(self, **kwargs: Any) -> None:
        try:
            self._target_validator(**kwargs)
        except Exception:
            raise NativeAuthSecurityError("secure browser target validation failed") from None

    def _run_fill_executor(self, **kwargs: Any) -> dict[str, Any]:
        try:
            return self._fill_executor(**kwargs)
        except Exception:
            raise NativeAuthSecurityError("secure browser fill failed") from None

    def _run_action_executor(self, **kwargs: Any) -> dict[str, Any]:
        try:
            return self._action_executor(**kwargs)
        except Exception:
            raise NativeAuthSecurityError("secure browser action failed") from None

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
        except Exception:
            raise NativeAuthSecurityError("secure browser target validation failed") from None

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

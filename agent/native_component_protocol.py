"""Strict parser for the model-authored Semreh native-component marker.

The marker is a compatibility transport for providers that cannot emit a
native structured-content part. It is intentionally metadata-only: the parser
rejects credential-shaped values, selectors, HTML, JavaScript, and arbitrary
component data. Browser targets are attached later from the trusted runtime
context, never accepted from the model marker.
"""

from __future__ import annotations

import json
import re
from typing import Any

from tools.native_auth_runtime import ACTION_KINDS, FIELD_KINDS, NATIVE_COMPONENT_SCHEMA


MARKER_OPEN = "<semreh.native-component>"
MARKER_CLOSE = "</semreh.native-component>"
MAX_MARKER_BYTES = 32 * 1024
_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_FORBIDDEN_KEYS = frozenset(
    {
        "value",
        "defaultvalue",
        "password",
        "passcode",
        "otp",
        "token",
        "secret",
        "credential",
        "credentials",
        "cookie",
        "storage",
        "storage_state",
        "authorization_code",
        "code",
        "state",
        "pkce",
        "selector",
        "selectors",
        "css",
        "xpath",
        "html",
        "javascript",
        "script",
        "innertext",
        "dom",
    }
)
_ALLOWED_TOP_KEYS = frozenset({"schema", "context_id", "title", "instruction", "fields", "actions"})
_ALLOWED_FIELD_KEYS = frozenset({"id", "field_id", "kind", "label", "required", "keyboard", "secure"})
_ALLOWED_ACTION_KEYS = frozenset({"id", "action_id", "kind", "label"})


def _safe_text(value: Any, *, maximum: int) -> str:
    if value is None:
        return ""
    if not isinstance(value, str) or len(value) > maximum:
        raise ValueError("native component text is invalid")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        raise ValueError("native component text contains control characters")
    return value.strip()


def _validate_id(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        raise ValueError(f"native component {name} is invalid")
    return value


def _reject_forbidden_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if str(key).replace("-", "_").lower() in _FORBIDDEN_KEYS:
                raise ValueError("native component contains forbidden credential metadata")
            _reject_forbidden_keys(nested)
    elif isinstance(value, list):
        for nested in value:
            _reject_forbidden_keys(nested)


def _normalize_component(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("native component must be an object")
    if value.get("schema") != NATIVE_COMPONENT_SCHEMA:
        raise ValueError("unsupported native component schema")
    _reject_forbidden_keys(value)
    if set(value) - _ALLOWED_TOP_KEYS:
        raise ValueError("native component contains unsupported metadata")
    context_id = _validate_id(value.get("context_id"), name="context id")
    fields = value.get("fields", [])
    actions = value.get("actions", [])
    if not isinstance(fields, list) or len(fields) > 32:
        raise ValueError("native component fields are invalid")
    if not isinstance(actions, list) or len(actions) > 16:
        raise ValueError("native component actions are invalid")

    normalized_fields = []
    field_ids = set()
    for raw in fields:
        if not isinstance(raw, dict) or set(raw) - _ALLOWED_FIELD_KEYS:
            raise ValueError("native component field metadata is invalid")
        field_id = _validate_id(raw.get("id", raw.get("field_id")), name="field id")
        if field_id in field_ids:
            raise ValueError("native component contains duplicate field ids")
        field_ids.add(field_id)
        kind = raw.get("kind")
        if kind not in FIELD_KINDS:
            raise ValueError("native component field kind is unsupported")
        required = raw.get("required", False)
        if not isinstance(required, bool):
            raise ValueError("native component required flag is invalid")
        item = {
            "id": field_id,
            "kind": kind,
            "label": _safe_text(raw.get("label"), maximum=120),
            "required": required,
        }
        for key in ("keyboard", "secure"):
            if key in raw:
                if key == "secure" and not isinstance(raw[key], bool):
                    raise ValueError("native component secure flag is invalid")
                item[key] = raw[key]
        normalized_fields.append(item)

    normalized_actions = []
    action_ids = set()
    for raw in actions:
        if not isinstance(raw, dict) or set(raw) - _ALLOWED_ACTION_KEYS:
            raise ValueError("native component action metadata is invalid")
        action_id = _validate_id(raw.get("id", raw.get("action_id")), name="action id")
        if action_id in action_ids:
            raise ValueError("native component contains duplicate action ids")
        action_ids.add(action_id)
        kind = raw.get("kind")
        if kind not in ACTION_KINDS:
            raise ValueError("native component action kind is unsupported")
        normalized_actions.append(
            {
                "id": action_id,
                "kind": kind,
                "label": _safe_text(raw.get("label"), maximum=120),
            }
        )

    return {
        "schema": NATIVE_COMPONENT_SCHEMA,
        "context_id": context_id,
        "title": _safe_text(value.get("title"), maximum=160),
        "instruction": _safe_text(value.get("instruction"), maximum=320),
        "fields": normalized_fields,
        "actions": normalized_actions,
    }


def extract_native_component(text: str) -> tuple[str, dict[str, Any] | None]:
    """Extract one strict marker and return ``(clean_text, component)``.

    Invalid or conflicting markers are removed from visible text and returned
    as ``None``. This prevents an untrusted model response from becoming a UI
    executable payload or from being displayed as a giant JSON block.
    """
    if not isinstance(text, str) or MARKER_OPEN not in text:
        return (text if isinstance(text, str) else "", None)
    if text.count(MARKER_OPEN) != 1 or text.count(MARKER_CLOSE) != 1:
        return ("", None)
    start = text.index(MARKER_OPEN)
    end_marker = text.find(MARKER_CLOSE, start + len(MARKER_OPEN))
    if end_marker < 0:
        return ("", None)
    end = end_marker + len(MARKER_CLOSE)
    raw_payload = text[start + len(MARKER_OPEN):end_marker].strip()
    if len(raw_payload.encode("utf-8")) > MAX_MARKER_BYTES:
        return ("", None)
    try:
        parsed = json.loads(raw_payload)
        component = _normalize_component(parsed)
    except (ValueError, TypeError, json.JSONDecodeError):
        component = None
    clean = (text[:start] + text[end:]).strip()
    clean = re.sub(r"\n{3,}", "\n\n", clean)
    return clean, component


class NativeComponentStreamFilter:
    """Remove a native-component marker from streamed visible text.

    Model providers may stream the assistant response before Hermes has the full
    response available for schema validation. This filter keeps a possible
    marker out of the UI while preserving ordinary text before/after it. It is
    not a validator and never parses or executes the buffered payload; the
    completed response is validated by ``extract_native_component`` later.
    """

    def __init__(self, *, max_buffer_bytes: int = 32 * 1024) -> None:
        self.max_buffer_bytes = max(1, int(max_buffer_bytes))
        self._pending = ""
        self._inside = False
        self.buffered = ""

    @staticmethod
    def _partial_suffix(value: str, marker: str) -> str:
        limit = min(len(value), len(marker) - 1)
        for length in range(limit, 0, -1):
            if value.endswith(marker[:length]):
                return value[-length:]
        return ""

    def feed(self, chunk: str) -> str:
        if not isinstance(chunk, str) or not chunk:
            return ""
        if self._inside:
            combined = self.buffered + chunk
            close_index = combined.find(MARKER_CLOSE)
            if close_index < 0:
                self.buffered = combined[-self.max_buffer_bytes:]
                return ""
            self.buffered = ""
            self._inside = False
            return combined[close_index + len(MARKER_CLOSE):]

        combined = self._pending + chunk
        self._pending = ""
        open_index = combined.find(MARKER_OPEN)
        if open_index >= 0:
            visible = combined[:open_index]
            remainder = combined[open_index + len(MARKER_OPEN):]
            close_index = remainder.find(MARKER_CLOSE)
            if close_index >= 0:
                return visible + remainder[close_index + len(MARKER_CLOSE):]
            self._inside = True
            self.buffered = remainder[-self.max_buffer_bytes:]
            return visible

        partial = self._partial_suffix(combined, MARKER_OPEN)
        if partial:
            self._pending = partial
            return combined[:-len(partial)]
        return combined

    def flush(self) -> str:
        """Drop an incomplete marker at stream end; never display its payload."""
        self._pending = ""
        self.buffered = ""
        self._inside = False
        return ""


__all__ = ["MARKER_OPEN", "MARKER_CLOSE", "extract_native_component", "NativeComponentStreamFilter"]

"""Permission-gated bridge for Cua Driver Computer History.

The Cua preview owns encryption, native-key custody, retention, and permission
checks. Hermes only discovers the two advertised read-only MCP tools, routes
calls through the session-owned Cua backend, and validates the published
metadata-only response contract before it reaches the model.
"""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from tools.registry import no_cache_check_fn, registry


_HISTORY_TOOL_NAMES = frozenset({"history_status", "history_query"})
_HISTORY_SCHEMA = "urn:cua-driver:schema:history-event:v0"
_HISTORY_PROFILE_PREFIX = "cua-history-profile-v1/"

_HEALTH_VALUES = frozenset(
    {
        "ready",
        "disabled",
        "paused",
        "not_admitted",
        "key_unavailable",
        "key_locked",
        "key_corrupt",
        "key_destroy_failed",
        "storage_unavailable",
        "storage_corrupt",
        "quota_reached",
        "events_dropped",
        "writer_stopped",
    }
)
_EVENT_TYPES = frozenset(
    {
        "cua-driver.history.control.v0",
        "cua-driver.history.action_started.v0",
        "cua-driver.history.action_completed.v0",
        "cua-driver.history.session_started.v0",
        "cua-driver.history.session_ended.v0",
        "cua-driver.history.access.v0",
        "cua-driver.history.health.v0",
    }
)
_PLATFORM_VALUES = frozenset({"macos", "windows", "linux"})
_OPAQUE_ID_RE = re.compile(r"^[0-9a-f]{32}$")
_QUERY_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,128}$")
_SAFE_CUA_TEXT_RE = re.compile(r"^[A-Za-z0-9_.:/@+-]{1,160}$")

_STATUS_FIELDS = (
    "supported",
    "admitted",
    "enabled",
    "paused",
    "encrypted",
    "profile",
    "retention_days",
    "quota_bytes",
    "bytes_used",
    "dropped_events",
    "health",
)

_STATUS_SCHEMA = {
    "name": "history_status",
    "description": (
        "Read the operational status of Cua Driver Computer History. This is "
        "read-only and never enables capture or returns history events. Use it "
        "only when continuing, resuming, or explaining prior Cua-mediated "
        "desktop work; absence or denial is non-fatal."
    ),
    "parameters": {
        "type": "object",
        "properties": {},
        "additionalProperties": False,
    },
}

_QUERY_SCHEMA = {
    "name": "history_query",
    "description": (
        "Read a bounded metadata-only slice from Cua Driver Computer History "
        "after history_status. Use only for a continue/resume/recent Cua-work "
        "request. Results may enter model context but contain no screenshots, "
        "URLs, paths, window titles, typed text, keystrokes, clipboard data, "
        "raw arguments, or raw tool results. This does not mutate capture."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 200,
                "default": 50,
            },
            "session_id": {
                "type": "string",
                "minLength": 1,
                "maxLength": 128,
                "pattern": r"^[A-Za-z0-9_-]{1,128}$",
                "description": "Optional opaque Cua History session ID.",
            },
            "since_sequence": {
                "type": "integer",
                "minimum": 1,
            },
            "until_sequence": {
                "type": "integer",
                "minimum": 1,
            },
        },
        "additionalProperties": False,
    },
}


def _resolve_cua_driver_cmd() -> str | None:
    """Resolve the same Cua binary used by the computer-use backend."""
    try:
        from tools.computer_use.cua_backend import resolve_cua_driver_cmd

        return resolve_cua_driver_cmd()
    except Exception:
        return None


def _cua_driver_child_env() -> dict[str, str]:
    """Use the backend's telemetry/sanitized child environment policy."""
    try:
        from tools.computer_use.cua_backend import cua_driver_child_env

        return cua_driver_child_env()
    except Exception:
        return {}


def _sanitized_cua_driver_child_env() -> dict[str, str]:
    """Remove Hermes provider/internal secrets before spawning Cua."""
    env = _cua_driver_child_env()
    try:
        from tools.environments.local import _sanitize_subprocess_env

        return _sanitize_subprocess_env(env)
    except Exception:
        # The Cua probe is a read-only availability check. If the canonical
        # sanitizer cannot load, fail closed rather than pass raw env through.
        return {}


def _advertised_tool_names(stdout: str) -> set[str]:
    """Extract exact tool names from Cua's stable list-tools text surface."""
    names: set[str] = set()
    for line in str(stdout or "").splitlines():
        name = line.split(":", 1)[0].strip()
        if name in _HISTORY_TOOL_NAMES:
            names.add(name)
    return names


def _history_tool_advertised(tool_name: str) -> bool:
    """Return true when the live Cua daemon admits the history preview.

    The standalone ``list-tools`` command is a static CLI catalog and does not
    reflect daemon admission. The structured status call is the cheap,
    read-only admission signal; ``call_cua_read_only_tool`` performs the final
    exact per-tool MCP discovery check before any history result is returned.
    """
    if tool_name not in _HISTORY_TOOL_NAMES:
        return False
    command = _resolve_cua_driver_cmd()
    if not command:
        return False
    try:
        result = subprocess.run(
            [command, "history", "status", "--json"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            env=_sanitized_cua_driver_child_env(),
            timeout=5.0,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    try:
        payload = json.loads((result.stdout or "").strip())
    except (TypeError, ValueError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("supported") is True
        and payload.get("admitted") is True
    )


@no_cache_check_fn
def check_history_status_requirements() -> bool:
    return _history_tool_advertised("history_status")


@no_cache_check_fn
def check_history_query_requirements() -> bool:
    return _history_tool_advertised("history_query")


def _error(code: str, message: str) -> str:
    return json.dumps({"error": message, "code": code}, ensure_ascii=False)


def _payload_from_driver_result(result: Any) -> Any:
    if not isinstance(result, dict):
        return None
    payload = result.get("structuredContent")
    if payload is None:
        payload = result.get("structured_content")
    if payload is None:
        payload = result.get("data")
    if isinstance(payload, str):
        try:
            return json.loads(payload)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
    return payload


def _driver_error_code(result: Any) -> str:
    payload = _payload_from_driver_result(result)
    candidate = payload.get("code") if isinstance(payload, dict) else None
    refusal = payload.get("refusal") if isinstance(payload, dict) else None
    if isinstance(refusal, dict) and refusal.get("code") == "authorization_required":
        return "history_authorization_required"
    allowed = {
        "invalid_history_query",
        "invalid_history_query_range",
        "history_preview_not_admitted",
        "history_authorization_required",
        "history_key_unavailable",
        "history_key_locked",
        "history_key_corrupt",
        "history_storage_unavailable",
        "history_storage_corrupt",
        "history_quota_reached",
        "history_events_dropped",
        "history_writer_stopped",
    }
    return candidate if isinstance(candidate, str) and candidate in allowed else "history_unavailable"


def _call_cua_read_only_tool(name: str, args: dict[str, Any], session_id: str) -> Any:
    """Route through the existing session-owned Cua MCP backend."""
    if name not in _HISTORY_TOOL_NAMES:
        return {"isError": True, "structuredContent": {"code": "history_unavailable"}}
    try:
        from tools.computer_use.tool import call_cua_read_only_tool

        return call_cua_read_only_tool(name, args, session_id=session_id)
    except Exception:
        return {"isError": True, "structuredContent": {"code": "history_unavailable"}}


def _history_result_or_error(result: Any) -> tuple[Any, str | None]:
    if not isinstance(result, dict) or result.get("isError") is True:
        return None, _driver_error_code(result)
    payload = _payload_from_driver_result(result)
    if payload is None:
        return None, "history_unavailable"
    return payload, None


def _safe_text(value: Any, *, max_length: int) -> str | None:
    if not isinstance(value, str) or not value or len(value) > max_length:
        return None
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in value):
        return None
    return value


def _safe_nonnegative_int(value: Any, *, maximum: int) -> int | None:
    if type(value) is not int or value < 0 or value > maximum:
        return None
    return value


def _sanitize_status(payload: Any) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return None
    result: dict[str, Any] = {}
    for key in _STATUS_FIELDS:
        if key not in payload:
            continue
        value = payload[key]
        if key in {"supported", "admitted", "enabled", "paused", "encrypted"}:
            if type(value) is not bool:
                return None
            result[key] = value
        elif key == "profile":
            value = _safe_text(value, max_length=160)
            if value is None or not value.startswith(_HISTORY_PROFILE_PREFIX):
                return None
            result[key] = value
        elif key == "health":
            if not isinstance(value, str) or value not in _HEALTH_VALUES:
                return None
            result[key] = value
        else:
            value = _safe_nonnegative_int(value, maximum=2**63 - 1)
            if value is None:
                return None
            result[key] = value
    required = {"supported", "admitted", "enabled", "paused", "encrypted", "health"}
    if not required.issubset(result):
        return None
    return result


def _validate_query(args: Any) -> dict[str, Any] | None:
    if not isinstance(args, dict):
        return None
    allowed = {"limit", "session_id", "since_sequence", "until_sequence"}
    if set(args) - allowed:
        return None
    normalized: dict[str, Any] = {}
    if "limit" in args:
        limit = args["limit"]
        if type(limit) is not int or not 1 <= limit <= 200:
            return None
        normalized["limit"] = limit
    if "session_id" in args:
        session_id = args["session_id"]
        if not isinstance(session_id, str) or not _QUERY_ID_RE.fullmatch(session_id):
            return None
        normalized["session_id"] = session_id
    for key in ("since_sequence", "until_sequence"):
        if key in args:
            value = args[key]
            if type(value) is not int or value < 1:
                return None
            normalized[key] = value
    lower = normalized.get("since_sequence")
    upper = normalized.get("until_sequence")
    if lower is not None and upper is not None and lower > upper:
        return {"__invalid_range__": True}
    return normalized


def _sanitize_id(value: Any) -> str | None:
    return value if isinstance(value, str) and _OPAQUE_ID_RE.fullmatch(value) else None


def _sanitize_application(value: Any) -> dict[str, str] | None:
    if not isinstance(value, dict) or not value or set(value) - {"bundle_id", "display_name"}:
        return None
    result: dict[str, str] = {}
    for key, limit in (("bundle_id", 160), ("display_name", 120)):
        if key in value:
            text = _safe_text(value[key], max_length=limit)
            if text is None:
                return None
            result[key] = text
    return result if result else None


def _sanitize_payload(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        return None
    kind = value["kind"]
    if kind == "control":
        if set(value) != {"kind", "operation"} or value.get("operation") not in {
            "enable", "disable", "pause", "resume", "flush", "delete"
        }:
            return None
        return {"kind": kind, "operation": value["operation"]}
    if kind == "action_started":
        return {"kind": kind} if set(value) == {"kind"} else None
    if kind == "action_completed":
        required = {"kind", "effect", "route", "evidence_kinds"}
        allowed = required | {"delivery", "delivered_count", "escalation_kind"}
        if not required.issubset(value) or set(value) - allowed:
            return None
        effects = {"confirmed", "partial", "unverifiable", "suspected_noop", "refused", "failed"}
        routes = {"accessibility", "synthetic_events", "global_input", "system_api", "dom", "trusted_input", "unknown"}
        deliveries = {"background", "foreground", "not_applicable", "unknown"}
        escalations = {
            "activate_target", "retry_with_pixel_target", "retry_with_page_action",
            "refresh_page_state", "request_permission", "elevate_access",
            "expand_capture_scope", "prepare_session", "retry_with_foreground_delivery",
        }
        if value["effect"] not in effects or value["route"] not in routes:
            return None
        evidence = value["evidence_kinds"]
        if not isinstance(evidence, list) or len(evidence) > 16 or any(
            item not in {"accessibility_readback", "browser_readback", "value_readback", "window_change"}
            for item in evidence
        ):
            return None
        result = {
            "kind": kind,
            "effect": value["effect"],
            "route": value["route"],
            "evidence_kinds": list(evidence),
        }
        if "delivery" in value:
            if value["delivery"] not in deliveries:
                return None
            result["delivery"] = value["delivery"]
        if "delivered_count" in value:
            delivered = _safe_nonnegative_int(value["delivered_count"], maximum=2**32 - 1)
            if delivered is None:
                return None
            result["delivered_count"] = delivered
        if "escalation_kind" in value:
            if value["escalation_kind"] not in escalations:
                return None
            result["escalation_kind"] = value["escalation_kind"]
        return result
    if kind == "session":
        if set(value) != {"kind", "phase"} or value["phase"] not in {"started", "ended"}:
            return None
        return {"kind": kind, "phase": value["phase"]}
    if kind == "access":
        if set(value) != {"kind", "operation", "returned_events"}:
            return None
        if value["operation"] not in {"agent_query", "local_cli"}:
            return None
        count = _safe_nonnegative_int(value["returned_events"], maximum=200)
        return {"kind": kind, "operation": value["operation"], "returned_events": count} if count is not None else None
    if kind == "health":
        if set(value) != {"kind", "category", "count"} or value["category"] not in _HEALTH_VALUES:
            return None
        count = _safe_nonnegative_int(value["count"], maximum=2**63 - 1)
        return {"kind": kind, "category": value["category"], "count": count} if count is not None else None
    return None


def _sanitize_event(event: Any) -> dict[str, Any] | None:
    required = {"specversion", "id", "source", "type", "subject", "time", "datacontenttype", "dataschema", "data"}
    if not isinstance(event, dict) or set(event) - required or not required.issubset(event):
        return None
    event_id = _sanitize_id(event["id"])
    source = event["source"]
    if event["specversion"] != "1.0" or event_id is None:
        return None
    if not isinstance(source, str) or source != "urn:cua-driver:history:" + source.rsplit(":", 1)[-1] or _sanitize_id(source.rsplit(":", 1)[-1]) is None:
        return None
    if event["type"] not in _EVENT_TYPES or event["datacontenttype"] != "application/json" or event["dataschema"] != _HISTORY_SCHEMA:
        return None
    subject = _safe_text(event["subject"], max_length=160)
    timestamp = _safe_text(event["time"], max_length=64)
    if subject is None or timestamp is None:
        return None

    data = event["data"]
    data_allowed = {"session_id", "action_id", "sequence", "platform", "process_model", "capability", "caller_category", "application", "payload"}
    if not isinstance(data, dict) or set(data) - data_allowed:
        return None
    if "sequence" not in data or "platform" not in data or "process_model" not in data or "caller_category" not in data or "payload" not in data:
        return None
    sequence = _safe_nonnegative_int(data["sequence"], maximum=2**63 - 1)
    if sequence is None or sequence < 1 or data["platform"] not in _PLATFORM_VALUES or data["process_model"] != "in_daemon" or data["caller_category"] != "cua_runtime":
        return None
    sanitized_data: dict[str, Any] = {
        "sequence": sequence,
        "platform": data["platform"],
        "process_model": "in_daemon",
        "caller_category": "cua_runtime",
    }
    for key in ("session_id", "action_id"):
        if key in data:
            value = _sanitize_id(data[key])
            if value is None:
                return None
            sanitized_data[key] = value
    if "capability" in data:
        capability = _safe_text(data["capability"], max_length=128)
        if capability is None:
            return None
        sanitized_data["capability"] = capability
    if "application" in data:
        application = _sanitize_application(data["application"])
        if application is None:
            return None
        sanitized_data["application"] = application
    payload = _sanitize_payload(data["payload"])
    if payload is None:
        return None
    sanitized_data["payload"] = payload
    return {
        "specversion": "1.0",
        "id": event_id,
        "source": source,
        "type": event["type"],
        "subject": subject,
        "time": timestamp,
        "datacontenttype": "application/json",
        "dataschema": _HISTORY_SCHEMA,
        "data": sanitized_data,
    }


def history_status(args: dict[str, Any], *, session_id: str = "") -> str:
    if not isinstance(args, dict) or args:
        return _error("invalid_history_query", "Computer History status accepts no arguments")
    payload, error = _history_result_or_error(
        _call_cua_read_only_tool("history_status", {}, str(session_id or ""))
    )
    if error:
        return _error(error, "Computer History status is unavailable or denied")
    sanitized = _sanitize_status(payload)
    if sanitized is None:
        return _error("history_storage_corrupt", "Computer History returned invalid status metadata")
    return json.dumps(sanitized, ensure_ascii=False)


def history_query(args: dict[str, Any], *, session_id: str = "") -> str:
    normalized = _validate_query(args)
    if normalized is None:
        return _error("invalid_history_query", "Computer History query arguments are invalid")
    if normalized.pop("__invalid_range__", False):
        return _error("invalid_history_query_range", "Computer History query range is invalid")
    payload, error = _history_result_or_error(
        _call_cua_read_only_tool("history_query", normalized, str(session_id or ""))
    )
    if error:
        return _error(error, "Computer History query is unavailable or denied")
    if not isinstance(payload, dict):
        return _error("history_storage_corrupt", "Computer History returned an invalid response")
    events = payload.get("events")
    if not isinstance(events, list) or len(events) > 200 or payload.get("metadata_only") is not True or payload.get("model_context_disclosure") is not True:
        return _error("history_storage_corrupt", "Computer History returned an invalid response")
    sanitized_events = []
    for event in events:
        sanitized = _sanitize_event(event)
        if sanitized is None:
            return _error("history_storage_corrupt", "Computer History returned an invalid event")
        sanitized_events.append(sanitized)
    return json.dumps(
        {
            "events": sanitized_events,
            "metadata_only": True,
            "model_context_disclosure": True,
        },
        ensure_ascii=False,
    )


def _status_handler(args: dict[str, Any], **kwargs: Any) -> str:
    return history_status(args, session_id=str(kwargs.get("session_id") or kwargs.get("task_id") or ""))


def _query_handler(args: dict[str, Any], **kwargs: Any) -> str:
    return history_query(args, session_id=str(kwargs.get("session_id") or kwargs.get("task_id") or ""))


registry.register(
    name="history_status",
    toolset="computer_history",
    schema=_STATUS_SCHEMA,
    handler=_status_handler,
    check_fn=check_history_status_requirements,
    requires_env=[],
    emoji="🧭",
)

registry.register(
    name="history_query",
    toolset="computer_history",
    schema=_QUERY_SCHEMA,
    handler=_query_handler,
    check_fn=check_history_query_requirements,
    requires_env=[],
    emoji="🧭",
)


__all__ = [
    "HISTORY_STATUS_SCHEMA",
    "HISTORY_QUERY_SCHEMA",
    "check_history_status_requirements",
    "check_history_query_requirements",
    "history_status",
    "history_query",
]

HISTORY_STATUS_SCHEMA = _STATUS_SCHEMA
HISTORY_QUERY_SCHEMA = _QUERY_SCHEMA

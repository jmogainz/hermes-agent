"""Model-facing generic native-auth v2 surface tool."""

from __future__ import annotations

from typing import Any

from tools.native_auth_runtime import (
    NativeAuthRuntime,
    NativeAuthSecurityError,
    native_auth_runtime,
)
from tools.registry import registry, tool_error, tool_result


NATIVE_AUTH_SCHEMA = {
    "name": "native_auth",
    "description": (
        "Inspect a named browser session for safe authentication controls, then "
        "present one generic secure UI surface using only the returned opaque refs."
    ),
    "parameters": {
        "type": "object",
        "additionalProperties": False,
        "properties": {
            "action": {
                "type": "string",
                "enum": ["inspect", "present"],
            },
            "browser_session": {
                "type": "string",
                "description": "The named browser session to inspect.",
            },
            "snapshot_id": {
                "type": "string",
                "description": "The short-lived snapshot id returned by inspect.",
            },
            "surface": {
                "type": "object",
                "description": "A bounded tree of generic stack, text, input, and action nodes.",
            },
        },
        "required": ["action"],
    },
}


def _validate_args(args: Any) -> tuple[str, dict[str, Any]]:
    if not isinstance(args, dict):
        raise NativeAuthSecurityError("native auth input must be an object")
    action = args.get("action")
    if action not in {"inspect", "present"}:
        raise NativeAuthSecurityError("native auth action is invalid")
    if action == "inspect":
        if set(args) != {"action", "browser_session"}:
            raise NativeAuthSecurityError("native auth inspect input is invalid")
        if not isinstance(args.get("browser_session"), str):
            raise NativeAuthSecurityError("browser session is invalid")
    else:
        if set(args) != {"action", "snapshot_id", "surface"}:
            raise NativeAuthSecurityError("native auth present input is invalid")
        if not isinstance(args.get("snapshot_id"), str):
            raise NativeAuthSecurityError("native auth snapshot is invalid")
        if not isinstance(args.get("surface"), dict):
            raise NativeAuthSecurityError("native auth surface must be an object")
    return action, args


def native_auth_tool(args: dict[str, Any], **kwargs: Any) -> str:
    """Dispatch the small model surface; task identity and runtime stay trusted."""
    try:
        action, validated = _validate_args(args)
        runtime = kwargs.get("runtime") or kwargs.get("native_auth_runtime") or native_auth_runtime
        task_id = kwargs.get("task_id")
        if not isinstance(runtime, NativeAuthRuntime):
            raise NativeAuthSecurityError("native auth runtime unavailable")
        if action == "inspect":
            result = runtime.inspect_v2(
                task_id=task_id,
                browser_session=validated["browser_session"],
            )
        else:
            component = runtime.present_v2(
                task_id=task_id,
                snapshot_id=validated["snapshot_id"],
                surface=validated["surface"],
            )
            result = runtime.wait_for_v2_component(
                component["component_id"],
                task_id=task_id,
            )
        return tool_result(result)
    except NativeAuthSecurityError as exc:
        return tool_error(str(exc))
    except Exception:
        return tool_error("native auth operation unavailable")


registry.register(
    name="native_auth",
    toolset="browser",
    schema=NATIVE_AUTH_SCHEMA,
    handler=native_auth_tool,
    emoji="🔐",
)


__all__ = ["NATIVE_AUTH_SCHEMA", "native_auth_tool"]

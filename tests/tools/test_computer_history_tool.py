"""Contract tests for the Cua Driver Computer History adapter."""

from __future__ import annotations

import json

from tools import computer_history_tool as history


def _event(*, extra_data: dict | None = None) -> dict:
    event = {
        "specversion": "1.0",
        "id": "a" * 32,
        "source": "urn:cua-driver:history:" + "b" * 32,
        "type": "cua-driver.history.action_completed.v0",
        "subject": "action/" + "c" * 32,
        "time": "2026-08-28T12:00:00Z",
        "datacontenttype": "application/json",
        "dataschema": "urn:cua-driver:schema:history-event:v0",
        "data": {
            "session_id": "d" * 32,
            "action_id": "e" * 32,
            "sequence": 42,
            "platform": "macos",
            "process_model": "in_daemon",
            "capability": "computer.pointer.click",
            "caller_category": "cua_runtime",
            "application": {
                "bundle_id": "com.example.synthetic",
                "display_name": "Example App",
            },
            "payload": {
                "kind": "action_completed",
                "effect": "confirmed",
                "route": "accessibility",
                "delivery": "background",
                "delivered_count": 1,
                "evidence_kinds": ["accessibility_readback"],
            },
        },
    }
    if extra_data:
        event["data"].update(extra_data)
    return event


def test_status_returns_only_published_operational_metadata(monkeypatch):
    calls = []

    def fake_call(name, args, session_id):
        calls.append((name, args, session_id))
        return {
            "isError": False,
            "structuredContent": {
                "supported": True,
                "admitted": True,
                "enabled": False,
                "paused": False,
                "encrypted": True,
                "profile": "cua-history-profile-v1/cbor-sequence+cose-encrypt0+cloudevents-json",
                "retention_days": 7,
                "quota_bytes": 104857600,
                "bytes_used": 128,
                "dropped_events": 0,
                "health": "disabled",
                "secret_field": "must not escape",
            },
        }

    monkeypatch.setattr(history, "_call_cua_read_only_tool", fake_call)

    result = json.loads(history.history_status({}, session_id="session-1"))

    assert calls == [("history_status", {}, "session-1")]
    assert result == {
        "supported": True,
        "admitted": True,
        "enabled": False,
        "paused": False,
        "encrypted": True,
        "profile": "cua-history-profile-v1/cbor-sequence+cose-encrypt0+cloudevents-json",
        "retention_days": 7,
        "quota_bytes": 104857600,
        "bytes_used": 128,
        "dropped_events": 0,
        "health": "disabled",
    }


def test_query_validates_bounds_and_sanitizes_metadata_only_events(monkeypatch):
    calls = []

    def fake_call(name, args, session_id):
        calls.append((name, args, session_id))
        return {
            "isError": False,
            "structuredContent": {
                "events": [_event()],
                "metadata_only": True,
                "model_context_disclosure": True,
            },
        }

    monkeypatch.setattr(history, "_call_cua_read_only_tool", fake_call)

    result = json.loads(
        history.history_query(
            {"limit": 20, "session_id": "f" * 32, "since_sequence": 40},
            session_id="session-2",
        )
    )

    assert calls == [
        (
            "history_query",
            {"limit": 20, "session_id": "f" * 32, "since_sequence": 40},
            "session-2",
        )
    ]
    assert result["metadata_only"] is True
    assert result["model_context_disclosure"] is True
    assert result["events"] == [_event()]


def test_query_rejects_unknown_fields_and_reversed_ranges_without_calling_driver(monkeypatch):
    calls = []
    monkeypatch.setattr(
        history,
        "_call_cua_read_only_tool",
        lambda name, args, session_id: calls.append((name, args, session_id)),
    )

    unknown = json.loads(history.history_query({"limit": 1, "url": "https://bad"}, session_id="s"))
    reversed_range = json.loads(
        history.history_query({"since_sequence": 9, "until_sequence": 2}, session_id="s")
    )
    bad_limit = json.loads(history.history_query({"limit": 201}, session_id="s"))

    assert unknown["code"] == "invalid_history_query"
    assert reversed_range["code"] == "invalid_history_query_range"
    assert bad_limit["code"] == "invalid_history_query"
    assert calls == []


def test_query_fails_closed_on_an_event_outside_the_rfc_schema(monkeypatch):
    monkeypatch.setattr(
        history,
        "_call_cua_read_only_tool",
        lambda name, args, session_id: {
            "isError": False,
            "structuredContent": {
                "events": [_event(extra_data={"url": "https://must-not-escape"})],
                "metadata_only": True,
                "model_context_disclosure": True,
            },
        },
    )

    result = json.loads(history.history_query({}, session_id="session-3"))

    assert result == {
        "error": "Computer History returned an invalid event",
        "code": "history_storage_corrupt",
    }


def test_status_preserves_cua_authorization_refusal_as_safe_code(monkeypatch):
    monkeypatch.setattr(
        history,
        "_call_cua_read_only_tool",
        lambda name, args, session_id: {
            "isError": True,
            "structuredContent": {
                "status": "refused",
                "refusal": {
                    "code": "authorization_required",
                    "message": "no request-bound confirmation provider is available",
                },
            },
        },
    )

    result = json.loads(history.history_status({}, session_id="session-auth"))

    assert result["code"] == "history_authorization_required"
    assert "request-bound" not in json.dumps(result)


def test_discovery_requires_the_exact_advertised_tool(monkeypatch):
    class Completed:
        returncode = 0
        stdout = json.dumps(
            {
                "supported": True,
                "admitted": True,
                "enabled": False,
                "paused": False,
                "encrypted": True,
                "health": "disabled",
            }
        )
        stderr = ""

    monkeypatch.setattr(history, "_resolve_cua_driver_cmd", lambda: "/usr/local/bin/cua-driver")
    monkeypatch.setattr(history, "_cua_driver_child_env", lambda: {"SAFE": "1"})
    monkeypatch.setattr(history.subprocess, "run", lambda *args, **kwargs: Completed())

    assert history._history_tool_advertised("history_status") is True
    assert history._history_tool_advertised("history_query") is True


def test_discovery_stays_off_when_the_daemon_is_not_admitted(monkeypatch):
    class Completed:
        returncode = 0
        stdout = json.dumps(
            {
                "supported": True,
                "admitted": False,
                "enabled": False,
                "paused": False,
                "encrypted": True,
                "health": "not_admitted",
            }
        )
        stderr = ""

    monkeypatch.setattr(history, "_resolve_cua_driver_cmd", lambda: "/usr/local/bin/cua-driver")
    monkeypatch.setattr(history, "_cua_driver_child_env", lambda: {"SAFE": "1"})
    monkeypatch.setattr(history.subprocess, "run", lambda *args, **kwargs: Completed())

    assert history._history_tool_advertised("history_status") is False
    assert history._history_tool_advertised("history_query") is False


def test_history_admission_probe_sanitizes_hermes_provider_environment(monkeypatch):
    captured = {}

    class Completed:
        returncode = 0
        stdout = json.dumps(
            {
                "supported": True,
                "admitted": True,
                "enabled": False,
                "paused": False,
                "encrypted": True,
                "health": "disabled",
            }
        )
        stderr = ""

    def fake_run(*args, **kwargs):
        captured.update(kwargs)
        return Completed()

    monkeypatch.setattr(history, "_resolve_cua_driver_cmd", lambda: "/usr/local/bin/cua-driver")
    monkeypatch.setattr(
        history,
        "_cua_driver_child_env",
        lambda: {"PATH": "/usr/bin", "OPENAI_API_KEY": "synthetic-secret"},
    )
    monkeypatch.setattr(history.subprocess, "run", fake_run)

    assert history._history_tool_advertised("history_status") is True
    assert "OPENAI_API_KEY" not in captured["env"]


def test_history_tools_are_in_the_computer_history_toolset():
    from toolsets import TOOLSETS, _HERMES_CORE_TOOLS

    assert TOOLSETS["computer_history"]["tools"] == ["history_status", "history_query"]
    assert "history_status" in _HERMES_CORE_TOOLS
    assert "history_query" in _HERMES_CORE_TOOLS

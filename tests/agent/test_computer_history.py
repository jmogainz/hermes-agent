"""Tests for deterministic Computer History continuation hydration."""

from __future__ import annotations

import json
from types import SimpleNamespace

from agent.computer_history import (
    computer_history_context_for_agent,
    is_history_consultation_request,
)


def _status(*, admitted=True, enabled=False, paused=False, health="disabled"):
    return json.dumps(
        {
            "supported": True,
            "admitted": admitted,
            "enabled": enabled,
            "paused": paused,
            "encrypted": True,
            "profile": "cua-history-profile-v1/cbor-sequence+cose-encrypt0+cloudevents-json",
            "retention_days": 7,
            "quota_bytes": 104857600,
            "bytes_used": 100,
            "dropped_events": 0,
            "health": health,
        }
    )


def _event(sequence=42):
    return {
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
            "sequence": sequence,
            "platform": "macos",
            "process_model": "in_daemon",
            "caller_category": "cua_runtime",
            "capability": "computer.pointer.click",
            "application": {
                "bundle_id": "com.example.editor",
                "display_name": "Example Editor",
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


def test_continuation_matcher_accepts_standalone_resume_requests():
    assert is_history_consultation_request("continue") is True
    assert is_history_consultation_request("  Resume  ") is True
    assert is_history_consultation_request("where were we?") is True
    assert is_history_consultation_request("pick back up on the desktop task") is True


def test_continuation_matcher_does_not_trigger_for_unrelated_work():
    assert is_history_consultation_request("continue this sentence") is False
    assert is_history_consultation_request("search for a new Cua release") is False
    assert is_history_consultation_request("hello") is False


def test_agent_preflight_calls_status_then_one_bounded_query():
    calls = []

    def status(args, *, session_id):
        calls.append(("status", args, session_id))
        return _status()

    def query(args, *, session_id):
        calls.append(("query", args, session_id))
        return json.dumps(
            {
                "events": [_event()],
                "metadata_only": True,
                "model_context_disclosure": True,
            }
        )

    agent = SimpleNamespace(
        valid_tool_names={"history_status", "history_query"},
        session_id="hermes-session",
    )
    context = computer_history_context_for_agent(
        agent,
        "continue",
        status_tool=status,
        query_tool=query,
    )

    assert calls == [
        ("status", {}, "hermes-session"),
        ("query", {"limit": 50}, "hermes-session"),
    ]
    assert "metadata-only" in context
    assert '"sequence":42' in context
    assert "Example Editor" in context
    assert "https://" not in context


def test_preflight_preserves_paused_and_dropped_status_and_does_not_claim_completeness():
    def status(args, *, session_id):
        return json.dumps(
            json.loads(_status(paused=True, health="events_dropped"))
            | {"dropped_events": 3}
        )

    def query(args, *, session_id):
        return json.dumps(
            {
                "events": [],
                "metadata_only": True,
                "model_context_disclosure": True,
            }
        )

    agent = SimpleNamespace(
        valid_tool_names={"history_status", "history_query"},
        session_id="session-paused",
    )
    context = computer_history_context_for_agent(
        agent,
        "resume",
        status_tool=status,
        query_tool=query,
    )

    assert '"paused":true' in context
    assert '"health":"events_dropped"' in context
    assert '"dropped_events":3' in context
    assert "may be incomplete" in context


def test_preflight_degrades_without_history_tools_or_when_not_admitted():
    no_tools = SimpleNamespace(valid_tool_names={"computer_use"}, session_id="s")
    assert computer_history_context_for_agent(no_tools, "continue") == ""

    calls = []

    def status(args, *, session_id):
        calls.append("status")
        return _status(admitted=False, health="not_admitted")

    def query(args, *, session_id):
        calls.append("query")
        return "should not be called"

    agent = SimpleNamespace(
        valid_tool_names={"history_status", "history_query"},
        session_id="s",
    )
    context = computer_history_context_for_agent(
        agent,
        "continue",
        status_tool=status,
        query_tool=query,
    )
    assert calls == ["status"]
    assert "not_admitted" in context
    assert "\nevents=" not in context


def test_preflight_preserves_authorization_denial_without_retrying_query():
    calls = []

    def status(args, *, session_id):
        calls.append("status")
        return json.dumps(
            {
                "error": "Computer History status is unavailable or denied",
                "code": "history_authorization_required",
            }
        )

    def query(args, *, session_id):
        calls.append("query")
        return "should not be called"

    agent = SimpleNamespace(
        valid_tool_names={"history_status", "history_query"},
        session_id="s",
    )
    context = computer_history_context_for_agent(
        agent,
        "continue",
        status_tool=status,
        query_tool=query,
    )

    assert calls == ["status"]
    assert "history_authorization_required" in context
    assert "do not retry" in context.lower()

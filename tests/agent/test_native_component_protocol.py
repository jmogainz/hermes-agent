"""Tests for Hermes' model-response native-component handling."""

from __future__ import annotations

import json

from run_agent import AIAgent
from tools.native_auth_runtime import NativeAuthRuntime


def _runtime() -> NativeAuthRuntime:
    return NativeAuthRuntime(
        target_validator=lambda **_: None,
        action_executor=lambda **_: {"state": "submitted"},
    )


def _context(runtime: NativeAuthRuntime) -> dict:
    return runtime.create_context(
        task_id="session-1",
        browser_session_key="browser-session-1",
        browser_session_id="browser-session-1",
        provider_origin="https://example.com",
        path="/login",
        flow="password",
        fields=[
            {
                "field_id": "email",
                "kind": "email",
                "label": "Email",
                "required": True,
                "target": {"strategy": "css", "value": "input[type=email]"},
            },
            {
                "field_id": "password",
                "kind": "password",
                "label": "Password",
                "required": True,
                "target": {"strategy": "css", "value": "input[type=password]"},
            },
        ],
        actions=[
            {
                "action_id": "continue",
                "kind": "submit",
                "label": "Sign in",
                "target": {"strategy": "css", "value": "button[type=submit]"},
            }
        ],
        browser_backend="fake",
    )


def _agent(runtime: NativeAuthRuntime) -> AIAgent:
    agent = AIAgent.__new__(AIAgent)
    agent.session_id = "session-1"
    agent.native_auth_runtime = runtime
    agent.native_component_callback = None
    return agent


from agent.native_component_protocol import NativeComponentStreamFilter


def test_stream_filter_hides_native_component_marker_when_split_across_chunks():
    stream = NativeComponentStreamFilter()
    assert stream.feed("Before <semreh.native-") == "Before "
    assert stream.feed("component>{\"type\":\"semreh.native-component.v1\"}") == ""
    assert stream.feed("</semreh.native-component> After") == " After"


def test_stream_filter_bounds_unterminated_marker_buffer():
    stream = NativeComponentStreamFilter(max_buffer_bytes=32)
    assert stream.feed("<semreh.native-component>" + "x" * 100) == ""
    assert len(stream.buffered) <= 32


def test_handler_ignores_normal_assistant_text():
    result = _agent(_runtime()).handle_native_component_response("Just a normal answer.")
    assert result is None


def test_handler_canonicalizes_component_against_browser_context():
    runtime = _runtime()
    context = _context(runtime)
    agent = _agent(runtime)
    result = agent.handle_native_component_response(
        """<semreh.native-component>{
          "schema":"semreh.native-component.v1",
          "context_id":"%s",
          "title":"Sign in",
          "fields":[{"id":"password","kind":"password"}],
          "actions":[{"id":"continue","kind":"submit"}]
        }</semreh.native-component>""" % context["context_id"]
    )

    assert result["handled"] is True
    assert result["valid"] is True
    assert result["component"]["fields"][0]["target"]["value"] == "input[type=password]"
    assert result["component"]["actions"][0]["target"]["value"] == "button[type=submit]"
    assert "evil" not in json.dumps(result["component"])


def test_handler_rejects_model_credential_value_and_executable_target():
    runtime = _runtime()
    context = _context(runtime)
    agent = _agent(runtime)
    result = agent.handle_native_component_response(
        """<semreh.native-component>{
          "schema":"semreh.native-component.v1",
          "context_id":"%s",
          "fields":[{"id":"password","kind":"password","value":"synthetic-secret"}],
          "actions":[]
        }</semreh.native-component>""" % context["context_id"]
    )

    assert result["handled"] is True
    assert result["valid"] is False
    assert "synthetic-secret" not in json.dumps(result)


def test_handler_callback_receives_only_trusted_component_metadata():
    runtime = _runtime()
    context = _context(runtime)
    agent = _agent(runtime)
    callbacks = []
    agent.native_component_callback = callbacks.append
    result = agent.handle_native_component_response(
        """<semreh.native-component>{
          "schema":"semreh.native-component.v1",
          "context_id":"%s",
          "title":"Sign in",
          "fields":[{"id":"email","kind":"email"},{"id":"password","kind":"password"}],
          "actions":[{"id":"continue","kind":"submit"}]
        }</semreh.native-component>""" % context["context_id"]
    )

    assert result["valid"] is True
    assert len(callbacks) == 1
    assert callbacks[0]["component_id"] == result["component"]["component_id"]
    assert "synthetic-secret" not in json.dumps(callbacks[0])

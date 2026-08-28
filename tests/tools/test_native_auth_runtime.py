"""TDD coverage for the in-process native-auth secure-fill boundary."""

from __future__ import annotations

import base64
import json
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from tools.native_auth_runtime import (
    NativeAuthRuntime,
    NativeAuthSecurityError,
    derive_envelope_key,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _make_context(runtime: NativeAuthRuntime, *, task_id: str = "session-1") -> dict:
    return runtime.create_context(
        task_id=task_id,
        browser_session_id="browser-session-1",
        provider_origin="https://example.com",
        path="/login",
        flow="password",
        fields=[
            {
                "field_id": "identifier",
                "kind": "identifier",
                "label": "Email",
                "required": True,
                "target": {"strategy": "css", "value": "form input[name=email]"},
            },
            {
                "field_id": "secret",
                "kind": "secret",
                "label": "Password",
                "required": True,
                "target": {"strategy": "css", "value": "form input[type=password]"},
            },
        ],
        actions=[
            {
                "action_id": "continue",
                "kind": "submit",
                "label": "Continue",
                "target": {"strategy": "css", "value": "form button[type=submit]"},
            }
        ],
    )


def _encrypt(runtime: NativeAuthRuntime, context: dict, fields: dict[str, str], action_id: str = "continue") -> dict:
    client_private = X25519PrivateKey.from_private_bytes(_CLIENT_KEY_BYTES)
    runtime_public = base64.urlsafe_b64decode(context["runtime_public_key"] + "==")
    key = derive_envelope_key(
        private_key=client_private,
        peer_public_key=runtime_public,
        key_id=context["key_id"],
    )
    nonce = bytes(range(12))
    sequence = 1
    component_id = context["component_id"]
    aad = f"{component_id}:{sequence}:{context['key_id']}".encode()
    sealed = AESGCM(key).encrypt(
        nonce,
        json.dumps({"fields": fields, "action_id": action_id}).encode(),
        aad,
    )
    return {
        "schema": "semreh.native-secret-envelope.v1",
        "component_id": component_id,
        "sequence": sequence,
        "key_id": context["key_id"],
        "client_public_key": _b64(client_private.public_key().public_bytes_raw()),
        "nonce": _b64(nonce),
        "ciphertext": _b64(sealed[:-16]),
        "tag": _b64(sealed[-16:]),
    }


_CLIENT_KEY_BYTES = bytes(range(33, 65))


def _runtime_with_test_key() -> NativeAuthRuntime:
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        action_executor=lambda **_: {"state": "submitted"},
    )
    runtime._private_key = X25519PrivateKey.from_private_bytes(_RUNTIME_KEY_BYTES)
    return runtime


_RUNTIME_KEY_BYTES = bytes(range(1, 33))


def test_create_context_returns_sanitized_browser_issued_capabilities():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)

    assert context["schema"] == "hermes.auth-context.v1"
    assert context["path"] == "/login"
    assert context["provider_origin"] == "https://example.com"
    assert context["fields"][0]["browser_field_handle"]
    assert context["fields"][0]["target"]["strategy"] == "css"
    assert context["fields"][0]["target"]["value"] == "form input[name=email]"
    assert context["fields"][0]["target"]["target_id"].startswith("ref_")
    assert "value" not in context["fields"][0]
    assert "private_key" not in json.dumps(context)

    wire_context = runtime.public_auth_context(context["context_id"])
    assert wire_context["type"] == "hermes.auth-context.v1"
    assert wire_context["issued_by"] == "browser"
    assert wire_context["component_ids"]
    wire_components = runtime.public_components(context["component_id"])
    assert len(wire_components) == 3
    assert all(item["type"] == "semreh.native-component.v1" for item in wire_components)
    assert all(item["binding"]["match_count"] == 1 for item in wire_components)


def test_prepare_component_uses_runtime_targets_not_model_targets():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    component = runtime.prepare_component(
        {
            "schema": "semreh.native-component.v1",
            "context_id": context["context_id"],
            "title": "Sign in",
            "fields": [
                {
                    "id": "secret",
                    "kind": "secret",
                    "label": "Password",
                    "target": {"strategy": "css", "value": "input#evil"},
                }
            ],
            "actions": [{"id": "continue", "kind": "submit"}],
        },
        task_id="session-1",
    )

    assert component["fields"][0]["target"]["value"] == "form input[type=password]"
    assert component["fields"][0]["browser_field_handle"] == context["fields"][1]["browser_field_handle"]
    assert component["actions"][0]["target"]["value"] == "form button[type=submit]"
    assert component["runtime_public_key"] == context["runtime_public_key"]


def test_model_browser_input_is_blocked_while_context_pending_but_not_for_other_target():
    runtime = NativeAuthRuntime(target_validator=lambda **_: None, action_executor=lambda **_: {"state": "submitted"})
    context = _make_context(runtime)
    auth_ref = context["fields"][1]["target"]["value"]
    assert runtime.model_action_guard("session-1", auth_ref, action="type")
    assert runtime.model_code_guard("session-1", 'fill_input("input[type=password]", "x")')
    assert runtime.model_action_guard("session-1", "@e999", action="type") is None


def test_submit_decrypts_only_inside_executor_and_rejects_replay():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    fills: list[tuple[str, str, str]] = []

    def fake_executor(*, context, field, plaintext):
        fills.append((context["context_id"], field["field_id"], plaintext))
        return {"state": "filled", "field_id": field["field_id"]}

    runtime.set_fill_executor(fake_executor)
    envelope = _encrypt(runtime, context, {"identifier": "jacob@example.test", "secret": "synthetic-password"})
    result = runtime.submit_envelope(envelope, task_id="session-1")

    assert result["state"] == "submitted"
    assert fills == [
        (context["context_id"], "identifier", "jacob@example.test"),
        (context["context_id"], "secret", "synthetic-password"),
    ]
    assert "synthetic-password" not in json.dumps(result)
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(envelope, task_id="session-1")


def test_submit_rejects_wrong_task_and_expired_context_before_decrypting():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    envelope = _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"})

    with pytest.raises(NativeAuthSecurityError, match="session"):
        runtime.submit_envelope(envelope, task_id="different-session")

    runtime.expire_context(context["context_id"])
    with pytest.raises(NativeAuthSecurityError, match="expired"):
        runtime.submit_envelope(envelope, task_id="session-1")


def test_submit_rejects_unknown_field_and_model_supplied_target():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    envelope = _encrypt(
        runtime,
        context,
        {"identifier": "synthetic", "secret": "synthetic", "admin": "must-reject"},
    )

    with pytest.raises(NativeAuthSecurityError, match="field"):
        runtime.submit_envelope(envelope, task_id="session-1")


def test_component_marker_parser_rejects_credential_bearing_payload():
    from agent.native_component_protocol import extract_native_component

    marker = (
        '<semreh.native-component>\n'
        '{"schema":"semreh.native-component.v1","context_id":"context_1234567890",'
        '"fields":[{"id":"secret","kind":"secret","value":"must-not-cross"}]}'
        '\n</semreh.native-component>'
    )
    clean, component = extract_native_component(marker)
    assert component is None
    assert clean == ""


def test_component_marker_parser_extracts_bounded_metadata():
    from agent.native_component_protocol import extract_native_component

    marker = (
        'Before\n<semreh.native-component>'
        '{"schema":"semreh.native-component.v1","context_id":"context_1234567890",'
        '"title":"Sign in","fields":[],"actions":[]}'
        '</semreh.native-component>\nAfter'
    )
    clean, component = extract_native_component(marker)
    assert clean == "Before\n\nAfter"
    assert component["context_id"] == "context_1234567890"

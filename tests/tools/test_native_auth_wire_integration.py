"""Contract-level tests for Hermes' in-process native-auth runtime."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tools.native_auth_runtime import NativeAuthRuntime, NativeAuthSecurityError, derive_envelope_key


def _decode_b64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * ((4 - len(value) % 4) % 4))


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _context(runtime: NativeAuthRuntime, *, browser_backend: str = "fake", browser_session_name: str | None = None) -> dict:
    return runtime.create_context(
        task_id="session-123",
        browser_session_key="browser-session-123",
        browser_session_id="browser-session-123",
        provider_origin="https://accounts.example.test",
        path="/login",
        flow="password",
        fields=[
            {
                "field_id": "email",
                "kind": "email",
                "label": "Email",
                "required": True,
                "target": {"strategy": "css", "value": "form input[type=email]", "target_id": "ref_email_12345678"},
            },
            {
                "field_id": "password",
                "kind": "password",
                "label": "Password",
                "required": True,
                "target": {"strategy": "css", "value": "form input[type=password]", "target_id": "ref_password_12345678"},
            },
        ],
        actions=[
            {
                "action_id": "submit",
                "kind": "submit",
                "label": "Sign in",
                "target": {"strategy": "css", "value": "form button[type=submit]", "target_id": "ref_submit_12345678"},
            }
        ],
        browser_backend=browser_backend,
        browser_session_name=browser_session_name,
    )


def _wire_envelope(context: dict, components: list[dict]) -> dict:
    client_private = X25519PrivateKey.generate()
    runtime_public = X25519PublicKey.from_public_bytes(_decode_b64(context["runtime_public_key"]))
    key = derive_envelope_key(
        private_key=client_private,
        peer_public_key=runtime_public,
        key_id=context["key_id"],
    )
    envelope_id = "env_1234567890"
    plaintext = json.dumps(
        {
            "fields": {
                components[0]["field"]: "jacob@example.test",
                components[1]["field"]: "synthetic-password",
            },
            "action_handle": components[2]["action_handle"],
        },
        separators=(",", ":"),
    ).encode()
    aad = f"{context['context_id']}:{envelope_id}:{context['key_id']}".encode()
    nonce = bytes(range(12))
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return {
        "type": "semreh.native-secret-envelope.v1",
        "issued_by": "semreh-native",
        "immutable": True,
        "context_id": context["context_id"],
        "browser_session_id": context["browser_session_id"],
        "envelope_id": envelope_id,
        "provider_origin": context["provider_origin"],
        "path": context["path"],
        "cipher_suite": "AES-256-GCM",
        "key_id": context["key_id"],
        "client_public_key": _b64(client_private.public_key().public_bytes_raw()),
        "nonce": _b64(nonce),
        "ciphertext": _b64(sealed[:-16]),
        "tag": _b64(sealed[-16:]),
        "journal_policy": "never",
        "expires_at": "2099-01-01T00:00:00Z",
    }


def test_generated_wire_context_and_envelope_fill_same_session_once():
    fills: list[tuple[str, str]] = []
    actions: list[str] = []
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda *, field, plaintext, **_: fills.append((field["field_id"], plaintext)) or {"state": "filled"},
        action_executor=lambda *, action, **_: actions.append(action["id"]) or {"state": "submitted"},
    )
    context = _context(runtime)
    components = runtime.public_components(context["context_id"])
    envelope = _wire_envelope(context, components)

    result = runtime.submit_envelope(envelope, task_id="session-123")

    assert result["state"] == "submitted"
    assert fills == [("email", "jacob@example.test"), ("password", "synthetic-password")]
    assert actions == ["submit"]
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(envelope, task_id="session-123")
    with pytest.raises(NativeAuthSecurityError, match="another session"):
        runtime.submit_envelope(envelope | {"envelope_id": "env_1234567891"}, task_id="other-session")


def test_wire_submit_preflights_all_targets_before_any_plaintext_fill(monkeypatch):
    import tools.browser_use_cli as browser_use_cli
    import tools.native_auth_runtime as runtime_module

    events = []
    decrypted = [False]
    original_aesgcm = runtime_module.AESGCM

    class ObservedAESGCM:
        def __init__(self, key):
            self._inner = original_aesgcm(key)

        def decrypt(self, nonce, data, aad):
            decrypted[0] = True
            return self._inner.decrypt(nonce, data, aad)

    monkeypatch.setattr(runtime_module, "AESGCM", ObservedAESGCM)
    runtime = NativeAuthRuntime()
    context = _context(runtime, browser_backend="browser-use", browser_session_name="named-auth-session")
    components = runtime.public_components(context["context_id"])

    def fake_preflight(**kwargs):
        events.append(("preflight", decrypted[0]))
        return {"state": "validated"}

    def fake_fill(**kwargs):
        events.append(("fill", decrypted[0]))
        return {"state": "filled"}

    def fake_action(**kwargs):
        events.append(("action", decrypted[0]))
        return {"state": "submitted"}

    monkeypatch.setattr(browser_use_cli, "secure_native_preflight", fake_preflight)
    monkeypatch.setattr(browser_use_cli, "secure_native_fill", fake_fill)
    monkeypatch.setattr(browser_use_cli, "secure_native_action", fake_action)
    runtime.set_fill_executor(runtime._default_fill_executor)
    runtime.set_action_executor(runtime._default_action_executor)
    envelope = _wire_envelope(context, components)

    result = runtime.submit_envelope(envelope, task_id="session-123")

    assert result["state"] == "submitted"
    assert [kind for kind, _ in events[:3]] == ["preflight", "preflight", "preflight"]
    assert all(decrypted_flag is False for _, decrypted_flag in events[:3])
    assert [kind for kind, _ in events[3:]] == ["fill", "fill", "action"]
    assert all(decrypted_flag is True for _, decrypted_flag in events[3:])


def test_each_auth_context_owns_an_ephemeral_key_and_old_context_remains_decryptable():
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=lambda **_: {"state": "submitted"},
    )
    first = _context(runtime)
    second = _context(runtime)

    assert first["runtime_public_key"] != second["runtime_public_key"]
    assert first["key_id"] != second["key_id"]
    assert runtime._contexts[first["context_id"]].private_key is not runtime._contexts[second["context_id"]].private_key

    result = runtime.submit_envelope(_wire_envelope(first, runtime.public_components(first["context_id"])), task_id="session-123")

    assert result["state"] == "submitted"


def test_public_auth_context_exposes_ephemeral_key_metadata_only():
    runtime = NativeAuthRuntime(target_validator=lambda **_: None, action_executor=lambda **_: {"state": "submitted"})
    context = _context(runtime)
    projected = runtime.public_auth_context(context["context_id"])

    assert projected["runtime_public_key"] == context["runtime_public_key"]
    assert projected["key_id"] == context["key_id"]
    assert isinstance(projected["expires_at"], str)
    assert "private_key" not in json.dumps(projected)


def test_browser_use_context_requires_browser_issued_target_ids():
    runtime = NativeAuthRuntime()
    with pytest.raises(NativeAuthSecurityError, match="target id"):
        runtime.create_context(
            task_id="session-123",
            browser_session_key="browser-session-123",
            browser_session_id="browser-session-123",
            provider_origin="https://accounts.example.test",
            path="/login",
            flow="password",
            fields=[{
                "field_id": "password",
                "kind": "password",
                "label": "Password",
                "required": True,
                "target": {"strategy": "css", "value": "input[type=password]"},
            }],
            actions=[],
            browser_backend="browser-use",
            browser_session_name="named-auth-session",
        )


def test_named_browser_session_is_carried_only_in_runtime_private_state():
    runtime = NativeAuthRuntime(target_validator=lambda **_: None, action_executor=lambda **_: {"state": "submitted"})
    context = runtime.create_context(
        task_id="session-123",
        browser_session_key="browser-session-123",
        browser_session_id="browser-session-123",
        provider_origin="https://accounts.example.test",
        path="/login",
        flow="password",
        fields=[{
            "field_id": "password",
            "kind": "password",
            "label": "Password",
            "required": True,
            "target": {"strategy": "css", "value": "input[type=password]", "target_id": "ref_password_12345678"},
        }],
        actions=[{
            "action_id": "submit",
            "kind": "submit",
            "label": "Sign in",
            "target": {"strategy": "css", "value": "button[type=submit]", "target_id": "ref_submit_12345678"},
        }],
        browser_backend="browser-use",
        browser_session_name="named-auth-session",
    )
    assert runtime._contexts[context["context_id"]].browser_session_name == "named-auth-session"
    assert runtime._contexts[context["context_id"]].browser_backend == "browser-use"
    assert "_browser_session_name" not in runtime._contexts[context["context_id"]].public
    assert "_browser_session_key" not in runtime._contexts[context["context_id"]].public
    assert "_browser_session_name" not in runtime.public_auth_context(context["context_id"])


def test_wire_component_projection_is_schema_shaped_and_model_cannot_change_target():
    runtime = NativeAuthRuntime(target_validator=lambda **_: None, action_executor=lambda **_: {"state": "submitted"})
    context = _context(runtime)
    components = runtime.public_components(context["context_id"])

    assert {component["kind"] for component in components} == {"identifier", "secret", "submit"}
    assert all(component["issued_by"] == "browser" and component["immutable"] is True for component in components)
    assert all(component["binding"]["target_ref"]["issued_by"] == "browser" for component in components)
    prepared = runtime.prepare_component(
        {
            "schema": "semreh.native-component.v1",
            "context_id": context["context_id"],
            "fields": [{"id": "password", "kind": "password"}],
            "actions": [{"id": "submit", "kind": "submit"}],
        },
        task_id="session-123",
    )
    assert all("target" in field for field in prepared["fields"])
    assert "input[type=password]" in json.dumps(prepared)
    assert "model" not in json.dumps(prepared)

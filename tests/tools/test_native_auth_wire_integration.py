"""Contract-level tests for Hermes' in-process native-auth runtime."""

from __future__ import annotations

import base64
import json
import threading
import time

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


def _wire_envelope(
    context: dict,
    components: list[dict],
    plaintext_override: bytes | None = None,
) -> dict:
    client_private = X25519PrivateKey.generate()
    runtime_public = X25519PublicKey.from_public_bytes(_decode_b64(context["runtime_public_key"]))
    key = derive_envelope_key(
        private_key=client_private,
        peer_public_key=runtime_public,
        key_id=context["key_id"],
    )
    envelope_id = "env_1234567890"
    plaintext = plaintext_override if plaintext_override is not None else json.dumps(
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


def _v2_runtime_component(
    *,
    v2_prepare_executor=None,
    v2_apply_executor=None,
    quarantine_executor=None,
    timeout_seconds: float = 30,
) -> tuple[NativeAuthRuntime, dict, dict[str, str]]:
    runtime = NativeAuthRuntime(
        timeout_seconds=timeout_seconds,
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "path": "/login",
            "targets": [
                {"ref": "@e1", "role": "textbox", "label": "Email", "hints": {"required": True}, "target": "private-email-target"},
                {"ref": "@e2", "role": "textbox", "label": "Passcode", "hints": {"required": True, "masked": True}, "target": "private-passcode-target"},
                {"ref": "@e3", "role": "button", "label": "Continue", "target": "private-submit-target"},
                {"ref": "@e4", "role": "button", "label": "Use another", "target": "private-other-target"},
            ],
        },
        v2_component_publisher=lambda _: None,
        v2_prepare_executor=v2_prepare_executor or (lambda **_: object()),
        v2_apply_executor=v2_apply_executor or (lambda **_: {"state": "submitted"}),
        quarantine_executor=quarantine_executor,
    )
    snapshot = runtime.inspect_v2(task_id="session-v2", browser_session="named-login")
    component = runtime.present_v2(
        task_id="session-v2",
        snapshot_id=snapshot["snapshot_id"],
        surface={
            "type": "stack",
            "id": "root",
            "children": [
                {"type": "input", "id": "email", "label": "Email", "ref": "@e1"},
                {"type": "input", "id": "passcode", "label": "Passcode", "ref": "@e2"},
                {"type": "action", "id": "continue", "label": "Continue", "ref": "@e3"},
                {"type": "action", "id": "alternate", "label": "Use another", "ref": "@e4"},
            ],
        },
    )
    nodes = component["surface"]["children"]
    return runtime, component, {
        "email": nodes[0]["binding_id"],
        "passcode": nodes[1]["binding_id"],
        "continue": nodes[2]["binding_id"],
        "alternate": nodes[3]["binding_id"],
    }


def _v2_envelope(
    component: dict,
    values: dict[str, str],
    action_binding_id: str,
    *,
    envelope_id: str = "env_v2_wire_123456",
    plaintext_override: bytes | None = None,
) -> dict:
    client_private = X25519PrivateKey.generate()
    runtime_public = X25519PublicKey.from_public_bytes(_decode_b64(component["runtime_public_key"]))
    key = derive_envelope_key(
        private_key=client_private,
        peer_public_key=runtime_public,
        key_id=component["key_id"],
    )
    plaintext = plaintext_override if plaintext_override is not None else json.dumps(
        {"values": values, "action_binding_id": action_binding_id},
        separators=(",", ":"),
    ).encode()
    aad = f"{component['component_id']}:{envelope_id}:{component['key_id']}".encode("ascii")
    sealed = AESGCM(key).encrypt(bytes(range(12)), plaintext, aad)
    return {
        "type": "semreh.native-secret-envelope.v2",
        "issued_by": "semreh-native",
        "immutable": True,
        "component_id": component["component_id"],
        "envelope_id": envelope_id,
        "sequence": 1,
        "cipher_suite": "AES-256-GCM",
        "key_id": component["key_id"],
        "client_public_key": _b64(client_private.public_key().public_bytes_raw()),
        "nonce": _b64(bytes(range(12))),
        "ciphertext": _b64(sealed[:-16]),
        "tag": _b64(sealed[-16:]),
        "journal_policy": "never",
    }


def test_generated_wire_context_and_envelope_exact_retry_is_idempotent():
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
    assert runtime.submit_envelope(envelope, task_id="session-123") == result
    assert fills == [("email", "jacob@example.test"), ("password", "synthetic-password")]
    assert actions == ["submit"]
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(envelope | {"ciphertext": envelope["ciphertext"] + "A"}, task_id="session-123")
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


def test_browser_context_callback_bridge_is_opaque():
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        action_executor=lambda **_: {"state": "submitted"},
    )
    context = _context(runtime)
    received = []
    runtime.register_component_callback("session-123", received.append)

    assert runtime.notify_component(context["context_id"], task_id="session-123") is True
    assert received == [{"component_id": context["context_id"]}]
    assert "provider_origin" not in json.dumps(received)
    assert "target" not in json.dumps(received)


def test_wire_submit_cancel_race_has_one_terminal_outcome():
    entered_preflight = threading.Event()
    release_preflight = threading.Event()
    effects: list[str] = []

    def blocking_validator(**_):
        if not entered_preflight.is_set():
            entered_preflight.set()
            assert release_preflight.wait(2)

    runtime = NativeAuthRuntime(
        target_validator=blocking_validator,
        fill_executor=lambda **_: effects.append("fill") or {"state": "filled"},
        action_executor=lambda **_: effects.append("submit") or {"state": "submitted"},
    )
    context = _context(runtime)
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    outcomes: dict[str, dict] = {}

    submit_thread = threading.Thread(
        target=lambda: outcomes.setdefault("submit", runtime.submit_envelope(envelope, task_id="session-123"))
    )
    cancel_thread = threading.Thread(
        target=lambda: outcomes.setdefault(
            "cancel", runtime.cancel_context(context["context_id"], task_id="session-123")
        )
    )
    submit_thread.start()
    assert entered_preflight.wait(2)
    cancel_thread.start()
    cancel_was_blocked = cancel_thread.is_alive()
    release_preflight.set()
    submit_thread.join(2)
    cancel_thread.join(2)

    assert cancel_was_blocked
    assert outcomes["submit"]["state"] == "submitted"
    assert outcomes["cancel"]["state"] == "submitted"
    assert effects == ["fill", "fill", "submit"]


def test_wire_crypto_failure_is_sanitized_cached_and_bounded():
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        max_terminal_entries=1,
    )
    context = _context(runtime)
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    broken = envelope | {"tag": _b64(b"x" * 16)}
    states = []
    runtime.set_status_callback(context["context_id"], lambda state: states.append(state["state"]))

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(broken, task_id="session-123")
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(broken, task_id="session-123")
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(broken | {"ciphertext": broken["ciphertext"] + "A"}, task_id="session-123")

    assert states == ["failed"]
    assert context["context_id"] not in runtime._contexts
    assert len(runtime._wire_consumed_envelopes) <= 1
    assert len(runtime._terminal_outcomes) <= 1
    assert "synthetic-password" not in repr(runtime._terminal_outcomes)
    assert broken["ciphertext"] not in repr(runtime._terminal_outcomes)


@pytest.mark.parametrize("plaintext", [b"\xff", b"not-json"])
def test_wire_invalid_utf8_and_json_are_sanitized_terminal_failures(plaintext):
    runtime = NativeAuthRuntime(target_validator=lambda **_: None)
    context = _context(runtime)
    envelope = _wire_envelope(
        context,
        runtime.public_components(context["context_id"]),
        plaintext_override=plaintext,
    )
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-123")
    assert context["context_id"] not in runtime._contexts


def test_wire_cancel_wins_inverse_race():
    runtime = NativeAuthRuntime(target_validator=lambda **_: None)
    context = _context(runtime)
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    entered = threading.Event()
    release = threading.Event()
    outcomes = {}

    def status(state):
        if state["state"] == "cancelled":
            entered.set()
            assert release.wait(2)

    runtime.set_status_callback(context["context_id"], status)
    cancel_thread = threading.Thread(target=lambda: outcomes.setdefault("cancel", runtime.cancel_context(context["context_id"], task_id="session-123")))

    def submit():
        try:
            runtime.submit_envelope(envelope, task_id="session-123")
        except NativeAuthSecurityError as exc:
            outcomes["submit"] = str(exc)

    cancel_thread.start()
    assert entered.wait(2)
    submit_thread = threading.Thread(target=submit)
    submit_thread.start()
    assert submit_thread.is_alive()
    release.set()
    cancel_thread.join(2)
    submit_thread.join(2)
    assert outcomes["cancel"]["state"] == "cancelled"
    assert outcomes["submit"] == "auth component cancelled"


def test_wire_failure_wins_cancel_and_exact_retry_cancel_races():
    entered = threading.Event()
    release = threading.Event()

    def fail(**_):
        entered.set()
        assert release.wait(2)
        raise NativeAuthSecurityError("private-canary")

    runtime = NativeAuthRuntime(target_validator=fail)
    context = _context(runtime)
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    outcomes = {}

    def submit_failure():
        try:
            runtime.submit_envelope(envelope, task_id="session-123")
        except NativeAuthSecurityError as exc:
            outcomes["submit"] = str(exc)

    submit_thread = threading.Thread(target=submit_failure)
    submit_thread.start()
    assert entered.wait(2)
    cancel_thread = threading.Thread(target=lambda: outcomes.setdefault("cancel", runtime.cancel_context(context["context_id"], task_id="session-123")))
    cancel_thread.start()
    release.set()
    submit_thread.join(2)
    cancel_thread.join(2)
    assert outcomes["submit"] == "native auth submission failed"
    assert outcomes["cancel"]["state"] == "failed"

    successful = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=lambda **_: {"state": "submitted"},
    )
    successful_context = _context(successful)
    successful_envelope = _wire_envelope(successful_context, successful.public_components(successful_context["context_id"]))
    original = successful.submit_envelope(successful_envelope, task_id="session-123")
    race_results = []
    threads = [
        threading.Thread(target=lambda: race_results.append(successful.submit_envelope(successful_envelope, task_id="session-123"))),
        threading.Thread(target=lambda: race_results.append(successful.cancel_context(successful_context["context_id"], task_id="session-123"))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert race_results == [original, original]


def test_trusted_browser_context_hold_survives_cleanup_and_releases_once(monkeypatch):
    from tools import browser_tool

    monkeypatch.setattr(browser_tool, "_browser_session_holds", {})
    monkeypatch.setattr(browser_tool, "_browser_hold_tokens", {})
    now = 50_000.0
    monkeypatch.setattr(browser_tool.time, "time", lambda: now)
    monkeypatch.setattr(browser_tool, "_session_last_activity", {"bu-named-ha1-pending-auth": now - 500})
    monkeypatch.setattr(browser_tool, "_active_sessions", {"bu-named-ha1-pending-auth": {"session_name": "held"}})
    cleaned = []
    monkeypatch.setattr(browser_tool, "cleanup_browser", cleaned.append)
    releases = []
    original_release = browser_tool.release_browser_session_hold

    def observed_release(token):
        releases.append(token)
        original_release(token)

    monkeypatch.setattr(browser_tool, "release_browser_session_hold", observed_release)
    runtime = NativeAuthRuntime(timeout_seconds=900, target_validator=lambda **_: None)
    context = _context(runtime, browser_backend="browser-use", browser_session_name="ha1-pending-auth")
    internal = runtime._contexts[context["context_id"]]
    token = internal.browser_hold_token
    assert token and "browser_hold_token" not in json.dumps(context)

    browser_tool._cleanup_inactive_browser_sessions()
    assert cleaned == []
    runtime.cancel_context(context["context_id"], task_id="session-123")
    runtime._remove_context(internal)
    assert releases == [token]
    assert browser_tool._browser_session_hold_active("bu-named-ha1-pending-auth", now=now) is False


def test_replacing_trusted_browser_context_releases_only_replaced_hold(monkeypatch):
    from tools import browser_tool

    acquired = []
    released = []
    monkeypatch.setattr(browser_tool, "acquire_browser_session_hold", lambda key, *, expires_at: acquired.append((key, expires_at)) or f"token-{len(acquired)}")
    monkeypatch.setattr(browser_tool, "release_browser_session_hold", released.append)
    runtime = NativeAuthRuntime(target_validator=lambda **_: None)
    first = _context(runtime, browser_backend="browser-use", browser_session_name="ha1-replaced")
    second = _context(runtime, browser_backend="browser-use", browser_session_name="ha1-replaced")

    assert first["context_id"] not in runtime._contexts
    assert second["context_id"] in runtime._contexts
    assert [key for key, _ in acquired] == ["bu-named-ha1-replaced", "bu-named-ha1-replaced"]
    assert released == ["token-1"]
    runtime.close_task("session-123")
    assert released == ["token-1", "token-2"]


@pytest.mark.parametrize("terminal", ["success", "failure", "cancel", "expire", "close"])
def test_trusted_browser_hold_releases_once_on_every_terminal_path(monkeypatch, terminal):
    from tools import browser_tool

    released = []
    monkeypatch.setattr(browser_tool, "acquire_browser_session_hold", lambda *_args, **_kwargs: "hold-token")
    monkeypatch.setattr(browser_tool, "release_browser_session_hold", released.append)
    runtime = NativeAuthRuntime(
        target_validator=(lambda **_: (_ for _ in ()).throw(NativeAuthSecurityError("canary"))) if terminal == "failure" else (lambda **_: None),
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=lambda **_: {"state": "submitted"},
    )
    context = _context(runtime, browser_backend="browser-use", browser_session_name=f"ha1-{terminal}")
    internal = runtime._contexts[context["context_id"]]

    if terminal in {"success", "failure"}:
        envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
        if terminal == "failure":
            with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
                runtime.submit_envelope(envelope, task_id="session-123")
        else:
            runtime.submit_envelope(envelope, task_id="session-123")
    elif terminal == "cancel":
        runtime.cancel_context(context["context_id"], task_id="session-123")
    elif terminal == "expire":
        runtime.expire_context(context["context_id"])
    else:
        runtime.close_task("session-123")

    runtime._remove_context(internal)
    assert released == ["hold-token"]


def test_post_mutation_fill_failure_quarantines_before_guard_and_hold_release(monkeypatch):
    from tools import browser_tool

    events: list[str] = []
    states: list[dict] = []
    fills: list[str] = []
    runtime: NativeAuthRuntime

    monkeypatch.setattr(browser_tool, "acquire_browser_session_hold", lambda *_args, **_kwargs: "hold-token")
    monkeypatch.setattr(browser_tool, "release_browser_session_hold", lambda _token: events.append("release"))

    def quarantine(**kwargs):
        assert kwargs == {
            "task_id": "session-123",
            "browser_session_name": "ha1-post-mutation",
            "tab_handle": context["tab_handle"],
        }
        assert runtime.model_browser_mutation_guard("session-123", action="click") is not None
        events.append("quarantine")

    def fill(*, field, **_kwargs):
        fills.append(field["field_id"])
        if field["field_id"] == "password":
            raise ConnectionError("ambiguous channel loss with secret-canary")
        return {"state": "filled"}

    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=fill,
        action_executor=lambda **_: events.append("action") or {"state": "submitted"},
        quarantine_executor=quarantine,
    )
    context = _context(runtime, browser_backend="browser-use", browser_session_name="ha1-post-mutation")
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    runtime.set_status_callback(context["context_id"], states.append)

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-123")
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-123")

    terminal = states[-1]
    assert terminal == {
        "schema": "semreh.native-component-state.v1",
        "component_id": context["component_id"],
        "state": "failed",
        "outcome": "remint_required",
        "reason": "browser_state_ambiguous",
    }
    assert [state["state"] for state in states].count("failed") == 1
    assert fills == ["email", "password"]
    assert events == ["quarantine", "release"]
    assert "secret-canary" not in json.dumps(terminal)


def test_wire_envelope_after_runtime_restart_returns_context_lost_remint():
    original = NativeAuthRuntime(target_validator=lambda **_: None)
    context = _context(original)
    envelope = _wire_envelope(context, original.public_components(context["context_id"]))
    restarted = NativeAuthRuntime(target_validator=lambda **_: None)

    result = restarted.submit_envelope(envelope, task_id="session-123")

    assert result == {
        "schema": "semreh.native-component-state.v1",
        "component_id": context["context_id"],
        "state": "context_lost",
        "outcome": "remint_required",
    }
    assert restarted.submit_envelope(envelope, task_id="session-123") == result


def test_first_browser_use_auth_context_reaps_dead_owner_artifacts_once(monkeypatch):
    import tools.browser_use_cli as browser_use_cli

    calls: list[int] = []
    monkeypatch.setattr(
        browser_use_cli,
        "reap_owned_browser_use_orphans",
        lambda *, limit=64: calls.append(limit) or 0,
    )
    runtime = NativeAuthRuntime(target_validator=lambda **_: None)

    _context(runtime, browser_backend="browser-use", browser_session_name="ha1-reap-first")
    _context(runtime, browser_backend="browser-use", browser_session_name="ha1-reap-second")

    assert calls == [64]


@pytest.mark.parametrize("failure_stage", ["preflight", "decrypt"])
def test_pre_mutation_failure_is_side_effect_free_and_does_not_quarantine(monkeypatch, failure_stage):
    import tools.browser_use_cli as browser_use_cli

    monkeypatch.setattr(browser_use_cli, "reap_owned_browser_use_orphans", lambda **_: 0)
    quarantines: list[dict] = []
    fills: list[str] = []
    actions: list[str] = []

    def validate(**_kwargs):
        if failure_stage == "preflight":
            raise RuntimeError("private-preflight-canary")

    runtime = NativeAuthRuntime(
        target_validator=validate,
        fill_executor=lambda **_: fills.append("fill") or {"state": "filled"},
        action_executor=lambda **_: actions.append("action") or {"state": "submitted"},
        quarantine_executor=lambda **kwargs: quarantines.append(kwargs),
    )
    context = _context(runtime, browser_backend="browser-use", browser_session_name=f"ha1-{failure_stage}")
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    if failure_stage == "decrypt":
        envelope = envelope | {"tag": _b64(b"x" * 16)}
    states: list[dict] = []
    runtime.set_status_callback(context["context_id"], states.append)

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-123")

    assert fills == []
    assert actions == []
    assert quarantines == []
    assert states == [{
        "schema": "semreh.native-component-state.v1",
        "component_id": context["component_id"],
        "state": "failed",
    }]


@pytest.mark.parametrize("terminal_operation", ["cancel", "expire"])
def test_terminal_operation_cannot_interleave_with_post_mutation_quarantine(monkeypatch, terminal_operation):
    import tools.browser_use_cli as browser_use_cli

    monkeypatch.setattr(browser_use_cli, "reap_owned_browser_use_orphans", lambda **_: 0)
    entered_quarantine = threading.Event()
    release_quarantine = threading.Event()
    actions: list[str] = []
    states: list[dict] = []
    outcomes: dict[str, object] = {}

    def ambiguous_action(**_kwargs):
        actions.append("action")
        raise TimeoutError("ambiguous action response")

    def quarantine(**_kwargs):
        entered_quarantine.set()
        assert release_quarantine.wait(2)

    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=ambiguous_action,
        quarantine_executor=quarantine,
    )
    context = _context(runtime, browser_backend="browser-use", browser_session_name=f"ha1-race-{terminal_operation}")
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))
    runtime.set_status_callback(context["context_id"], states.append)

    def submit():
        try:
            runtime.submit_envelope(envelope, task_id="session-123")
        except NativeAuthSecurityError as exc:
            outcomes["submit"] = str(exc)

    submit_thread = threading.Thread(target=submit)
    submit_thread.start()
    assert entered_quarantine.wait(2)
    if terminal_operation == "cancel":
        terminal_thread = threading.Thread(
            target=lambda: outcomes.setdefault(
                "terminal",
                runtime.cancel_context(context["context_id"], task_id="session-123"),
            )
        )
    else:
        terminal_thread = threading.Thread(
            target=lambda: outcomes.setdefault(
                "terminal",
                runtime.expire_context(context["context_id"]),
            )
        )
    terminal_thread.start()
    assert terminal_thread.is_alive()
    release_quarantine.set()
    submit_thread.join(2)
    terminal_thread.join(2)

    assert outcomes["submit"] == "native auth submission failed"
    if terminal_operation == "cancel":
        assert outcomes["terminal"]["outcome"] == "remint_required"
    else:
        assert outcomes["terminal"] is None
    assert actions == ["action"]
    assert [state["state"] for state in states].count("failed") == 1


def test_default_quarantine_targets_only_the_owning_browser_use_task(monkeypatch):
    import tools.browser_use_cli as browser_use_cli

    cleaned: list[str] = []
    monkeypatch.setattr(browser_use_cli, "reap_owned_browser_use_orphans", lambda **_: 0)
    monkeypatch.setattr(browser_use_cli, "cleanup_browser_use_task", cleaned.append)
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=lambda **_: (_ for _ in ()).throw(TimeoutError("lost response")),
    )
    context = _context(runtime, browser_backend="browser-use", browser_session_name="ha1-exact-owner")
    envelope = _wire_envelope(context, runtime.public_components(context["context_id"]))

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-123")

    assert cleaned == ["session-123"]


def test_v2_wire_envelope_has_exact_outer_shape_and_no_private_context_fields():
    runtime, component, ids = _v2_runtime_component()
    envelope = _v2_envelope(
        component,
        {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
        ids["continue"],
    )

    assert set(envelope) == {
        "type", "issued_by", "immutable", "component_id", "envelope_id", "sequence",
        "cipher_suite", "key_id", "client_public_key", "nonce", "ciphertext", "tag",
        "journal_policy",
    }
    assert envelope["type"] == "semreh.native-secret-envelope.v2"
    assert envelope["issued_by"] == "semreh-native"
    assert envelope["immutable"] is True
    assert envelope["sequence"] == 1
    assert envelope["cipher_suite"] == "AES-256-GCM"
    assert envelope["journal_policy"] == "never"
    wire = json.dumps(envelope)
    for forbidden in (
        "browser_session", "origin", "path", "selector", "target", "frame", "document",
        "backend", "value", "opaque-email-canary", "opaque-passcode-canary",
    ):
        assert forbidden not in wire


def test_v2_success_prepares_all_bindings_decrypts_exact_aad_applies_once_and_exact_retry_is_idempotent():
    events: list[tuple[str, object]] = []

    def prepare(*, component, bindings):
        assert component["component_id"]
        assert "ciphertext" not in json.dumps(component)
        assert all("value" not in binding for binding in bindings)
        assert {binding["binding_id"] for binding in bindings} == {
            ids["email"], ids["passcode"], ids["continue"], ids["alternate"],
        }
        events.append(("prepare", len(bindings)))
        return {"lease": "private-lease"}

    def apply(*, lease, values, action_binding_id):
        assert lease == {"lease": "private-lease"}
        assert values == {
            ids["email"]: "opaque-email-canary",
            ids["passcode"]: "opaque-passcode-canary",
        }
        assert action_binding_id == ids["continue"]
        events.append(("apply", action_binding_id))
        return {"state": "submitted"}

    runtime, component, ids = _v2_runtime_component(
        v2_prepare_executor=prepare,
        v2_apply_executor=apply,
    )
    envelope = _v2_envelope(
        component,
        {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
        ids["continue"],
    )
    original = runtime.submit_envelope(envelope, task_id="session-v2")

    assert original == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "submitted",
    }
    assert events == [("prepare", 4), ("apply", ids["continue"])]
    assert runtime.submit_envelope(envelope, task_id="session-v2") == original
    assert events == [("prepare", 4), ("apply", ids["continue"])]
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(envelope | {"ciphertext": envelope["ciphertext"] + "A"}, task_id="session-v2")
    assert "opaque-email-canary" not in json.dumps(original)
    assert "opaque-passcode-canary" not in json.dumps(original)


def test_v2_action_only_envelope_has_empty_values_and_selects_one_of_multiple_actions():
    applied: list[dict] = []
    runtime, _unused_component, _unused_ids = _v2_runtime_component(
        v2_apply_executor=lambda **kwargs: applied.append(kwargs) or {"state": "submitted"},
    )
    snapshot = runtime.inspect_v2(task_id="session-v2", browser_session="named-login")
    component = runtime.present_v2(
        task_id="session-v2",
        snapshot_id=snapshot["snapshot_id"],
        surface={"type": "action", "id": "alternate-only", "label": "Use another", "ref": "@e4"},
    )
    action_binding_id = component["surface"]["binding_id"]
    result = runtime.submit_envelope(
        _v2_envelope(component, {}, action_binding_id, envelope_id="env_v2_action_only_123"),
        task_id="session-v2",
    )

    assert result == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "submitted",
    }
    assert len(applied) == 1
    assert applied[0]["values"] == {}
    assert applied[0]["action_binding_id"] == action_binding_id


@pytest.mark.parametrize("case", ["missing_required", "unknown_binding", "cross_component", "wrong_shape"])
def test_v2_rejects_invalid_decrypted_binding_contract_before_apply(case):
    applied: list[dict] = []
    runtime, component, ids = _v2_runtime_component(
        v2_apply_executor=lambda **kwargs: applied.append(kwargs) or {"state": "submitted"},
    )
    values = {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"}
    plaintext_override = None
    if case == "missing_required":
        values.pop(ids["passcode"])
    elif case == "unknown_binding":
        values["bind_unknown_123456"] = "opaque-extra-canary"
    elif case == "cross_component":
        other_snapshot = runtime.inspect_v2(task_id="session-v2", browser_session="named-login")
        other = runtime.present_v2(
            task_id="session-v2",
            snapshot_id=other_snapshot["snapshot_id"],
            surface={"type": "action", "id": "other", "label": "Other", "ref": "@e3"},
        )
        values = {other["surface"]["binding_id"]: "opaque-cross-component-canary"}
    elif case == "wrong_shape":
        plaintext_override = json.dumps(
            {"values": values, "action_binding_id": ids["continue"], "extra": True},
            separators=(",", ":"),
        ).encode()

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(
            _v2_envelope(
                component,
                values,
                ids["continue"],
                envelope_id=f"env_v2_invalid_{case}_123",
                plaintext_override=plaintext_override,
            ),
            task_id="session-v2",
        )
    assert applied == []


def test_v2_rejects_duplicate_binding_keys_and_non_action_selection():
    runtime, component, ids = _v2_runtime_component()
    duplicate = (
        '{"values":{"%s":"first","%s":"second"},"action_binding_id":"%s"}'
        % (ids["email"], ids["email"], ids["continue"])
    ).encode()
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(
            _v2_envelope(component, {}, ids["continue"], envelope_id="env_v2_duplicate_123456", plaintext_override=duplicate),
            task_id="session-v2",
        )

    runtime, component, ids = _v2_runtime_component()
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(
            _v2_envelope(
                component,
                {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
                ids["email"],
                envelope_id="env_v2_input_action_123456",
            ),
            task_id="session-v2",
        )


def test_v2_rejects_wrong_task_key_sequence_shape_expired_and_replayed_envelopes():
    runtime, component, ids = _v2_runtime_component()
    required_values = {
        ids["email"]: "opaque-email-canary",
        ids["passcode"]: "opaque-passcode-canary",
    }
    envelope = _v2_envelope(component, required_values, ids["continue"], envelope_id="env_v2_wrong_task_123456")
    with pytest.raises(NativeAuthSecurityError, match="another session"):
        runtime.submit_envelope(envelope, task_id="other-session")

    runtime, component, ids = _v2_runtime_component()
    envelope = _v2_envelope(component, required_values, ids["continue"], envelope_id="env_v2_wrong_key_123456")
    with pytest.raises(NativeAuthSecurityError):
        runtime.submit_envelope(envelope | {"key_id": "key_wrong_123456"}, task_id="session-v2")

    runtime, component, ids = _v2_runtime_component()
    envelope = _v2_envelope(component, required_values, ids["continue"], envelope_id="env_v2_wrong_seq_123456")
    with pytest.raises(NativeAuthSecurityError):
        runtime.submit_envelope(envelope | {"sequence": 2}, task_id="session-v2")

    runtime, component, ids = _v2_runtime_component()
    envelope = _v2_envelope(component, required_values, ids["continue"], envelope_id="env_v2_wrong_shape_123456")
    with pytest.raises(NativeAuthSecurityError):
        runtime.submit_envelope(envelope | {"origin": "https://not-on-wire.test"}, task_id="session-v2")

    runtime, component, ids = _v2_runtime_component(timeout_seconds=0.01)
    envelope = _v2_envelope(component, required_values, ids["continue"], envelope_id="env_v2_expired_123456")
    time.sleep(0.05)
    with pytest.raises(NativeAuthSecurityError, match="expired"):
        runtime.submit_envelope(envelope, task_id="session-v2")

    runtime, component, ids = _v2_runtime_component()
    envelope = _v2_envelope(component, required_values, ids["continue"], envelope_id="env_v2_replay_123456")
    result = runtime.submit_envelope(envelope, task_id="session-v2")
    assert runtime.submit_envelope(envelope, task_id="session-v2") == result
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(envelope | {"ciphertext": envelope["ciphertext"] + "A"}, task_id="session-v2")


def test_v2_cancel_vs_submit_is_linearized_and_exactly_one_terminal_state_wins():
    entered_prepare = threading.Event()
    release_prepare = threading.Event()
    outcomes: dict[str, object] = {}

    def prepare(**_kwargs):
        entered_prepare.set()
        assert release_prepare.wait(2)
        return {"lease": "private-lease"}

    runtime, component, ids = _v2_runtime_component(v2_prepare_executor=prepare)
    envelope = _v2_envelope(
        component,
        {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
        ids["continue"],
        envelope_id="env_v2_cancel_race_123456",
    )
    submit_thread = threading.Thread(
        target=lambda: outcomes.setdefault("submit", runtime.submit_envelope(envelope, task_id="session-v2")),
    )
    cancel_thread = threading.Thread(
        target=lambda: outcomes.setdefault(
            "cancel", runtime.cancel_v2_component(component["component_id"], task_id="session-v2"),
        ),
    )
    submit_thread.start()
    assert entered_prepare.wait(2)
    cancel_thread.start()
    assert cancel_thread.is_alive()
    release_prepare.set()
    submit_thread.join(2)
    cancel_thread.join(2)

    assert not submit_thread.is_alive()
    assert not cancel_thread.is_alive()
    assert outcomes["submit"]["state"] == "submitted"
    assert outcomes["cancel"] == outcomes["submit"]


def test_v2_runtime_restart_returns_context_lost_remint_safe_state():
    runtime, component, ids = _v2_runtime_component()
    envelope = _v2_envelope(
        component,
        {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
        ids["continue"],
        envelope_id="env_v2_restart_123456",
    )
    restarted = NativeAuthRuntime()

    result = restarted.submit_envelope(envelope, task_id="session-v2")

    assert result == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "context_lost",
        "outcome": "remint_required",
    }
    assert restarted.submit_envelope(envelope, task_id="session-v2") == result


def test_v2_expiry_is_enforced_at_mutation_boundary(monkeypatch):
    import tools.native_auth_runtime as runtime_module

    entered_prepare = threading.Event()
    release_prepare = threading.Event()
    events: list[str] = []
    applies: list[str] = []
    quarantines: list[dict] = []
    outcome: dict[str, object] = {}
    original_aesgcm = runtime_module.AESGCM

    class ObservedAESGCM:
        def __init__(self, key):
            self._inner = original_aesgcm(key)

        def decrypt(self, nonce, data, aad):
            events.append("decrypt")
            return self._inner.decrypt(nonce, data, aad)

    def prepare(**_kwargs):
        events.append("prepare-entered")
        entered_prepare.set()
        assert release_prepare.wait(1)
        events.append("prepare-released")
        return {"lease": "private-lease"}

    def apply(**_kwargs):
        events.append("apply")
        applies.append("apply")
        return {"state": "submitted"}

    monkeypatch.setattr(runtime_module, "AESGCM", ObservedAESGCM)
    runtime, component, ids = _v2_runtime_component(
        v2_prepare_executor=prepare,
        v2_apply_executor=apply,
        quarantine_executor=lambda **kwargs: quarantines.append(kwargs),
        timeout_seconds=0.05,
    )
    envelope = _v2_envelope(
        component,
        {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
        ids["continue"],
        envelope_id="env_v2_expiry_boundary_123",
    )

    def submit():
        try:
            outcome["result"] = runtime.submit_envelope(envelope, task_id="session-v2")
        except BaseException as exc:  # Capture the worker result without losing its failure.
            outcome["error"] = exc

    submit_thread = threading.Thread(target=submit)
    submit_thread.start()
    assert entered_prepare.wait(1)

    deadline = runtime._v2_components[component["component_id"]].expires_at
    poll_deadline = time.monotonic() + 1
    while time.time() < deadline + 0.02:
        assert time.monotonic() < poll_deadline
        time.sleep(0.005)
    assert time.time() >= deadline + 0.02

    release_prepare.set()
    submit_thread.join(1)
    assert not submit_thread.is_alive()
    assert "result" not in outcome
    assert isinstance(outcome.get("error"), NativeAuthSecurityError)
    assert str(outcome["error"]) == "native auth envelope expired"
    assert applies == []
    assert quarantines == []
    assert events == ["prepare-entered", "prepare-released"]
    assert runtime.wait_for_v2_component(
        component["component_id"], task_id="session-v2", timeout=0,
    ) == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "expired",
    }


def test_v2_concurrent_identical_valid_submits_prepare_and_apply_once():
    entered_prepare = threading.Event()
    release_prepare = threading.Event()
    start_barrier = threading.Barrier(3)
    submit_started = [threading.Event(), threading.Event()]
    prepare_calls: list[str] = []
    apply_calls: list[str] = []
    quarantines: list[dict] = []
    outcomes: list[object] = [None, None]

    def prepare(**_kwargs):
        prepare_calls.append("prepare")
        entered_prepare.set()
        assert release_prepare.wait(1)
        return {"lease": "private-lease"}

    def apply(**_kwargs):
        apply_calls.append("apply")
        return {"state": "submitted"}

    runtime, component, ids = _v2_runtime_component(
        v2_prepare_executor=prepare,
        v2_apply_executor=apply,
        quarantine_executor=lambda **kwargs: quarantines.append(kwargs),
    )
    envelope = _v2_envelope(
        component,
        {ids["email"]: "opaque-email-canary", ids["passcode"]: "opaque-passcode-canary"},
        ids["continue"],
        envelope_id="env_v2_identical_concurrent_123",
    )

    def submit(index: int):
        try:
            start_barrier.wait(1)
            submit_started[index].set()
            outcomes[index] = runtime.submit_envelope(envelope, task_id="session-v2")
        except BaseException as exc:  # Keep thread failures explicit in the assertion below.
            outcomes[index] = exc

    threads = [threading.Thread(target=submit, args=(index,)) for index in range(2)]
    for thread in threads:
        thread.start()
    start_barrier.wait(1)
    assert all(event.wait(1) for event in submit_started)
    assert entered_prepare.wait(1)
    assert any(thread.is_alive() for thread in threads)

    release_prepare.set()
    for thread in threads:
        thread.join(1)
    assert all(not thread.is_alive() for thread in threads)
    assert all(isinstance(result, dict) for result in outcomes)
    expected = {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "submitted",
    }
    assert outcomes == [expected, expected]
    assert prepare_calls == ["prepare"]
    assert apply_calls == ["apply"]
    assert quarantines == []
    assert runtime.wait_for_v2_component(
        component["component_id"], task_id="session-v2", timeout=0,
    ) == expected
    assert runtime.submit_envelope(envelope, task_id="session-v2") == expected
    assert prepare_calls == ["prepare"]
    assert apply_calls == ["apply"]

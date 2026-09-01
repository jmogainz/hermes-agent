"""TDD coverage for the in-process native-auth secure-fill boundary."""

from __future__ import annotations

import base64
import json
import threading
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


def _encrypt(
    runtime: NativeAuthRuntime,
    context: dict,
    fields: dict[str, str],
    action_id: str = "continue",
    plaintext_override: bytes | None = None,
) -> dict:
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
        plaintext_override if plaintext_override is not None else json.dumps({"fields": fields, "action_id": action_id}).encode(),
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


def _v2_component_runtime(
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
                {"ref": "@e1", "role": "textbox", "label": "Account", "hints": {"required": True}, "target": "private-input"},
                {"ref": "@e2", "role": "button", "label": "Continue", "target": "private-submit"},
                {"ref": "@e3", "role": "button", "label": "Use another", "target": "private-alternate"},
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
                {"type": "input", "id": "account", "label": "Account", "ref": "@e1"},
                {"type": "action", "id": "continue", "label": "Continue", "ref": "@e2"},
                {"type": "action", "id": "alternate", "label": "Use another", "ref": "@e3"},
            ],
        },
    )
    nodes = component["surface"]["children"]
    return runtime, component, {
        "input": nodes[0]["binding_id"],
        "continue": nodes[1]["binding_id"],
        "alternate": nodes[2]["binding_id"],
    }


def _encrypt_v2(component: dict, values: dict[str, str], action_binding_id: str, *, envelope_id: str = "env_v2_runtime_123456") -> dict:
    client_private = X25519PrivateKey.from_private_bytes(_CLIENT_KEY_BYTES)
    runtime_public = base64.urlsafe_b64decode(component["runtime_public_key"] + "==")
    key = derive_envelope_key(
        private_key=client_private,
        peer_public_key=runtime_public,
        key_id=component["key_id"],
    )
    plaintext = json.dumps(
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


def test_submit_decrypts_once_and_exact_retry_returns_original_result():
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
    assert runtime.submit_envelope(envelope, task_id="session-1") == result
    assert fills == [
        (context["context_id"], "identifier", "jacob@example.test"),
        (context["context_id"], "secret", "synthetic-password"),
    ]
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(envelope | {"ciphertext": envelope["ciphertext"] + "A"}, task_id="session-1")


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

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
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


def test_v2_present_publication_failure_is_transactional(monkeypatch):
    import tools.native_auth_runtime as native_auth_runtime_module

    timers: list[threading.Timer] = []
    real_timer = native_auth_runtime_module.threading.Timer

    def tracking_timer(*args, **kwargs):
        timer = real_timer(*args, **kwargs)
        timers.append(timer)
        return timer

    monkeypatch.setattr(native_auth_runtime_module.threading, "Timer", tracking_timer)

    publish_calls = 0
    published: list[dict] = []

    def publisher(component):
        nonlocal publish_calls
        publish_calls += 1
        if publish_calls == 1:
            raise RuntimeError("publisher canary")
        published.append(component)

    runtime = NativeAuthRuntime(
        timeout_seconds=30,
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [{
                "ref": "@e1",
                "role": "button",
                "label": "Continue",
                "target": "private-submit",
            }],
        },
        v2_component_publisher=publisher,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    surface = {
        "type": "action",
        "id": "continue",
        "label": "Continue",
        "ref": "@e1",
    }

    with pytest.raises(NativeAuthSecurityError, match="^native auth publisher unavailable$"):
        runtime.present_v2(
            task_id="task-1",
            snapshot_id=snapshot["snapshot_id"],
            surface=surface,
        )

    assert runtime._v2_components == {}
    assert runtime._v2_snapshots[snapshot["snapshot_id"]].used_refs == set()
    assert timers and all(timer.finished.is_set() for timer in timers)

    component = runtime.present_v2(
        task_id="task-1",
        snapshot_id=snapshot["snapshot_id"],
        surface=surface,
    )

    assert publish_calls == 2
    assert published == [component]
    assert len({item["component_id"] for item in published}) == 1
    assert set(runtime._v2_components) == {component["component_id"]}
    assert runtime._v2_snapshots == {}
    assert runtime._v2_closed[snapshot["snapshot_id"]][1] == "used"

    assert runtime.cancel_v2_component(component["component_id"], task_id="task-1")["state"] == "cancelled"
    runtime.expire_v2_component(component["component_id"])
    assert runtime._v2_components[component["component_id"]].expiry_timer is None


def test_notify_component_is_idempotent_for_one_context():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    published: list[dict] = []

    runtime.register_component_callback("session-1", published.append)

    assert runtime.notify_component(context["context_id"], task_id="session-1") is True
    assert runtime.notify_component(context["context_id"], task_id="session-1") is True
    assert published == [{"component_id": context["context_id"]}]


def test_cross_owner_notification_is_rejected():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime, task_id="owner-session")
    published: list[dict] = []

    runtime.register_component_callback("other-session", published.append)

    assert runtime.notify_component(context["context_id"], task_id="other-session") is False
    assert published == []


def test_submit_cancel_race_has_one_terminal_outcome():
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
    context = _make_context(runtime)
    envelope = _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"})
    outcomes: dict[str, dict] = {}

    submit_thread = threading.Thread(
        target=lambda: outcomes.setdefault("submit", runtime.submit_envelope(envelope, task_id="session-1"))
    )
    cancel_thread = threading.Thread(
        target=lambda: outcomes.setdefault(
            "cancel", runtime.cancel_context(context["component_id"], task_id="session-1")
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


def test_abandoned_context_expires_and_releases_runtime_state():
    runtime = NativeAuthRuntime(
        timeout_seconds=0.05,
        target_validator=lambda **_: None,
        action_executor=lambda **_: {"state": "submitted"},
    )
    context = _make_context(runtime)
    internal = runtime._contexts[context["context_id"]]
    terminal = threading.Event()
    states: list[str] = []

    def on_state(state):
        states.append(state["state"])
        if state["state"] == "expired":
            terminal.set()

    runtime.set_status_callback(context["component_id"], on_state)

    assert terminal.wait(1)
    assert context["context_id"] not in runtime._contexts
    assert context["component_id"] not in runtime._contexts
    assert internal.status_callback is None
    assert runtime.model_code_guard("session-1", "model browser code") is None
    assert states == ["expired"]


def test_callback_replacement_during_notify_is_generation_safe():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    first_entered = threading.Event()
    release_first = threading.Event()
    published: list[str] = []

    def first_callback(_):
        first_entered.set()
        assert release_first.wait(2)
        published.append("first")

    runtime.register_component_callback("session-1", first_callback)
    notify_thread = threading.Thread(
        target=lambda: runtime.notify_component(context["context_id"], task_id="session-1")
    )
    notify_thread.start()
    assert first_entered.wait(2)
    runtime.register_component_callback("session-1", lambda _: published.append("second"))
    release_first.set()
    notify_thread.join(2)

    assert runtime.notify_component(context["context_id"], task_id="session-1") is True
    assert published == ["first", "second"]


def test_close_task_detaches_callback_and_cleans_owned_contexts():
    runtime = _runtime_with_test_key()
    first = _make_context(runtime, task_id="owner-session")
    second = _make_context(runtime, task_id="owner-session")
    other = _make_context(runtime, task_id="other-session")
    internal = runtime._contexts[first["context_id"]]
    states: list[str] = []
    runtime.set_status_callback(first["component_id"], lambda state: states.append(state["state"]))
    runtime.register_component_callback("owner-session", lambda _: None)

    assert runtime.close_task("owner-session") == 2

    assert first["context_id"] not in runtime._contexts
    assert second["context_id"] not in runtime._contexts
    assert other["context_id"] in runtime._contexts
    assert "owner-session" not in runtime._component_callbacks
    assert internal.status_callback is None
    assert internal.expiry_timer is None
    assert states == ["cancelled"]
    assert runtime.model_code_guard("owner-session", "model browser code") is None


def test_terminal_tombstones_are_size_and_ttl_bounded_without_secret_material():
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=lambda **_: {"state": "submitted"},
        terminal_ttl_seconds=0.05,
        max_terminal_entries=3,
    )
    envelopes = []
    for index in range(5):
        context = _make_context(runtime, task_id=f"session-{index}")
        envelope = _encrypt(runtime, context, {"identifier": f"canary-{index}", "secret": "synthetic"})
        envelopes.append(envelope)
        runtime.submit_envelope(envelope, task_id=f"session-{index}")
        runtime.register_component_callback(f"callback-{index}", lambda _: None)

    assert len(runtime._closed) <= 3
    assert len(runtime._closed_owners) <= 3
    assert len(runtime._callback_generations) <= 3
    assert len(runtime._terminal_outcomes) <= 3
    retained = repr(runtime._terminal_outcomes)
    assert "canary-" not in retained
    assert all(envelope["ciphertext"] not in retained for envelope in envelopes)

    with runtime._lock:
        runtime._prune_state_locked(now=time.time() + 1)
    assert runtime._closed == {}
    assert runtime._closed_owners == {}
    assert runtime._callback_generations == {}
    assert runtime._terminal_outcomes == {}


def test_crypto_failure_is_sanitized_terminal_idempotent_and_cleans_every_alias():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    states = []
    runtime.set_status_callback(context["component_id"], lambda state: states.append(state["state"]))
    runtime._notified_contexts[context["component_id"]] = 9
    runtime._notification_inflight[context["context_id"]] = 9
    envelope = _encrypt(runtime, context, {"identifier": "crypto-canary", "secret": "synthetic"})
    broken = envelope | {"tag": _b64(b"x" * 16)}

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(broken, task_id="session-1")
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(broken, task_id="session-1")
    with pytest.raises(NativeAuthSecurityError, match="replay"):
        runtime.submit_envelope(broken | {"ciphertext": broken["ciphertext"] + "A"}, task_id="session-1")

    assert states == ["failed"]
    assert context["context_id"] not in runtime._contexts
    assert context["component_id"] not in runtime._contexts
    assert context["context_id"] not in runtime._notification_inflight
    assert context["component_id"] not in runtime._notified_contexts
    assert "crypto-canary" not in repr(runtime._terminal_outcomes)


@pytest.mark.parametrize("plaintext", [b"\xff", b"not-json"])
def test_legacy_invalid_utf8_and_json_are_sanitized_terminal_failures(plaintext):
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    envelope = _encrypt(runtime, context, {}, plaintext_override=plaintext)
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-1")
    assert context["context_id"] not in runtime._contexts


@pytest.mark.parametrize("boundary", ["validator", "fill", "action"])
def test_external_security_errors_are_sanitized_and_terminal(boundary):
    canary = "selector-and-secret-canary"

    def fail(**_):
        raise NativeAuthSecurityError(canary)

    runtime = NativeAuthRuntime(
        target_validator=fail if boundary == "validator" else (lambda **_: None),
        fill_executor=fail if boundary == "fill" else (lambda **_: {"state": "filled"}),
        action_executor=fail if boundary == "action" else (lambda **_: {"state": "submitted"}),
    )
    context = _make_context(runtime)
    envelope = _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"})

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$") as caught:
        runtime.submit_envelope(envelope, task_id="session-1")
    assert canary not in str(caught.value)
    assert context["context_id"] not in runtime._contexts


def test_legacy_cancel_wins_inverse_race():
    runtime = _runtime_with_test_key()
    context = _make_context(runtime)
    envelope = _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"})
    cancel_entered = threading.Event()
    release_cancel = threading.Event()
    outcomes = {}

    def status(state):
        if state["state"] == "cancelled":
            cancel_entered.set()
            assert release_cancel.wait(2)

    runtime.set_status_callback(context["component_id"], status)
    cancel_thread = threading.Thread(target=lambda: outcomes.setdefault("cancel", runtime.cancel_context(context["component_id"], task_id="session-1")))

    def submit():
        try:
            runtime.submit_envelope(envelope, task_id="session-1")
        except NativeAuthSecurityError as exc:
            outcomes["submit"] = str(exc)

    cancel_thread.start()
    assert cancel_entered.wait(2)
    submit_thread = threading.Thread(target=submit)
    submit_thread.start()
    assert submit_thread.is_alive()
    release_cancel.set()
    cancel_thread.join(2)
    submit_thread.join(2)

    assert outcomes["cancel"]["state"] == "cancelled"
    assert outcomes["submit"] == "auth component cancelled"


def test_legacy_failure_wins_cancel_and_exact_retry_cancel_races():
    entered = threading.Event()
    release = threading.Event()

    def failing_validator(**_):
        entered.set()
        assert release.wait(2)
        raise NativeAuthSecurityError("private-canary")

    runtime = NativeAuthRuntime(target_validator=failing_validator)
    context = _make_context(runtime)
    envelope = _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"})
    outcomes = {}

    def submit_failure():
        try:
            runtime.submit_envelope(envelope, task_id="session-1")
        except NativeAuthSecurityError as exc:
            outcomes["submit"] = str(exc)

    submit_thread = threading.Thread(target=submit_failure)
    submit_thread.start()
    assert entered.wait(2)
    cancel_thread = threading.Thread(target=lambda: outcomes.setdefault("cancel", runtime.cancel_context(context["component_id"], task_id="session-1")))
    cancel_thread.start()
    release.set()
    submit_thread.join(2)
    cancel_thread.join(2)
    assert outcomes["submit"] == "native auth submission failed"
    assert outcomes["cancel"]["state"] == "failed"

    successful = _runtime_with_test_key()
    successful.set_fill_executor(lambda **_: {"state": "filled"})
    successful_context = _make_context(successful)
    successful_envelope = _encrypt(successful, successful_context, {"identifier": "synthetic", "secret": "synthetic"})
    original = successful.submit_envelope(successful_envelope, task_id="session-1")
    race_results = []
    threads = [
        threading.Thread(target=lambda: race_results.append(successful.submit_envelope(successful_envelope, task_id="session-1"))),
        threading.Thread(target=lambda: race_results.append(successful.cancel_context(successful_context["component_id"], task_id="session-1"))),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(2)
    assert race_results == [original, original]


def test_legacy_preflight_completes_before_decrypt(monkeypatch):
    import tools.native_auth_runtime as runtime_module

    decrypted = [False]
    events = []
    original_aesgcm = runtime_module.AESGCM

    class ObservedAESGCM:
        def __init__(self, key):
            self.inner = original_aesgcm(key)

        def decrypt(self, nonce, data, aad):
            decrypted[0] = True
            return self.inner.decrypt(nonce, data, aad)

    monkeypatch.setattr(runtime_module, "AESGCM", ObservedAESGCM)
    runtime = NativeAuthRuntime(
        target_validator=lambda **_: events.append(("preflight", decrypted[0])),
        fill_executor=lambda **_: events.append(("fill", decrypted[0])) or {"state": "filled"},
        action_executor=lambda **_: events.append(("action", decrypted[0])) or {"state": "submitted"},
    )
    context = _make_context(runtime)
    runtime.submit_envelope(
        _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"}),
        task_id="session-1",
    )
    assert [kind for kind, _ in events[:3]] == ["preflight", "preflight", "preflight"]
    assert all(flag is False for _, flag in events[:3])
    assert all(flag is True for _, flag in events[3:])


def test_legacy_ambiguous_action_failure_is_quarantined_and_never_retried():
    quarantines: list[dict] = []
    actions: list[str] = []

    def ambiguous_action(**_kwargs):
        actions.append("submit")
        raise TimeoutError("lost action response with private-canary")

    runtime = NativeAuthRuntime(
        target_validator=lambda **_: None,
        fill_executor=lambda **_: {"state": "filled"},
        action_executor=ambiguous_action,
        quarantine_executor=lambda **kwargs: quarantines.append(kwargs),
    )
    context = _make_context(runtime)
    internal = runtime._contexts[context["context_id"]]
    internal.browser_backend = "browser-use"
    internal.browser_session_name = "ha1-legacy-action"
    states: list[dict] = []
    runtime.set_status_callback(context["component_id"], states.append)
    envelope = _encrypt(runtime, context, {"identifier": "synthetic", "secret": "synthetic"})

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-1")
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-1")

    assert actions == ["submit"]
    assert quarantines == [{
        "task_id": "session-1",
        "browser_session_name": "ha1-legacy-action",
        "tab_handle": context["tab_handle"],
    }]
    assert states[-1]["outcome"] == "remint_required"
    assert states[-1]["reason"] == "browser_state_ambiguous"
    assert "private-canary" not in json.dumps(states[-1])


def test_legacy_envelope_after_runtime_restart_returns_context_lost_remint():
    original = _runtime_with_test_key()
    context = _make_context(original)
    envelope = _encrypt(original, context, {"identifier": "synthetic", "secret": "synthetic"})
    restarted = NativeAuthRuntime(target_validator=lambda **_: None)

    result = restarted.submit_envelope(envelope, task_id="session-1")

    assert result == {
        "schema": "semreh.native-component-state.v1",
        "component_id": context["component_id"],
        "state": "context_lost",
        "outcome": "remint_required",
    }
    assert restarted.submit_envelope(envelope, task_id="session-1") == result


def test_v2_prepare_all_decrypt_apply_one_and_clear_plaintext_in_finally(monkeypatch):
    import tools.native_auth_runtime as runtime_module

    events: list[str] = []
    original_aesgcm = runtime_module.AESGCM
    original_bytearray = bytearray
    buffers = []

    class ObservedAESGCM:
        def __init__(self, key):
            self.inner = original_aesgcm(key)

        def decrypt(self, nonce, data, aad):
            events.append("decrypt")
            return self.inner.decrypt(nonce, data, aad)

    class ObservedBytearray(original_bytearray):
        def __new__(cls, *args, **kwargs):
            value = super().__new__(cls, *args, **kwargs)
            buffers.append(value)
            return value

        def clear(self):
            events.append("clear")
            return super().clear()

    def prepare(**kwargs):
        assert set(kwargs) == {"component", "bindings"}
        assert "ciphertext" not in repr(kwargs)
        assert "plaintext" not in repr(kwargs)
        assert {binding["binding_id"] for binding in kwargs["bindings"]} == {
            ids["input"], ids["continue"], ids["alternate"],
        }
        events.append("prepare")
        return {"lease": "private-preflight-lease"}

    def apply(*, lease, values, action_binding_id):
        assert lease == {"lease": "private-preflight-lease"}
        assert values == {ids["input"]: "opaque-input-canary"}
        assert action_binding_id == ids["continue"]
        events.append("apply")
        return {"state": "submitted"}

    monkeypatch.setattr(runtime_module, "AESGCM", ObservedAESGCM)
    monkeypatch.setattr(runtime_module, "bytearray", ObservedBytearray, raising=False)
    runtime, component, ids = _v2_component_runtime(
        v2_prepare_executor=prepare,
        v2_apply_executor=apply,
    )
    result = runtime.submit_envelope(
        _encrypt_v2(component, {ids["input"]: "opaque-input-canary"}, ids["continue"]),
        task_id="session-v2",
    )

    assert result == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "submitted",
    }
    assert events == ["prepare", "decrypt", "apply", "clear"]
    assert len(buffers) == 1
    assert buffers[0] == ObservedBytearray()
    assert "opaque-input-canary" not in repr(runtime._terminal_outcomes)


def test_v2_prepare_failure_happens_before_decrypt_and_apply():
    import tools.native_auth_runtime as runtime_module

    events: list[str] = []
    original_aesgcm = runtime_module.AESGCM

    class ObservedAESGCM:
        def __init__(self, key):
            self.inner = original_aesgcm(key)

        def decrypt(self, nonce, data, aad):
            events.append("decrypt")
            return self.inner.decrypt(nonce, data, aad)

    def prepare(**_kwargs):
        events.append("prepare")
        raise RuntimeError("private-preflight-canary")

    def apply(**_kwargs):
        events.append("apply")
        return {"state": "submitted"}

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(runtime_module, "AESGCM", ObservedAESGCM)
    try:
        runtime, component, ids = _v2_component_runtime(
            v2_prepare_executor=prepare,
            v2_apply_executor=apply,
        )
        with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
            runtime.submit_envelope(
                _encrypt_v2(component, {ids["input"]: "opaque-input-canary"}, ids["continue"]),
                task_id="session-v2",
            )
    finally:
        monkeypatch.undo()
    assert events == ["prepare"]


def test_v2_apply_failure_quarantines_once_returns_safe_remint_state_and_never_retries():
    quarantines: list[dict] = []
    applies: list[str] = []

    def apply(**_kwargs):
        applies.append("apply")
        raise TimeoutError("private-apply-canary")

    runtime, component, ids = _v2_component_runtime(
        v2_apply_executor=apply,
        quarantine_executor=lambda **kwargs: quarantines.append(kwargs),
    )
    envelope = _encrypt_v2(component, {ids["input"]: "opaque-input-canary"}, ids["continue"])

    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-v2")
    with pytest.raises(NativeAuthSecurityError, match="^native auth submission failed$"):
        runtime.submit_envelope(envelope, task_id="session-v2")

    terminal = runtime.wait_for_v2_component(component["component_id"], task_id="session-v2", timeout=0)
    assert terminal == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "failed",
        "outcome": "remint_required",
        "reason": "browser_state_ambiguous",
    }
    assert applies == ["apply"]
    assert len(quarantines) == 1
    assert "private-apply-canary" not in json.dumps(terminal)


def test_v2_present_waits_for_submit_or_cancel_and_has_one_terminal_result():
    runtime, component, ids = _v2_component_runtime()
    status: list[dict] = []
    runtime.set_v2_status_callback(component["component_id"], status.append)
    outcome: dict[str, dict] = {}

    waiter = threading.Thread(
        target=lambda: outcome.setdefault(
            "wait", runtime.wait_for_v2_component(component["component_id"], task_id="session-v2", timeout=2),
        )
    )
    waiter.start()
    time.sleep(0.05)
    assert waiter.is_alive()
    cancelled = runtime.cancel_v2_component(component["component_id"], task_id="session-v2")
    waiter.join(2)

    assert not waiter.is_alive()
    assert cancelled == outcome["wait"]
    assert cancelled == {
        "schema": "semreh.native-component-state.v2",
        "component_id": component["component_id"],
        "state": "cancelled",
    }
    assert status == [cancelled]


def _nested_v2_private_target(levels: int) -> dict:
    target: dict = {"target_id": "private-target-canary"}
    for _ in range(levels):
        target = {"next": target}
    return target


def _v2_capacity_runtime(*, timeout_seconds: float = 30) -> NativeAuthRuntime:
    return NativeAuthRuntime(
        timeout_seconds=timeout_seconds,
        v2_ref_ttl_seconds=timeout_seconds,
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "path": "/login",
            "targets": [{
                "ref": "@e1",
                "role": "button",
                "label": "Continue",
                "target": "private-action",
            }],
        },
        v2_component_publisher=lambda _: None,
    )


def _v2_one_action_surface() -> dict:
    return {
        "type": "action",
        "id": "continue",
        "label": "Continue",
        "ref": "@e1",
    }


@pytest.mark.parametrize(
    "private_target",
    [
        pytest.param(
            {"target_id": "private-target-canary", "payload": "x" * (9 * 1024)},
            id="canonical-json-over-8k",
        ),
        pytest.param(_nested_v2_private_target(9), id="nested-deeper-than-8-levels"),
    ],
)
def test_v2_inspect_rejects_bounded_private_targets_without_retaining_state(private_target):
    canonical = json.dumps(
        private_target,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    if "payload" in private_target:
        assert len(canonical) > 8 * 1024
    else:
        depth = 0
        node = private_target
        while isinstance(node, dict) and "next" in node:
            depth += 1
            node = node["next"]
        assert depth > 8

    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [{
                "ref": "@e1",
                "role": "button",
                "label": "Continue",
                "target": private_target,
            }],
        },
        v2_component_publisher=lambda _: None,
    )

    with pytest.raises(NativeAuthSecurityError) as caught:
        runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    assert str(caught.value) == "secure browser inspect unavailable"
    assert runtime._v2_snapshots == {}
    assert runtime._v2_components == {}
    assert "private-target-canary" not in repr(runtime._v2_snapshots)


@pytest.mark.parametrize(
    "private_target",
    [
        pytest.param(None, id="null"),
        pytest.param("", id="empty-string"),
        pytest.param({}, id="empty-object"),
        pytest.param([], id="empty-array"),
        pytest.param(0, id="zero"),
        pytest.param(False, id="false"),
    ],
)
def test_v2_inspect_rejects_invalid_private_target_roots_without_retaining_state(private_target):
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [{
                "ref": "@e1",
                "role": "button",
                "label": "Continue",
                "target": private_target,
            }],
        },
        v2_component_publisher=lambda _: None,
    )

    with pytest.raises(NativeAuthSecurityError) as caught:
        runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    assert str(caught.value) == "secure browser inspect unavailable"
    assert runtime._v2_snapshots == {}
    assert runtime._v2_components == {}


def test_v2_snapshot_capacity_is_eight_per_task_and_expired_snapshots_are_reclaimed():
    runtime = _v2_capacity_runtime(timeout_seconds=0.1)
    snapshots = [
        runtime.inspect_v2(task_id="task-1", browser_session="named-login")
        for _ in range(8)
    ]
    snapshot_ids = {snapshot["snapshot_id"] for snapshot in snapshots}

    with pytest.raises(NativeAuthSecurityError, match="^native auth snapshot capacity exceeded$"):
        runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    assert set(runtime._v2_snapshots) == snapshot_ids
    assert len(runtime._v2_snapshots) == 8
    assert all(snapshot.task_id == "task-1" for snapshot in runtime._v2_snapshots.values())

    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        if all(snapshot.expires_at <= time.time() for snapshot in runtime._v2_snapshots.values()):
            break
        time.sleep(0.01)
    assert all(snapshot.expires_at <= time.time() for snapshot in runtime._v2_snapshots.values())

    recovered = runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    assert recovered["snapshot_id"] not in snapshot_ids
    assert len(runtime._v2_snapshots) == 1


def test_v2_snapshot_capacity_is_sixty_four_runtime_wide():
    runtime = _v2_capacity_runtime()
    task_ids = [f"snapshot-task-{index}" for index in range(8)]
    try:
        for task_id in task_ids:
            for _ in range(8):
                runtime.inspect_v2(task_id=task_id, browser_session="named-login")

        assert len(runtime._v2_snapshots) == 64
        assert all(
            sum(snapshot.task_id == task_id for snapshot in runtime._v2_snapshots.values()) == 8
            for task_id in task_ids
        )

        with pytest.raises(NativeAuthSecurityError, match="^native auth snapshot capacity exceeded$"):
            runtime.inspect_v2(task_id="snapshot-overflow", browser_session="named-login")
        assert len(runtime._v2_snapshots) == 64
    finally:
        for task_id in task_ids + ["snapshot-overflow"]:
            runtime.close_task(task_id)


def test_v2_component_capacity_is_eight_per_task_before_snapshot_consumption(monkeypatch):
    import tools.native_auth_runtime as runtime_module

    timers: list[threading.Timer] = []
    real_timer = runtime_module.threading.Timer

    def tracking_timer(*args, **kwargs):
        timer = real_timer(*args, **kwargs)
        timers.append(timer)
        return timer

    monkeypatch.setattr(runtime_module.threading, "Timer", tracking_timer)
    runtime = _v2_capacity_runtime()
    task_id = "component-task-1"
    snapshots = []
    components = []
    try:
        for _ in range(8):
            snapshot = runtime.inspect_v2(task_id=task_id, browser_session="named-login")
            snapshots.append(snapshot)
            components.append(
                runtime.present_v2(
                    task_id=task_id,
                    snapshot_id=snapshot["snapshot_id"],
                    surface=_v2_one_action_surface(),
                )
            )

        snapshots.append(runtime.inspect_v2(task_id=task_id, browser_session="named-login"))

        assert len(runtime._v2_components) == 8
        assert len(timers) == 8
        overflow_snapshot = runtime._v2_snapshots[snapshots[8]["snapshot_id"]]

        with pytest.raises(NativeAuthSecurityError, match="^native auth component capacity exceeded$"):
            runtime.present_v2(
                task_id=task_id,
                snapshot_id=snapshots[8]["snapshot_id"],
                surface=_v2_one_action_surface(),
            )

        assert len(runtime._v2_components) == 8
        assert set(runtime._v2_snapshots) == {snapshots[8]["snapshot_id"]}
        assert overflow_snapshot.used_refs == set()
        assert len(timers) == 8

        cancelled = runtime.cancel_v2_component(components[0]["component_id"], task_id=task_id)
        assert cancelled["state"] == "cancelled"
        assert runtime._v2_components[components[0]["component_id"]].result == cancelled

        retried = runtime.present_v2(
            task_id=task_id,
            snapshot_id=snapshots[8]["snapshot_id"],
            surface=_v2_one_action_surface(),
        )
        assert retried["component_id"] not in {component["component_id"] for component in components}
        assert len(runtime._v2_components) == 9
        assert len(timers) == 9
    finally:
        runtime.close_task(task_id)


def test_v2_component_capacity_is_sixty_four_runtime_wide(monkeypatch):
    import tools.native_auth_runtime as runtime_module

    timers: list[threading.Timer] = []
    real_timer = runtime_module.threading.Timer

    def tracking_timer(*args, **kwargs):
        timer = real_timer(*args, **kwargs)
        timers.append(timer)
        return timer

    monkeypatch.setattr(runtime_module.threading, "Timer", tracking_timer)
    runtime = _v2_capacity_runtime()
    task_ids = [f"component-task-{index}" for index in range(8)]
    try:
        for task_id in task_ids:
            for _ in range(8):
                snapshot = runtime.inspect_v2(task_id=task_id, browser_session="named-login")
                runtime.present_v2(
                    task_id=task_id,
                    snapshot_id=snapshot["snapshot_id"],
                    surface=_v2_one_action_surface(),
                )

        assert len(runtime._v2_components) == 64
        assert len(timers) == 64

        overflow_snapshot = runtime.inspect_v2(
            task_id="component-overflow", browser_session="named-login"
        )
        with pytest.raises(NativeAuthSecurityError, match="^native auth component capacity exceeded$"):
            runtime.present_v2(
                task_id="component-overflow",
                snapshot_id=overflow_snapshot["snapshot_id"],
                surface=_v2_one_action_surface(),
            )

        assert len(runtime._v2_components) == 64
        assert overflow_snapshot["snapshot_id"] in runtime._v2_snapshots
        assert runtime._v2_snapshots[overflow_snapshot["snapshot_id"]].used_refs == set()
        assert len(timers) == 64
    finally:
        for task_id in task_ids + ["component-overflow"]:
            runtime.close_task(task_id)

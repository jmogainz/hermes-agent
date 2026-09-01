"""Focused contract tests for the generic native-auth v2 tool."""

from __future__ import annotations

import base64
import json
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tools.native_auth_runtime import (
    NativeAuthRuntime,
    NativeAuthSecurityError,
    derive_envelope_key,
)


def _v2_binding_ids(component: dict) -> tuple[list[str], str]:
    bindings: list[str] = []

    def visit(node: dict) -> None:
        if "binding_id" in node:
            bindings.append(node["binding_id"])
        for child in node.get("children", []):
            visit(child)

    visit(component["surface"])
    input_bindings = [
        node["binding_id"]
        for node in _surface_nodes(component["surface"])
        if node.get("type") == "input"
    ]
    action_bindings = [
        node["binding_id"]
        for node in _surface_nodes(component["surface"])
        if node.get("type") == "action" and "binding_id" in node
    ]
    assert bindings and action_bindings
    return input_bindings, action_bindings[0]


def _surface_nodes(node: dict):
    yield node
    for child in node.get("children", []):
        yield from _surface_nodes(child)


def _encrypt_v2(component: dict, values: dict[str, str], action_binding_id: str) -> dict:
    client_private = X25519PrivateKey.generate()
    runtime_public = base64.urlsafe_b64decode(component["runtime_public_key"] + "==")
    key = derive_envelope_key(
        private_key=client_private,
        peer_public_key=runtime_public,
        key_id=component["key_id"],
    )
    envelope_id = "env_v2_tool_123456789"
    plaintext = json.dumps(
        {"values": values, "action_binding_id": action_binding_id},
        separators=(",", ":"),
    ).encode()
    aad = f"{component['component_id']}:{envelope_id}:{component['key_id']}".encode("ascii")
    sealed = AESGCM(key).encrypt(bytes(range(12)), plaintext, aad)
    encoded = base64.urlsafe_b64encode
    return {
        "type": "semreh.native-secret-envelope.v2",
        "issued_by": "semreh-native",
        "immutable": True,
        "component_id": component["component_id"],
        "envelope_id": envelope_id,
        "sequence": 1,
        "cipher_suite": "AES-256-GCM",
        "key_id": component["key_id"],
        "client_public_key": encoded(client_private.public_key().public_bytes_raw()).rstrip(b"=").decode(),
        "nonce": encoded(bytes(range(12))).rstrip(b"=").decode(),
        "ciphertext": encoded(sealed[:-16]).rstrip(b"=").decode(),
        "tag": encoded(sealed[-16:]).rstrip(b"=").decode(),
        "journal_policy": "never",
    }


def test_inspect_v2_does_not_fall_back_to_legacy_inspect_resolver():
    calls = []

    def legacy_only(**_kwargs):
        calls.append("legacy")
        return {
            "origin": "https://legacy.example.test",
            "targets": [{"ref": "@e1", "role": "button", "label": "Legacy", "target": "private"}],
        }

    runtime = NativeAuthRuntime(inspect_resolver=legacy_only)

    with pytest.raises(NativeAuthSecurityError, match="secure browser inspect unavailable"):
        runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    assert calls == []


def test_explicit_v2_inspect_resolver_wins_over_legacy_resolver():
    calls = []

    def legacy_only(**_kwargs):
        calls.append("legacy")
        raise AssertionError("legacy resolver must not run")

    def fixed_v2(**_kwargs):
        calls.append("v2")
        return {
            "origin": "https://accounts.example.test",
            "targets": [{
                "ref": "@e1",
                "role": "textbox",
                "label": "Account",
                "hints": {},
                "target": "private-account",
            }],
        }

    runtime = NativeAuthRuntime(
        inspect_resolver=legacy_only,
        v2_inspect_resolver=fixed_v2,
    )

    inspected = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    assert calls == ["v2"]
    assert inspected["targets"][0]["ref"] == "@e1"


def test_generic_surface_uses_private_inspect_refs_and_runtime_bindings():
    private_targets = {
        "@e1": {"tab": "private-tab-account", "node": "private-node-account"},
        "@e2": {"tab": "private-tab-submit", "node": "private-node-submit"},
    }

    def fixed_resolver(*, browser_session: str, task_id: str):
        assert browser_session == "named-login"
        assert task_id == "task-1"
        return {
            "origin": "https://accounts.example.test",
            "targets": [
                {
                    "ref": ref,
                    "role": role,
                    "label": label,
                    "hints": {"masked": False, "required": True, "keyboard": "text"}
                    if role == "textbox" else {},
                    "target": private_target,
                }
                for ref, role, label, private_target in (
                    ("@e1", "textbox", "Account", private_targets["@e1"]),
                    ("@e2", "button", "Continue", private_targets["@e2"]),
                )
            ],
        }

    published: list[dict] = []
    runtime = NativeAuthRuntime(
        timeout_seconds=30,
        v2_inspect_resolver=fixed_resolver,
        v2_component_publisher=published.append,
    )

    from tools.native_auth_tool import native_auth_tool

    inspected = json.loads(
        native_auth_tool(
            {"action": "inspect", "browser_session": "named-login"},
            runtime=runtime,
            task_id="task-1",
        )
    )
    assert inspected["snapshot_id"]
    assert [target["ref"] for target in inspected["targets"]] == ["@e1", "@e2"]
    assert all(set(target) == {"ref", "role", "trusted_label", "hints"} for target in inspected["targets"])
    assert inspected["targets"][0]["hints"] == {
        "masked": False, "required": True, "keyboard": "text",
    }
    assert inspected["targets"][1]["hints"] == {}

    surface = {
        "type": "stack",
        "id": "root",
        "children": [
            {
                "type": "input",
                "id": "account",
                "label": "Account name",
                "ref": "@e1",
                "masked": False,
                "required": True,
            },
            {"type": "action", "id": "continue", "label": "Continue", "ref": "@e2"},
        ],
    }
    presented = runtime.present_v2(
        task_id="task-1",
        snapshot_id=inspected["snapshot_id"],
        surface=surface,
    )

    assert published == [presented]
    assert presented["schema"] == "semreh.native-component.v2"
    assert presented["component_id"]
    nodes = presented["surface"]["children"]
    assert all(node["binding_id"].startswith("bind_") for node in nodes)
    assert nodes[0]["trusted_label"] == "Account"
    assert nodes[1]["trusted_label"] == "Continue"
    assert nodes[0]["binding_id"] not in {"@e1", "@e2"}
    wire = json.dumps(presented)
    for forbidden in (
        "@e1",
        "@e2",
        "private-tab-account",
        "private-node-account",
        "selector",
        "target_id",
        "frame_id",
        "document_id",
        "value",
    ):
        assert forbidden not in wire


def test_trusted_searchbox_ref_can_be_presented_as_input_with_hints():
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [{
                "ref": "@e1", "role": "searchbox", "label": "Account search",
                "hints": {"required": True, "keyboard": "search"}, "target": "private-search",
            }],
        },
        v2_component_publisher=lambda _: None,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    presented = runtime.present_v2(
        task_id="task-1", snapshot_id=snapshot["snapshot_id"],
        surface={"type": "input", "id": "query", "label": "Search", "ref": "@e1"},
    )
    node = presented["surface"]
    assert node["role"] == "searchbox"
    assert node["trusted_label"] == "Account search"
    assert node["required"] is True
    assert node["keyboard"] == "search"


def test_present_rejects_non_string_model_style_with_a_safe_runtime_error():
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [
                {"ref": "@e1", "role": "button", "label": "Continue", "target": "private-target"},
            ],
        },
        v2_component_publisher=lambda _: None,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    with pytest.raises(NativeAuthSecurityError, match="native auth action style is invalid"):
        runtime.present_v2(
            task_id="task-1",
            snapshot_id=snapshot["snapshot_id"],
            surface={
                "type": "action",
                "id": "continue",
                "label": "Continue",
                "style": [],
                "ref": "@e1",
            },
        )


def test_inspect_refs_are_individually_one_use_and_task_scoped():
    published: list[dict] = []
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [
                {"ref": "@e1", "role": "button", "label": "First", "target": "private-first"},
                {"ref": "@e2", "role": "button", "label": "Second", "target": "private-second"},
            ],
        },
        v2_component_publisher=published.append,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    def action_surface(ref: str) -> dict:
        return {"type": "action", "id": "continue", "label": "Continue", "ref": ref}

    with pytest.raises(NativeAuthSecurityError, match="another session"):
        runtime.present_v2(
            task_id="task-2",
            snapshot_id=snapshot["snapshot_id"],
            surface=action_surface("@e1"),
        )

    runtime.present_v2(
        task_id="task-1",
        snapshot_id=snapshot["snapshot_id"],
        surface=action_surface("@e1"),
    )
    with pytest.raises(NativeAuthSecurityError, match="already used"):
        runtime.present_v2(
            task_id="task-1",
            snapshot_id=snapshot["snapshot_id"],
            surface=action_surface("@e1"),
        )

    runtime.present_v2(
        task_id="task-1",
        snapshot_id=snapshot["snapshot_id"],
        surface=action_surface("@e2"),
    )
    assert len(published) == 2


def test_inspect_sanitizes_injected_resolver_errors():
    def failing_resolver(**_):
        raise NativeAuthSecurityError("private-selector-canary")

    runtime = NativeAuthRuntime(v2_inspect_resolver=failing_resolver)

    from tools.native_auth_tool import native_auth_tool

    result = json.loads(
        native_auth_tool(
            {"action": "inspect", "browser_session": "named-login"},
            runtime=runtime,
            task_id="task-1",
        )
    )

    assert result == {"error": "secure browser inspect unavailable"}
    assert "private-selector-canary" not in json.dumps(result)


def test_model_cannot_supply_runtime_identity_or_private_target_metadata():
    published: list[dict] = []
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [
                {"ref": "@e1", "role": "button", "label": "Continue", "target": "private-target"},
            ],
        },
        v2_component_publisher=published.append,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    from tools.native_auth_tool import native_auth_tool

    with_identity = native_auth_tool(
        {
            "action": "present",
            "snapshot_id": snapshot["snapshot_id"],
            "surface": {"type": "action", "id": "continue", "label": "Continue", "ref": "@e1"},
            "component_id": "model-supplied-component",
        },
        runtime=runtime,
        task_id="task-1",
    )
    with_target = native_auth_tool(
        {
            "action": "present",
            "snapshot_id": snapshot["snapshot_id"],
            "surface": {
                "type": "action",
                "id": "continue",
                "label": "Continue",
                "ref": "@e1",
                "target": "model-supplied-target",
            },
        },
        runtime=runtime,
        task_id="task-1",
    )

    assert json.loads(with_identity) == {"error": "native auth present input is invalid"}
    assert json.loads(with_target) == {"error": "native auth surface contains unsupported metadata"}
    assert published == []


def test_close_task_invalidates_v2_snapshot_state():
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://accounts.example.test",
            "targets": [
                {"ref": "@e1", "role": "button", "label": "Continue", "target": "private-target"},
            ],
        },
        v2_component_publisher=lambda _: None,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    assert runtime.close_task("task-1") == 0

    with pytest.raises(NativeAuthSecurityError, match="no longer active"):
        runtime.present_v2(
            task_id="task-1",
            snapshot_id=snapshot["snapshot_id"],
            surface={"type": "action", "id": "continue", "label": "Continue", "ref": "@e1"},
        )


def test_present_v2_enforces_trusted_generic_masking_and_required_hints():
    published = []
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://safe.test",
            "targets": [{
                "ref": "@e1",
                "role": "textbox",
                "label": "Secure input",
                "hints": {"masked": True, "required": True, "keyboard": "text"},
                "target": {"target_id": "private-target", "frame_id": "private-frame", "loader_id": "private-loader"},
            }],
        },
        v2_component_publisher=published.append,
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    component = runtime.present_v2(
        task_id="task-1",
        snapshot_id=snapshot["snapshot_id"],
        surface={
            "type": "input", "id": "secret", "label": "Enter value", "ref": "@e1",
            "masked": False, "required": False,
        },
    )

    node = component["surface"]
    assert node["masked"] is True
    assert node["required"] is True
    assert node["keyboard"] == "text"
    assert published == [component]


def test_inspect_v2_public_result_exposes_only_opaque_refs_and_safe_metadata():
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://safe.test",
            "path": "/signin",
            "targets": [{
                "ref": "@e1",
                "role": "textbox",
                "label": "Account",
                "hints": {"masked": False, "required": True, "keyboard": "text"},
                "target": {"target_id": "private-target", "frame_id": "private-frame", "loader_id": "private-loader", "backend_node_id": 9},
            }],
        },
    )

    inspected = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    assert inspected["path"] == "/signin"
    assert inspected["targets"] == [{
        "ref": "@e1",
        "role": "textbox",
        "trusted_label": "Account",
        "hints": {"masked": False, "required": True, "keyboard": "text"},
    }]
    assert inspected["targets"][0]["hints"] == {
        "masked": False, "required": True, "keyboard": "text",
    }
    wire = json.dumps(inspected)
    for forbidden in ("private-target", "private-frame", "loader_id", "backend_node_id", "query", "fragment"):
        assert forbidden not in wire


def test_v2_components_have_distinct_private_keys_and_public_projection_has_no_binding_targets():
    published: list[dict] = []
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://safe.test",
            "path": "/signin",
            "targets": [
                {"ref": "@e1", "role": "button", "label": "Continue", "target": {"node": "private-a"}},
                {"ref": "@e2", "role": "button", "label": "Use another", "target": {"node": "private-b"}},
            ],
        },
        v2_component_publisher=published.append,
        v2_prepare_executor=lambda **_: object(),
        v2_apply_executor=lambda **_: {"state": "submitted"},
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")

    runtime.present_v2(
        task_id="task-1",
        snapshot_id=snapshot["snapshot_id"],
        surface={"type": "action", "id": "continue", "label": "Continue", "ref": "@e1"},
    )
    runtime.present_v2(
        task_id="task-1",
        snapshot_id=snapshot["snapshot_id"],
        surface={"type": "action", "id": "alternate", "label": "Use another", "ref": "@e2"},
    )

    assert len(published) == 2
    assert published[0]["schema"] == "semreh.native-component.v2"
    assert published[0]["runtime_public_key"] != published[1]["runtime_public_key"]
    assert published[0]["key_id"] != published[1]["key_id"]
    assert published[0]["component_id"] != published[1]["component_id"]
    assert set(published[0]) == {
        "schema", "issued_by", "immutable", "component_id", "surface", "origin", "path",
        "runtime_public_key", "key_id", "expires_at", "state",
    }
    public_wire = json.dumps(published)
    for forbidden in ("private-a", "private-b", "target", "selector", "values", "ciphertext"):
        assert forbidden not in public_wire


def test_v2_native_auth_present_blocks_until_submit_and_returns_only_safe_terminal_state():
    from tools.native_auth_tool import native_auth_tool

    published: list[dict] = []
    published_event = threading.Event()
    runtime = NativeAuthRuntime(
        v2_inspect_resolver=lambda **_: {
            "origin": "https://safe.test",
            "targets": [
                {"ref": "@e1", "role": "textbox", "label": "Account", "hints": {"required": True}, "target": "private-input"},
                {"ref": "@e2", "role": "button", "label": "Continue", "target": "private-action"},
            ],
        },
        v2_component_publisher=lambda component: (published.append(component), published_event.set()),
        v2_prepare_executor=lambda **_: object(),
        v2_apply_executor=lambda **_: {"state": "submitted"},
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    surface = {
        "type": "stack",
        "id": "root",
        "children": [
            {"type": "input", "id": "account", "label": "Account", "ref": "@e1"},
            {"type": "action", "id": "continue", "label": "Continue", "ref": "@e2"},
        ],
    }
    result: dict[str, str] = {}
    worker = threading.Thread(
        target=lambda: result.setdefault(
            "value",
            native_auth_tool(
                {"action": "present", "snapshot_id": snapshot["snapshot_id"], "surface": surface},
                runtime=runtime,
                task_id="task-1",
            ),
        )
    )
    worker.start()
    assert published_event.wait(2)
    time.sleep(0.05)
    assert worker.is_alive()

    input_bindings, action_binding_id = _v2_binding_ids(published[0])
    envelope = _encrypt_v2(
        published[0],
        {input_bindings[0]: "opaque-account-canary"},
        action_binding_id,
    )
    assert runtime.submit_envelope(envelope, task_id="task-1")["state"] == "submitted"
    worker.join(2)

    assert not worker.is_alive()
    safe_result = json.loads(result["value"])
    assert safe_result == {
        "schema": "semreh.native-component-state.v2",
        "component_id": published[0]["component_id"],
        "state": "submitted",
    }
    assert set(safe_result) <= {"schema", "component_id", "state", "outcome", "reason"}
    result_wire = json.dumps(safe_result)
    for forbidden in ("opaque-account-canary", "private-input", "private-action", "ciphertext", "binding_id", "target"):
        assert forbidden not in result_wire


def test_v2_native_auth_present_without_lifecycle_executors_still_blocks_until_cancel():
    from tools.native_auth_tool import native_auth_tool

    published: list[dict] = []
    published_event = threading.Event()
    runtime = NativeAuthRuntime(
        timeout_seconds=2,
        v2_inspect_resolver=lambda **_: {
            "origin": "https://safe.test",
            "targets": [{
                "ref": "@e1",
                "role": "button",
                "label": "Continue",
                "target": "private-action",
            }],
        },
        v2_component_publisher=lambda component: (published.append(component), published_event.set()),
    )
    snapshot = runtime.inspect_v2(task_id="task-1", browser_session="named-login")
    result: dict[str, str] = {}
    worker = threading.Thread(
        target=lambda: result.setdefault(
            "value",
            native_auth_tool(
                {
                    "action": "present",
                    "snapshot_id": snapshot["snapshot_id"],
                    "surface": {
                        "type": "action",
                        "id": "continue",
                        "label": "Continue",
                        "ref": "@e1",
                    },
                },
                runtime=runtime,
                task_id="task-1",
            ),
        )
    )
    worker.start()
    assert published_event.wait(2)
    try:
        assert worker.is_alive()
    finally:
        cancelled = runtime.cancel_v2_component(published[0]["component_id"], task_id="task-1")
        worker.join(2)

    assert not worker.is_alive()
    safe_result = json.loads(result["value"])
    assert safe_result == {
        "schema": "semreh.native-component-state.v2",
        "component_id": published[0]["component_id"],
        "state": "cancelled",
    }
    assert cancelled == safe_result
    assert set(safe_result) <= {"schema", "component_id", "state", "outcome", "reason"}
    result_wire = json.dumps(safe_result)
    for forbidden in (
        "private-action",
        "https://safe.test",
        "Continue",
        "path",
        "binding_id",
        "key_id",
        "origin",
        "target",
    ):
        assert forbidden not in result_wire

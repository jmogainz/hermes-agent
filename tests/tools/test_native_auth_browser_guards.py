"""Regression tests for blocking model browser mutations during native auth."""

from __future__ import annotations

import json

import pytest

from tools.native_auth_runtime import native_auth_runtime


def _pending_context(task_id: str) -> None:
    native_auth_runtime.create_context(
        task_id=task_id,
        browser_session_key=f"browser-{task_id}",
        browser_session_id=f"session-{task_id}",
        provider_origin="https://accounts.example.test",
        path="/login",
        flow="password",
        fields=[
            {
                "field_id": "password",
                "kind": "password",
                "label": "Password",
                "required": True,
                "target": {"strategy": "ref", "value": "@e1"},
            }
        ],
        actions=[
            {
                "action_id": "submit",
                "kind": "submit",
                "label": "Sign in",
                "target": {"strategy": "ref", "value": "@e2"},
            }
        ],
        browser_backend="fake",
    )


def test_browser_navigate_is_blocked_for_pending_native_auth(monkeypatch):
    import tools.browser_tool as browser_tool

    task_id = "guard-navigate-123"
    _pending_context(task_id)
    monkeypatch.setattr(browser_tool, "_get_session_info", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("navigation must not create/use a browser session")))

    result = json.loads(browser_tool.browser_navigate("https://example.com", task_id=task_id))

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_click_is_blocked_for_pending_native_auth(monkeypatch):
    import tools.browser_tool as browser_tool

    task_id = "guard-click-123"
    _pending_context(task_id)
    monkeypatch.setattr(browser_tool, "_blocked_private_page_action", lambda *args: None)
    monkeypatch.setattr(browser_tool, "_is_camofox_mode", lambda: False)
    monkeypatch.setattr(
        browser_tool,
        "_run_browser_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("browser click must not run")),
    )

    result = json.loads(browser_tool.browser_click("@e1", task_id=task_id))

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_scroll_is_blocked_before_backend_dispatch(monkeypatch):
    import tools.browser_tool as browser_tool

    task_id = "guard-scroll-123"
    _pending_context(task_id)
    monkeypatch.setattr(
        browser_tool,
        "_is_camofox_mode",
        lambda: (_ for _ in ()).throw(AssertionError("scroll backend selection must not run")),
    )
    monkeypatch.setattr(
        browser_tool,
        "_run_browser_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("scroll backend must not run")),
    )

    result = json.loads(browser_tool.browser_scroll("down", task_id=task_id))

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_back_is_blocked_before_backend_dispatch(monkeypatch):
    import tools.browser_tool as browser_tool

    task_id = "guard-back-123"
    _pending_context(task_id)
    monkeypatch.setattr(
        browser_tool,
        "_is_camofox_mode",
        lambda: (_ for _ in ()).throw(AssertionError("back backend selection must not run")),
    )
    monkeypatch.setattr(
        browser_tool,
        "_run_browser_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("back backend must not run")),
    )

    result = json.loads(browser_tool.browser_back(task_id=task_id))

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_press_is_blocked_for_pending_native_auth(monkeypatch):
    import tools.browser_tool as browser_tool

    task_id = "guard-press-123"
    _pending_context(task_id)
    monkeypatch.setattr(browser_tool, "_blocked_private_page_action", lambda *args: None)
    monkeypatch.setattr(browser_tool, "_is_camofox_mode", lambda: False)
    monkeypatch.setattr(
        browser_tool,
        "_run_browser_command",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("browser press must not run")),
    )

    result = json.loads(browser_tool.browser_press("Enter", task_id=task_id))

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_console_eval_is_blocked_for_pending_native_auth(monkeypatch):
    import tools.browser_tool as browser_tool

    task_id = "guard-eval-123"
    _pending_context(task_id)
    monkeypatch.setattr(
        browser_tool,
        "_browser_eval",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("browser eval must not run")),
    )

    result = json.loads(
        browser_tool.browser_console(
            expression="document.querySelector('input').value = 'not-allowed'",
            task_id=task_id,
        )
    )

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_dialog_is_blocked_before_supervisor_dispatch(monkeypatch):
    import tools.browser_dialog_tool as browser_dialog_tool

    task_id = "guard-dialog-123"
    _pending_context(task_id)
    monkeypatch.setattr(
        browser_dialog_tool.SUPERVISOR_REGISTRY,
        "get",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("dialog backend must not run")),
    )

    result = json.loads(
        browser_dialog_tool.browser_dialog(action="accept", task_id=task_id)
    )

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]


def test_browser_cdp_page_mutation_is_blocked_for_pending_native_auth(monkeypatch):
    import tools.browser_cdp_tool as browser_cdp_tool

    task_id = "guard-cdp-123"
    _pending_context(task_id)
    monkeypatch.setattr(browser_cdp_tool, "_browser_cdp_private_guard", lambda **kwargs: None)
    monkeypatch.setattr(browser_cdp_tool, "_resolve_cdp_endpoint", lambda: "ws://127.0.0.1:9222/devtools/browser/test")
    monkeypatch.setattr(
        browser_cdp_tool,
        "_run_async",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("CDP mutation must not run")),
    )

    result = json.loads(
        browser_cdp_tool.browser_cdp(
            method="Runtime.evaluate",
            params={"expression": "document.body.click()"},
            task_id=task_id,
        )
    )

    assert result["auth_boundary_required"] is True
    assert "auth_boundary_required" in result["error"]

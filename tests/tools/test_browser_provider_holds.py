"""Provider-lifetime pins for pending native browser authentication."""

import time

import tools.browser_tool as browser_tool


def _reset_holds(monkeypatch):
    monkeypatch.setattr(browser_tool, "_browser_session_holds", {})
    monkeypatch.setattr(browser_tool, "_browser_hold_tokens", {})


def test_browser_session_holds_are_refcounted_and_release_is_idempotent(monkeypatch):
    _reset_holds(monkeypatch)
    now = time.time()
    key = "bu-named-ha1-provider-hold"

    first = browser_tool.acquire_browser_session_hold(key, expires_at=now + 900)
    second = browser_tool.acquire_browser_session_hold(key, expires_at=now + 600)

    assert first != second
    assert browser_tool._browser_session_hold_active(key, now=now + 1) is True
    browser_tool.release_browser_session_hold(first)
    browser_tool.release_browser_session_hold(first)
    assert browser_tool._browser_session_hold_active(key, now=now + 1) is True
    browser_tool.release_browser_session_hold(second)
    assert browser_tool._browser_session_hold_active(key, now=now + 1) is False


def test_inactivity_cleanup_skips_unexpired_hold(monkeypatch):
    _reset_holds(monkeypatch)
    now = 10_000.0
    key = "bu-named-ha1-pending-auth"
    monkeypatch.setattr(browser_tool.time, "time", lambda: now)
    monkeypatch.setattr(browser_tool, "BROWSER_SESSION_INACTIVITY_TIMEOUT", 120)
    monkeypatch.setattr(browser_tool, "_session_last_activity", {key: now - 500})
    monkeypatch.setattr(browser_tool, "_active_sessions", {key: {"session_name": "held"}})
    cleaned = []
    monkeypatch.setattr(browser_tool, "cleanup_browser", cleaned.append)

    token = browser_tool.acquire_browser_session_hold(key, expires_at=now + 900)
    browser_tool._cleanup_inactive_browser_sessions()

    assert cleaned == []
    assert browser_tool._browser_session_hold_active(key, now=now) is True
    browser_tool.release_browser_session_hold(token)


def test_provider_expiry_wins_over_unexpired_hold(monkeypatch):
    _reset_holds(monkeypatch)
    now = 20_000.0
    key = "bu-named-ha1-provider-expired"
    monkeypatch.setattr(browser_tool.time, "time", lambda: now)
    monkeypatch.setattr(browser_tool, "BROWSER_SESSION_INACTIVITY_TIMEOUT", 120)
    monkeypatch.setattr(browser_tool, "_session_last_activity", {key: now - 500})
    monkeypatch.setattr(
        browser_tool,
        "_active_sessions",
        {key: {"session_name": "expired", "expires_at": now - 1}},
    )
    cleaned = []
    monkeypatch.setattr(browser_tool, "cleanup_browser", cleaned.append)

    browser_tool.acquire_browser_session_hold(key, expires_at=now + 900)
    browser_tool._cleanup_inactive_browser_sessions()

    assert cleaned == [key]


def test_expired_hold_no_longer_blocks_inactivity_cleanup(monkeypatch):
    _reset_holds(monkeypatch)
    now = 30_000.0
    key = "bu-named-ha1-prompt-expired"
    monkeypatch.setattr(browser_tool.time, "time", lambda: now)
    monkeypatch.setattr(browser_tool, "BROWSER_SESSION_INACTIVITY_TIMEOUT", 120)
    monkeypatch.setattr(browser_tool, "_session_last_activity", {key: now - 500})
    monkeypatch.setattr(browser_tool, "_active_sessions", {key: {"session_name": "inactive"}})
    cleaned = []
    monkeypatch.setattr(browser_tool, "cleanup_browser", cleaned.append)

    browser_tool.acquire_browser_session_hold(key, expires_at=now - 1)
    browser_tool._cleanup_inactive_browser_sessions()

    assert cleaned == [key]

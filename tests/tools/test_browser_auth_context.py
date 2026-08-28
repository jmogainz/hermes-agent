"""Tests for browser login-wall classification and capability minting."""

from __future__ import annotations

import json

from tools.browser_auth_context import detect_auth_context
from tools.native_auth_runtime import NativeAuthRuntime


def _runtime() -> NativeAuthRuntime:
    return NativeAuthRuntime()


def test_detects_email_password_form_and_mints_exact_refs_without_values():
    snapshot = '''
- textbox "Email address" [ref=@e1]
- textbox "Password" [ref=@e2]
- button "Log in" [ref=@e3]
'''
    context = detect_auth_context(
        runtime=_runtime(),
        task_id="session-1",
        browser_session_key="browser-session-1",
        browser_session_id="browser-session-1",
        provider_origin="https://example.com",
        path="/login?next=/app#ignored",
        title="Sign in",
        snapshot=snapshot,
        refs={},
        browser_backend="browser-use",
        browser_session_name="auth-test",
    )

    assert context is not None
    assert context["provider_origin"] == "https://example.com"
    assert context["path"] == "/login"
    assert [field["kind"] for field in context["fields"]] == ["email", "password"]
    assert context["fields"][0]["target"]["strategy"] == "ref"
    assert context["fields"][0]["target"]["value"] == "@e1"
    assert context["fields"][0]["target"]["target_id"].startswith("ref_")
    assert context["fields"][1]["target"]["strategy"] == "ref"
    assert context["fields"][1]["target"]["value"] == "@e2"
    assert context["actions"][0]["target"]["strategy"] == "ref"
    assert context["actions"][0]["target"]["value"] == "@e3"
    encoded = json.dumps(context)
    assert '"password123"' not in encoded
    assert '"synthetic-password"' not in encoded
    assert '"credential"' not in encoded


def test_detects_totp_sms_recovery_and_security_question_kinds():
    snapshot = '''
- textbox "Authenticator app code" [ref=e1]
- textbox "SMS verification code" [ref=e2]
- textbox "Recovery code" [ref=e3]
- textbox "Security question answer" [ref=e4]
- button "Verify" [ref=e5]
'''
    context = detect_auth_context(
        runtime=_runtime(),
        task_id="session-1",
        browser_session_key="browser-session-1",
        browser_session_id="browser-session-1",
        provider_origin="https://example.com",
        path="/verify",
        title="Two-factor authentication",
        snapshot=snapshot,
        refs={},
        browser_backend="browser-use",
        browser_session_name="auth-test",
    )

    assert context is not None
    assert [field["kind"] for field in context["fields"]] == [
        "totp_code",
        "sms_code",
        "recovery_code",
        "security_answer",
    ]


def test_detects_browser_owned_passkey_captcha_and_sso_without_secret_fields():
    snapshot = '''
- button "Continue with Google" [ref=e1]
- button "Use a passkey" [ref=e2]
- generic "Complete the CAPTCHA verification" [ref=e3]
'''
    context = detect_auth_context(
        runtime=_runtime(),
        task_id="session-1",
        browser_session_key="browser-session-1",
        browser_session_id="browser-session-1",
        provider_origin="https://id.example.com",
        path="/authorize",
        title="Continue to application",
        snapshot=snapshot,
        refs={},
        browser_backend="browser-use",
        browser_session_name="auth-test",
    )

    assert context is not None
    assert context["fields"] == []
    kinds = {action["kind"] for action in context["actions"]}
    assert {"sso_continue", "passkey", "captcha"}.issubset(kinds)


def test_ordinary_form_is_not_classified_as_login_wall():
    snapshot = '''
- textbox "Search products" [ref=e1]
- button "Search" [ref=e2]
'''
    context = detect_auth_context(
        runtime=_runtime(),
        task_id="session-1",
        browser_session_key="browser-session-1",
        browser_session_id="browser-session-1",
        provider_origin="https://example.com",
        path="/search",
        title="Search",
        snapshot=snapshot,
        refs={},
        browser_backend="browser-use",
        browser_session_name="auth-test",
    )
    assert context is None


def test_rejects_unsafe_origin_and_does_not_return_snapshot_text():
    snapshot = '- textbox "Password" [ref=e1]\n- button "Sign in" [ref=e2]'
    context = detect_auth_context(
        runtime=_runtime(),
        task_id="session-1",
        browser_session_key="browser-session-1",
        browser_session_id="browser-session-1",
        provider_origin="http://example.com",
        path="/login",
        title="Sign in",
        snapshot=snapshot,
        refs={},
        browser_backend="browser-use",
        browser_session_name="auth-test",
    )
    assert context is None

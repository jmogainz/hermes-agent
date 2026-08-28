"""Focused tests for the metadata-only native website-login seam."""

from __future__ import annotations

import json

import pytest

from agent.tool_dispatch_helpers import _NEVER_PARALLEL_TOOLS
from tools.registry import registry
from tools.website_login_tool import WEBSITE_LOGIN_SCHEMA, website_login


OPAQUE_REQUEST_ID = "req_1234567890abcd"


def _payload(result: str) -> dict:
    value = json.loads(result)
    assert isinstance(value, dict)
    return value


def test_registry_exposes_flat_openai_function_schema() -> None:
    entry = registry.get_entry("website_login")
    assert entry is not None
    assert entry.schema == WEBSITE_LOGIN_SCHEMA
    assert set(entry.schema) == {"name", "description", "parameters"}
    assert entry.schema["name"] == "website_login"
    assert "OIDC" in entry.schema["description"]
    assert "SSO" in entry.schema["description"]
    assert "never fills" in entry.schema["description"]
    assert "approved" not in entry.schema["description"].lower()
    assert "https" in entry.schema["description"].lower()
    assert entry.schema["parameters"]["additionalProperties"] is False
    assert set(entry.schema["parameters"]["properties"]) == {"origin", "site_name"}

    definitions = registry.get_definitions({"website_login"})
    assert len(definitions) == 1
    assert definitions[0]["type"] == "function"
    assert definitions[0]["function"]["name"] == "website_login"
    assert "function" not in definitions[0]["function"]


def test_website_login_requires_native_callback() -> None:
    result = _payload(website_login("https://example.com"))
    assert result["error"] == "website login is unavailable without a native credential boundary"


def test_website_login_normalizes_origin_and_returns_only_opaque_metadata() -> None:
    calls: list[tuple[str, str | None]] = []

    def callback(origin: str, site_name: str | None) -> dict:
        calls.append((origin, site_name))
        return {
            "requestID": OPAQUE_REQUEST_ID,
            "result": "completed",
            "password": "must-not-cross-boundary",
            "cookies": {"session": "must-not-cross-boundary"},
        }

    result = _payload(website_login(" HTTPS://Example.COM:443/ ", " Example ", callback=callback))

    assert calls == [("https://example.com", "Example")]
    assert result == {"requestID": OPAQUE_REQUEST_ID, "result": "completed"}
    assert "password" not in result
    assert "cookies" not in result


@pytest.mark.parametrize(
    "origin",
    [
        "http://example.com",
        "https://example.com/path",
        "https://example.com?next=/login",
        "https://example.com#login",
        "https://user:password@example.com",
        "https://example.com:bad",
        "https://example.com:0",
        "https://",
    ],
)
def test_website_login_rejects_non_exact_https_origins(origin: str) -> None:
    callback_called = False

    def callback(*_args):
        nonlocal callback_called
        callback_called = True
        return {"requestID": OPAQUE_REQUEST_ID, "result": "completed"}

    result = _payload(website_login(origin, callback=callback))
    assert result["error"] == "website login requires an exact HTTPS origin"
    assert callback_called is False


@pytest.mark.parametrize(
    ("origin", "expected"),
    [
        ("https://[2001:db8::1]", "https://[2001:db8::1]"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
    ],
)
def test_website_login_canonicalizes_ipv6_and_idna_origins(origin: str, expected: str) -> None:
    calls: list[str] = []

    def callback(normalized_origin: str, _site_name: str | None) -> dict:
        calls.append(normalized_origin)
        return {"requestID": OPAQUE_REQUEST_ID, "result": "completed"}

    result = _payload(website_login(origin, callback=callback))
    assert result == {"requestID": OPAQUE_REQUEST_ID, "result": "completed"}
    assert calls == [expected]


def test_website_login_rejects_secret_shaped_metadata() -> None:
    result = _payload(
        website_login(
            "https://example.com",
            "password=must-not-be-forwarded",
            callback=lambda *_args: {
                "requestID": OPAQUE_REQUEST_ID,
                "result": "completed",
            },
        )
    )
    assert result["error"] == "website login site label is invalid"


def test_website_login_rejects_unknown_arguments_without_callback() -> None:
    entry = registry.get_entry("website_login")
    assert entry is not None
    result = _payload(
        entry.handler(
            {
                "origin": "https://example.com",
                "password": "must-not-be-read",
            }
        )
    )
    assert result["error"] == "website login accepts metadata only"


def test_website_login_rejects_invalid_boundary_results() -> None:
    invalid_payloads = [
        lambda *_args: {"requestID": "short", "result": "completed"},
        lambda *_args: {"requestID": OPAQUE_REQUEST_ID, "result": "pending"},
        lambda *_args: {"requestID": OPAQUE_REQUEST_ID},
    ]

    for callback in invalid_payloads:
        result = _payload(website_login("https://example.com", callback=callback))
        assert result["error"] == "website login boundary returned an invalid result"

    failed = _payload(website_login("https://example.com", callback=lambda *_args: "not-json"))
    assert failed["error"] == "website login boundary failed"

    stripped = _payload(
        website_login(
            "https://example.com",
            callback=lambda *_args: {
                "requestID": OPAQUE_REQUEST_ID,
                "result": "completed",
                "token": "secret",
            },
        )
    )
    assert stripped == {"requestID": OPAQUE_REQUEST_ID, "result": "completed"}
    assert "token" not in stripped


def test_website_login_is_serialized_with_other_interactive_tools() -> None:
    assert "website_login" in _NEVER_PARALLEL_TOOLS
    assert "clarify" in _NEVER_PARALLEL_TOOLS

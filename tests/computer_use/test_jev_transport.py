"""Transport parity for the Jev decision lane: direct TypeSafe vs OpenRouter.

OpenRouter serves the same System One model over its own decisions route
(`/api/alpha/decisions`, model `~typesafe/jev-latest`). These tests pin the
provider selection, URL/auth construction, and the availability gate - no
network: urllib is stubbed.
"""

from __future__ import annotations

import json
import urllib.request
from unittest.mock import patch

import pytest

from tools.computer_use import decision_lane, decision_stages
from tools.computer_use.system_one import TransportError

_ENV_NAMES = (
    "TYPESAFE_API_KEY", "JEV_API_KEY", "OPENROUTER_API_KEY",
    "TYPESAFE_BASE_URL", "JEV_BASE_URL", "OPENROUTER_BASE_URL",
    "TYPESAFE_MODEL", "JEV_MODEL", "OPENROUTER_JEV_MODEL",
)


@pytest.fixture
def clean_env(monkeypatch):
    for name in _ENV_NAMES:
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def read(self):
        return json.dumps(self._payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _transport_call():
    captured = []

    def fake_urlopen(req, timeout=None):
        captured.append(req)
        return _FakeResp({"model": "typesafe/jev-1.13", "answers": {}, "usage": {}})

    def call(payload):
        with patch.object(urllib.request, "urlopen", fake_urlopen):
            decision_stages.http_transport(payload)
        return captured[-1]

    return call


def test_availability_includes_openrouter(clean_env):
    assert decision_lane.jev_available() is False
    clean_env.setenv("OPENROUTER_API_KEY", "sk-or-test")
    assert decision_lane.jev_available() is True


def test_openrouter_transport_url_auth_model(clean_env):
    clean_env.setenv("OPENROUTER_API_KEY", "sk-or-test")
    assert decision_stages._jev_model() == "~typesafe/jev-latest"
    req = _transport_call()({"state": "x", "model": decision_stages._jev_model(), "questions": {}})
    assert req.full_url == "https://openrouter.ai/api/alpha/decisions"
    assert req.get_header("Authorization") == "Bearer sk-or-test"
    assert json.loads(req.data)["model"] == "~typesafe/jev-latest"


def test_openrouter_env_overrides(clean_env):
    clean_env.setenv("OPENROUTER_API_KEY", "sk-or-test")
    clean_env.setenv("OPENROUTER_BASE_URL", "https://or.internal/")
    clean_env.setenv("OPENROUTER_JEV_MODEL", "typesafe/jev-1.13-20260917")
    assert decision_stages._jev_model() == "typesafe/jev-1.13-20260917"
    req = _transport_call()({"state": "x", "model": "m", "questions": {}})
    assert req.full_url == "https://or.internal/api/alpha/decisions"


def test_direct_key_wins_over_openrouter(clean_env):
    clean_env.setenv("OPENROUTER_API_KEY", "sk-or-test")
    clean_env.setenv("TYPESAFE_API_KEY", "ts-test")
    assert decision_stages._direct_transport() is True
    assert decision_stages._jev_model() == "jev-latest"
    req = _transport_call()({"state": "x", "model": "jev-latest", "questions": {}})
    assert req.full_url == "https://api.typesafe.ai/v1/systemone"
    assert req.get_header("Authorization") == "Bearer ts-test"


def test_missing_keys_raise(clean_env):
    with pytest.raises(TransportError):
        decision_stages.http_transport({"state": "x", "questions": {}})


def test_jev_stage_absent_without_any_key(clean_env):
    from tools.computer_use.decision_lane import ElementCandidate, SemanticState

    cands = (ElementCandidate("1", "Submit", role="button"),)
    assert decision_stages.jev_stage(SemanticState(goal_hint="Submit"), cands) is None

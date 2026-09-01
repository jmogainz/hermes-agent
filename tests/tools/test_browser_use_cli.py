"""Tests for the Browser Use CLI 3.0 backend (tools/browser_use_cli.py).

Covers the three seams the integration relies on:

* Mode detection — ``browser.backend: browser-use`` in config (set via the
  ``hermes tools`` picker); off by default.
* Tool-surface swap — when the mode is on, ``check_browser_requirements``
  returns False so every legacy ``browser_*`` tool (including
  browser_cdp/browser_dialog, whose check_fns funnel through it) is hidden,
  and ``browser_exec`` is advertised instead.
* ``browser_exec`` execution — code is piped on stdin, ``session`` becomes
  ``BU_NAME``, bad session names and a missing CLI produce actionable errors.
"""
import json
import os
import re
import shlex
import shutil
import socket
import stat
import subprocess
import tempfile
import threading
import time

import pytest

import tools.browser_use_cli as bu_cli


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("BU_NAME", raising=False)
    monkeypatch.delenv("BU_AUTOSPAWN", raising=False)
    monkeypatch.delenv("BROWSER_USE_API_KEY", raising=False)
    yield


def _fake_cli(tmp_path, body):
    """Write an executable fake browser-use CLI and return its path."""
    script = tmp_path / "browser-use"
    script.write_text("#!/bin/sh\n" + body)
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script)


def _start_private_ipc_server(tmp_path, session, response, *, delay=0.0):
    """Start one fake browser-harness AF_UNIX request/response exchange."""
    runtime = tmp_path.__class__(tempfile.mkdtemp(prefix="bh-test-", dir="/tmp"))
    runtime.chmod(0o700)
    endpoint = runtime / f"bu-{session}.sock"
    pid_path = runtime / f"bu-{session}.pid"
    pid_path.write_text(str(os.getpid()))
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(endpoint))
    endpoint.chmod(0o600)
    server.listen(1)
    server.settimeout(1.0)
    captured = []

    def serve():
        conn = None
        try:
            conn, _ = server.accept()
            data = b""
            while not data.endswith(b"\n"):
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data += chunk
            captured.append(data)
            if delay:
                time.sleep(delay)
            conn.sendall(response + b"\n")
        except OSError:
            pass
        finally:
            if conn is not None:
                conn.close()
            server.close()
            try:
                endpoint.unlink()
                pid_path.unlink()
                runtime.rmdir()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return runtime, endpoint, captured, thread


def _start_harness_019_server(
    tmp_path,
    session,
    handler,
    *,
    socket_mode=0o700,
    pid=None,
    max_connections=3,
):
    """Run a bounded server with browser-harness 0.1.9's wire/layout contract."""
    runtime = tmp_path.__class__(tempfile.mkdtemp(prefix="bh-019-", dir="/tmp"))
    runtime.chmod(0o700)
    endpoint = runtime / f"bu-{session}.sock"
    pid_path = runtime / f"bu-{session}.pid"
    pid_path.write_text(str(pid if pid is not None else os.getpid()))
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(endpoint))
    endpoint.chmod(socket_mode)
    server.listen(max_connections)
    server.settimeout(0.5)
    captured = []

    def serve():
        try:
            for _ in range(max_connections):
                try:
                    conn, _ = server.accept()
                except TimeoutError:
                    break
                with conn:
                    data = b""
                    while not data.endswith(b"\n"):
                        chunk = conn.recv(65536)
                        if not chunk:
                            break
                        data += chunk
                    request = json.loads(data)
                    captured.append(request)
                    response = handler(request)
                    conn.sendall(json.dumps(response).encode() + b"\n")
        finally:
            server.close()
            try:
                endpoint.unlink()
                pid_path.unlink()
                runtime.rmdir()
            except OSError:
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return runtime, endpoint, captured, thread


class TestModeDetection:
    def test_default_on_when_cli_available(self, monkeypatch):
        """Backend unset: Browser Use mode is the default when the CLI runs."""
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {})
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: ["/usr/bin/browser-use"])
        assert bu_cli.is_browser_use_cli_mode() is True

    def test_default_off_when_cli_unavailable(self, monkeypatch):
        """Backend unset + no runnable CLI: keep the built-in browser tools."""
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {})
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_explicit_off_wins_over_default(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": bu_cli.BACKEND_DISABLED}},
        )
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: ["/usr/bin/browser-use"])
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_yaml_bool_off_means_disabled(self, monkeypatch):
        """YAML 1.1 parses unquoted `off` as False — must mean disabled."""
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": False}},
        )
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: ["/usr/bin/browser-use"])
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_config_opt_in(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": "browser-use"}},
        )
        assert bu_cli.is_browser_use_cli_mode() is True

    def test_other_backend_value_is_not_cli_mode(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": "something-else"}},
        )
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_config_read_failure_uses_default(self, monkeypatch):
        def boom():
            raise RuntimeError("config unreadable")

        monkeypatch.setattr("hermes_cli.config.read_raw_config", boom)
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False


class TestSubprocessEnvironment:
    def test_browser_use_telemetry_defaults_off(self, monkeypatch):
        import sys
        from types import ModuleType

        browser_tool = ModuleType("tools.browser_tool")
        browser_tool._build_browser_env = lambda: {}
        monkeypatch.setitem(sys.modules, "tools.browser_tool", browser_tool)
        env = bu_cli._base_subprocess_env()
        assert env["ANONYMIZED_TELEMETRY"] == "false"

    def test_subprocess_env_strips_parent_python_import_paths(self, monkeypatch):
        """#83427/#84841/#86006/#86104: the browser-use CLI runs under its
        own Python — inherited PYTHONPATH/PYTHONHOME pointing at Hermes's
        venv make it import wrong-ABI C-extensions (pydantic_core) and
        crash. Both must be stripped; unrelated vars survive."""
        import sys
        from types import ModuleType

        browser_tool = ModuleType("tools.browser_tool")
        browser_tool._build_browser_env = lambda: {
            "PYTHONPATH": "/hermes:/hermes/venv/lib/site-packages",
            "PYTHONHOME": "/hermes/venv",
            "KEEP_ME": "yes",
        }
        monkeypatch.setitem(sys.modules, "tools.browser_tool", browser_tool)

        env = bu_cli._base_subprocess_env()

        assert "PYTHONPATH" not in env
        assert "PYTHONHOME" not in env
        assert env["KEEP_ME"] == "yes"

    @pytest.mark.skipif(os.name == "nt", reason="POSIX PATH-floor semantics")
    def test_subprocess_env_floors_version_manager_only_path(self, monkeypatch):
        """Profile workers (kanban bots, cron) can inherit a PATH of only
        version-manager dirs (observed in the wild: one nvm dir repeated
        7x). The uv browser-use trampoline resolves dirname/realpath
        through PATH, so /usr/bin must be guaranteed or the CLI dies
        'realpath: not found' (exit 127) before its Python starts."""
        import sys
        from types import ModuleType

        browser_tool = ModuleType("tools.browser_tool")
        browser_tool._build_browser_env = lambda: {
            "PATH": os.pathsep.join(
                ["/home/u/.nvm/versions/node/v24.18.0/bin"] * 7
            ),
        }
        monkeypatch.setitem(sys.modules, "tools.browser_tool", browser_tool)

        env = bu_cli._base_subprocess_env()

        parts = env["PATH"].split(os.pathsep)
        assert "/usr/bin" in parts
        assert "/bin" in parts

    @pytest.mark.skipif(os.name == "nt", reason="POSIX PATH-floor semantics")
    def test_floor_preserves_existing_entries_and_order(self):
        """The floor only adds dirs — never drops or reorders what the
        caller's environment already had."""
        original = "/opt/toolchain/bin:/usr/bin:/snap/bin"
        merged = bu_cli._floor_subprocess_path(original).split(os.pathsep)

        assert set(original.split(os.pathsep)) <= set(merged)
        positions = [merged.index(p) for p in original.split(os.pathsep)]
        assert positions == sorted(positions)

    @pytest.mark.skipif(os.name == "nt", reason="POSIX PATH-floor semantics")
    def test_floor_survives_missing_sibling_helper(self, monkeypatch):
        """If browser_tool stops exporting _merge_browser_path, the floor
        degrades to appending FHS bin dirs instead of vanishing."""
        import sys
        from types import ModuleType

        browser_tool = ModuleType("tools.browser_tool")
        browser_tool._build_browser_env = lambda: {
            "PATH": "/home/u/.nvm/versions/node/v24.18.0/bin"
        }
        monkeypatch.setitem(sys.modules, "tools.browser_tool", browser_tool)

        env = bu_cli._base_subprocess_env()

        parts = env["PATH"].split(os.pathsep)
        assert "/usr/bin" in parts
        assert "/home/u/.nvm/versions/node/v24.18.0/bin" in parts


class TestToolSurfaceSwap:
    def test_legacy_browser_tools_hidden_in_cli_mode(self, monkeypatch):
        import tools.browser_tool as browser_tool

        monkeypatch.setattr(browser_tool, "_is_browser_use_cli_mode", lambda: True)
        assert browser_tool.check_browser_requirements() is False
        assert browser_tool.check_browser_vision_requirements() is False

    def test_browser_exec_registered_with_mode_check(self):
        from tools.registry import registry

        entry = registry.get_entry("browser_exec")
        assert entry is not None
        assert entry.check_fn is bu_cli.is_browser_use_cli_mode
        assert entry.toolset == "browser-use"

    def test_browser_exec_in_browser_toolsets(self):
        from toolsets import TOOLSETS, _HERMES_CORE_TOOLS

        assert "browser_exec" in _HERMES_CORE_TOOLS
        assert "browser_exec" in TOOLSETS["browser"]["tools"]
        assert "browser_exec" in TOOLSETS["coding"]["tools"]

    def test_browser_exec_stripped_without_terminal(self, monkeypatch):
        """Sessions without the terminal surface must not regain host code
        execution through browser_exec (arbitrary Python via the CLI)."""
        monkeypatch.setattr(bu_cli, "is_browser_use_cli_mode", lambda: True)
        from tools.registry import registry

        entry = registry.get_entry("browser_exec")
        monkeypatch.setattr(entry, "check_fn", lambda: True)
        import model_tools

        defs = model_tools.get_tool_definitions(
            enabled_toolsets=["browser"], quiet_mode=False
        )
        names = {t["function"]["name"] for t in defs}
        assert "browser_exec" not in names

    def test_browser_exec_present_with_terminal(self, monkeypatch):
        monkeypatch.setattr(bu_cli, "is_browser_use_cli_mode", lambda: True)
        from tools.registry import registry

        entry = registry.get_entry("browser_exec")
        monkeypatch.setattr(entry, "check_fn", lambda: True)
        import model_tools

        defs = model_tools.get_tool_definitions(
            enabled_toolsets=["browser", "terminal"], quiet_mode=False
        )
        names = {t["function"]["name"] for t in defs}
        assert "browser_exec" in names


class TestFindCli:
    """The tests/tools conftest pins _find_cli to None (host isolation);
    exercise the real function via the preserved _find_cli_unpatched."""

    def test_prefers_installed_binary(self, monkeypatch):
        monkeypatch.setattr(
            bu_cli.shutil, "which",
            lambda name, path=None: "/usr/local/bin/browser-use" if name == "browser-use" and path is None else ("/usr/local/bin/uvx" if path is None else None),
        )
        assert bu_cli._find_cli_unpatched() == ["/usr/local/bin/browser-use"]

    def test_falls_back_to_uvx(self, monkeypatch):
        monkeypatch.setattr(
            bu_cli.shutil, "which",
            lambda name, path=None: "/usr/local/bin/uvx" if name == "uvx" and path is None else None,
        )
        assert bu_cli._find_cli_unpatched() == ["/usr/local/bin/uvx", "browser-use"]

    def test_none_when_neither_available(self, monkeypatch):
        monkeypatch.setattr(bu_cli.shutil, "which", lambda name, path=None: None)
        assert bu_cli._find_cli_unpatched() is None


class TestLegacyCloudMigration:
    """Pre-CLI direct-API Browser Use cloud configs (cloud_provider:
    "browser-use" + BROWSER_USE_API_KEY) auto-route to the CLI backend;
    Nous-gateway users stay on the legacy provider path."""

    _LEGACY = {"browser": {"cloud_provider": "browser-use"}}

    def test_direct_api_config_migrates(self, monkeypatch):
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: self._LEGACY)
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        assert bu_cli.is_browser_use_cli_mode() is True

    def test_gateway_config_stays_on_legacy_path(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"cloud_provider": "browser-use", "use_gateway": True}},
        )
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_no_api_key_stays_on_legacy_path(self, monkeypatch):
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: self._LEGACY)
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_camofox_user_does_not_migrate(self, monkeypatch):
        """A Camofox user (env-var selected, cloud_provider unset) with a
        stray BROWSER_USE_API_KEY keeps Camofox — no silent mode flip."""
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config", lambda: {"browser": {}}
        )
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        import tools.browser_camofox as camofox

        monkeypatch.setattr(camofox, "is_camofox_mode", lambda: True)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_camofox_overrides_explicit_backend(self, monkeypatch):
        """Even with browser.backend: browser-use, an active Camofox setup
        falls back to the built-in tools (no CDP surface to drive)."""
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": "browser-use"}},
        )
        import tools.browser_camofox as camofox

        monkeypatch.setattr(camofox, "is_camofox_mode", lambda: True)
        assert bu_cli.is_browser_use_cli_mode() is False


    def test_explicit_other_backend_wins(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"cloud_provider": "browser-use", "backend": "something-else"}},
        )
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_other_cloud_provider_does_not_migrate(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"cloud_provider": "browserbase"}},
        )
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_explicit_local_does_not_migrate(self, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"cloud_provider": "local"}},
        )
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_auto_detect_with_key_migrates(self, monkeypatch):
        """No cloud_provider configured + BROWSER_USE_API_KEY set: credential
        auto-detection prefers Browser Use (even when Browserbase creds are
        also present), which now means Browser Use mode."""
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {})
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        monkeypatch.setenv("BROWSERBASE_API_KEY", "bb-key")
        monkeypatch.setenv("BROWSERBASE_PROJECT_ID", "bb-project")
        assert bu_cli.is_browser_use_cli_mode() is True

    def test_auto_detect_without_key_does_not_migrate(self, monkeypatch):
        """No key, no CLI: nothing to migrate and no default flip."""
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {})
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.is_browser_use_cli_mode() is False

    def test_migrated_config_gets_bu_autospawn(self, tmp_path, monkeypatch):
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: self._LEGACY)
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "autospawn:$BU_AUTOSPAWN"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)"))
        assert "autospawn:1" in result["output"]

    def test_explicit_backend_does_not_set_bu_autospawn(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": "browser-use"}},
        )
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "autospawn:[$BU_AUTOSPAWN]"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)"))
        assert "autospawn:[]" in result["output"]

    def test_picker_highlights_cli_row_for_migrated_config(self, monkeypatch):
        from hermes_cli.tools_config import TOOL_CATEGORIES, _is_provider_active

        cli_row = next(
            r for r in TOOL_CATEGORIES["browser"]["providers"] if r.get("browser_backend")
        )
        monkeypatch.setenv("BROWSER_USE_API_KEY", "bu-key")
        assert _is_provider_active(cli_row, dict(self._LEGACY)) is True
        monkeypatch.delenv("BROWSER_USE_API_KEY")
        assert _is_provider_active(cli_row, dict(self._LEGACY)) is False


class TestBackendCdpResolution:
    """browser_exec routes through the configured browser backend by reusing
    the legacy stack's provider session machinery (_get_session_info)."""

    def _env(self):
        return {}

    def test_existing_bu_env_wins(self, monkeypatch):
        env = {"BU_CDP_WS": "ws://operator-override:9222"}
        assert bu_cli._resolve_backend_cdp(env, "t1") is None
        assert env["BU_CDP_WS"] == "ws://operator-override:9222"

    def test_cdp_override_exported(self, monkeypatch):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "http://127.0.0.1:9222")
        env = self._env()
        assert bu_cli._resolve_backend_cdp(env, "t1") is None
        assert env["BU_CDP_URL"] == "http://127.0.0.1:9222"

    def test_webui_thread_local_cdp_override_precedes_process_backend(
        self, monkeypatch
    ):
        import sys
        import types
        import tools.browser_tool as bt

        fake_api = types.ModuleType("api")
        fake_config = types.ModuleType("api.config")
        fake_config._thread_local_env_value = (
            lambda name, default="": (
                "http://127.0.0.1:9246"
                if name == "HERMES_WEBUI_BROWSER_CDP_URL"
                else default
            )
        )
        monkeypatch.setitem(sys.modules, "api", fake_api)
        monkeypatch.setitem(sys.modules, "api.config", fake_config)
        monkeypatch.delenv("HERMES_WEBUI_BROWSER_CDP_URL", raising=False)
        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "http://127.0.0.1:9222")

        env = self._env()
        assert bu_cli._resolve_backend_cdp(env, "t1") is None
        assert env["BU_CDP_URL"] == "http://127.0.0.1:9246"

    def test_ws_override_uses_bu_cdp_ws(self, monkeypatch):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "wss://connect.example/x")
        env = self._env()
        assert bu_cli._resolve_backend_cdp(env, "t1") is None
        assert env["BU_CDP_WS"] == "wss://connect.example/x"

    def test_cloud_provider_session_exported(self, monkeypatch):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
        monkeypatch.setattr(
            bt, "_get_session_info",
            lambda task_id: {"cdp_url": "wss://browser.example/cdp/abc"},
        )
        env = self._env()
        assert bu_cli._resolve_backend_cdp(env, "t1") is None
        assert env["BU_CDP_WS"] == "wss://browser.example/cdp/abc"

    def test_no_provider_leaves_env_untouched(self, monkeypatch):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: None)
        env = self._env()
        assert bu_cli._resolve_backend_cdp(env, "t1") is None
        assert "BU_CDP_WS" not in env and "BU_CDP_URL" not in env

    def test_provider_failure_returns_error(self, monkeypatch):
        import tools.browser_tool as bt

        def boom(task_id):
            raise RuntimeError("api down")

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
        monkeypatch.setattr(bt, "_get_session_info", boom)
        err = bu_cli._resolve_backend_cdp(self._env(), "t1")
        assert err and "api down" in err

    def test_provider_without_cdp_returns_error(self, monkeypatch):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
        monkeypatch.setattr(bt, "_get_session_info", lambda task_id: {"cdp_url": None})
        err = bu_cli._resolve_backend_cdp(self._env(), "t1")
        assert err and "no" in err.lower() and "CDP" in err

    def test_named_session_composes_with_provider_backend(self, tmp_path, monkeypatch):
        """session=<name> composes with a configured provider backend: the
        name keys its OWN provider browser (bu-named-<name>), so concurrent
        named sessions never share one browser (#86894)."""
        import tools.browser_tool as bt

        seen = []

        def fake_session_info(key):
            seen.append(key)
            return {"cdp_url": "wss://browser.example/cdp/" + key}

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
        monkeypatch.setattr(bt, "_get_session_info", fake_session_info)
        monkeypatch.setattr(bu_cli, "_PROCESS_GENERATION", "provider-test-generation")
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "bu:$BU_NAME ws:$BU_CDP_WS"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)", session="r7k2"))
        effective = bu_cli._effective_session_name("r7k2", None)
        assert result["success"] is True
        assert seen == [f"bu-named-{effective}"]
        assert f"bu:{effective}" in result["output"]
        assert f"ws:wss://browser.example/cdp/bu-named-{effective}" in result["output"]
        assert result["session"] == "r7k2"

    def test_effective_named_session_is_task_and_process_scoped(self):
        same_a = bu_cli._effective_session_name("research", "task-A", process_generation="gen-1")
        same_b = bu_cli._effective_session_name("research", "task-A", process_generation="gen-1")
        other_task = bu_cli._effective_session_name("research", "task-B", process_generation="gen-1")
        other_process = bu_cli._effective_session_name("research", "task-A", process_generation="gen-2")

        assert same_a == same_b
        assert same_a != other_task
        assert same_a != other_process
        assert same_a.startswith("ha1-")
        assert len(same_a) <= 64
        assert bu_cli._SESSION_RE.fullmatch(same_a)

    def test_browser_exec_uses_effective_name_but_returns_requested_label(self, tmp_path, monkeypatch):
        import tools.browser_tool as bt

        seen = []
        monkeypatch.setattr(bu_cli, "_PROCESS_GENERATION", "test-generation")
        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
        monkeypatch.setattr(
            bt,
            "_get_session_info",
            lambda key: seen.append(key) or {"cdp_url": "wss://x/cdp/a"},
        )
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "effective:$BU_NAME"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])

        result = json.loads(
            bu_cli.browser_exec(
                "print(1)",
                session="research",
                task_id="task-A",
                _internal_native_auth=True,
                _disable_native_auth_probe=True,
            )
        )
        effective = bu_cli._effective_session_name("research", "task-A")
        assert seen == [f"bu-named-{effective}"]
        assert f"effective:{effective}" in result["output"]
        assert result["session"] == "research"
        runtime = tmp_path / "runtime"
        runtime.mkdir(mode=0o700)
        runtime.chmod(0o700)
        monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
        monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")
        resolved_runtime, stem = bu_cli._harness_runtime_layout(effective)
        assert resolved_runtime == runtime.resolve()
        assert resolved_runtime / f"{stem}.sock" == runtime.resolve() / f"bu-{effective}.sock"

    def test_named_session_direct_api_bu_cloud_still_skips_provider(
        self, tmp_path, monkeypatch
    ):
        """Direct-API Browser Use cloud configs keep the native named-daemon
        path: resolving through the provider would double-session and
        double-bill."""
        import tools.browser_tool as bt

        class _BUProvider:
            name = "browser-use"

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: _BUProvider())
        monkeypatch.setattr(
            bt, "_get_session_info",
            lambda key: (_ for _ in ()).throw(AssertionError("must skip provider")),
        )
        monkeypatch.setattr(bu_cli, "_read_browser_cfg", lambda: {"cloud_provider": "browser-use"})
        env = {}
        assert bu_cli._resolve_backend_cdp(env, "t1", session_name="r7k2") is None
        assert "BU_CDP_WS" not in env and "BU_CDP_URL" not in env


class TestOwnTabPreamble:
    """Named sessions on SHARED browsers get the own-tab preamble prepended;
    private per-name browsers and unnamed sessions do not."""

    def _run(self, tmp_path, monkeypatch, *, session="", private=False, provider=False):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        if provider:
            monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
            monkeypatch.setattr(
                bt, "_get_session_info",
                lambda key: {"cdp_url": "wss://browser.example/cdp/" + key},
            )
        else:
            monkeypatch.setattr(bt, "_get_cloud_provider", lambda: None)
        # fake CLI echoes stdin back so we can inspect what code was sent
        cli = _fake_cli(tmp_path, "cat\n")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        return json.loads(bu_cli.browser_exec("print('payload')", session=session))

    def test_named_shared_browser_gets_preamble(self, tmp_path, monkeypatch):
        result = self._run(tmp_path, monkeypatch, session="r7k2")
        assert result["success"] is True
        assert "_hermes_ensure_own_tab" in result["output"]
        # model code still present, after the preamble
        assert result["output"].index("_hermes_ensure_own_tab") < result["output"].index("print('payload')")

    def test_unnamed_session_gets_no_preamble(self, tmp_path, monkeypatch):
        result = self._run(tmp_path, monkeypatch, session="")
        assert result["success"] is True
        assert "_hermes_ensure_own_tab" not in result["output"]

    def test_named_provider_browser_skips_preamble(self, tmp_path, monkeypatch):
        """Per-name provider browsers are private — preamble would leak a tab."""
        result = self._run(tmp_path, monkeypatch, session="r7k2", provider=True)
        assert result["success"] is True
        assert "_hermes_ensure_own_tab" not in result["output"]

    def test_sentinel_never_reaches_subprocess_env(self, tmp_path, monkeypatch):
        import tools.browser_tool as bt

        monkeypatch.setattr(bt, "_get_cdp_override", lambda: "")
        monkeypatch.setattr(bt, "_get_cloud_provider", lambda: object())
        monkeypatch.setattr(
            bt, "_get_session_info",
            lambda key: {"cdp_url": "wss://browser.example/cdp/" + key},
        )
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "sentinel:${_HERMES_BU_PRIVATE_BROWSER:-unset}"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)", session="r7k2"))
        assert "sentinel:unset" in result["output"]

    def test_preamble_is_valid_python(self):
        import ast

        ast.parse(bu_cli._OWN_TAB_PREAMBLE)
        # and composes with model code
        ast.parse(bu_cli._OWN_TAB_PREAMBLE + "print('x')")


class TestOwnedBrowserUseDaemonLifecycle:
    def test_register_and_task_cleanup_are_private_and_idempotent(self, tmp_path, monkeypatch):
        runtime = tmp_path / "runtime"
        runtime.mkdir(mode=0o700)
        runtime.chmod(0o700)
        monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
        monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")
        monkeypatch.setattr(bu_cli, "_OWNED_DAEMONS", {})
        calls = []

        def control(session, action, *, timeout_s=None):
            calls.append((session, action))
            return True

        monkeypatch.setattr(bu_cli, "_private_daemon_control", control)
        daemon_identity = (4242, ("sha256", "daemon-fingerprint"))
        monkeypatch.setattr(bu_cli, "_private_daemon_identity", lambda *_a, **_k: daemon_identity)
        name = "ha1-owned-session"
        assert bu_cli._register_owned_daemon(name, "task-owned") is True
        marker = runtime / f"{name}.owner.json"
        assert marker.exists()
        assert stat.S_IMODE(marker.stat().st_mode) == 0o600
        payload = json.loads(marker.read_text())
        assert payload == {
            "version": 2,
            "session": name,
            "task_id": "task-owned",
            "owner_pid": os.getpid(),
            "daemon_pid": daemon_identity[0],
            "daemon_identity": list(daemon_identity[1]),
        }

        bu_cli.cleanup_browser_use_task("task-owned")
        bu_cli.cleanup_browser_use_task("task-owned")
        assert calls == [(name, "ping"), (name, "shutdown")]
        assert not marker.exists()

    @pytest.mark.parametrize("mutation", ["symlink", "mode", "owner_pid", "daemon_pid", "daemon_identity", "task", "session", "legacy", "malformed_version"])
    def test_verify_native_auth_owner_rejects_untrusted_marker_variants(
        self, tmp_path, monkeypatch, mutation
    ):
        name, task_id = "ha1-owned-session", "task-owned"
        daemon_identity = (4242, ("sha256", "daemon-fingerprint"))
        marker = tmp_path / f"{name}.owner.json"
        payload = {
            "version": 2, "session": name, "task_id": task_id,
            "owner_pid": os.getpid(), "daemon_pid": daemon_identity[0],
            "daemon_identity": list(daemon_identity[1]),
        }
        marker.write_text(json.dumps(payload))
        marker.chmod(0o600)
        if mutation == "symlink":
            target = tmp_path / "marker-target.json"
            target.write_text(json.dumps(payload))
            target.chmod(0o600)
            marker.unlink()
            marker.symlink_to(target)
        elif mutation == "mode":
            marker.chmod(0o644)
        elif mutation == "daemon_pid":
            payload["daemon_pid"] += 1
            marker.write_text(json.dumps(payload))
        elif mutation == "owner_pid":
            payload["owner_pid"] += 1
            marker.write_text(json.dumps(payload))
        elif mutation == "daemon_identity":
            payload["daemon_identity"] = ["sha256", "wrong"]
            marker.write_text(json.dumps(payload))
        elif mutation == "task":
            payload["task_id"] = "other-task"
            marker.write_text(json.dumps(payload))
        elif mutation == "session":
            payload["session"] = "ha1-other-session"
            marker.write_text(json.dumps(payload))
        elif mutation == "legacy":
            payload = {"version": 1, "session": name, "task_id": task_id, "owner_pid": os.getpid()}
            marker.write_text(json.dumps(payload))
        elif mutation == "malformed_version":
            payload["version"] = "2"
            marker.write_text(json.dumps(payload))

        monkeypatch.setattr(bu_cli, "_effective_session_name", lambda *_a, **_k: name)
        monkeypatch.setattr(bu_cli, "_OWNED_DAEMONS", {name: task_id})
        monkeypatch.setattr(bu_cli, "_owned_daemon_marker", lambda _session: marker)
        monkeypatch.setattr(bu_cli, "_private_daemon_identity", lambda *_a, **_k: daemon_identity)
        monkeypatch.setattr(bu_cli, "_private_daemon_control", lambda *_a, **_k: pytest.fail("fallback ping must not authorize"))
        assert bu_cli._verify_native_auth_owner(name, task_id) is False

    def test_verify_native_auth_owner_accepts_exact_regular_marker(self, tmp_path, monkeypatch):
        name, task_id = "ha1-owned-session", "task-owned"
        daemon_identity = (4242, ("sha256", "daemon-fingerprint"))
        marker = tmp_path / f"{name}.owner.json"
        marker.write_text(json.dumps({
            "version": 2, "session": name, "task_id": task_id,
            "owner_pid": os.getpid(), "daemon_pid": daemon_identity[0],
            "daemon_identity": list(daemon_identity[1]),
        }))
        marker.chmod(0o600)
        monkeypatch.setattr(bu_cli, "_effective_session_name", lambda *_a, **_k: name)
        monkeypatch.setattr(bu_cli, "_OWNED_DAEMONS", {name: task_id})
        monkeypatch.setattr(bu_cli, "_owned_daemon_marker", lambda _session: marker)
        monkeypatch.setattr(bu_cli, "_private_daemon_identity", lambda *_a, **_k: daemon_identity)
        assert bu_cli._verify_native_auth_owner(name, task_id) is True

    def test_verify_native_auth_owner_rejects_symlink_when_nofollow_is_unavailable(self, tmp_path, monkeypatch):
        name, task_id = "ha1-owned-session", "task-owned"
        daemon_identity = (4242, ("sha256", "daemon-fingerprint"))
        target = tmp_path / "marker-target.json"
        target.write_text(json.dumps({
            "version": 2, "session": name, "task_id": task_id,
            "owner_pid": os.getpid(), "daemon_pid": daemon_identity[0],
            "daemon_identity": list(daemon_identity[1]),
        }))
        target.chmod(0o600)
        marker = tmp_path / f"{name}.owner.json"
        marker.symlink_to(target)

        # Model a platform without O_NOFOLLOW and an ineffective open boundary:
        # the path lookup and open both resolve the symlink target.
        real_open = os.open
        monkeypatch.delattr(bu_cli.os, "O_NOFOLLOW", raising=False)
        monkeypatch.setattr(type(marker), "lstat", lambda _path: target.stat())
        monkeypatch.setattr(bu_cli.os, "open", lambda _path, _flags: real_open(target, os.O_RDONLY))
        monkeypatch.setattr(bu_cli, "_effective_session_name", lambda *_a, **_k: name)
        monkeypatch.setattr(bu_cli, "_OWNED_DAEMONS", {name: task_id})
        monkeypatch.setattr(bu_cli, "_owned_daemon_marker", lambda _session: marker)
        monkeypatch.setattr(bu_cli, "_private_daemon_identity", lambda *_a, **_k: daemon_identity)

        assert bu_cli._verify_native_auth_owner(name, task_id) is False

    @pytest.mark.parametrize("daemon_identity", [
        ["sha256", True],
        ["sha256"],
        "sha256:daemon-fingerprint",
        {"algorithm": "sha256", "value": "daemon-fingerprint"},
    ])
    def test_verify_native_auth_owner_rejects_non_exact_daemon_identity_types(
        self, tmp_path, monkeypatch, daemon_identity
    ):
        name, task_id = "ha1-owned-session", "task-owned"
        live_identity = (4242, ("sha256", 1))
        marker = tmp_path / f"{name}.owner.json"
        marker.write_text(json.dumps({
            "version": 2, "session": name, "task_id": task_id,
            "owner_pid": os.getpid(), "daemon_pid": live_identity[0],
            "daemon_identity": daemon_identity,
        }))
        marker.chmod(0o600)
        monkeypatch.setattr(bu_cli, "_effective_session_name", lambda *_a, **_k: name)
        monkeypatch.setattr(bu_cli, "_OWNED_DAEMONS", {name: task_id})
        monkeypatch.setattr(bu_cli, "_owned_daemon_marker", lambda _session: marker)
        monkeypatch.setattr(bu_cli, "_private_daemon_identity", lambda *_a, **_k: live_identity)

        assert bu_cli._verify_native_auth_owner(name, task_id) is False


    def test_native_auth_descriptor_fails_closed_for_aria_disabled_and_readonly(self):
        descriptor = bu_cli._NATIVE_AUTH_V2_DESCRIPTOR_FUNCTION
        disabled_check = re.compile(r"getAttribute\(['\"]aria-disabled['\"]\)\s*===\s*['\"]true['\"]")
        readonly_check = re.compile(r"this\.readOnly\s*===\s*true")
        eligibility_return = "return {eligible:true"
        disabled_match = disabled_check.search(descriptor)
        readonly_match = readonly_check.search(descriptor)
        assert disabled_match
        assert readonly_match
        assert disabled_match.start() < descriptor.index(eligibility_return)
        assert readonly_match.start() < descriptor.index(eligibility_return)

    def test_native_auth_descriptor_rejects_disabled_ancestors_and_nonfillable_roles(self):
        descriptor = bu_cli._NATIVE_AUTH_V2_DESCRIPTOR_FUNCTION
        for guard in (
            "this.closest('[aria-disabled=\"true\"]')",
            "this.closest('[inert]')",
            "this.closest('fieldset:disabled')",
        ):
            assert guard in descriptor
            assert descriptor.index(guard) < descriptor.index("return {eligible:true")

        # A role alone must not turn an arbitrary non-editable element into a
        # fill target; native editable controls remain the eligible cases.
        assert re.search(
            r"role\s*===\s*['\"]textbox['\"]\s*&&\s*!\s*\([^)]*HTMLInputElement",
            descriptor,
        )
        assert "HTMLTextAreaElement" in descriptor
        assert "isContentEditable" in descriptor

    def test_native_auth_descriptor_role_and_ancestor_contract_in_dom_harness(self):
        if not shutil.which("node"):
            pytest.skip("node is required for the browser-side descriptor contract probe")

        function_declaration = json.dumps(bu_cli._NATIVE_AUTH_V2_DESCRIPTOR_FUNCTION)
        harness = f"""
global.document = {{}};
global.getComputedStyle = () => ({{display: 'block', visibility: 'visible'}});
class Element {{
  constructor({{role = '', editable = false, ancestors = []}} = {{}}) {{
    this.isConnected = true;
    this.ownerDocument = global.document;
    this.disabled = false;
    this.readOnly = false;
    this.hidden = false;
    this.required = false;
    this.textContent = '';
    this.isContentEditable = editable;
    this._role = role;
    this._ancestors = ancestors;
  }}
  getAttribute(name) {{
    if (name === 'role') return this._role || null;
    return null;
  }}
  hasAttribute() {{ return false; }}
  getBoundingClientRect() {{ return {{width: 10, height: 10}}; }}
  closest(selector) {{
    return this._ancestors.find((ancestor) =>
      (selector.includes('[aria-disabled="true"]') && ancestor.ariaDisabled) ||
      (selector.includes('[inert]') && ancestor.inert) ||
      (selector.includes('fieldset:disabled') && ancestor.fieldsetDisabled)
    ) || null;
  }}
}}
class HTMLInputElement extends Element {{
  constructor(options = {{}}) {{ super(options); this.type = 'text'; }}
}}
class HTMLTextAreaElement extends Element {{
  constructor(options = {{}}) {{ super(options); }}
}}
class HTMLSelectElement extends Element {{}}
class HTMLButtonElement extends Element {{}}
class HTMLAnchorElement extends Element {{}}
global.Element = Element;
global.HTMLInputElement = HTMLInputElement;
global.HTMLTextAreaElement = HTMLTextAreaElement;
global.HTMLSelectElement = HTMLSelectElement;
global.HTMLButtonElement = HTMLButtonElement;
global.HTMLAnchorElement = HTMLAnchorElement;
const fn = eval('(' + {function_declaration} + ')');
const inspect = (element) => {{
  try {{ return fn.call(element).eligible === true; }}
  catch (_error) {{ return 'error'; }}
}};
const ancestor = (key) => [{{[key]: true}}];
const result = {{
  arbitraryRoleTextbox: inspect(new Element({{role: 'textbox'}})),
  ariaDisabledAncestor: inspect(new HTMLInputElement({{ancestors: ancestor('ariaDisabled')}})),
  inertAncestor: inspect(new HTMLInputElement({{ancestors: ancestor('inert')}})),
  disabledFieldsetAncestor: inspect(new HTMLInputElement({{ancestors: ancestor('fieldsetDisabled')}})),
  input: inspect(new HTMLInputElement()),
  textarea: inspect(new HTMLTextAreaElement()),
  contenteditable: inspect(new Element({{editable: true}})),
}};
process.stdout.write(JSON.stringify(result));
"""

        proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True, check=True)

        assert json.loads(proc.stdout) == {
            "arbitraryRoleTextbox": False,
            "ariaDisabledAncestor": False,
            "inertAncestor": False,
            "disabledFieldsetAncestor": False,
            "input": True,
            "textarea": True,
            "contenteditable": True,
        }

    def test_orphan_reaper_only_touches_versioned_dead_owned_daemons(self, tmp_path, monkeypatch):
        runtime = tmp_path / "runtime"
        runtime.mkdir(mode=0o700)
        runtime.chmod(0o700)
        monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
        monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")
        monkeypatch.setattr(bu_cli, "_OWNED_DAEMONS", {})
        live_name = "ha1-dead-owner"
        (runtime / f"{live_name}.owner.json").write_text(
            json.dumps({"version": 1, "session": live_name, "task_id": "old", "owner_pid": 424242})
        )
        (runtime / f"{live_name}.owner.json").chmod(0o600)
        (runtime / "legacy.owner.json").write_text(
            json.dumps({"version": 1, "session": "legacy", "owner_pid": 424242})
        )
        calls = []
        monkeypatch.setattr(bu_cli, "_pid_is_alive", lambda pid: False)

        def control(session, action, *, timeout_s=None):
            calls.append((session, action))
            return True

        monkeypatch.setattr(bu_cli, "_private_daemon_control", control)
        assert bu_cli.reap_owned_browser_use_orphans(limit=8) == 1
        assert calls == [(live_name, "ping"), (live_name, "shutdown")]
        assert not (runtime / f"{live_name}.owner.json").exists()
        assert (runtime / "legacy.owner.json").exists()


class TestProviderPickerIntegration:
    """The `hermes tools` Browser Automation picker row (browser_backend
    marker) must enter/leave CLI mode cleanly and highlight correctly."""

    def _rows(self):
        from hermes_cli.tools_config import TOOL_CATEGORIES

        return TOOL_CATEGORIES["browser"]["providers"]

    def test_picker_has_browser_use_cli_row(self):
        row = next(r for r in self._rows() if r.get("browser_backend"))
        assert row["browser_backend"] == "browser-use"
        assert row["name"] == "Browser Use"

    def test_picker_row_names_stay_unique(self):
        """The CLI row is named "Browser Use"; the legacy plugin API row must
        keep a distinct name — apply_provider_selection matches by name."""
        from hermes_cli.tools_config import TOOL_CATEGORIES, _plugin_browser_providers

        names = [r["name"] for r in TOOL_CATEGORIES["browser"]["providers"]]
        names += [r["name"] for r in _plugin_browser_providers()]
        assert len(names) == len(set(names))

    def test_selecting_cli_row_writes_backend_and_keeps_cloud_provider(self):
        from hermes_cli.tools_config import _write_provider_config

        row = next(r for r in self._rows() if r.get("browser_backend"))
        config = {"browser": {"cloud_provider": "browserbase"}}
        assert row["name"] == "Browser Use"
        _write_provider_config(row, config, managed_feature=None)
        assert config["browser"]["backend"] == "browser-use"
        assert config["browser"]["cloud_provider"] == "browserbase"

    def test_selecting_provider_row_keeps_cli_mode(self):
        """Backend composes with the provider: switching browser source
        (local/Browserbase/Firecrawl/gateway) keeps the driver choice."""
        from hermes_cli.tools_config import _write_provider_config

        local_row = next(
            r for r in self._rows() if r.get("browser_provider") == "local"
        )
        config = {"browser": {"backend": "browser-use"}}
        _write_provider_config(local_row, config, managed_feature=None)
        assert config["browser"]["backend"] == "browser-use"
        assert config["browser"]["cloud_provider"] == "local"

    def test_provider_row_stays_active_alongside_cli_mode(self, monkeypatch):
        from hermes_cli.tools_config import _is_provider_active

        cli_row = next(r for r in self._rows() if r.get("browser_backend"))
        local_row = next(
            r for r in self._rows() if r.get("browser_provider") == "local"
        )
        cli_config = {"browser": {"cloud_provider": "local", "backend": "browser-use"}}
        assert _is_provider_active(cli_row, cli_config) is True
        # Provider row remains highlighted: it supplies the browser the CLI
        # driver attaches to.
        assert _is_provider_active(local_row, cli_config) is True

        # Explicit off: the CLI row must not highlight even with the CLI
        # installed (default-on only applies while backend is unset).
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: ["/usr/bin/browser-use"])
        off_config = {"browser": {"cloud_provider": "local", "backend": "off"}}
        assert _is_provider_active(cli_row, off_config) is False
        assert _is_provider_active(local_row, off_config) is True

        # Backend unset: default-on — the CLI row highlights when the CLI
        # is runnable, and not when it isn't.
        default_config = {"browser": {"cloud_provider": "local"}}
        assert _is_provider_active(cli_row, default_config) is True
        assert _is_provider_active(local_row, default_config) is True
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert _is_provider_active(cli_row, default_config) is False


class TestBrowserUseSlashCommand:
    """/browser use [off] toggles browser.backend and resets the session,
    mirroring the /tools enable/disable flow."""

    class _Stub:
        def __init__(self):
            self.session_resets = 0

        def new_session(self):
            self.session_resets += 1

    def _run(self, cmd, config, monkeypatch):
        import hermes_cli.config as hc
        from hermes_cli.cli_commands_mixin import CLICommandsMixin

        saved = {}
        monkeypatch.setattr(hc, "load_config", lambda: config)
        monkeypatch.setattr(hc, "save_config", lambda c: saved.update(c))
        stub = self._Stub()
        CLICommandsMixin._handle_browser_command(stub, cmd)
        return stub, saved

    def test_use_enables_backend_and_resets_session(self, monkeypatch):
        stub, saved = self._run("/browser use", {}, monkeypatch)
        assert saved["browser"]["backend"] == "browser-use"
        assert stub.session_resets == 1

    def test_use_off_pins_backend_off(self, monkeypatch):
        """`off` must be written explicitly (BACKEND_DISABLED), not removed:
        with the key merely deleted, is_legacy_browser_use_cloud_config()
        would re-activate CLI mode on the next start for anyone with
        BROWSER_USE_API_KEY set, so /browser use off wouldn't stick."""
        config = {"browser": {"backend": "browser-use"}}
        stub, saved = self._run("/browser use off", config, monkeypatch)
        assert saved["browser"]["backend"] == bu_cli.BACKEND_DISABLED
        assert stub.session_resets == 1

    def test_use_bad_arg_prints_usage_without_writing(self, monkeypatch):
        stub, saved = self._run("/browser use whatever", {}, monkeypatch)
        assert saved == {}
        assert stub.session_resets == 0


class TestNativeScreenshots:
    """Screenshots printed by capture_screenshot() attach directly to the
    model's context when it has native vision — no aux vision-LLM detour."""

    def _shot(self, tmp_path):
        shot = tmp_path / "shot.png"
        shot.write_bytes(b"\x89PNG fake")
        return str(shot)

    def test_find_screenshot_returns_last_fresh_path(self, tmp_path):
        a, b = self._shot(tmp_path), str(tmp_path / "b.png")
        (tmp_path / "b.png").write_bytes(b"\x89PNG fake2")
        out = f"step one saved {a}\nthen saved {b}\n"
        assert bu_cli._find_screenshot(out, since=time.time() - 5) == b

    def test_find_screenshot_rejects_stale_and_missing(self, tmp_path):
        stale = self._shot(tmp_path)
        os.utime(stale, (time.time() - 900, time.time() - 900))
        out = f"{stale}\n/nonexistent/dir/x.png\n"
        assert bu_cli._find_screenshot(out, since=time.time()) is None

    def test_vision_model_gets_multimodal_envelope(self, tmp_path, monkeypatch):
        shot = self._shot(tmp_path)
        cli = _fake_cli(tmp_path, f'cat > /dev/null\necho "{shot}"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        monkeypatch.setattr(
            "tools.vision_tools._should_use_native_vision_fast_path", lambda: True
        )
        monkeypatch.setattr(
            "tools.vision_tools._resize_image_for_vision",
            lambda p, **kw: "data:image/png;base64,QUJD",
        )
        result = bu_cli.browser_exec("print(capture_screenshot())")
        assert isinstance(result, dict) and result["_multimodal"] is True
        kinds = [part["type"] for part in result["content"]]
        assert kinds == ["text", "image_url"]
        assert result["meta"]["screenshot_path"] == shot
        assert shot in result["text_summary"]

    def test_text_only_model_gets_plain_result_with_path(self, tmp_path, monkeypatch):
        shot = self._shot(tmp_path)
        cli = _fake_cli(tmp_path, f'cat > /dev/null\necho "{shot}"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        monkeypatch.setattr(
            "tools.vision_tools._should_use_native_vision_fast_path", lambda: False
        )
        result = json.loads(bu_cli.browser_exec("print(capture_screenshot())"))
        assert result["screenshot_path"] == shot

    def test_no_screenshot_keeps_string_result(self, tmp_path, monkeypatch):
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "no images here"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)"))
        assert "screenshot_path" not in result


class TestStepLabels:
    """browser_exec code leads with a `# …` comment (per the tool
    description); the TUI surfaces it as the step label and keeps the code
    collapsed behind display.tool_preview_length."""

    _CODE = "# Searching Amazon for paper towels\nnew_tab('https://amazon.com')\nwait_for_load()"

    def test_leading_comment_becomes_step_label(self):
        from agent.display import _browser_exec_step_label

        assert _browser_exec_step_label({"code": self._CODE}) == "Searching Amazon for paper towels"

    def test_no_comment_returns_none(self):
        from agent.display import _browser_exec_step_label

        assert _browser_exec_step_label({"code": "new_tab('x')"}) is None
        assert _browser_exec_step_label({"code": ""}) is None
        assert _browser_exec_step_label({"code": "#   "}) is None

    def test_label_hard_capped_regardless_of_global_setting(self):
        from agent.display import _browser_exec_step_label

        long = "# " + "x" * 200
        label = _browser_exec_step_label({"code": long})
        assert len(label) <= 80 and label.endswith("…")

    def test_preview_prefers_comment_over_code(self):
        from agent.display import build_tool_preview

        assert build_tool_preview("browser_exec", {"code": self._CODE}) == (
            "Searching Amazon for paper towels"
        )
        assert "new_tab" in build_tool_preview("browser_exec", {"code": "new_tab('x')"})

    def test_progress_line_shows_label(self):
        from agent.display import get_cute_tool_message

        line = get_cute_tool_message("browser_exec", {"code": self._CODE}, 1.2)
        assert "Searching Amazon for paper towels" in line
        assert "new_tab" not in line

    def test_header_instructs_leading_comment(self):
        assert "one-line comment" in bu_cli._HEADER_BASE
        assert "step label" in bu_cli._HEADER_BASE


class TestHeaderVariants:
    def test_schema_requires_navigation_and_actions_in_separate_calls(self):
        description = bu_cli._HEADER_BASE + bu_cli._HELPERS_DIGEST

        assert "Navigation/target changes and actions must use separate calls" in description
        assert "Batch each sub-procedure (navigate, wait, extract, act) into one call" not in description

    def test_vision_header_forbids_vision_tool_detour(self, monkeypatch):
        monkeypatch.setattr(
            "tools.vision_tools._should_use_native_vision_fast_path", lambda: True
        )
        header = bu_cli._description_header()
        assert header.startswith(bu_cli._HEADER_BASE)
        assert "attached to your context automatically" in header

    def test_text_only_header_teaches_text_workflow(self, monkeypatch):
        monkeypatch.setattr(
            "tools.vision_tools._should_use_native_vision_fast_path", lambda: False
        )
        header = bu_cli._description_header()
        assert "cannot view images" in header
        assert "page_info()" in header


class TestSkillTextDescription:
    """The schema description is fully pinned: header + _HELPERS_DIGEST.

    The live ``browser-use skill`` fetch was removed after A/B benchmarking
    showed the pinned digest matches the full skill dump on success rate
    (36/36 vs 36/36, opus-4.8 + kimi-k3) — see tools/browser_use_cli.py.
    """

    def test_description_is_pinned_header_plus_digest(self, monkeypatch):
        # Even with a CLI present, the description must NOT shell out.
        monkeypatch.setattr(
            bu_cli, "_find_cli",
            lambda: (_ for _ in ()).throw(AssertionError("schema must not invoke the CLI")),
        )
        overrides = bu_cli._dynamic_schema_overrides()
        assert overrides["description"].startswith(bu_cli._HEADER_BASE)
        assert overrides["description"].endswith(bu_cli._HELPERS_DIGEST)

    def test_digest_names_core_helpers(self):
        for helper in ("new_tab(", "page_info()", "js(", "fill_input(",
                       "click_at_xy(", "capture_screenshot()", "cdp("):
            assert helper in bu_cli._HELPERS_DIGEST

    def test_digest_routes_auth_walls_to_native_component_request(self):
        assert "<semreh.native-component>" in bu_cli._HELPERS_DIGEST
        assert "website_login" not in bu_cli._HELPERS_DIGEST
        assert "never" in bu_cli._HELPERS_DIGEST.lower()
        assert "credential" in bu_cli._HELPERS_DIGEST.lower()

    def test_static_fallback_carries_digest_and_install_hint(self):
        desc = bu_cli.BROWSER_EXEC_SCHEMA["description"]
        assert bu_cli._HELPERS_DIGEST in desc
        assert "uv tool install browser-use" in desc


class TestBrowserExec:
    def test_missing_cli_returns_install_hint(self, monkeypatch):
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        result = json.loads(bu_cli.browser_exec("print(page_info())"))
        assert "uv tool install browser-use" in result["error"]

    def test_empty_code_rejected(self):
        result = json.loads(bu_cli.browser_exec("   "))
        assert "error" in result

    def test_new_tab_then_fill_is_rejected_before_cli_dispatch(self, monkeypatch):
        monkeypatch.setattr(
            bu_cli,
            "_find_cli",
            lambda: (_ for _ in ()).throw(AssertionError("browser-use CLI must not run")),
        )

        result = json.loads(
            bu_cli.browser_exec(
                "new_tab('https://example.test/login')\n"
                "fill_input('input[name=email]', 'person@example.test')"
            )
        )

        assert "separate browser_exec calls" in result["error"]

    def test_goto_then_click_aliases_are_rejected_before_cli_dispatch(self, monkeypatch):
        monkeypatch.setattr(
            bu_cli,
            "_find_cli",
            lambda: (_ for _ in ()).throw(AssertionError("browser-use CLI must not run")),
        )

        result = json.loads(
            bu_cli.browser_exec(
                "go = goto_url\n"
                "click = click_at_xy\n"
                "go('https://example.test/login')\n"
                "click(20, 30)"
            )
        )

        assert "separate browser_exec calls" in result["error"]

    def test_raw_cdp_navigate_then_input_is_rejected_before_cli_dispatch(self, monkeypatch):
        monkeypatch.setattr(
            bu_cli,
            "_find_cli",
            lambda: (_ for _ in ()).throw(AssertionError("browser-use CLI must not run")),
        )

        result = json.loads(
            bu_cli.browser_exec(
                "cdp('Page.navigate', url='https://example.test/login')\n"
                "cdp('Input.insertText', text='person@example.test')"
            )
        )

        assert "separate browser_exec calls" in result["error"]

    def test_terminal_navigation_still_runs_pre_and_post_probes(self, tmp_path, monkeypatch):
        probes = []
        cli = _fake_cli(tmp_path, "cat > /dev/null\necho navigated\n")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        monkeypatch.setattr(
            bu_cli,
            "_run_privileged_native_auth_probe",
            lambda **kwargs: probes.append(kwargs) or (True, None, {"success": True}),
        )

        result = json.loads(
            bu_cli.browser_exec(
                "new_tab('https://example.test/login')",
                task_id="phase-probe-task",
            )
        )

        assert result["success"] is True
        assert len(probes) == 2

    def test_code_piped_on_stdin(self, tmp_path, monkeypatch):
        cli = _fake_cli(tmp_path, 'code=$(cat)\necho "got:$code"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec('print("hi")'))
        assert result["success"] is True
        assert result["exit_code"] == 0
        assert 'got:print("hi")' in result["output"]
        assert "session" not in result

    def test_session_sets_bu_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(bu_cli, "_PROCESS_GENERATION", "exec-test-generation")
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "bu:$BU_NAME"\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)", session="r7k2"))
        effective = bu_cli._effective_session_name("r7k2", None)
        assert f"bu:{effective}" in result["output"]
        assert result["session"] == "r7k2"

    def test_invalid_session_name_rejected(self, monkeypatch, tmp_path):
        cli = _fake_cli(tmp_path, "cat > /dev/null\n")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)", session="bad name!"))
        assert "error" in result
        assert "session" in result["error"].lower()

    def test_nonzero_exit_reports_failure_and_stderr(self, tmp_path, monkeypatch):
        cli = _fake_cli(tmp_path, 'cat > /dev/null\necho "boom" >&2\nexit 3\n')
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        result = json.loads(bu_cli.browser_exec("print(1)"))
        assert result["success"] is False
        assert result["exit_code"] == 3
        assert "boom" in result["stderr"]

    def test_timeout_returns_actionable_error(self, tmp_path, monkeypatch):
        cli = _fake_cli(tmp_path, "cat > /dev/null\nsleep 30\n")
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
        monkeypatch.setattr(bu_cli, "_MIN_TIMEOUT_S", 1)
        result = json.loads(bu_cli.browser_exec("print(1)", timeout_s=1))
        assert "timed out" in result["error"]


class TestFindCliManagedBin:
    """MANAGED-FIRST: _find_cli probes $HERMES_HOME/bin before PATH and
    ~/.local/bin, so the Hermes-installed copy always wins."""

    @pytest.fixture(autouse=True)
    def _hermetic_home(self, tmp_path, monkeypatch):
        """Pin HOME so the ~/.local/bin probe can't leak the host's real
        user-level installs into these real-PATH-probing tests."""
        monkeypatch.setenv("HOME", str(tmp_path / "userhome"))
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    def test_managed_bin_browser_use_found(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "home" / "bin"
        bin_dir.mkdir(parents=True)
        bu = bin_dir / "browser-use"
        bu.write_text("#!/bin/sh\n")
        bu.chmod(bu.stat().st_mode | stat.S_IXUSR)
        assert bu_cli._find_cli_unpatched() == [str(bu)]

    def test_managed_bin_uvx_fallback(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "home" / "bin"
        bin_dir.mkdir(parents=True)
        uvx = bin_dir / "uvx"
        uvx.write_text("#!/bin/sh\n")
        uvx.chmod(uvx.stat().st_mode | stat.S_IXUSR)
        assert bu_cli._find_cli_unpatched() == [str(uvx), "browser-use"]

    def test_nothing_found(self, tmp_path, monkeypatch):
        assert bu_cli._find_cli_unpatched() is None

    def test_user_local_bin_browser_use_found(self, tmp_path, monkeypatch):
        """#83788: Desktop/TUI workers spawn with a minimal PATH that omits
        ~/.local/bin, where `uv tool install browser-use` links the binary
        by default — _find_cli must probe it explicitly."""
        cli_dir = tmp_path / "userhome" / ".local" / "bin"
        cli_dir.mkdir(parents=True)
        cli = cli_dir / "browser-use"
        cli.write_text("#!/bin/sh\n")
        cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
        assert bu_cli._find_cli_unpatched() == [str(cli)]

    def test_managed_bin_precedes_user_local_bin(self, tmp_path, monkeypatch):
        """MANAGED-FIRST: Hermes' managed copy wins over a user-level side
        install — every backend selection provisions/updates the managed
        copy, so resolution must land on the binary we control (no version
        drift from stray `uv tool install` runs)."""
        user_dir = tmp_path / "userhome" / ".local" / "bin"
        user_dir.mkdir(parents=True)
        user_cli = user_dir / "browser-use"
        user_cli.write_text("#!/bin/sh\n")
        user_cli.chmod(user_cli.stat().st_mode | stat.S_IXUSR)
        managed_dir = tmp_path / "home" / "bin"
        managed_dir.mkdir(parents=True)
        managed_cli = managed_dir / "browser-use"
        managed_cli.write_text("#!/bin/sh\n")
        managed_cli.chmod(managed_cli.stat().st_mode | stat.S_IXUSR)
        assert bu_cli._find_cli_unpatched() == [str(managed_cli)]

    def test_managed_bin_precedes_path(self, tmp_path, monkeypatch):
        """MANAGED-FIRST: the managed copy also wins over one on PATH."""
        path_dir = tmp_path / "onpath"
        path_dir.mkdir()
        path_cli = path_dir / "browser-use"
        path_cli.write_text("#!/bin/sh\n")
        path_cli.chmod(path_cli.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("PATH", str(path_dir))
        managed_dir = tmp_path / "home" / "bin"
        managed_dir.mkdir(parents=True)
        managed_cli = managed_dir / "browser-use"
        managed_cli.write_text("#!/bin/sh\n")
        managed_cli.chmod(managed_cli.stat().st_mode | stat.S_IXUSR)
        assert bu_cli._find_cli_unpatched() == [str(managed_cli)]

    def test_user_local_bin_uvx_fallback(self, tmp_path, monkeypatch):
        cli_dir = tmp_path / "userhome" / ".local" / "bin"
        cli_dir.mkdir(parents=True)
        uvx = cli_dir / "uvx"
        uvx.write_text("#!/bin/sh\n")
        uvx.chmod(uvx.stat().st_mode | stat.S_IXUSR)
        assert bu_cli._find_cli_unpatched() == [str(uvx), "browser-use"]


class TestInstallCli:
    def test_path_install_does_not_short_circuit(self, tmp_path, monkeypatch):
        """MANAGED-FIRST: a browser-use on PATH is a user-level side install
        and must NOT satisfy install_cli() — only the managed copy does,
        otherwise resolution stays pinned to a binary Hermes can't update."""
        cli = _fake_cli(tmp_path, "")
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        monkeypatch.setattr(bu_cli.shutil, "which", lambda name, path=None: cli if name == "browser-use" and path is None else None)
        import sys as _sys
        import types as _types
        fake = _types.ModuleType("hermes_cli.managed_uv")
        fake.ensure_uv = lambda **kw: None
        monkeypatch.setitem(_sys.modules, "hermes_cli.managed_uv", fake)
        ok, msg = bu_cli.install_cli()
        # No uv available in this fixture, so the attempted managed install
        # fails — the point is that the PATH copy did not short-circuit.
        assert ok is False
        assert "already installed" not in msg

    def test_already_installed_in_managed_bin(self, tmp_path, monkeypatch):
        bin_dir = tmp_path / "home" / "bin"
        bin_dir.mkdir(parents=True)
        cli = bin_dir / "browser-use"
        cli.write_text("#!/bin/sh\n")
        cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        ok, msg = bu_cli.install_cli()
        assert ok is True
        assert "already installed" in msg

    def test_no_uv_anywhere_fails_with_guidance(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        import sys as _sys
        import types as _types
        fake = _types.ModuleType("hermes_cli.managed_uv")
        fake.ensure_uv = lambda **kw: None
        monkeypatch.setitem(_sys.modules, "hermes_cli.managed_uv", fake)
        ok, msg = bu_cli.install_cli()
        assert ok is False
        assert "uv" in msg

    def test_successful_install_via_fake_uv(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        bin_dir = home / "bin"
        bin_dir.mkdir(parents=True)
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        # install_cli verifies via _find_cli(), which the tests/tools conftest
        # pins to None — restore the real resolver for this test.
        monkeypatch.setattr(bu_cli, "_find_cli", bu_cli._find_cli_unpatched)
        # fake uv: `uv tool install browser-use` drops a binary into UV_TOOL_BIN_DIR.
        # Absolute /bin/chmod: PATH is emptied above, so bare chmod won't resolve.
        uv = tmp_path / "uv"
        uv.write_text(
            "#!/bin/sh\n"
            'target="$UV_TOOL_BIN_DIR/browser-use"\n'
            'echo "#!/bin/sh" > "$target"\n'
            '/bin/chmod +x "$target"\n'
        )
        uv.chmod(uv.stat().st_mode | stat.S_IXUSR)
        import sys as _sys
        import types as _types
        fake = _types.ModuleType("hermes_cli.managed_uv")
        fake.ensure_uv = lambda **kw: str(uv)
        monkeypatch.setitem(_sys.modules, "hermes_cli.managed_uv", fake)
        ok, msg = bu_cli.install_cli()
        assert ok is True, msg
        assert (bin_dir / "browser-use").exists()

    def test_failed_install_surfaces_stderr_tail(self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        monkeypatch.setenv("HERMES_HOME", str(home))
        monkeypatch.setenv("PATH", str(tmp_path / "empty"))
        uv = tmp_path / "uv"
        uv.write_text('#!/bin/sh\necho "no network" >&2\nexit 1\n')
        uv.chmod(uv.stat().st_mode | stat.S_IXUSR)
        import sys as _sys
        import types as _types
        fake = _types.ModuleType("hermes_cli.managed_uv")
        fake.ensure_uv = lambda **kw: str(uv)
        monkeypatch.setitem(_sys.modules, "hermes_cli.managed_uv", fake)
        ok, msg = bu_cli.install_cli()
        assert ok is False
        assert "no network" in msg


class TestDefaultDowngradeNotice:
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        monkeypatch.setattr("hermes_cli.config.read_raw_config", lambda: {})

    def test_notice_when_default_and_cli_missing(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        notice = bu_cli.default_downgrade_notice()
        assert notice is not None
        assert "hermes tools" in notice

    def test_rate_limited_within_24h(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.default_downgrade_notice() is not None
        assert bu_cli.default_downgrade_notice() is None

    def test_no_notice_when_cli_runnable(self, tmp_path, monkeypatch):
        self._isolate(tmp_path, monkeypatch)
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: ["/usr/bin/browser-use"])
        assert bu_cli.default_downgrade_notice() is None

    def test_no_notice_on_explicit_backend(self, tmp_path, monkeypatch):
        monkeypatch.setenv("HERMES_HOME", str(tmp_path / "home"))
        monkeypatch.setattr(
            "hermes_cli.config.read_raw_config",
            lambda: {"browser": {"backend": bu_cli.BACKEND_DISABLED}},
        )
        monkeypatch.setattr(bu_cli, "_find_cli", lambda: None)
        assert bu_cli.default_downgrade_notice() is None
def test_model_browser_exec_is_blocked_during_pending_native_auth(monkeypatch):
    from tools.native_auth_runtime import native_auth_runtime

    native_auth_runtime.create_context(
        task_id="guard-task-1",
        browser_session_key="guard-browser-1",
        browser_session_id="guard-browser-1",
        provider_origin="https://accounts.example.test",
        path="/login",
        flow="password",
        fields=[{
            "field_id": "password",
            "kind": "password",
            "label": "Password",
            "required": True,
            "target": {"strategy": "css", "value": "input[type=password]", "target_id": "ref_guard_password_12345678"},
        }],
        actions=[{
            "action_id": "submit",
            "kind": "submit",
            "label": "Sign in",
            "target": {"strategy": "css", "value": "button[type=submit]", "target_id": "ref_guard_submit_12345678"},
        }],
        browser_backend="browser-use",
    )
    result = json.loads(bu_cli.browser_exec(
        'fill_input("input[type=password]", "should-not-run")',
        task_id="guard-task-1",
    ))
    assert "auth_boundary_required" in result["error"]


def test_builtin_browser_type_is_blocked_for_reserved_auth_ref(monkeypatch):
    import tools.browser_tool as browser_tool
    from tools.native_auth_runtime import native_auth_runtime

    native_auth_runtime.create_context(
        task_id="guard-task-2",
        browser_session_key="guard-browser-2",
        browser_session_id="guard-browser-2",
        provider_origin="https://accounts.example.test",
        path="/login",
        flow="password",
        fields=[{
            "field_id": "password",
            "kind": "password",
            "label": "Password",
            "required": True,
            "target": {"strategy": "ref", "value": "@e1"},
        }],
        actions=[{
            "action_id": "submit",
            "kind": "submit",
            "label": "Sign in",
            "target": {"strategy": "ref", "value": "@e2"},
        }],
        browser_backend="fake",
    )
    monkeypatch.setattr(browser_tool, "_blocked_private_page_action", lambda *args: None)
    monkeypatch.setattr(browser_tool, "_run_browser_command", lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("browser command must not run")))
    result = json.loads(browser_tool.browser_type("@e1", "should-not-run", task_id="guard-task-2"))
    assert result["success"] is False
    assert result["auth_boundary_required"] is True


def test_validate_native_target_accepts_bounded_locator_strategies_and_rejects_code():
    from tools.browser_use_cli import validate_native_target
    from tools.native_auth_runtime import NativeAuthSecurityError

    for target in (
        {"strategy": "css", "value": "form input[type=password]"},
        {"strategy": "xpath", "value": "//input[@autocomplete='current-password']"},
        {"strategy": "role", "value": "textbox:Password"},
        {"strategy": "label", "value": "Password"},
    ):
        validate_native_target(target)

    with pytest.raises(NativeAuthSecurityError):
        validate_native_target({"strategy": "css", "value": "javascript:alert(1)"})
    with pytest.raises(NativeAuthSecurityError):
        validate_native_target({"strategy": "css", "value": "<script>evil</script>"})


def test_default_browser_use_fill_uses_private_session_binding(monkeypatch):
    from tools.native_auth_runtime import NativeAuthRuntime
    import tools.browser_use_cli as browser_use_cli

    runtime = NativeAuthRuntime()
    public = runtime.create_context(
        task_id="session-123",
        browser_session_key="browser-key-123",
        browser_session_id="browser-session-123",
        provider_origin="https://accounts.example.test",
        path="/login",
        flow="password",
        fields=[{
            "field_id": "password",
            "kind": "password",
            "label": "Password",
            "required": True,
            "target": {"strategy": "css", "value": "input[type=password]", "target_id": "ref_fill_password_12345678"},
        }],
        actions=[],
        browser_backend="browser-use",
        browser_session_name="named-auth-session",
    )
    internal = runtime._contexts[public["context_id"]]
    field = internal.public["fields"][0]
    captured = {}

    def fake_fill(**kwargs):
        captured.update(kwargs)
        return {"state": "filled"}

    monkeypatch.setattr(browser_use_cli, "secure_native_fill", fake_fill)
    result = runtime._default_fill_executor(
        context=internal.public,
        field=field,
        plaintext="synthetic-value",
    )

    assert result["state"] == "filled"
    assert captured["session"] == "named-auth-session"
    assert captured["expected_origin"] == "https://accounts.example.test"
    assert captured["expected_path"] == "/login"
    assert captured["plaintext"] == "synthetic-value"


def test_secure_native_preflight_revalidates_form_method_action_and_identity():
    target = {
        "strategy": "css",
        "value": "#password",
        "target_id": "ref_f_field12345678__form_login12345678",
    }
    expression = bu_cli._secure_target_preflight_script(
        target,
        expected_origin="https://accounts.example.test",
        expected_path="/login",
    )

    assert "HTMLFormElement" in expression
    assert "__hermesNativeAuthFormRefs" in expression
    assert "form_login12345678" in expression
    assert "form.method" in expression
    assert "form.action" in expression
    assert "record.method !== 'post'" in expression
    assert "action.protocol !== 'https:'" in expression


def test_secure_native_preflight_returns_only_opaque_ack(monkeypatch):
    import tools.browser_use_cli as browser_use_cli

    captured = {}

    def fake_cdp(session, method, params, *, timeout_s=None):
        captured.update(session=session, method=method, params=params)
        return {"result": {"type": "boolean", "value": True}}

    monkeypatch.setattr(browser_use_cli, "_private_cdp_request", fake_cdp)
    result = browser_use_cli.secure_native_preflight(
        session="named-auth-session",
        target={"strategy": "css", "value": "input[type=password]", "target_id": "ref_12345678"},
        expected_origin="https://accounts.example.test",
        expected_path="/login",
        expected_tab_handle="tab_12345678",
        expected_frame_handle="frame_12345678",
        expected_document_generation="doc_12345678",
    )

    assert result == {"state": "validated"}
    assert captured["session"] == "named-auth-session"
    assert captured["method"] == "Runtime.evaluate"
    expression = captured["params"]["expression"]
    assert "accounts.example.test" in expression
    assert "/login" in expression
    assert "input[type=password]" in expression
    assert "ref_12345678" in expression
    assert "tab_12345678" in expression
    assert "frame_12345678" in expression
    assert "doc_12345678" in expression
    assert captured["params"]["returnByValue"] is True
    assert "synthetic-value" not in repr(captured)


def test_secure_native_preflight_fails_closed_without_ack(monkeypatch):
    import tools.browser_use_cli as browser_use_cli
    from tools.native_auth_runtime import NativeAuthSecurityError

    monkeypatch.setattr(
        browser_use_cli,
        "_private_cdp_request",
        lambda *_args, **_kwargs: {"result": {"type": "boolean", "value": False}},
    )
    with pytest.raises(NativeAuthSecurityError, match="preflight"):
        browser_use_cli.secure_native_preflight(
            session="named-auth-session",
            target={"strategy": "css", "value": "input[type=password]"},
            expected_origin="https://accounts.example.test",
            expected_path="/login",
        )


def test_secure_target_binding_rejects_same_selector_replacement():
    """A replacement node must not inherit the browser-minted target ID."""
    target = {
        "strategy": "css",
        "value": "input[type=password]",
        "target_id": "ref_exact_node_12345678",
    }
    expression = bu_cli._secure_target_preflight_script(
        target,
        expected_origin="https://accounts.example.test",
        expected_path="/login",
    )
    harness = f"""
class Element {{
  constructor() {{ this.disabled = false; this.readOnly = false; }}
  getBoundingClientRect() {{ return {{width: 10, height: 10}}; }}
  getAttribute() {{ return null; }}
  hasAttribute() {{ return false; }}
}}
const original = new Element();
const replacement = new Element();
global.Element = Element;
global.location = {{origin: 'https://accounts.example.test', pathname: '/login'}};
global.getComputedStyle = () => ({{display: 'block', visibility: 'visible'}});
global.document = {{querySelectorAll: () => [replacement]}};
global.window = {{__hermesNativeAuthTargetRefs: {{'input[type=password]': 'ref_exact_node_12345678'}}}};
process.stdout.write(String({expression}));
"""
    proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True, check=True)

    assert proc.stdout == "false"
    assert "WeakMap" in bu_cli._NATIVE_AUTH_PROBE_PREAMBLE
    assert ".get(element)" in expression


def test_secure_native_fill_uses_only_final_cdp_argument_for_plaintext(monkeypatch):
    """Plaintext crosses the process boundary only as callFunctionOn data."""
    secret = "synthetic-secret-direct-cdp-canary"
    calls = []

    def fake_cdp(session, method, params, *, timeout_s=None):
        calls.append((session, method, params))
        if method == "Runtime.evaluate" and params.get("returnByValue") is True:
            return {"result": {"type": "boolean", "value": True}}
        if method == "Runtime.evaluate":
            return {"result": {"type": "object", "objectId": "remote-object-1"}}
        if method == "Runtime.callFunctionOn":
            assert params["arguments"] == [{"value": secret}]
            assert secret not in params["functionDeclaration"]
            return {"result": {"type": "boolean", "value": True}}
        if method == "Runtime.releaseObject":
            return {}
        raise AssertionError(method)

    monkeypatch.setattr(
        bu_cli,
        "browser_exec",
        lambda **_: (_ for _ in ()).throw(AssertionError("browser_exec forbidden")),
    )
    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_cdp)

    result = bu_cli.secure_native_fill(
        session="auth-test",
        target={"strategy": "css", "value": "form input[type=password]"},
        plaintext=secret,
        expected_origin="https://accounts.example.test",
        expected_path="/login",
    )

    assert result == {"state": "filled"}
    assert [method for _, method, _ in calls] == [
        "Runtime.evaluate",
        "Runtime.evaluate",
        "Runtime.callFunctionOn",
        "Runtime.releaseObject",
    ]
    for _, method, params in calls:
        if method != "Runtime.callFunctionOn":
            assert secret not in repr(params)
    assert secret not in json.dumps(result)


def test_native_fill_function_rejects_detached_or_replaced_element():
    """The final CDP call must close the resolve-to-fill TOCTOU window."""
    if not shutil.which("node"):
        pytest.skip("node is required for the browser-side fill guard probe")

    function_declaration = json.dumps(bu_cli._NATIVE_FILL_FUNCTION)
    harness = f"""
global.document = {{}};
class HTMLInputElement {{
  constructor() {{
    this.isConnected = false;
    this.ownerDocument = global.document;
    this.disabled = false;
    this.readOnly = false;
  }}
  focus() {{ throw new Error('detached target must not be focused'); }}
  blur() {{}}
  dispatchEvent() {{}}
  hasAttribute() {{ return false; }}
  getAttribute() {{ return null; }}
}}
class HTMLTextAreaElement extends HTMLInputElement {{}}
global.HTMLInputElement = HTMLInputElement;
global.HTMLTextAreaElement = HTMLTextAreaElement;
global.Event = class Event {{ constructor() {{}} }};
const fn = eval('(' + {function_declaration} + ')');
let result;
try {{
  result = String(fn.call(new HTMLInputElement(), 'synthetic'));
}} catch (_error) {{
  result = 'threw';
}}
process.stdout.write(result);
"""

    proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True, check=True)

    assert proc.stdout == "false"


def test_private_cdp_ipc_sends_one_json_line_and_returns_only_result(tmp_path, monkeypatch):
    runtime, _endpoint, captured, thread = _start_private_ipc_server(
        tmp_path,
        "auth-ipc",
        b'{"result":{"result":{"type":"boolean","value":true}}}',
    )
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")

    result = bu_cli._private_harness_request(
        "auth-ipc",
        {
            "method": "Runtime.evaluate",
            "params": {"expression": "true", "returnByValue": True},
        },
    )
    thread.join(timeout=2)

    assert result == {"result": {"result": {"type": "boolean", "value": True}}}
    assert len(captured) == 1
    assert captured[0].endswith(b"\n")
    assert captured[0].count(b"\n") == 1
    assert json.loads(captured[0]) == {
        "method": "Runtime.evaluate",
        "params": {"expression": "true", "returnByValue": True},
    }


def test_private_cdp_matches_harness_019_permissions_wire_and_pid(tmp_path, monkeypatch):
    def handler(request):
        if request == {"meta": "ping"}:
            return {"pong": True, "pid": os.getpid(), "browser_kind": "cdp"}
        return {"result": {"result": {"type": "boolean", "value": True}}}

    runtime, endpoint, captured, thread = _start_harness_019_server(
        tmp_path,
        "auth-019",
        handler,
        socket_mode=0o700,
    )
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")
    assert stat.S_IMODE(endpoint.lstat().st_mode) == 0o700

    result = bu_cli._private_cdp_request(
        "auth-019",
        "Runtime.evaluate",
        {"expression": "true", "returnByValue": True},
    )
    thread.join(timeout=2)

    assert result == {"result": {"type": "boolean", "value": True}}
    assert captured == [
        {"meta": "ping"},
        {
            "method": "Runtime.evaluate",
            "params": {"expression": "true", "returnByValue": True},
        },
    ]


def test_private_cdp_rejects_socket_owned_by_pid_other_than_pid_file(tmp_path, monkeypatch):
    recorded_pid = os.getpid()

    def handler(request):
        if request == {"meta": "ping"}:
            return {"pong": True, "pid": recorded_pid + 100000}
        return {"result": {"result": {"type": "boolean", "value": True}}}

    runtime, _endpoint, captured, thread = _start_harness_019_server(
        tmp_path,
        "auth-stale",
        handler,
        pid=recorded_pid,
    )
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")

    from tools.native_auth_runtime import NativeAuthSecurityError

    with pytest.raises(NativeAuthSecurityError, match="channel unavailable"):
        bu_cli._private_cdp_request(
            "auth-stale",
            "Runtime.evaluate",
            {"expression": "true", "returnByValue": True},
        )
    thread.join(timeout=2)

    assert captured == [{"meta": "ping"}]


def test_private_cdp_sends_no_plaintext_if_endpoint_rebinds_before_send(tmp_path, monkeypatch):
    from tools.native_auth_runtime import NativeAuthSecurityError

    secret = "synthetic-rebind-secret-canary"
    expected = (os.getpid(), (1, 100))
    rebound = (os.getpid(), (1, 101))
    identities = iter([expected, rebound])
    sent = []

    class FakeClient:
        def settimeout(self, _timeout):
            pass

        def connect(self, _endpoint):
            pass

        def sendall(self, data):
            sent.append(data)

        def close(self):
            pass

    monkeypatch.setattr(bu_cli, "_private_daemon_identity", lambda *_a, **_k: expected)
    monkeypatch.setattr(
        bu_cli,
        "_harness_runtime_layout",
        lambda _session: (tmp_path, "bu-auth-race"),
    )
    monkeypatch.setattr(
        bu_cli,
        "_private_harness_identity",
        lambda _runtime, _stem: next(identities),
    )
    monkeypatch.setattr(bu_cli.socket, "socket", lambda *_a, **_k: FakeClient())

    with pytest.raises(NativeAuthSecurityError) as exc_info:
        bu_cli._private_cdp_request(
            "auth-race",
            "Runtime.callFunctionOn",
            {"arguments": [{"value": secret}]},
        )

    assert sent == []
    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value)


@pytest.mark.parametrize("bad_mode", [0o755, 0o777])
def test_private_cdp_ipc_rejects_nonprivate_runtime_mode(tmp_path, monkeypatch, bad_mode):
    from tools.native_auth_runtime import NativeAuthSecurityError

    runtime = tmp_path / "runtime"
    runtime.mkdir()
    runtime.chmod(bad_mode)
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")

    with pytest.raises(NativeAuthSecurityError, match="channel unavailable"):
        bu_cli._private_cdp_request("auth-mode", "Runtime.evaluate", {"expression": "true"})


def test_private_cdp_ipc_rejects_nonprivate_socket_mode(tmp_path, monkeypatch):
    from tools.native_auth_runtime import NativeAuthSecurityError

    runtime, endpoint, _captured, _thread = _start_private_ipc_server(
        tmp_path,
        "auth-mode",
        b'{"result":{}}',
    )
    endpoint.chmod(0o666)
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")

    with pytest.raises(NativeAuthSecurityError, match="channel unavailable"):
        bu_cli._private_cdp_request("auth-mode", "Runtime.evaluate", {"expression": "true"})


@pytest.mark.parametrize(
    "response",
    [
        b"not-json",
        b'{"error":"daemon raw secret synthetic-daemon-canary"}',
        b'{"result":[]}',
    ],
)
def test_private_cdp_ipc_sanitizes_malformed_and_daemon_errors(
    tmp_path, monkeypatch, caplog, response
):
    from tools.native_auth_runtime import NativeAuthSecurityError

    runtime, _endpoint, _captured, thread = _start_private_ipc_server(
        tmp_path, "auth-error", response
    )
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")

    with pytest.raises(NativeAuthSecurityError) as exc_info:
        bu_cli._private_cdp_request("auth-error", "Runtime.evaluate", {"expression": "true"})
    thread.join(timeout=2)
    assert str(exc_info.value) == "secure browser channel unavailable"
    assert "synthetic-daemon-canary" not in repr(exc_info.value)
    assert "synthetic-daemon-canary" not in caplog.text


def test_private_cdp_ipc_timeout_is_sanitized(tmp_path, monkeypatch):
    from tools.native_auth_runtime import NativeAuthSecurityError

    runtime, _endpoint, _captured, thread = _start_private_ipc_server(
        tmp_path,
        "auth-timeout",
        b'{"result":{}}',
        delay=0.3,
    )
    monkeypatch.setenv("BH_RUNTIME_DIR", str(runtime))
    monkeypatch.setenv("BH_RUNTIME_DIR_SHARED", "1")

    with pytest.raises(NativeAuthSecurityError) as exc_info:
        bu_cli._private_cdp_request(
            "auth-timeout", "Runtime.evaluate", {"expression": "true"}, timeout_s=0.1
        )
    thread.join(timeout=2)
    assert str(exc_info.value) == "secure browser channel unavailable"


def test_secure_native_fill_rejects_target_change_after_preflight(monkeypatch):
    from tools.native_auth_runtime import NativeAuthSecurityError

    calls = []

    def fake_cdp(_session, method, params, *, timeout_s=None):
        calls.append((method, params))
        if len(calls) == 1:
            return {"result": {"type": "boolean", "value": True}}
        return {"result": {"type": "boolean", "value": False}}

    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_cdp)
    with pytest.raises(NativeAuthSecurityError, match="target changed"):
        bu_cli.secure_native_fill(
            session="auth-test",
            target={"strategy": "css", "value": "input[type=password]"},
            plaintext="synthetic-never-transferred",
            expected_origin="https://accounts.example.test",
            expected_path="/login",
        )
    assert [method for method, _ in calls] == ["Runtime.evaluate", "Runtime.evaluate"]
    assert "synthetic-never-transferred" not in repr(calls)


def test_secure_native_fill_releases_remote_object_on_fill_failure(monkeypatch):
    from tools.native_auth_runtime import NativeAuthSecurityError

    secret = "synthetic-failing-fill-canary"
    calls = []

    def fake_cdp(_session, method, params, *, timeout_s=None):
        calls.append((method, params))
        if len(calls) == 1:
            return {"result": {"type": "boolean", "value": True}}
        if method == "Runtime.evaluate":
            return {"result": {"type": "object", "objectId": "remote-failure"}}
        if method == "Runtime.callFunctionOn":
            raise NativeAuthSecurityError("secure browser channel unavailable")
        return {}

    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_cdp)
    with pytest.raises(NativeAuthSecurityError) as exc_info:
        bu_cli.secure_native_fill(
            session="auth-test",
            target={"strategy": "css", "value": "input[type=password]"},
            plaintext=secret,
            expected_origin="https://accounts.example.test",
            expected_path="/login",
        )

    assert calls[-1] == ("Runtime.releaseObject", {"objectId": "remote-failure"})
    assert secret not in str(exc_info.value)
    assert secret not in repr(exc_info.value)


def test_extract_native_auth_probe_output_strips_marker_and_returns_metadata():
    payload = {
        "origin": "https://example.com",
        "path": "/login",
        "title": "Sign in",
        "fields": [
            {
                "field_id": "field_1",
                "kind": "password",
                "label": "Password",
                "required": True,
                "target": {"strategy": "css", "value": "form input[type=password]"},
            }
        ],
        "actions": [],
    }
    output = "ordinary output\n" + bu_cli._NATIVE_AUTH_CONTEXT_PREFIX + json.dumps(payload) + "\n"
    clean, extracted = bu_cli._extract_native_auth_probe_output(output)
    assert clean == "ordinary output"
    assert extracted == payload


def test_browser_exec_returns_wire_auth_context_from_browser_probe(tmp_path, monkeypatch):
    probe_payload = {
        "origin": "https://accounts.example.test",
        "path": "/login",
        "title": "Sign in",
        "document_generation": "doc_12345678",
        "tab_handle": "tab_12345678",
        "frame_handle": "frame_12345678",
        "form": {
            "form_id": "form_login_12345678",
            "method": "post",
            "action": "https://accounts.example.test/session",
        },
        "fields": [{
            "field_id": "field_1",
            "kind": "password",
            "label": "Password",
            "required": True,
            "target": {"strategy": "css", "value": "input[type=password]", "target_id": "ref_f_password_12345678__form_login_12345678"},
        }],
        "actions": [{
            "action_id": "submit",
            "kind": "submit",
            "label": "Sign in",
            "target": {"strategy": "css", "value": "button[type=submit]", "target_id": "ref_a_submit_12345678__form_login_12345678"},
        }],
        "signals": "Sign in password",
    }
    body = (
        "printf '%s%s\n' 'HERMES_NATIVE_AUTH_PROBE_STATUS:ok' ''; "
        "printf '%s%s\n' 'HERMES_NATIVE_AUTH_CONTEXT:' "
        + shlex.quote(json.dumps(probe_payload, separators=(",", ":")))
        + "\n"
    )
    cli = _fake_cli(tmp_path, body)
    monkeypatch.setattr(bu_cli, "_find_cli", lambda: [cli])
    monkeypatch.setattr(bu_cli, "_base_subprocess_env", lambda: {"PATH": os.environ.get("PATH", "")})
    monkeypatch.setattr(bu_cli, "_resolve_backend_cdp", lambda env, task_id, session_name=None: None)
    monkeypatch.setattr(bu_cli, "_workspace_dir", lambda task_id: None)
    monkeypatch.setattr(bu_cli, "is_legacy_browser_use_cloud_config", lambda _: False)

    result = json.loads(bu_cli.browser_exec(
        "print('browser work')",
        session="auth-probe-test",
        task_id="auth-probe-task",
    ))
    assert result["success"] is True, result
    auth_context = result["auth_context"]
    assert auth_context["type"] == "hermes.auth-context.v1"
    assert auth_context["provider_origin"] == "https://accounts.example.test"
    assert auth_context["component_ids"]
    from tools.native_auth_runtime import native_auth_runtime
    internal = native_auth_runtime._contexts[auth_context["context_id"]]
    assert internal.public["document_generation"] == "doc_12345678"
    assert internal.public["tab_handle"] == "tab_12345678"
    assert internal.public["frame_handle"] == "frame_12345678"
    assert internal.public["fields"][0]["target"]["target_id"] == "ref_f_password_12345678__form_login_12345678"
    assert "input[type=password]" not in json.dumps(auth_context)


def test_native_auth_probe_rejects_cross_form_descriptor_aggregation_before_context_minting():
    payload = {
        "origin": "https://accounts.example.test",
        "path": "/login",
        "title": "Sign in",
        "document_generation": "doc_cross_form_12345678",
        "tab_handle": "tab_cross_form_12345678",
        "frame_handle": "frame_cross_form_12345678",
        "form": {
            "form_id": "form_primary_12345678",
            "method": "post",
            "action": "https://accounts.example.test/session",
        },
        "fields": [{
            "field_id": "field_1",
            "kind": "password",
            "label": "Password",
            "required": True,
            "target": {
                "strategy": "css",
                "value": "#form-a-password",
                "target_id": "ref_f_field12345678__form_primary_12345678",
            },
        }],
        "actions": [{
            "action_id": "submit",
            "kind": "submit",
            "label": "Sign in",
            "target": {
                "strategy": "css",
                "value": "#form-b-submit",
                "target_id": "ref_a_action12345678__form_other_12345678",
            },
        }],
        "signals": "Sign in password",
    }

    assert bu_cli._native_auth_context_from_probe(
        payload,
        task_id="cross-form-probe-task",
        session="cross-form-probe-session",
    ) is None


def test_native_auth_probe_rejects_url_leaking_get_submission_before_context_minting():
    canary = "synthetic-get-url-canary"
    payload = {
        "form": {
            "form_id": "form_get_12345678",
            "method": "get",
            "action": f"https://accounts.example.test/login?password={canary}",
        },
        "fields": [{
            "target": {
                "target_id": "ref_f_password_12345678__form_get_12345678",
            },
        }],
        "actions": [{
            "kind": "submit",
            "target": {
                "target_id": "ref_a_submit_12345678__form_get_12345678",
            },
        }],
    }

    assert bu_cli._is_form_bound_probe_payload(payload) is False


def test_native_auth_probe_discovers_exactly_one_safe_form_instead_of_aggregating_document_controls():
    probe = bu_cli._NATIVE_AUTH_PROBE_PREAMBLE

    assert "Array.from(document.forms)" in probe
    assert "viableForms.length !== 1" in probe
    assert "element.form === form" in probe
    assert "rawMethod !== \"post\"" in probe
    assert "effectiveMethod !== \"post\"" in probe
    assert "effectiveAction.protocol !== \"https:\"" in probe
    assert "submitCandidates.length !== 1" in probe
    assert "form: formRecord" in probe


def test_native_auth_probe_emits_a_bounded_submit_action_for_explicit_submit_controls():
    probe = bu_cli._NATIVE_AUTH_PROBE_PREAMBLE

    assert "const submitCandidates" in probe
    assert "Array.from(form.elements)" in probe
    assert '(element.type || \"\").toLowerCase() === \"submit\"' in probe
    assert 'kind: "submit"' in probe


def test_native_auth_probe_uses_associated_labels_and_humanizes_names():
    probe = bu_cli._NATIVE_AUTH_PROBE_PREAMBLE

    assert 'querySelectorAll("label")' in probe
    assert 'getAttribute("for")' in probe
    assert 'replace(/[_-]+/g, " ")' in probe


def test_native_auth_probe_emits_working_whitespace_and_control_regexes():
    probe = bu_cli._NATIVE_AUTH_PROBE_PREAMBLE

    assert '.replace(/\\s+/g, " ")' in probe
    assert '.replace(/[\\u0000-\\u001f\\u007f]/g, " ")' in probe


def test_resolve_native_auth_v2_inventories_current_react_page_without_form(monkeypatch):
    calls = []

    element_objects = {"element-account": 101, "element-submit": 102}

    def fake_private_cdp(session, method, params, **kwargs):
        calls.append((session, method, params))
        if method == "Target.getTargetInfo":
            return {"targetInfo": {
                "targetId": "target-current",
                "type": "page",
                "url": "https://accounts.example.test/signin?from=mail#fragment",
            }}
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {
                "id": "frame-current",
                "loaderId": "loader-current",
                "url": "https://accounts.example.test/signin?from=mail#fragment",
            }}}
        if method == "Runtime.evaluate":
            assert params["returnByValue"] is False
            return {"result": {"type": "object", "objectId": "array-object"}}
        if method == "Runtime.getProperties":
            assert params == {"objectId": "array-object", "ownProperties": True}
            return {"result": [
                {"name": "0", "value": {"type": "object", "objectId": "element-account"}},
                {"name": "1", "value": {"type": "object", "objectId": "element-submit"}},
            ]}
        if method == "Runtime.callFunctionOn":
            assert params["returnByValue"] is True
            descriptor = {
                "element-account": {
                    "eligible": True,
                    "role": "textbox",
                    "label": "Account",
                    "hints": {"masked": False, "required": True, "keyboard": "text"},
                },
                "element-submit": {"eligible": True, "role": "button", "label": "Continue", "hints": {}},
            }[params["objectId"]]
            return {"result": {"type": "object", "value": descriptor}}
        if method == "DOM.describeNode":
            return {"node": {"backendNodeId": element_objects[params["objectId"]]}}
        if method == "Runtime.releaseObject":
            return {}
        raise AssertionError(method)

    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_private_cdp)
    monkeypatch.setattr(bu_cli, "_verify_native_auth_owner", lambda **_: True, raising=False)

    result = bu_cli.resolve_native_auth_v2(browser_session="named-login", task_id="task-1")

    assert result["origin"] == "https://accounts.example.test"
    assert result["path"] == "/signin"
    assert [target["ref"] for target in result["targets"]] == ["@e1", "@e2"]
    assert all(set(target) == {"ref", "role", "label", "hints", "target"} for target in result["targets"])
    assert result["targets"][0]["hints"] == {
        "masked": False, "required": True, "keyboard": "text",
    }
    assert result["targets"][1]["hints"] == {}
    assert result["targets"][0]["target"] == {
        "target_id": "target-current", "frame_id": "frame-current",
        "loader_id": "loader-current", "backend_node_id": 101,
    }
    assert result["targets"][1]["target"] == {
        "target_id": "target-current", "frame_id": "frame-current",
        "loader_id": "loader-current", "backend_node_id": 102,
    }
    assert [params["objectId"] for _, method, params in calls if method == "Runtime.releaseObject"] == [
        "element-account", "element-submit", "array-object",
    ]
    assert not any("selector" in json.dumps(params) or "target:" in json.dumps(params)
                   for _, _, params in calls)


def test_resolve_native_auth_v2_binds_current_target_not_same_url_tab(monkeypatch):
    calls = []

    def fake_private_cdp(session, method, params, **kwargs):
        calls.append((method, params))
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "current-target", "type": "page",
                                    "url": "https://same.test/signin?tab=old#fragment"}}
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "current-frame", "loaderId": "current-loader", "url": "https://same.test/signin"}}}
        if method == "Runtime.evaluate":
            assert params["returnByValue"] is False
            return {"result": {"type": "object", "objectId": "array-object"}}
        if method == "Runtime.getProperties":
            return {"result": [
                {"name": "0", "value": {"type": "object", "objectId": "current-element"}},
            ]}
        if method == "Runtime.callFunctionOn":
            assert params["objectId"] == "current-element"
            assert params["returnByValue"] is True
            return {"result": {"type": "object", "value": {
                "eligible": True,
                "role": "textbox",
                "label": "Account",
                "hints": {"masked": False, "required": True, "keyboard": "text"},
            }}}
        if method == "DOM.describeNode":
            assert params["objectId"] == "current-element"
            return {"node": {"backendNodeId": 404}}
        if method == "Runtime.releaseObject":
            return {}
        raise AssertionError(method)

    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_private_cdp)
    monkeypatch.setattr(bu_cli, "_verify_native_auth_owner", lambda **_: True, raising=False)

    result = bu_cli.resolve_native_auth_v2(browser_session="named-login", task_id="task-1")

    assert result["targets"]
    assert result["targets"] == [{
        "ref": "@e1",
        "role": "textbox",
        "label": "Account",
        "hints": {"masked": False, "required": True, "keyboard": "text"},
        "target": {
            "target_id": "current-target",
            "frame_id": "current-frame",
            "loader_id": "current-loader",
            "backend_node_id": 404,
        },
    }]

    methods = [method for method, _ in calls]
    assert "Target.getTargetInfo" in methods
    assert not any(method == "Target.getTargets" for method in methods)
    evaluate_code = [params["expression"] for method, params in calls if method == "Runtime.evaluate"]
    assert evaluate_code
    assert all("current-target" not in code for code in evaluate_code)
    assert not any(method == "Target.getTargets" for method, _ in calls)
    assert any(
        method == "DOM.describeNode" and params["objectId"] == "current-element"
        for method, params in calls
    )


@pytest.mark.parametrize("bad_target", [
    {"eligible": False, "role": "textbox", "label": "Hidden", "hints": {}},
    {"eligible": False, "role": "textbox", "label": "Disabled", "hints": {}},
    {"eligible": True, "role": "textbox", "label": "Duplicate", "hints": {}},
    {"eligible": False, "role": "textbox", "label": "Detached", "hints": {}},
])
def test_resolve_native_auth_v2_omits_unsafe_candidates_and_leaks_no_page_data(monkeypatch, bad_target):
    calls = []

    def fake_private_cdp(session, method, params, **kwargs):
        calls.append((method, params))
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "target-safe", "type": "page",
                                    "url": "https://safe.test/signin?secret=1#frag"}}
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "frame-safe", "loaderId": "loader-safe",
                                               "url": "https://safe.test/signin?secret=1#frag"}}}
        if method == "Runtime.evaluate":
            return {"result": {"type": "object", "objectId": "array-object"}}
        if method == "Runtime.getProperties":
            return {"result": [
                {"name": "0", "value": {"type": "object", "objectId": "unsafe-element"}},
                {"name": "1", "value": {"type": "object", "objectId": "safe-element"}},
            ]}
        if method == "Runtime.callFunctionOn":
            descriptor = bad_target if params["objectId"] == "unsafe-element" else {
                "eligible": True, "role": "button", "label": "Continue", "hints": {},
            }
            return {"result": {"type": "object", "value": descriptor}}
        if method == "DOM.describeNode":
            backend_id = 78 if bad_target.get("label") == "Duplicate" else (
                77 if params["objectId"] == "unsafe-element" else 78
            )
            return {"node": {"backendNodeId": backend_id}}
        if method == "Runtime.releaseObject":
            return {}
        raise AssertionError(method)

    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_private_cdp)
    monkeypatch.setattr(bu_cli, "_verify_native_auth_owner", lambda **_: True, raising=False)

    result = bu_cli.resolve_native_auth_v2(browser_session="named-login", task_id="task-1")

    assert result["path"] == "/signin"
    assert [target["ref"] for target in result["targets"]] == ["@e2"]

    assert any(method == "Runtime.releaseObject" for method, _ in calls)
    request_code = "\n".join(
        params.get(key, "") for method, params in calls
        for key in ("expression", "functionDeclaration")
        if method in {"Runtime.evaluate", "Runtime.callFunctionOn"}
    )
    for forbidden in (".value", "defaultValue", "innerHTML", "outerHTML",
                      "document.cookie", "localStorage", "sessionStorage"):
        assert forbidden not in request_code


@pytest.mark.parametrize("malformed", [
    {"origin": "https://safe.test", "path": "/signin", "targets": "not-a-list"},
    {"origin": "https://safe.test", "path": "/signin", "targets": [{"ref": "@e1", "role": "textbox"}]},
    {"origin": "https://safe.test", "path": "/signin", "targets": [{"ref": "@e1", "role": "textbox", "owner": "other-task"}]},
])
def test_resolve_native_auth_v2_fails_closed_on_malformed_or_wrong_owner_inventory(monkeypatch, malformed):
    calls = []

    def fake_private_cdp(session, method, params, **kwargs):
        calls.append((method, params))
        if method == "Target.getTargetInfo":
            return {"targetInfo": {"targetId": "target-safe", "type": "page",
                                    "url": "https://safe.test/signin"}}
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "frame-safe", "loaderId": "loader-safe",
                                               "url": "https://safe.test/signin"}}}
        if method == "Runtime.evaluate":
            return {"result": {"type": "object", "objectId": "array-object"}}
        if method == "Runtime.getProperties":
            if isinstance(malformed.get("targets"), list):
                entries = [{"name": str(index), "value": {"type": "object", "objectId": f"element-{index}"}}
                           for index, _ in enumerate(malformed["targets"])]
            else:
                entries = []
            return {"result": entries}
        if method == "Runtime.callFunctionOn":
            index = int(params["objectId"].split("-")[-1])
            descriptor = malformed["targets"][index] if isinstance(malformed.get("targets"), list) else {}
            return {"result": {"type": "object", "value": descriptor}}
        if method == "DOM.describeNode":
            return {"node": {"backendNodeId": 100 + int(params["objectId"].split("-")[-1])}}
        if method == "Runtime.releaseObject":
            return {}
        raise AssertionError(method)

    monkeypatch.setattr(bu_cli, "_private_cdp_request", fake_private_cdp)
    monkeypatch.setattr(bu_cli, "_verify_native_auth_owner", lambda **_: True, raising=False)
    if isinstance(malformed.get("targets"), list) and any("owner" in item for item in malformed["targets"]):
        monkeypatch.setattr(bu_cli, "_verify_native_auth_owner", lambda **_: False, raising=False)

    from tools.native_auth_runtime import NativeAuthSecurityError

    with pytest.raises(NativeAuthSecurityError, match="secure browser inspect unavailable"):
        bu_cli.resolve_native_auth_v2(browser_session="named-login", task_id="task-1")
    if any("owner" in item for item in malformed.get("targets", [])):
        assert calls == []
    else:
        assert any(method == "Runtime.releaseObject" for method, _ in calls)

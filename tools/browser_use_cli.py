"""Use the Browser Use CLI 3.0 (https://browser-use.com) for browser automation

When browser.backend is "browser-use", the model gets ``browser_exec`` tool
instead of default browser tools
"""

import ast
import atexit
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import socket
import stat
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit

from utils import is_truthy_value

logger = logging.getLogger(__name__)

_BACKEND_KEY = "browser-use"
BACKEND_DISABLED = "off"

# Cloud daemon names become the BU_NAME env var
_SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")

# Internal marker set by _resolve_backend_cdp on the env dict when the
# resolved browser is EXCLUSIVE to this named session (per-name provider
# browser, or a named Browser Use cloud browser). Popped before the
# subprocess launches — never exported to the CLI.
_PRIVATE_BROWSER_SENTINEL = "_HERMES_BU_PRIVATE_BROWSER"

# Preamble prepended to the model's code for named sessions on SHARED
# browsers (local Chrome / CDP override). The harness daemon attaches to the
# first existing page at startup, so two fresh named daemons can land on the
# SAME tab; steering this daemon onto a tab it created keeps concurrent named
# sessions from clobbering each other before their first new_tab(). Runs
# once per daemon (marker file keyed by BU_NAME under the harness runtime
# state), costs one IPC round-trip on later calls.
_OWN_TAB_PREAMBLE = """\
# hermes: pin this named session to its own tab (once per daemon process)
def _hermes_ensure_own_tab():
    import os as _os, tempfile as _tf
    _name = _os.environ.get("BU_NAME", "default")
    try:
        # Key the marker by the daemon's pid so a daemon restart (which
        # re-attaches to the first shared page) re-pins automatically,
        # while agent-driven tab switches mid-session are left alone.
        from browser_harness import _ipc as _bipc
        _dpid = _bipc.pid_path(_name).read_text().strip() or "0"
    except Exception:
        _dpid = "0"
    _uid = _os.getuid() if hasattr(_os, "getuid") else 0
    _marker = _os.path.join(
        _tf.gettempdir(), "hermes-bu-owntab-%s-%s-%s" % (_uid, _name, _dpid)
    )
    if _os.path.exists(_marker):
        return
    try:
        # Force a fresh target: new_tab() would REUSE a blank current tab,
        # which is exactly the tab a sibling daemon may also hold.
        _tid = cdp("Target.createTarget", url="about:blank").get("targetId")
        if _tid:
            switch_tab(_tid)
    except Exception:
        pass  # best-effort: worst case is pre-fix behavior
    try:
        open(_marker, "w").close()
    except OSError:
        pass
_hermes_ensure_own_tab()
del _hermes_ensure_own_tab
"""

_DEFAULT_TIMEOUT_S = 300
_MIN_TIMEOUT_S = 5
_MAX_TIMEOUT_S = 1800
_STDERR_CAP_CHARS = 4000
_PRIVATE_IPC_TIMEOUT_S = 5.0
_PRIVATE_IPC_MAX_RESPONSE = 1 << 20
_PROCESS_GENERATION = hashlib.sha256(
    f"{os.getpid()}:{time.time_ns()}:{secrets.token_hex(16)}".encode("ascii")
).hexdigest()[:16]
_OWNED_DAEMONS: dict[str, str] = {}
_OWNED_DAEMONS_LOCK = threading.Lock()
_ORPHAN_REAPED = False

_NATIVE_FILL_FUNCTION = """function(value) {
  if (!this || !this.isConnected || this.ownerDocument !== document) return false;
  if (!(this instanceof HTMLInputElement || this instanceof HTMLTextAreaElement)) return false;
  if (this.disabled || this.readOnly || this.getAttribute("aria-disabled") === "true" || this.hasAttribute("inert")) return false;
  const style = getComputedStyle(this);
  const rect = this.getBoundingClientRect();
  if (style.display === "none" || style.visibility === "hidden" || rect.width <= 0 || rect.height <= 0) return false;
  this.focus();
  const prototype = this instanceof HTMLTextAreaElement
    ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
  const setter = Object.getOwnPropertyDescriptor(prototype, "value").set;
  setter.call(this, value);
  this.dispatchEvent(new Event("input", {bubbles: true}));
  this.dispatchEvent(new Event("change", {bubbles: true}));
  this.blur();
  return true;
}"""


def _harness_runtime_layout(session: str) -> tuple[Path, str]:
    """Resolve browser-harness 0.1.9's exact runtime directory and stem."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        raise NativeAuthSecurityError("secure browser session is invalid")
    try:
        runtime_raw = os.environ.get("BH_RUNTIME_DIR") or os.environ.get("BH_TMP_DIR")
        if runtime_raw:
            runtime = Path(runtime_raw).expanduser().resolve()
            shared = os.environ.get("BH_RUNTIME_DIR_SHARED") == "1"
            stem = f"bu-{session}" if shared else "bu"
        else:
            home_raw = os.environ.get("BH_HOME") or os.environ.get("BROWSER_HARNESS_HOME")
            if home_raw:
                home = Path(home_raw).expanduser().resolve()
            elif os.environ.get("XDG_CONFIG_HOME"):
                home = (Path(os.environ["XDG_CONFIG_HOME"]).expanduser() / "browser-harness").resolve()
            else:
                home = (Path.home() / ".config" / "browser-harness").resolve()
            runtime = home / "runtime"
            stem = f"bu-{session}"
        runtime_stat = runtime.stat()
        if os.name != "nt":
            if (
                not stat.S_ISDIR(runtime_stat.st_mode)
                or runtime_stat.st_uid != os.getuid()
                or stat.S_IMODE(runtime_stat.st_mode) != 0o700
            ):
                raise PermissionError
        return runtime, stem
    except NativeAuthSecurityError:
        raise
    except Exception:
        raise NativeAuthSecurityError("secure browser channel unavailable") from None


def _private_harness_identity(runtime: Path, stem: str) -> tuple[int, tuple[Any, ...]]:
    """Return the live 0.1.9 endpoint identity without trusting a stale pid file."""
    pid_path = runtime / f"{stem}.pid"
    pid_stat = pid_path.lstat()
    if not stat.S_ISREG(pid_stat.st_mode) or (
        os.name != "nt" and pid_stat.st_uid != os.getuid()
    ):
        raise PermissionError
    pid_text = pid_path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[1-9][0-9]{0,9}", pid_text):
        raise ValueError
    pid = int(pid_text)
    if pid >= (1 << 31) or not _pid_is_alive(pid):
        raise ValueError

    endpoint = runtime / (f"{stem}.sock" if os.name != "nt" else f"{stem}.port")
    endpoint_stat = endpoint.lstat()
    mode = stat.S_IMODE(endpoint_stat.st_mode)
    if os.name != "nt":
        # browser-harness 0.1.9 intends 0600; macOS reports its AF_UNIX
        # listener as 0700. Both are owner-only. Never accept group/world bits.
        if (
            not stat.S_ISSOCK(endpoint_stat.st_mode)
            or endpoint_stat.st_uid != os.getuid()
            or mode & 0o077
            or mode & 0o600 != 0o600
        ):
            raise PermissionError
    elif not stat.S_ISREG(endpoint_stat.st_mode):  # pragma: no cover - Windows
        raise PermissionError
    if os.name != "nt":
        fingerprint = (endpoint_stat.st_dev, endpoint_stat.st_ino)
    else:  # pragma: no cover - Windows
        fingerprint = (
            endpoint_stat.st_dev,
            endpoint_stat.st_ino,
            endpoint_stat.st_size,
            endpoint_stat.st_mtime_ns,
        )
    return pid, fingerprint


def _private_harness_request(
    session: str,
    request: dict[str, Any],
    *,
    timeout_s: float | None = None,
    expected_identity: tuple[int, tuple[Any, ...]] | None = None,
) -> dict[str, Any]:
    """Perform one private JSON-line browser-harness request."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    timeout = max(0.1, min(float(timeout_s or _PRIVATE_IPC_TIMEOUT_S), 10.0))
    client = None
    try:
        runtime, stem = _harness_runtime_layout(session)
        initial_identity = _private_harness_identity(runtime, stem)
        if expected_identity is not None and initial_identity != expected_identity:
            raise PermissionError
        wire_request = dict(request)
        if os.name != "nt":
            endpoint = runtime / f"{stem}.sock"
            client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            client.settimeout(timeout)
            client.connect(str(endpoint))
        else:  # pragma: no cover - exercised with platform fakes on Windows CI
            port_data = json.loads((runtime / f"{stem}.port").read_text(encoding="utf-8"))
            port = port_data.get("port")
            token = port_data.get("token")
            if type(port) is not int or not (0 < port < 65536):
                raise ValueError
            if not isinstance(token, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", token):
                raise ValueError
            client = socket.create_connection(("127.0.0.1", port), timeout=timeout)
            client.settimeout(timeout)
            wire_request["token"] = token

        # A concurrent stale daemon can unlink/rebind the named socket. Connect
        # first, then verify the path still names the identity we selected,
        # before any request data (especially plaintext) crosses the channel.
        if _private_harness_identity(runtime, stem) != initial_identity:
            raise PermissionError
        client.sendall(json.dumps(wire_request, ensure_ascii=False, separators=(",", ":")).encode("utf-8") + b"\n")
        response_bytes = bytearray()
        while not response_bytes.endswith(b"\n"):
            chunk = client.recv(min(65536, _PRIVATE_IPC_MAX_RESPONSE + 1 - len(response_bytes)))
            if not chunk:
                break
            response_bytes.extend(chunk)
            if len(response_bytes) > _PRIVATE_IPC_MAX_RESPONSE:
                raise ValueError
        response = json.loads(bytes(response_bytes or b"{}"))
        if not isinstance(response, dict) or "error" in response:
            raise ValueError
        return response
    except NativeAuthSecurityError:
        raise
    except Exception:
        raise NativeAuthSecurityError("secure browser channel unavailable") from None
    finally:
        if client is not None:
            try:
                client.close()
            except OSError:
                pass


def _private_daemon_identity(
    session: str,
    *,
    timeout_s: float | None = None,
) -> tuple[int, tuple[Any, ...]]:
    """Bind a harness name to the exact live daemon answering its private IPC."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    try:
        runtime, stem = _harness_runtime_layout(session)
        identity = _private_harness_identity(runtime, stem)
        response = _private_harness_request(
            session,
            {"meta": "ping"},
            timeout_s=timeout_s,
            expected_identity=identity,
        )
        if response.get("pong") is not True or response.get("pid") != identity[0]:
            raise ValueError
        return identity
    except NativeAuthSecurityError:
        raise
    except Exception:
        raise NativeAuthSecurityError("secure browser channel unavailable") from None


def _private_cdp_request(
    session: str,
    method: str,
    params: dict[str, Any],
    *,
    timeout_s: float | None = None,
) -> dict[str, Any]:
    """Send one sanitized CDP request to the named harness daemon."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    if method not in {
        "Target.getTargetInfo",
        "Page.getFrameTree",
        "Runtime.evaluate",
        "Runtime.getProperties",
        "Runtime.callFunctionOn",
        "DOM.describeNode",
        "Runtime.releaseObject",
    } or not isinstance(params, dict):
        raise NativeAuthSecurityError("secure browser request is invalid")
    identity = _private_daemon_identity(session, timeout_s=timeout_s)
    response = _private_harness_request(
        session,
        {"method": method, "params": params},
        timeout_s=timeout_s,
        expected_identity=identity,
    )
    if not isinstance(response.get("result"), dict):
        raise NativeAuthSecurityError("secure browser channel unavailable")
    return response["result"]


def _verify_native_auth_owner(browser_session: str, task_id: str) -> bool:
    """Verify the task's generation-scoped daemon before private inspection."""
    try:
        effective = _effective_session_name(browser_session, task_id)
        with _OWNED_DAEMONS_LOCK:
            owned_task = _OWNED_DAEMONS.get(effective)
        if owned_task != str(task_id):
            return False
        marker = _owned_daemon_marker(effective)
        if not hasattr(os, "O_NOFOLLOW"):
            return False
        marker_stat = marker.lstat()
        flags = os.O_RDONLY
        flags |= os.O_NOFOLLOW
        fd = os.open(marker, flags)
        try:
            opened_stat = os.fstat(fd)
            if not stat.S_ISREG(opened_stat.st_mode):
                return False
            if os.name != "nt" and (
                opened_stat.st_uid != os.getuid()
                or stat.S_IMODE(opened_stat.st_mode) != 0o600
                or marker_stat.st_dev != opened_stat.st_dev
                or marker_stat.st_ino != opened_stat.st_ino
            ):
                return False
            raw = os.read(fd, 8193)
        finally:
            os.close(fd)
        if len(raw) > 8192:
            return False
        payload = json.loads(raw.decode("utf-8"))
        if not isinstance(payload, dict) or set(payload) != {
            "version", "session", "task_id", "owner_pid", "daemon_pid", "daemon_identity",
        }:
            return False
        if (
            payload.get("version") != 2
            or payload.get("session") != effective
            or payload.get("task_id") != str(task_id)
            or payload.get("owner_pid") != os.getpid()
        ):
            return False
        daemon_pid, daemon_identity = _private_daemon_identity(effective, timeout_s=1.0)
        marker_identity = payload.get("daemon_identity")
        if (
            type(marker_identity) is not list
            or len(marker_identity) != len(daemon_identity)
            or any(
                type(marker_value) is not type(live_value)
                or marker_value != live_value
                for marker_value, live_value in zip(marker_identity, daemon_identity)
            )
        ):
            return False
        return (
            type(payload.get("daemon_pid")) is int
            and payload["daemon_pid"] == daemon_pid
        )
    except Exception:
        return False


def resolve_native_auth_v2(*, browser_session: str, task_id: str) -> dict[str, Any]:
    """Return a bounded, generic inventory from the exact owned page."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    try:
        if not _verify_native_auth_owner(browser_session=browser_session, task_id=task_id):
            raise NativeAuthSecurityError("secure browser inspect unavailable")
        session = _effective_session_name(browser_session, task_id)
        target = _private_cdp_request(session, "Target.getTargetInfo", {})
        info = target.get("targetInfo")
        if not isinstance(info, dict) or info.get("type") != "page":
            raise ValueError
        target_id = info.get("targetId")
        target_url = _inspect_url(info.get("url"))
        if not isinstance(target_id, str) or not target_id:
            raise ValueError
        tree = _private_cdp_request(session, "Page.getFrameTree", {})
        frame = tree.get("frameTree", {}).get("frame")
        if not isinstance(frame, dict):
            raise ValueError
        frame_id, loader_id = frame.get("id"), frame.get("loaderId")
        frame_url = _inspect_url(frame.get("url"))
        if not isinstance(frame_id, str) or not frame_id or not isinstance(loader_id, str) or not loader_id:
            raise ValueError
        if target_url != frame_url:
            raise ValueError
        origin, path = target_url
        array_result = _private_cdp_request(session, "Runtime.evaluate", {
            "expression": _NATIVE_AUTH_V2_INVENTORY_EXPRESSION,
            "returnByValue": False,
        })
        remote = array_result.get("result", {})
        array_id = remote.get("objectId")
        if remote.get("type") != "object" or not isinstance(array_id, str) or not array_id:
            raise ValueError
        element_ids: list[tuple[int, str]] = []
        try:
            props = _private_cdp_request(session, "Runtime.getProperties", {"objectId": array_id, "ownProperties": True})
            entries = props.get("result")
            if not isinstance(entries, list):
                raise ValueError
            for position, entry in enumerate(entries[:32]):
                if not isinstance(entry, dict) or entry.get("name") != str(position):
                    continue
                value = entry.get("value")
                object_id = value.get("objectId") if isinstance(value, dict) else None
                if isinstance(object_id, str) and object_id:
                    element_ids.append((position, object_id))
            targets: list[dict[str, Any]] = []
            backend_ids: set[int] = set()
            backend_positions: dict[int, int] = {}
            for position, object_id in element_ids:
                descriptor = _private_cdp_request(session, "Runtime.callFunctionOn", {
                    "objectId": object_id,
                    "functionDeclaration": _NATIVE_AUTH_V2_DESCRIPTOR_FUNCTION,
                    "returnByValue": True,
                }).get("result", {})
                descriptor = descriptor.get("value") if isinstance(descriptor, dict) else None
                if not isinstance(descriptor, dict) or descriptor.get("eligible") is not True:
                    continue
                role, label, hints = descriptor.get("role"), descriptor.get("label"), descriptor.get("hints")
                if role not in {"textbox", "searchbox", "combobox", "button", "link", "checkbox", "radio", "switch"}:
                    continue
                if not isinstance(label, str) or not isinstance(hints, dict):
                    continue
                described = _private_cdp_request(session, "DOM.describeNode", {"objectId": object_id})
                backend_id = described.get("node", {}).get("backendNodeId")
                if type(backend_id) is not int or backend_id <= 0:
                    continue
                safe_hints = {key: hints[key] for key in ("masked", "required", "keyboard") if key in hints}
                candidate = {"ref": f"@e{position + 1}", "role": role, "label": label, "hints": safe_hints,
                             "target": {"target_id": target_id, "frame_id": frame_id, "loader_id": loader_id, "backend_node_id": backend_id}}
                previous = backend_positions.get(backend_id)
                if previous is None:
                    backend_ids.add(backend_id)
                    backend_positions[backend_id] = len(targets)
                    targets.append(candidate)
                else:
                    targets[previous] = candidate
            if not targets:
                raise ValueError
            return {"origin": origin, "path": path, "targets": targets}
        finally:
            for _, object_id in element_ids:
                try:
                    _private_cdp_request(session, "Runtime.releaseObject", {"objectId": object_id})
                except Exception:
                    pass
            try:
                _private_cdp_request(session, "Runtime.releaseObject", {"objectId": array_id})
            except Exception:
                pass
    except NativeAuthSecurityError:
        raise NativeAuthSecurityError("secure browser inspect unavailable") from None
    except Exception:
        raise NativeAuthSecurityError("secure browser inspect unavailable") from None


def _inspect_url(value: Any) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ValueError
    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https" or parsed.username is not None or parsed.password is not None or not parsed.hostname:
        raise ValueError
    origin = urlunsplit(("https", parsed.netloc.lower(), "", "", ""))
    return origin, parsed.path or "/"


_NATIVE_AUTH_V2_INVENTORY_EXPRESSION = """(() => Array.from(document.querySelectorAll('input,textarea,select,button,a,[role]')).slice(0,32))()"""
_NATIVE_AUTH_V2_DESCRIPTOR_FUNCTION = """function() {
  if (!this || !this.isConnected || this.ownerDocument !== document) return {eligible:false};
  if (this.closest('[aria-disabled="true"]') || this.closest('[inert]') || this.closest('fieldset:disabled')) return {eligible:false};
  const style = getComputedStyle(this), rect = this.getBoundingClientRect();
  if (this.disabled || this.getAttribute('aria-disabled') === 'true' || this.readOnly === true || this.hidden || style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) return {eligible:false};
  let role = this.getAttribute('role') || '';
  if (!role && this instanceof HTMLInputElement) role = this.type === 'search' ? 'searchbox' : (this.type === 'checkbox' || this.type === 'radio' ? this.type : 'textbox');
  if (!role && this instanceof HTMLTextAreaElement) role = 'textbox';
  if (!role && this instanceof HTMLSelectElement) role = 'combobox';
  if (!role && this instanceof HTMLButtonElement) role = 'button';
  if (!role && this instanceof HTMLAnchorElement) role = 'link';
  const fillable = this instanceof HTMLInputElement || this instanceof HTMLTextAreaElement || this instanceof HTMLSelectElement || this.isContentEditable === true;
  if (role === 'textbox' && !(this instanceof HTMLInputElement || this instanceof HTMLTextAreaElement || this instanceof HTMLSelectElement || this.isContentEditable === true)) return {eligible:false};
  if ((role === 'searchbox' || role === 'combobox') && !fillable) return {eligible:false};
  const label = (this.getAttribute('aria-label') || this.getAttribute('title') || this.textContent || '').trim().slice(0,120);
  const hints = {masked: this instanceof HTMLInputElement && this.type === 'password', required: this.required === true};
  if (this instanceof HTMLInputElement && ['email','tel','url','number','text','search'].includes(this.type)) hints.keyboard = this.type;
  return {eligible:true, role:role, label:label, hints:hints};
}"""


def _effective_session_name(
    requested_session: str,
    task_id: str | None,
    *,
    process_generation: str | None = None,
) -> str:
    """Return a process-generation/task-scoped private harness name."""
    if not isinstance(requested_session, str) or not _SESSION_RE.fullmatch(requested_session):
        raise ValueError("invalid browser session label")
    generation = process_generation if process_generation is not None else _PROCESS_GENERATION
    material = json.dumps(
        [str(generation), str(task_id or "process-default"), requested_session],
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "ha1-" + hashlib.sha256(material).hexdigest()[:40]


def _private_daemon_control(
    session: str,
    action: str,
    *,
    timeout_s: float | None = None,
) -> bool:
    """Ping or stop one exact private harness daemon without exposing errors."""
    if action not in {"ping", "shutdown"}:
        return False
    try:
        identity = _private_daemon_identity(session, timeout_s=timeout_s)
        if action == "ping":
            return True
        response = _private_harness_request(
            session,
            {"meta": action},
            timeout_s=timeout_s,
            expected_identity=identity,
        )
    except Exception:
        return False
    return response.get("ok") is True


def _owned_daemon_marker(session: str) -> Path:
    runtime, _stem = _harness_runtime_layout(session)
    return runtime / f"{session}.owner.json"


def _register_owned_daemon(session: str, task_id: str | None) -> bool:
    """Mark a newly started ha1 daemon as owned by this process/task."""
    if not session.startswith("ha1-") or not _SESSION_RE.fullmatch(session):
        return False
    if not _private_daemon_control(session, "ping", timeout_s=1.0):
        return False
    try:
        daemon_pid, daemon_identity = _private_daemon_identity(session, timeout_s=1.0)
        marker = _owned_daemon_marker(session)
        temp = marker.with_name(marker.name + f".{os.getpid()}.tmp")
        payload = {
            "version": 2,
            "session": session,
            "task_id": str(task_id or ""),
            "owner_pid": os.getpid(),
            "daemon_pid": daemon_pid,
            "daemon_identity": list(daemon_identity),
        }
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        fd = os.open(temp, flags, 0o600)
        try:
            os.write(fd, json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        finally:
            os.close(fd)
        if os.name != "nt":
            os.chmod(temp, 0o600)
        os.replace(temp, marker)
        with _OWNED_DAEMONS_LOCK:
            _OWNED_DAEMONS[session] = str(task_id or "")
        return True
    except Exception:
        try:
            temp.unlink()
        except Exception:
            pass
        return False


def cleanup_browser_use_task(task_id: str | None) -> None:
    """Idempotently stop only ha1 daemons owned by one task."""
    owner = str(task_id or "")
    with _OWNED_DAEMONS_LOCK:
        sessions = [name for name, value in _OWNED_DAEMONS.items() if value == owner]
        for name in sessions:
            _OWNED_DAEMONS.pop(name, None)
    for session in sessions:
        stopped = _private_daemon_control(session, "shutdown", timeout_s=1.0)
        if stopped:
            try:
                _owned_daemon_marker(session).unlink()
            except OSError:
                pass


def cleanup_all_owned_browser_use_daemons() -> None:
    """Stop every ha1 daemon started and registered by this process."""
    with _OWNED_DAEMONS_LOCK:
        task_ids = set(_OWNED_DAEMONS.values())
    for task_id in task_ids:
        cleanup_browser_use_task(task_id)


def _pid_is_alive(pid: int) -> bool:
    if type(pid) is not int or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def reap_owned_browser_use_orphans(*, limit: int = 64) -> int:
    """Boundedly stop dead-owner daemons described by ha1 marker files only."""
    try:
        runtime, _stem = _harness_runtime_layout("ha1-orphan-scan")
    except Exception:
        return 0
    reaped = 0
    for marker in sorted(runtime.glob("ha1-*.owner.json"))[: max(0, min(int(limit), 256))]:
        try:
            marker_stat = marker.lstat()
            if os.name != "nt" and (
                marker_stat.st_uid != os.getuid()
                or stat.S_IMODE(marker_stat.st_mode) != 0o600
                or not stat.S_ISREG(marker_stat.st_mode)
            ):
                continue
            payload = json.loads(marker.read_text(encoding="utf-8"))
            session = payload.get("session")
            owner_pid = payload.get("owner_pid")
            if (
                payload.get("version") != 1
                or not isinstance(session, str)
                or not session.startswith("ha1-")
                or marker.name != f"{session}.owner.json"
                or type(owner_pid) is not int
                or _pid_is_alive(owner_pid)
            ):
                continue
            if not _private_daemon_control(session, "ping", timeout_s=1.0):
                continue
            if not _private_daemon_control(session, "shutdown", timeout_s=1.0):
                continue
            marker.unlink()
            reaped += 1
        except Exception:
            continue
    return reaped


atexit.register(cleanup_all_owned_browser_use_daemons)

# Filesystem-safe task ids for per-task workspace dirs.
_TASK_ID_SAFE_RE = re.compile(r"[^A-Za-z0-9._-]+")

# Screenshot paths printed by capture_screenshot() in the exec output.
# Two alternatives: POSIX absolute (/tmp/shot.png) and Windows drive-letter
# absolute (C:\Users\...\shot.png or C:/Users/.../shot.png). Browser Use on
# Windows prints native paths — the POSIX-only pattern silently dropped them
# and screenshot_path / the multimodal attach never fired (#83884).
_IMAGE_PATH_RE = re.compile(
    r"((?:[A-Za-z]:[\\/]|/)[^\s\"']+?\.(?:png|jpe?g|webp))", re.IGNORECASE
)

# http(s) URL literals in exec code checked against browser_navigate's policy
_URL_RE = re.compile(r"https?://[^\s'\"\\)]+", re.IGNORECASE)


def _blocked_url_in_code(code: str) -> Optional[str]:
    """Return an error if a URL literal fails the built-in navigation checks."""
    from tools.browser_tool import evaluate_url_safety

    for url in _URL_RE.findall(code or ""):
        err = evaluate_url_safety(url)
        if err:
            return err.get("error", "Blocked: unsafe URL")
    return None


def _base_subprocess_env() -> dict:
    from tools.browser_tool import _build_browser_env

    env = _build_browser_env()
    # The browser-use CLI runs under its own Python (uv tool / uvx), which
    # may differ from Hermes's venv Python. PYTHONPATH/PYTHONHOME inherited
    # from the agent process point at Hermes's venv site-packages, and a
    # child interpreter honors them ahead of its own site-packages — so the
    # CLI imports compiled C-extensions (e.g. pydantic_core) built for the
    # wrong interpreter and crashes on ABI mismatch (#83427, #84841, #86006,
    # #86104). Strip both — the CLI manages its own environment and never
    # needs Hermes's import path.
    env.pop("PYTHONPATH", None)
    env.pop("PYTHONHOME", None)
    # Same class of hazard, PATH flavor: profile-spawned workers (kanban
    # bots, cron jobs) can hand down a PATH of only version-manager dirs,
    # which kills the uv trampoline before the CLI's Python starts. Floor
    # the PATH so coreutils are always reachable (see below).
    env["PATH"] = _floor_subprocess_path(env.get("PATH", ""))
    env.setdefault("ANONYMIZED_TELEMETRY", "false")
    return env


def _floor_subprocess_path(path: str) -> str:
    """Guarantee core system dirs survive onto the CLI subprocess PATH.

    Profile workers can inherit a PATH holding only version-manager dirs
    (observed: the nvm node dir repeated 7x, nothing else). That is fatal
    for the uv-installed browser-use binary: its POSIX sh trampoline
    resolves ``dirname``/``realpath`` through PATH, so without /usr/bin it
    dies with ``realpath: not found … exec: /python: not found`` (exit
    127) before its own Python ever starts. Reuses browser_tool's
    ``_merge_browser_path`` floor — same hazard, same sane-dir list — and
    falls back to appending FHS bin dirs if that import is unavailable.
    Windows .cmd shims don't trampoline through PATH, so no-op there.
    """
    if os.name == "nt":
        return path
    try:
        from tools.browser_tool import _merge_browser_path

        return _merge_browser_path(path or "")
    except Exception:
        pass
    parts = [p for p in (path or "").split(os.pathsep) if p]
    existing = set(parts)
    for directory in (
        "/usr/local/sbin",
        "/usr/local/bin",
        "/usr/sbin",
        "/usr/bin",
        "/sbin",
        "/bin",
    ):
        if directory not in existing and os.path.isdir(directory):
            parts.append(directory)
    return os.pathsep.join(parts)


def _read_browser_cfg() -> dict:
    """Return the ``browser:`` config section, or {} on any failure."""
    try:
        from hermes_cli.config import cfg_get, read_raw_config

        cfg = cfg_get(read_raw_config(), "browser", default={})
        return cfg if isinstance(cfg, dict) else {}
    except Exception as e:
        logger.debug("Could not read browser config section: %s", e)
        return {}


def get_browser_backend() -> str:
    """Return the configured browser backend key ("" = unset → default).

    YAML 1.1 parses an unquoted ``off`` as boolean False — a hand-edited
    ``backend: off`` must mean BACKEND_DISABLED, not "unset". (True has no
    sensible backend meaning; normalize it to unset.)
    """
    raw = _read_browser_cfg().get("backend")
    if raw is False:
        return BACKEND_DISABLED
    if raw is True:
        return ""
    return str(raw or "").strip().lower()


def is_legacy_browser_use_cloud_config(browser_cfg: dict) -> bool:
    """True for pre-CLI direct-API Browser Use cloud configs"""
    if not isinstance(browser_cfg, dict):
        return False
    if browser_cfg.get("backend"):
        return False  # an explicit backend choice wins
    provider = str(browser_cfg.get("cloud_provider") or "").strip().lower()
    if provider not in {"browser-use", ""}:
        return False  # explicit local/Browserbase/… choices win
    if is_truthy_value(browser_cfg.get("use_gateway"), default=False):
        return False
    # Camofox is selected via env var, not cloud_provider — a Camofox user
    # with a stray BROWSER_USE_API_KEY must keep their explicit choice.
    try:
        from tools.browser_camofox import is_camofox_mode

        if is_camofox_mode():
            return False
    except Exception as e:
        logger.debug("Camofox activity check failed during migration: %s", e)
    return bool(os.getenv("BROWSER_USE_API_KEY"))


def is_browser_use_cli_mode() -> bool:
    """True when the Browser Use CLI replaces the built-in browser stack.

    Browser Use mode is the DEFAULT: an unset ``browser.backend`` ("") enables
    it whenever the browser-use CLI is runnable (installed binary or uvx).
    Set ``browser.backend: off`` (or ``/browser use off``) for the built-in
    browser_* tools.

    Camofox always falls back to the built-in tools regardless of
    ``browser.backend`` — it is Firefox-based with a custom HTTP API and no
    CDP surface, so the CDP-only browser-use harness cannot drive it.
    """
    try:
        from tools.browser_camofox import is_camofox_mode

        if is_camofox_mode():
            return False
    except Exception as e:
        logger.debug("Camofox activity check failed: %s", e)
    backend = get_browser_backend()
    if backend:
        return backend == _BACKEND_KEY
    if is_legacy_browser_use_cloud_config(_read_browser_cfg()):
        return True
    # Default (backend unset): Browser Use mode when the CLI can run at all;
    # otherwise keep the built-in tools so browsing never silently breaks.
    return _find_cli() is not None


_NOTICE_STAMP_NAME = ".browser_use_default_notice"
_NOTICE_INTERVAL_S = 24 * 3600


def default_downgrade_notice() -> Optional[str]:
    """One-line notice when the default Browser Use backend silently downgraded.

    Returns the notice string when ``browser.backend`` is unset (Browser Use
    would be the default) but the CLI is not runnable, so the session fell
    back to the built-in browser tools. Rate-limited to once per 24h via a
    stamp file so it nudges without nagging. Returns ``None`` otherwise.
    """
    try:
        if get_browser_backend():
            return None  # explicit choice — nothing downgraded
        try:
            from tools.browser_camofox import is_camofox_mode

            if is_camofox_mode():
                return None
        except Exception:
            pass
        if _find_cli() is not None:
            return None

        from hermes_constants import get_hermes_home

        stamp = Path(get_hermes_home()) / "cache" / _NOTICE_STAMP_NAME
        try:
            if 0 <= time.time() - stamp.stat().st_mtime < _NOTICE_INTERVAL_S:
                return None
        except OSError:
            pass
        try:
            stamp.parent.mkdir(parents=True, exist_ok=True)
            stamp.touch()
        except OSError:
            pass
        return (
            "Browser Use CLI not found — using the built-in browser tools. "
            "Run `hermes tools` (Browser Automation → Browser Use) to install it, "
            "or `browser.backend: off` in config.yaml to silence this."
        )
    except Exception as e:  # pragma: no cover — a notice must never break startup
        logger.debug("browser-use downgrade notice failed: %s", e)
        return None


def _managed_bin_dir() -> Optional[str]:
    """Hermes' own bin dir ($HERMES_HOME/bin) — where install.sh puts uv/uvx
    and where install_cli() links the browser-use binary."""
    try:
        from hermes_constants import get_hermes_home

        return str(Path(get_hermes_home()) / "bin")
    except Exception as e:  # pragma: no cover — defensive
        logger.debug("Could not resolve managed bin dir: %s", e)
        return None


def _user_local_bin_dir() -> Optional[str]:
    """The standard user-level tool dir (~/.local/bin on POSIX; uv's default
    tool bin dir on Windows). Desktop/TUI workers may start with a minimal
    PATH that omits it even when `uv tool install browser-use` put the
    binary there."""
    try:
        if os.name == "nt":
            base = os.environ.get("APPDATA")
            if base:
                return str(Path(base) / "uv" / "bin")
            return None
        return str(Path(os.path.expanduser("~")) / ".local" / "bin")
    except Exception as e:  # pragma: no cover — defensive
        logger.debug("Could not resolve user-local bin dir: %s", e)
        return None


def _find_cli() -> Optional[List[str]]:
    """Locate the browser-use CLI, or None when it can't be run.

    MANAGED-FIRST resolution: Hermes' own ``$HERMES_HOME/bin`` copy — the
    one every browser backend selection installs and updates via
    ``install_cli()`` — always wins, so all sessions drive one canonical,
    Hermes-controlled binary. PATH and the user-level tool dir
    (~/.local/bin / %APPDATA%\\uv\\bin, where a manual ``uv tool install``
    links binaries) are fallbacks for setups that never ran our install,
    and cover Desktop/TUI workers that spawn with a minimal PATH. The uvx
    zero-install path (same probe order) is the final fallback.
    """
    probe_paths = (_managed_bin_dir(), None, _user_local_bin_dir())
    for probe_path in probe_paths:
        if probe_path is None or probe_path:
            direct = shutil.which("browser-use", path=probe_path)
            if direct:
                return [direct]
    for probe_path in probe_paths:
        if probe_path is None or probe_path:
            uvx = shutil.which("uvx", path=probe_path)
            if uvx:
                return [uvx, "browser-use"]
    return None


def install_cli(timeout_s: int = 600) -> Tuple[bool, str]:
    """Install the browser-use CLI persistently via ``uv tool install``.

    Resolution order for uv: Hermes' managed uv (bootstrapped on demand via
    ``hermes_cli.managed_uv.ensure_uv``) → uv on PATH. The binary is linked
    into ``$HERMES_HOME/bin`` (``UV_TOOL_BIN_DIR``) so ``_find_cli()``
    resolves it for every profile without touching the user's PATH.

    Returns ``(ok, message)`` — never raises.
    """
    # MANAGED-FIRST: only the managed copy short-circuits the install. A
    # browser-use found on PATH is a user-level side install — it must NOT
    # prevent provisioning the canonical Hermes-managed copy, or resolution
    # stays pinned to a binary we don't control (version drift, no updates
    # through hermes tools).
    bin_dir = _managed_bin_dir()
    if bin_dir:
        managed = shutil.which("browser-use", path=bin_dir)
        if managed:
            return True, f"browser-use CLI already installed ({managed})"

    uv_bin: Optional[str] = None
    try:
        from hermes_cli.managed_uv import ensure_uv

        uv_bin = str(ensure_uv() or "") or None
    except Exception as e:
        logger.debug("Managed uv bootstrap unavailable: %s", e)
    if not uv_bin:
        uv_bin = shutil.which("uv")
    if not uv_bin:
        return False, (
            "uv is not available and could not be bootstrapped. Install uv "
            "(https://docs.astral.sh/uv/) and run `uv tool install browser-use`."
        )

    env = dict(os.environ)
    env["UV_NO_CONFIG"] = "1"
    if bin_dir:
        try:
            Path(bin_dir).mkdir(parents=True, exist_ok=True)
            env["UV_TOOL_BIN_DIR"] = bin_dir
        except OSError as e:
            logger.debug("Could not prepare %s: %s", bin_dir, e)

    try:
        result = subprocess.run(
            [uv_bin, "tool", "install", "browser-use"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env=env,
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired:
        return False, f"`uv tool install browser-use` timed out after {timeout_s}s"
    except Exception as e:
        return False, f"Failed to run `uv tool install browser-use`: {e}"

    if result.returncode != 0:
        tail = "\n".join(
            (result.stderr or result.stdout or "").strip().splitlines()[-3:]
        )
        return False, f"`uv tool install browser-use` failed:\n{tail}"

    found = _find_cli()
    if not found or len(found) != 1:
        return False, (
            "install reported success but the browser-use binary is still "
            "not resolvable — run `uv tool install browser-use` manually"
        )
    return True, f"browser-use CLI installed ({found[0]})"


def _workspace_dir(task_id: Optional[str]) -> Optional[str]:
    """Stable per-task scratch dir that persists across browser_exec calls"""
    existing = os.environ.get("BH_AGENT_WORKSPACE")
    if existing:
        return existing
    try:
        from pathlib import Path

        from hermes_constants import get_hermes_home

        safe = _TASK_ID_SAFE_RE.sub("_", str(task_id or "default"))[:80] or "default"
        path = Path(get_hermes_home()) / "cache" / "browser-use" / "workspace" / safe
        path.mkdir(parents=True, exist_ok=True)
        return str(path)
    except Exception as e:
        logger.debug("browser_exec workspace unavailable: %s", e)
        return None


def _find_screenshot(stdout: str, since: float) -> Optional[str]:
    """Return the last screenshot path printed during this exec, or None.

    Only accepts files that exist and were written after the exec started
    """
    for path in reversed(_IMAGE_PATH_RE.findall(stdout or "")):
        try:
            if os.path.isfile(path) and os.path.getmtime(path) >= since - 1:
                return path
        except OSError:
            continue
    return None


def _native_screenshot_result(result: Dict[str, Any], path: str) -> Optional[Dict[str, Any]]:
    """Build a multimodal tool result attaching path for vision models"""
    try:
        from pathlib import Path

        from tools.vision_tools import (
            _EMBED_MAX_DIMENSION,
            _EMBED_TARGET_BYTES,
            _resize_image_for_vision,
            _should_use_native_vision_fast_path,
        )

        if not _should_use_native_vision_fast_path():
            return None
        # History-reuse cap (#92699): this data URL bakes into the tool
        # result and is re-sent on every later turn — same policy as the
        # vision_analyze / browser_vision native embeds (256 KB / 1568 px,
        # JPEG quality ladder instead of PNG dimension-halving).
        data_url = _resize_image_for_vision(
            Path(path),
            mime_type="image/png",
            max_base64_bytes=_EMBED_TARGET_BYTES,
            max_dimension=_EMBED_MAX_DIMENSION,
            force_jpeg=True,
        )
        text = json.dumps(result, ensure_ascii=False)
        return {
            "_multimodal": True,
            "content": [
                {
                    "type": "text",
                    "text": (
                        text
                        + "\n\nThe screenshot from this call is attached — "
                        "inspect it with your native vision."
                    ),
                },
                {"type": "image_url", "image_url": {"url": data_url}},
            ],
            "text_summary": text,
            "meta": {"screenshot_path": path, "native_vision": True},
        }
    except Exception as e:
        logger.debug("Native screenshot attach failed (falling back to text): %s", e)
        return None


def _resolve_backend_cdp(
    env: dict, task_id: Optional[str], session_name: str = ""
) -> Optional[str]:
    """Point the harness at the configured browser backend's CDP endpoint.

    Resolution order (first hit wins):

    1. ``BU_CDP_WS`` / ``BU_CDP_URL`` already in the environment — explicit
       user/operator override, passed through untouched.
    2. ``BROWSER_CDP_URL`` env / ``browser.cdp_url`` config override — the
       ``/browser connect`` path, same precedence the built-in tools honor.
    3. A configured cloud browser provider (Browserbase, Firecrawl, Nous
       gateway/Browser Use cloud, …): reuse the legacy stack's
       ``_get_session_info()`` so browser_exec shares the SAME provider
       session machinery — per-task session cache, expiry replacement,
       inactivity reaper, and atexit cleanup — instead of duplicating it.
    4. Nothing configured: return None; the harness attaches to local
       Chrome (or Browser Use cloud via BU_AUTOSPAWN for legacy configs).

    ``session_name`` (the tool's ``session`` argument / BU_NAME) keys the
    provider session cache when set, so every distinct name gets its OWN
    cloud browser and the same name reuses one — that is what makes named
    sessions actually concurrent-safe on provider backends instead of all
    names sharing a single per-task browser.

    Returns an error string on provider failure, None on success.
    """
    # WebUI runs concurrent profile-scoped turns with a thread-local env overlay.
    # Prefer that overlay when available; raw os.environ may still contain the
    # default profile's browser endpoint. The import is intentionally optional so
    # standalone CLI/gateway use remains independent of the WebUI package.
    scoped_override = ""
    try:
        from api.config import _thread_local_env_value

        scoped_override = _thread_local_env_value(
            "HERMES_WEBUI_BROWSER_CDP_URL", ""
        ).strip()
    except (ImportError, AttributeError):
        pass
    if not scoped_override:
        scoped_override = os.environ.get(
            "HERMES_WEBUI_BROWSER_CDP_URL", ""
        ).strip()
    if scoped_override:
        if not scoped_override.startswith(("http://", "https://", "ws://", "wss://")):
            return "HERMES_WEBUI_BROWSER_CDP_URL must use http(s) or ws(s)"
        env[
            "BU_CDP_URL"
            if scoped_override.startswith(("http://", "https://"))
            else "BU_CDP_WS"
        ] = scoped_override
        return None
    if env.get("BU_CDP_WS") or env.get("BU_CDP_URL"):
        return None

    try:
        from tools.browser_tool import (
            _get_cdp_override,
            _get_cloud_provider,
            _get_session_info,
        )
    except Exception as e:  # pragma: no cover — stubbed browser_tool in tests
        logger.debug("browser_tool backend resolution unavailable: %s", e)
        return None

    try:
        override = _get_cdp_override()
    except Exception:
        override = ""
    if override:
        env["BU_CDP_URL" if override.startswith(("http://", "https://")) else "BU_CDP_WS"] = override
        return None

    try:
        provider = _get_cloud_provider()
    except Exception as e:
        logger.debug("Cloud provider lookup failed: %s", e)
        provider = None
    if provider is None:
        return None

    # Browser Use direct-API configs: the CLI talks to Browser Use cloud
    # natively (BU_AUTOSPAWN / auth login) — routing through the legacy
    # provider here would just create a second, redundant session. The
    # Nous-gateway variant (use_gateway: true) DOES resolve through the
    # provider: the gateway provisions the cloud browser server-side and
    # returns its CDP URL, giving subscribers CLI mode with no raw key.
    provider_key = str(getattr(provider, "name", "") or "").strip().lower()
    if provider_key == _BACKEND_KEY and not is_truthy_value(
        _read_browser_cfg().get("use_gateway"), default=False
    ):
        # Named BU cloud browsers are exclusive to their daemon — no shared
        # tab to isolate from.
        env[_PRIVATE_BROWSER_SENTINEL] = "1"
        return None

    try:
        # Named sessions get their OWN provider browser, keyed by name so the
        # same name reuses one browser across calls and tasks, and different
        # names never collide. Unnamed calls keep the per-task key.
        cache_key = f"bu-named-{session_name}" if session_name else (task_id or "browser-exec-default")
        session_info = _get_session_info(cache_key)
    except Exception as e:
        return (
            f"Cloud browser provider {type(provider).__name__} failed to "
            f"provide a session: {e}. Fix the provider configuration or "
            "switch backends via `hermes tools` → Browser Automation."
        )
    cdp = str((session_info or {}).get("cdp_url") or "")
    if not cdp:
        return (
            f"Cloud browser provider {type(provider).__name__} returned no "
            "CDP endpoint, so Browser Use mode cannot drive it. Switch to "
            "the built-in browser tools for this provider."
        )
    env["BU_CDP_URL" if cdp.startswith(("http://", "https://")) else "BU_CDP_WS"] = cdp
    # A provider browser keyed bu-named-<name> is exclusive to this session —
    # the own-tab preamble is unnecessary there (it would just leak a blank
    # tab into a browser nobody else touches).
    if session_name:
        env[_PRIVATE_BROWSER_SENTINEL] = "1"
    return None


def _real_profile_consented() -> bool:
    """Whether the user opted in to real-profile local browsing (config read)."""
    try:
        from tools.browser_tool import _use_real_profile

        return _use_real_profile()
    except Exception as e:  # pragma: no cover — stubbed browser_tool in tests
        logger.debug("real-profile consent lookup failed: %s", e)
        return False


def _resolve_real_profile_cdp(env: dict, force_local: bool) -> Optional[str]:
    """Point the harness at the user's real-profile copy-browser when consented.

    With ``browser.use_real_profile`` on, local browsing must mean the user's
    default Chromium with their logins — a browser Hermes launches on a
    SNAPSHOT of their real profile (see hermes_cli.browser_connect). Two ways
    in:

    - the effective backend is already local (no cloud provider, no CDP
      override, no legacy Browser Use cloud config): every local attach
      upgrades to the real profile, silently — this is requirement one; or
    - ``force_local`` (the consent-gated ``local`` tool arg): the model was
      asked to drive the user's actual browser even though a cloud backend
      is configured. The cloud backend keeps serving everything else.

    Explicit operator overrides (BU_CDP_WS/BU_CDP_URL env, /browser connect,
    ``browser.cdp_url``) own the session either way, matching the built-in
    lane's precedence.

    Sets BU_CDP_URL/BU_CDP_WS on success. Returns an error string when the
    real-profile launch fails (fail closed — a consented user is never
    silently downgraded to a throwaway browser), else None.
    """
    if not _real_profile_consented():
        return None
    if env.get("BU_CDP_WS") or env.get("BU_CDP_URL"):
        return None

    try:
        from tools.browser_tool import (
            _get_cdp_override_raw,
            _get_cloud_provider,
            _real_profile_cdp,
        )
    except Exception as e:  # pragma: no cover — stubbed browser_tool in tests
        logger.debug("real-profile backend resolution unavailable: %s", e)
        return None

    try:
        if _get_cdp_override_raw():
            return None
    except Exception:
        pass

    if not force_local:
        # Only auto-upgrade genuinely-local attaches; any cloud path (provider
        # or legacy Browser Use cloud config) stays on its backend unless the
        # model passes local=true.
        try:
            if _get_cloud_provider() is not None:
                return None
        except Exception:
            return None
        if is_legacy_browser_use_cloud_config(_read_browser_cfg()):
            return None

    cdp, err = _real_profile_cdp()
    if err:
        return err
    if cdp:
        env["BU_CDP_URL" if cdp.startswith(("http://", "https://")) else "BU_CDP_WS"] = cdp
    return None
def validate_native_target(target: dict[str, Any]) -> dict[str, Any]:
    """Validate a browser-issued target before any secret is decrypted.

    This is intentionally a small data validator.  The target must have been
    minted by the browser auth-context runtime; this function only guarantees
    that the descriptor is bounded and cannot become executable Python/JS.
    """
    from tools.native_auth_runtime import NativeAuthSecurityError

    if not isinstance(target, dict):
        raise NativeAuthSecurityError("browser target is invalid")
    allowed = {"strategy", "value", "frame_path", "target_id"}
    if set(target) - allowed:
        raise NativeAuthSecurityError("browser target contains unsupported metadata")
    strategy = target.get("strategy")
    value = target.get("value")
    if strategy not in {"css", "xpath", "role", "label", "ref", "cdp"} or not isinstance(value, str):
        raise NativeAuthSecurityError("browser target is invalid")
    value = value.strip()
    if not value or len(value) > 2048 or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise NativeAuthSecurityError("browser target is invalid")
    lowered = value.lower()
    if "javascript:" in lowered or "<script" in lowered or "innerhtml" in lowered:
        raise NativeAuthSecurityError("browser target contains executable content")
    if strategy == "ref" and not re.fullmatch(r"@e[0-9]{1,8}", value):
        raise NativeAuthSecurityError("browser ref target is invalid")
    frame_path = target.get("frame_path")
    if frame_path is not None:
        if not isinstance(frame_path, list) or len(frame_path) > 8:
            raise NativeAuthSecurityError("browser frame path is invalid")
        if any(not isinstance(item, str) or not item or len(item) > 160 for item in frame_path):
            raise NativeAuthSecurityError("browser frame path is invalid")
    return dict(target, value=value)


def _validate_expected_page_metadata(expected_origin: str, expected_path: str) -> tuple[str, str]:
    from tools.native_auth_runtime import NativeAuthSecurityError
    from urllib.parse import urlsplit

    if not isinstance(expected_origin, str) or len(expected_origin) > 2048:
        raise NativeAuthSecurityError("secure browser origin is invalid")
    parsed = urlsplit(expected_origin)
    if parsed.scheme.lower() != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise NativeAuthSecurityError("secure browser origin must be HTTPS")
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise NativeAuthSecurityError("secure browser origin is invalid")
    if not isinstance(expected_path, str) or len(expected_path) > 512:
        raise NativeAuthSecurityError("secure browser path is invalid")
    if not expected_path.startswith("/") or "?" in expected_path or "#" in expected_path or "\\" in expected_path:
        raise NativeAuthSecurityError("secure browser path is invalid")
    return expected_origin, expected_path


def _secure_target_preflight_script(
    target: dict[str, Any],
    *,
    expected_origin: str,
    expected_path: str,
    expected_tab_handle: str | None = None,
    expected_frame_handle: str | None = None,
    expected_document_generation: str | None = None,
) -> str:
    selector = target["value"]
    selector_literal = json.dumps(selector, ensure_ascii=False)
    if target["strategy"] == "css":
        lookup = f"Array.from(document.querySelectorAll({selector_literal}))"
    else:
        lookup = (
            "(() => { const result = []; const iterator = document.evaluate("
            f"{selector_literal}, document, null, XPathResult.ORDERED_NODE_ITERATOR_TYPE, null); "
            "let node; while ((node = iterator.iterateNext())) result.push(node); return result; })()"
        )
    target_id = target.get("target_id")
    target_check = ""
    if target_id:
        target_check = (
            "const targetRefs = window.__hermesNativeAuthTargetRefs;"
            "if (!(targetRefs instanceof WeakMap) || targetRefs.get(element) !== "
            f"{json.dumps(target_id, ensure_ascii=False)}) return false;"
        )
    binding_match = re.fullmatch(r"ref_([fa])_[A-Za-z0-9_-]{8,64}__(form_[A-Za-z0-9_-]{8,80})", str(target_id or ""))
    if binding_match:
        target_role, form_id = binding_match.groups()
        role_check = (
            "if (!(element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement)) return false;"
            "const fieldType = (element.getAttribute('type') || 'text').toLowerCase();"
            "if (['hidden','submit','button','reset','image','file','checkbox','radio'].includes(fieldType)) return false;"
            if target_role == "f"
            else
            "if (!(element instanceof HTMLButtonElement || element instanceof HTMLInputElement)) return false;"
            "if ((element.type || '').toLowerCase() !== 'submit') return false;"
        )
        target_check += (
            "const form = element.form; if (!(form instanceof HTMLFormElement)) return false;"
            "const formRefs = window.__hermesNativeAuthFormRefs;"
            "if (!(formRefs instanceof WeakMap)) return false;"
            "const record = formRefs.get(form);"
            f"if (!record || record.form_id !== {json.dumps(form_id, ensure_ascii=False)}) return false;"
            "const rawMethod = (form.getAttribute('method') || 'get').trim().toLowerCase();"
            "if (record.method !== 'post' || rawMethod !== record.method || form.method.toLowerCase() !== record.method) return false;"
            "if (form.action !== record.action) return false;"
            "let action; try { action = new URL(form.action, document.baseURI); } catch (_) { return false; }"
            "if (action.href !== record.action || action.protocol !== 'https:' || action.username || action.password) return false;"
            f"{role_check}"
        )
    else:
        target_check += "return false;"
    identity_checks = ""
    if expected_tab_handle:
        identity_checks += (
            f"if (window.__hermesNativeAuthTabHandle !== "
            f"{json.dumps(expected_tab_handle, ensure_ascii=False)}) return false;"
        )
    if expected_frame_handle:
        identity_checks += (
            f"if (window.__hermesNativeAuthFrameHandle !== "
            f"{json.dumps(expected_frame_handle, ensure_ascii=False)}) return false;"
        )
    generation_check = ""
    if expected_document_generation:
        generation_check = (
            f"if (window.__hermesNativeAuthDocumentGeneration !== "
            f"{json.dumps(expected_document_generation, ensure_ascii=False)}) return false;"
        )
    return (
        "(() => {"
        f"if (location.origin !== {json.dumps(expected_origin, ensure_ascii=False)} || "
        f"location.pathname !== {json.dumps(expected_path, ensure_ascii=False)}) return false;"
        f"{identity_checks}{generation_check}"
        f"const nodes = {lookup}; if (nodes.length !== 1) return false;"
        "const element = nodes[0]; if (!(element instanceof Element)) return false;"
        f"{target_check}"
        "const style = getComputedStyle(element); const rect = element.getBoundingClientRect();"
        "if (style.display === 'none' || style.visibility === 'hidden' || rect.width <= 0 || rect.height <= 0) return false;"
        "if (element.disabled === true || element.readOnly === true || element.getAttribute('aria-disabled') === 'true' || element.hasAttribute('inert')) return false;"
        "return true;"
        "})()"
    )


def secure_native_preflight(
    *,
    session: str,
    target: dict[str, Any],
    expected_origin: str,
    expected_path: str,
    expected_tab_handle: str | None = None,
    expected_frame_handle: str | None = None,
    expected_document_generation: str | None = None,
) -> dict[str, Any]:
    """Validate the live Browser Use page without receiving any secret."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        raise NativeAuthSecurityError("secure browser session is invalid")
    target = validate_native_target(target)
    if target["strategy"] not in {"css", "xpath"} or target.get("frame_path"):
        raise NativeAuthSecurityError("secure browser target strategy is unsupported by this adapter")
    expected_origin, expected_path = _validate_expected_page_metadata(expected_origin, expected_path)
    for name, value in (("tab", expected_tab_handle), ("frame", expected_frame_handle), ("document", expected_document_generation)):
        if value is not None and (not isinstance(value, str) or not value or len(value) > 128 or any(ord(ch) < 0x20 for ch in value)):
            raise NativeAuthSecurityError(f"secure browser {name} handle is invalid")

    script = _secure_target_preflight_script(
        target,
        expected_origin=expected_origin,
        expected_path=expected_path,
        expected_tab_handle=expected_tab_handle,
        expected_frame_handle=expected_frame_handle,
        expected_document_generation=expected_document_generation,
    )
    result = _private_cdp_request(
        session,
        "Runtime.evaluate",
        {
            "expression": script,
            "returnByValue": True,
            "awaitPromise": False,
        },
    )
    remote = result.get("result")
    if not isinstance(remote, dict) or remote.get("type") != "boolean" or remote.get("value") is not True:
        raise NativeAuthSecurityError("secure browser target preflight failed")
    return {"state": "validated"}
def _decode_internal_browser_result(result: Any) -> dict[str, Any]:
    from tools.native_auth_runtime import NativeAuthSecurityError

    if isinstance(result, str):
        try:
            result = json.loads(result)
        except (TypeError, ValueError):
            raise NativeAuthSecurityError("secure browser operation returned invalid status") from None
    if not isinstance(result, dict) or result.get("success") is not True:
        raise NativeAuthSecurityError("secure browser operation failed")
    return result


def secure_native_fill(
    *,
    session: str,
    target: dict[str, Any],
    plaintext: str,
    expected_origin: str | None = None,
    expected_path: str | None = None,
    expected_tab_handle: str | None = None,
    expected_frame_handle: str | None = None,
    expected_document_generation: str | None = None,
) -> dict[str, Any]:
    """Fill one browser-issued field through the private harness CDP channel."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        raise NativeAuthSecurityError("secure browser session is invalid")
    target = validate_native_target(target)
    if target["strategy"] not in {"css", "xpath"} or target.get("frame_path"):
        raise NativeAuthSecurityError("secure browser target strategy is unsupported by this adapter")
    if not isinstance(plaintext, str) or len(plaintext) > 4096 or "\x00" in plaintext:
        raise NativeAuthSecurityError("secure browser field value is invalid")
    if expected_origin is None or expected_path is None:
        raise NativeAuthSecurityError("secure browser page binding is incomplete")
    expected_origin, expected_path = _validate_expected_page_metadata(expected_origin, expected_path)
    secure_native_preflight(
        session=session,
        target=target,
        expected_origin=expected_origin,
        expected_path=expected_path,
        expected_tab_handle=expected_tab_handle,
        expected_frame_handle=expected_frame_handle,
        expected_document_generation=expected_document_generation,
    )

    live_script = _secure_target_preflight_script(
        target,
        expected_origin=expected_origin,
        expected_path=expected_path,
        expected_tab_handle=expected_tab_handle,
        expected_frame_handle=expected_frame_handle,
        expected_document_generation=expected_document_generation,
    )
    suffix = "return true;})()"
    if not live_script.endswith(suffix):
        raise NativeAuthSecurityError("secure browser target resolver is invalid")
    resolve_script = live_script[:-len(suffix)] + "return element;})()"
    resolved = _private_cdp_request(
        session,
        "Runtime.evaluate",
        {
            "expression": resolve_script,
            "objectGroup": "hermes-native-auth",
            "returnByValue": False,
            "awaitPromise": False,
        },
    )
    remote = resolved.get("result")
    object_id = remote.get("objectId") if isinstance(remote, dict) else None
    if not isinstance(object_id, str) or not object_id:
        raise NativeAuthSecurityError("secure browser target changed")
    try:
        filled = _private_cdp_request(
            session,
            "Runtime.callFunctionOn",
            {
                "objectId": object_id,
                "functionDeclaration": _NATIVE_FILL_FUNCTION,
                "arguments": [{"value": plaintext}],
                "returnByValue": True,
                "awaitPromise": False,
            },
        )
        fill_result = filled.get("result")
        if not isinstance(fill_result, dict) or fill_result.get("type") != "boolean" or fill_result.get("value") is not True:
            raise NativeAuthSecurityError("secure browser fill failed")
        return {"state": "filled"}
    except NativeAuthSecurityError:
        raise
    except Exception:
        raise NativeAuthSecurityError("secure browser fill failed") from None
    finally:
        try:
            _private_cdp_request(
                session,
                "Runtime.releaseObject",
                {"objectId": object_id},
            )
        except Exception:
            pass


def secure_native_action(
    *,
    session: str,
    target: dict[str, Any] | None,
    expected_origin: str | None = None,
    expected_path: str | None = None,
    expected_tab_handle: str | None = None,
    expected_frame_handle: str | None = None,
    expected_document_generation: str | None = None,
) -> dict[str, Any]:
    """Click a browser-issued action without exposing page state."""
    from tools.native_auth_runtime import NativeAuthSecurityError

    if not isinstance(session, str) or not _SESSION_RE.fullmatch(session):
        raise NativeAuthSecurityError("secure browser session is invalid")
    target = validate_native_target(target or {})
    if target["strategy"] not in {"css", "xpath"} or target.get("frame_path"):
        raise NativeAuthSecurityError("secure browser action strategy is unsupported by this adapter")
    if expected_origin is None or expected_path is None:
        raise NativeAuthSecurityError("secure browser page binding is incomplete")
    expected_origin, expected_path = _validate_expected_page_metadata(expected_origin, expected_path)
    secure_native_preflight(
        session=session,
        target=target,
        expected_origin=expected_origin,
        expected_path=expected_path,
        expected_tab_handle=expected_tab_handle,
        expected_frame_handle=expected_frame_handle,
        expected_document_generation=expected_document_generation,
    )
    script = _secure_target_preflight_script(
        target,
        expected_origin=expected_origin,
        expected_path=expected_path,
        expected_tab_handle=expected_tab_handle,
        expected_frame_handle=expected_frame_handle,
        expected_document_generation=expected_document_generation,
    )
    suffix = "return true;})()"
    if not script.endswith(suffix):
        raise NativeAuthSecurityError("secure browser action preflight is invalid")
    script = script[:-len(suffix)] + "element.click(); return true;})()"
    result = _private_cdp_request(
        session,
        "Runtime.evaluate",
        {"expression": script, "returnByValue": True, "awaitPromise": False},
    )
    remote = result.get("result")
    if not isinstance(remote, dict) or remote.get("type") != "boolean" or remote.get("value") is not True:
        raise NativeAuthSecurityError("secure browser action was not acknowledged")
    return {"state": "submitted"}


def _json_string(value: str) -> str:
    """Return a Python string literal for internally generated browser code."""
    return json.dumps(value, ensure_ascii=False)


_NATIVE_AUTH_CONTEXT_PREFIX = "HERMES_NATIVE_AUTH_CONTEXT:"

# This helper runs inside the Browser Use/Playwright process. It deliberately
# reads labels/roles/attributes only; it never reads input.value, innerText of
# controls, cookies, storage, or page HTML. The generated CSS path is still
# validated again by the parent secure-fill operation before decryption.
_NATIVE_AUTH_PROBE_PREAMBLE = r'''
def _hermes_native_auth_identity():
    """Resolve the current Browser Use page to real CDP target/frame IDs."""
    try:
        from urllib.parse import urlsplit

        current = js("location.origin + location.pathname")
        if not isinstance(current, str) or not current.startswith("https://"):
            return None
        targets = cdp("Target.getTargets")
        infos = targets.get("targetInfos", []) if isinstance(targets, dict) else []
        matches = []
        for info in infos:
            if not isinstance(info, dict) or info.get("type") != "page":
                continue
            parsed = urlsplit(str(info.get("url") or ""))
            candidate = f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}"
            if candidate == current:
                matches.append(info)
        if len(matches) != 1:
            return None
        tree = cdp("Page.getFrameTree")
        root = ((tree or {}).get("frameTree") or {}).get("frame") or {}
        target_id = matches[0].get("targetId")
        frame_id = root.get("id")
        if not isinstance(target_id, str) or not isinstance(frame_id, str):
            return None
        return {
            "tab_handle": target_id,
            "frame_handle": frame_id,
            "browser_context_id": str(matches[0].get("browserContextId") or ""),
        }
    except Exception:
        return None


def _hermes_native_auth_probe():
    import json as _hermes_probe_json
    identity = _hermes_native_auth_identity()
    if not identity:
        return None
    _hermes_probe_script = r"""(() => {
      const clean = (value, limit = 120) => String(value ?? "")
        .replace(/[\u0000-\u001f\u007f]/g, " ")
        .replace(/\s+/g, " ")
        .trim()
        .slice(0, limit);
      const visible = (element) => {
        if (!element || !(element instanceof Element)) return false;
        const style = getComputedStyle(element);
        const rect = element.getBoundingClientRect();
        return style.visibility !== "hidden" && style.display !== "none" &&
          rect.width > 0 && rect.height > 0;
      };
      const escaped = (value) => {
        if (window.CSS && typeof window.CSS.escape === "function") return window.CSS.escape(value);
        return String(value).replace(/[^A-Za-z0-9_-]/g, "\\\\$&");
      };
      const unique = (selector) => {
        try { return document.querySelectorAll(selector).length === 1; }
        catch (_) { return false; }
      };
      const randomHandle = (prefix) => {
        try { return prefix + "_" + crypto.randomUUID().replace(/-/g, ""); }
        catch (_) { return prefix + "_" + Math.random().toString(36).slice(2) + Date.now().toString(36); }
      };
      const documentGeneration = window.__hermesNativeAuthDocumentGeneration || randomHandle("doc");
      const tabHandle = window.__hermesNativeAuthTabHandle || randomHandle("tab");
      const frameHandle = window.__hermesNativeAuthFrameHandle || randomHandle("frame");
      window.__hermesNativeAuthDocumentGeneration = documentGeneration;
      window.__hermesNativeAuthTabHandle = tabHandle;
      window.__hermesNativeAuthFrameHandle = frameHandle;
      const targetRefs = window.__hermesNativeAuthTargetRefs instanceof WeakMap
        ? window.__hermesNativeAuthTargetRefs : new WeakMap();
      const formRefs = window.__hermesNativeAuthFormRefs instanceof WeakMap
        ? window.__hermesNativeAuthFormRefs : new WeakMap();
      window.__hermesNativeAuthTargetRefs = targetRefs;
      window.__hermesNativeAuthFormRefs = formRefs;
      const targetFor = (element) => {
        if (!element || !(element instanceof Element)) return null;
        if (element.id) {
          const selector = "#" + escaped(element.id);
          if (unique(selector)) return selector;
        }
        const tag = element.tagName.toLowerCase();
        for (const attribute of ["name", "autocomplete", "type", "aria-label"]) {
          const raw = element.getAttribute(attribute);
          if (!raw || raw.length > 100) continue;
          const selector = tag + "[" + attribute + "=\\\"" + escaped(raw) + "\\\"]";
          if (unique(selector)) return selector;
        }
        const parts = [];
        let current = element;
        for (let depth = 0; current && current.nodeType === 1 && depth < 8; depth += 1) {
          const currentTag = current.tagName.toLowerCase();
          let ordinal = 1;
          for (let sibling = current.previousElementSibling; sibling; sibling = sibling.previousElementSibling) {
            if (sibling.tagName === current.tagName) ordinal += 1;
          }
          parts.unshift(currentTag + ":nth-of-type(" + ordinal + ")");
          const candidate = parts.join(" > ");
          if (unique(candidate)) return candidate;
          current = current.parentElement;
        }
        return null;
      };
      const targetRefFor = (element, role, formId) => {
        const selector = targetFor(element);
        if (!selector) return null;
        let targetId = targetRefs.get(element);
        if (!targetId) {
          targetId = randomHandle("ref_" + role).replace("ref_" + role + "_", "ref_" + role + "_") + "__" + formId;
          targetRefs.set(element, targetId);
        }
        return {strategy: "css", value: selector, target_id: targetId};
      };
      const humanize = (value) => clean(value)
        .replace(/[_-]+/g, " ")
        .replace(/([a-z])([A-Z])/g, "$1 $2")
        .replace(/\s+/g, " ")
        .trim();
      const labelFor = (element) => {
        const labelledBy = element.getAttribute("aria-labelledby");
        if (labelledBy) {
          const text = labelledBy.split(/\\s+/).map((id) => document.getElementById(id)?.textContent || "").join(" ");
          if (clean(text)) return humanize(text);
        }
        if (element.id) {
          const associated = Array.from(document.querySelectorAll("label"))
            .find((label) => label.getAttribute("for") === element.id);
          if (associated && clean(associated.textContent)) return humanize(associated.textContent);
        }
        const wrapping = element.closest("label");
        if (wrapping && clean(wrapping.textContent)) return humanize(wrapping.textContent);
        return humanize(element.getAttribute("aria-label") || element.getAttribute("placeholder") || element.getAttribute("name") || "");
      };
      const kindFor = (element, label) => {
        const text = (label + " " + (element.getAttribute("autocomplete") || "") + " " + (element.getAttribute("type") || "")).toLowerCase();
        const type = (element.getAttribute("type") || "").toLowerCase();
        if (type === "password" || text.includes("password")) return "password";
        if (text.includes("passcode") || text.includes("pass code")) return "passcode";
        if (text.includes("pin") && !text.includes("opinion")) return "pin";
        if (text.includes("authenticator") || text.includes("totp")) return "totp_code";
        if (text.includes("sms") || text.includes("text message")) return "sms_code";
        if (text.includes("recovery")) return "recovery_code";
        if (text.includes("backup") && text.includes("code")) return "backup_code";
        if (text.includes("security question") || text.includes("security answer")) return "security_answer";
        if (text.includes("date of birth") || text.includes("birth date")) return "date_of_birth";
        if (text.includes("phone") || text.includes("mobile")) return "phone";
        if (text.includes("organization") || text.includes("company")) return "organization";
        if (text.includes("tenant") || text.includes("workspace")) return "tenant";
        if (text.includes("invite") || text.includes("access code")) return "access_code";
        if (text.includes("one-time") || text.includes("one time") || text.includes("otp")) return "one_time_code";
        if (text.includes("verification") || text.includes("verify")) return "verification_code";
        if (text.includes("username") || text.includes("user name")) return "username";
        if (text.includes("email")) return "email";
        if (type === "number") return "numeric";
        return "identifier";
      };
      const unavailable = (element) => element.matches(":disabled") || element.disabled === true ||
        element.readOnly === true || element.getAttribute("aria-disabled") === "true" ||
        Boolean(element.closest('[inert], [aria-disabled="true"]'));
      const fieldTypes = new Set(["text", "password", "email", "tel", "number", "url", "search"]);
      let hasFormFields = false;
      const viableForms = Array.from(document.forms).map((form) => {
        const allControls = Array.from(form.elements).filter((element) => element.form === form);
        const formFields = allControls.filter((element) =>
          element instanceof HTMLTextAreaElement ||
          (element instanceof HTMLInputElement && fieldTypes.has((element.getAttribute("type") || "text").toLowerCase()))
        );
        if (!formFields.length) return null;
        hasFormFields = true;
        if (formFields.length > 32 || formFields.some((element) => !visible(element) || unavailable(element))) return null;
        const labels = formFields.map((element) => labelFor(element).toLowerCase());
        if (labels.some((label) => !label) || new Set(labels).size !== labels.length) return null;
        if (formFields.some((element) => element.id && document.querySelectorAll("#" + escaped(element.id)).length !== 1)) return null;
        const submitCandidates = allControls.filter((element) =>
          (element instanceof HTMLButtonElement || element instanceof HTMLInputElement) &&
          (element.type || "").toLowerCase() === "submit" && element.form === form
        );
        if (submitCandidates.length !== 1 || !visible(submitCandidates[0]) || unavailable(submitCandidates[0])) return null;
        const rawMethod = clean(form.getAttribute("method") || "get").toLowerCase();
        const effectiveMethod = clean(form.method || "").toLowerCase();
        if (rawMethod !== "post" || effectiveMethod !== "post") return null;
        let effectiveAction;
        try { effectiveAction = new URL(form.action, document.baseURI); }
        catch (_) { return null; }
        if (effectiveAction.protocol !== "https:" || effectiveAction.username || effectiveAction.password || effectiveAction.href.length > 2048) return null;
        if (formFields.some((element) => !targetFor(element)) || !targetFor(submitCandidates[0])) return null;
        return {form, formFields, submit: submitCandidates[0], method: effectiveMethod, action: effectiveAction.href};
      }).filter(Boolean);

      let fields = [];
      let actions = [];
      let formRecord = null;
      if (viableForms.length === 1) {
        const candidate = viableForms[0];
        const existing = formRefs.get(candidate.form);
        if (existing && (existing.method !== candidate.method || existing.action !== candidate.action)) return null;
        formRecord = existing || Object.freeze({form_id: randomHandle("form"), method: candidate.method, action: candidate.action});
        formRefs.set(candidate.form, formRecord);
        fields = candidate.formFields.map((element, index) => {
          const target = targetRefFor(element, "f", formRecord.form_id);
          const label = labelFor(element);
          return target ? {
            field_id: "field_" + (index + 1),
            kind: kindFor(element, label),
            label: label,
            required: element.required || element.getAttribute("aria-required") === "true",
            target: target
          } : null;
        }).filter(Boolean);
        const target = targetRefFor(candidate.submit, "a", formRecord.form_id);
        const label = clean(candidate.submit.getAttribute("aria-label") || candidate.submit.getAttribute("title") || candidate.submit.value || candidate.submit.textContent || "Submit") || "Submit";
        if (target) actions = [{action_id: "action_submit", kind: "submit", label: label, target: target}];
      } else if (!hasFormFields) {
        const browserOwnedElements = Array.from(document.querySelectorAll("button, [role=button]"));
        actions = browserOwnedElements.filter((element) => visible(element) && !unavailable(element)).map((element, index) => {
          const label = clean(element.getAttribute("aria-label") || element.getAttribute("title") || element.textContent || "");
          const lower = label.toLowerCase();
          let kind = null;
          if (lower.includes("passkey")) kind = "passkey";
          else if (lower.includes("security key") || lower.includes("hardware key")) kind = "security_key";
          else if (lower.includes("captcha") || lower.includes("verification challenge")) kind = "captcha";
          else if (lower.includes("push") && (lower.includes("approve") || lower.includes("approval"))) kind = "push_approval";
          else if (lower.includes("device") && lower.includes("approv")) kind = "device_approval";
          else if (lower.includes("continue with") || lower.includes("google") || lower.includes("microsoft") || lower.includes("okta") || lower.includes("sso")) kind = "sso_continue";
          else if (lower.includes("magic link")) kind = "email_magic_link";
          else if (lower.includes("phone verification")) kind = "phone_verification";
          return kind ? {action_id: "action_" + (index + 1), kind: kind, label: label} : null;
        }).filter(Boolean).slice(0, 16);
      }
      if (hasFormFields && viableForms.length !== 1) { fields = []; actions = []; formRecord = null; }
      const labels = fields.map((field) => field.label).concat(actions.map((action) => action.label));
      return JSON.stringify({
        origin: location.origin,
        path: location.pathname,
        title: clean(document.title, 160),
        browser_session_id: clean(window.__hermesNativeAuthBrowserContextId || "", 128),
        document_generation: documentGeneration,
        tab_handle: tabHandle,
        frame_handle: frameHandle,
        form: formRecord,
        fields: fields,
        actions: actions,
        signals: clean([document.title, location.pathname].concat(labels).join(" "), 512)
      });
    })()"""
    try:
        _identity_script = (
            "(() => {"
            f"window.__hermesNativeAuthTabHandle = {_hermes_probe_json.dumps(identity['tab_handle'])};"
            f"window.__hermesNativeAuthFrameHandle = {_hermes_probe_json.dumps(identity['frame_handle'])};"
            f"window.__hermesNativeAuthBrowserContextId = {_hermes_probe_json.dumps(identity.get('browser_context_id', ''))};"
            f"return {_hermes_probe_script};"
            "})()"
        )
        raw = js(_identity_script)
        if isinstance(raw, str):
            return _hermes_probe_json.loads(raw)
        return raw if isinstance(raw, dict) else None
    except Exception:
        return None
'''

_NATIVE_AUTH_PROBE_CALL = r'''
try:
    _hermes_probe_identity = _hermes_native_auth_identity()
    if _hermes_probe_identity:
        print("HERMES_NATIVE_AUTH_PROBE_STATUS:ok")
        _hermes_probe_payload = _hermes_native_auth_probe()
        if _hermes_probe_payload:
            print("HERMES_NATIVE_AUTH_CONTEXT:" + json.dumps(_hermes_probe_payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print("HERMES_NATIVE_AUTH_PROBE_STATUS:unavailable")
except Exception:
    print("HERMES_NATIVE_AUTH_PROBE_STATUS:unavailable")
'''


def _extract_native_auth_probe_output(output: str) -> tuple[str, dict[str, Any] | None]:
    """Remove the private probe line from Browser Use stdout."""
    if not isinstance(output, str):
        return "", None
    clean_lines: list[str] = []
    extracted: dict[str, Any] | None = None
    for line in output.splitlines():
        if line.startswith(_NATIVE_AUTH_CONTEXT_PREFIX):
            if extracted is not None:
                return "", None
            try:
                payload = json.loads(line[len(_NATIVE_AUTH_CONTEXT_PREFIX):])
            except (TypeError, ValueError, json.JSONDecodeError):
                return "\n".join(clean_lines).strip(), None
            if not isinstance(payload, dict):
                return "\n".join(clean_lines).strip(), None
            extracted = payload
        else:
            clean_lines.append(line)
    return "\n".join(clean_lines).strip(), extracted


def _is_form_bound_probe_payload(payload: dict[str, Any]) -> bool:
    """Fail closed unless fillable descriptors bind one safe POST form."""
    from urllib.parse import urlsplit

    fields = payload.get("fields")
    actions = payload.get("actions")
    form = payload.get("form")
    if not isinstance(fields, list):
        return False
    if not fields:
        browser_owned_kinds = {
            "passkey", "security_key", "captcha", "push_approval",
            "device_approval", "sso_continue", "email_magic_link",
            "phone_verification",
        }
        return (
            form is None
            and isinstance(actions, list)
            and bool(actions)
            and all(
                isinstance(action, dict)
                and action.get("kind") in browser_owned_kinds
                and action.get("target") is None
                for action in actions
            )
        )
    if not isinstance(form, dict) or set(form) != {"form_id", "method", "action"}:
        return False
    form_id = form.get("form_id")
    if not isinstance(form_id, str) or not re.fullmatch(r"form_[A-Za-z0-9_-]{8,80}", form_id):
        return False
    if form.get("method") != "post":
        return False
    action = form.get("action")
    if not isinstance(action, str) or len(action) > 2048:
        return False
    try:
        parsed_action = urlsplit(action)
    except (TypeError, ValueError):
        return False
    if (
        parsed_action.scheme.lower() != "https"
        or not parsed_action.hostname
        or parsed_action.username is not None
        or parsed_action.password is not None
    ):
        return False
    if not isinstance(actions, list) or len(actions) != 1 or actions[0].get("kind") != "submit":
        return False
    for role, descriptors in (("f", fields), ("a", actions)):
        for descriptor in descriptors:
            if not isinstance(descriptor, dict):
                return False
            target = descriptor.get("target")
            target_id = target.get("target_id") if isinstance(target, dict) else None
            if (
                not isinstance(target_id, str)
                or not target_id.startswith(f"ref_{role}_")
                or not target_id.endswith("__" + form_id)
            ):
                return False
    return True


def _native_auth_context_from_probe(payload: dict[str, Any], *, task_id: str | None, session: str) -> dict[str, Any] | None:
    if not isinstance(payload, dict) or not task_id or not _is_form_bound_probe_payload(payload):
        return None
    from tools.browser_auth_context import detect_auth_context_from_descriptors
    from tools.native_auth_runtime import native_auth_runtime
    browser_session_id = payload.get("browser_session_id") or session or task_id
    if not isinstance(browser_session_id, str) or not browser_session_id:
        return None
    internal = detect_auth_context_from_descriptors(
        runtime=native_auth_runtime,
        task_id=task_id,
        browser_session_key=session or task_id,
        browser_session_id=browser_session_id,
        provider_origin=payload.get("origin", ""),
        path=payload.get("path", "/"),
        title=payload.get("title", ""),
        fields=payload.get("fields") or [],
        actions=payload.get("actions") or [],
        signals=payload.get("signals", ""),
        browser_backend="browser-use",
        browser_session_name=session or "default",
        document_generation=payload.get("document_generation"),
        tab_handle=payload.get("tab_handle"),
        frame_handle=payload.get("frame_handle"),
    )
    if internal is None:
        return None
    return native_auth_runtime.public_auth_context(internal["context_id"])


def _decode_browser_exec_result(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return None
        return decoded if isinstance(decoded, dict) else None
    return None


def _browser_code_requires_interaction(code: str) -> bool:
    """Return true for model code that can mutate/fill the browser page."""
    if not isinstance(code, str):
        return True
    lowered = code.lower()
    return any(
        token in lowered
        for token in (
            "fill_input(",
            "click_at_xy(",
            "keyboard",
            "press(",
            ".click(",
            "cdp(",
            "js(",
            "evaluate(",
        )
    )


def _run_privileged_native_auth_probe(
    *,
    session: str,
    task_id: str | None,
    timeout_s: int,
    local: bool,
) -> tuple[bool, dict[str, Any] | None, dict[str, Any] | None]:
    """Run the fixed auth probe in a separate Browser Use invocation.

    The model's browser Python is never included in this invocation, so stdout
    cannot forge the probe marker or its browser-issued capabilities.
    """
    raw = browser_exec(
        code=_NATIVE_AUTH_PROBE_PREAMBLE + "\n" + _NATIVE_AUTH_PROBE_CALL,
        session=session,
        task_id=task_id,
        local=local,
        timeout_s=min(int(timeout_s or _DEFAULT_TIMEOUT_S), _MAX_TIMEOUT_S),
        _internal_native_auth=True,
        _disable_native_auth_probe=True,
        _privileged_native_auth_probe=True,
    )
    result = _decode_browser_exec_result(raw)
    if result is None:
        return False, None, None
    output = str(result.get("output") or "")
    status = None
    for line in output.splitlines():
        if line.startswith("HERMES_NATIVE_AUTH_PROBE_STATUS:"):
            status = line.rsplit(":", 1)[-1].strip()
            break
    if result.get("success") is not True or status != "ok":
        return False, None, result
    return True, result.get("auth_context") if isinstance(result.get("auth_context"), dict) else None, result


def _browser_phase_split_error(code: str) -> str | None:
    """Reject an ordinary helper flow that acts after navigation.

    This source validation is defense in depth for normal model-generated
    helper programs, not a formal boundary around unrestricted Python.
    """
    try:
        tree = ast.parse(code)
    except (SyntaxError, TypeError, ValueError):
        return "Browser code could not be validated; fix its Python syntax and retry."

    navigation_helpers = {
        "new_tab",
        "goto_url",
        "switch_tab",
        "activate_tab",
        "ensure_real_tab",
        "close_tab",
    }
    browser_helpers = navigation_helpers | {
        "wait_for_load",
        "page_info",
        "js",
        "cdp",
        "fill_input",
        "click_at_xy",
        "capture_screenshot",
        "scroll",
        "type_text",
        "press_key",
        "dispatch_key",
        "upload_file",
    }
    navigation_cdp_methods = {
        "Page.navigate",
        "Page.navigateToHistoryEntry",
        "Page.reload",
        "Target.activateTarget",
        "Target.attachToTarget",
        "Target.closeTarget",
        "Target.createTarget",
    }
    aliases = {name: name for name in browser_helpers}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            for imported in node.names:
                if imported.name in browser_helpers:
                    aliases[imported.asname or imported.name] = imported.name

    assignments = [node for node in ast.walk(tree) if isinstance(node, ast.Assign)]
    for _ in range(len(assignments) + 1):
        changed = False
        for assignment in assignments:
            if not isinstance(assignment.value, ast.Name):
                continue
            canonical = aliases.get(assignment.value.id)
            if canonical is None:
                continue
            for target in assignment.targets:
                if isinstance(target, ast.Name) and aliases.get(target.id) != canonical:
                    aliases[target.id] = canonical
                    changed = True
        if not changed:
            break

    def canonical_call(call: ast.Call) -> str | None:
        if isinstance(call.func, ast.Name):
            return aliases.get(call.func.id)
        if isinstance(call.func, ast.Attribute) and call.func.attr in browser_helpers:
            return call.func.attr
        return None

    def literal_cdp_method(call: ast.Call) -> str | None:
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            return call.args[0].value
        for keyword in call.keywords:
            if (
                keyword.arg == "method"
                and isinstance(keyword.value, ast.Constant)
                and isinstance(keyword.value.value, str)
            ):
                return keyword.value.value
        return None

    calls = sorted(
        (node for node in ast.walk(tree) if isinstance(node, ast.Call)),
        key=lambda node: (getattr(node, "lineno", 0), getattr(node, "col_offset", 0)),
    )
    navigation_seen = False
    for call in calls:
        name = canonical_call(call)
        if navigation_seen and name in browser_helpers:
            return (
                "Navigation/target changes and later browser interactions must use "
                "separate browser_exec calls so Hermes can probe the new page first."
            )
        if name in navigation_helpers or (
            name == "cdp" and literal_cdp_method(call) in navigation_cdp_methods
        ):
            navigation_seen = True
    return None


def browser_exec(
    code: str,
    session: str = "",
    timeout_s: int = _DEFAULT_TIMEOUT_S,
    task_id: Optional[str] = None,
    local: bool = False,
    *,
    _internal_native_auth: bool = False,
    _disable_native_auth_probe: bool = False,
    _privileged_native_auth_probe: bool = False,
):
    """Run Python code through the browser-use CLI, and return its output"""
    from tools.registry import tool_error, tool_result

    if not code or not code.strip():
        return tool_error("No code provided. Pass Python that uses the pre-imported helpers, e.g. new_tab(\"https://example.com\") in one call, then print(page_info()) in the next.")

    requested_session = session
    if session:
        if not _SESSION_RE.fullmatch(session):
            return tool_error(
                f"Invalid session name {session!r}: use 1-64 letters, digits, "
                "dashes, or underscores (e.g. 'r7k2')."
            )
        effective_session = _effective_session_name(session, task_id)
    else:
        effective_session = ""

    if not _internal_native_auth:
        try:
            from tools.native_auth_runtime import native_auth_runtime

            guard = native_auth_runtime.model_code_guard(
                task_id or session or "default",
                code,
            )
            if guard:
                return tool_error(guard)
        except Exception:
            logger.debug("native auth model-code guard failed", exc_info=True)
            return tool_error(
                "Native auth browser guard is unavailable; refusing to execute "
                "browser code until the auth boundary is healthy."
            )

        phase_error = _browser_phase_split_error(code)
        if phase_error:
            return tool_error(phase_error)

    blocked = _blocked_url_in_code(code)
    if blocked:
        return tool_error(blocked)
    model_code = code

    if task_id and not _internal_native_auth and not _disable_native_auth_probe:
        probe_ok, auth_context, probe_result = _run_privileged_native_auth_probe(
            session=session,
            task_id=task_id,
            timeout_s=timeout_s,
            local=local,
        )
        if auth_context is not None:
            return tool_result({
                "success": True,
                "exit_code": 0,
                "output": "",
                "auth_boundary_required": True,
                "auth_context": auth_context,
                "session": session,
            })
        if not probe_ok and _browser_code_requires_interaction(code):
            return tool_error(
                "Native auth browser probe is unavailable; refusing to execute "
                "browser interaction code until the exact active page can be verified."
            )

    cmd = _find_cli()
    if not cmd:
        return tool_error(
            "browser-use CLI not found on PATH, and uvx is unavailable for a "
            "zero-install run. Install it with `uv tool install browser-use` "
            "(or `pipx install browser-use`), then run `browser-use --doctor` "
            "to verify the setup."
        )

    env = _base_subprocess_env()
    if effective_session:
        env["BU_NAME"] = effective_session
    # Real-profile consent: on a local backend this upgrades the attach to
    # the user's default browser (profile snapshot, logins included); with
    # local=True it forces that even under a cloud backend. Runs BEFORE
    # provider resolution so a real-profile hit short-circuits the cloud
    # path via the BU_CDP_* env contract.
    rp_err = _resolve_real_profile_cdp(env, force_local=bool(local))
    if rp_err:
        return tool_error(rp_err)
    if local and not (env.get("BU_CDP_URL") or env.get("BU_CDP_WS")):
        # local=True is only served by the real-profile route; anything else
        # (consent off — schema normally hidden, but be explicit; or an
        # operator CDP override owning the session) must not pretend.
        if not _real_profile_consented():
            return tool_error(
                "local=true was requested but browser.use_real_profile is off. "
                "Enable it in config.yaml (browser.use_real_profile: true) or "
                "the desktop Settings → Browser section, then retry."
            )
    # Route through the configured browser backend (Browserbase, Firecrawl,
    # Nous gateway, CDP override, local Chrome, …). Named sessions compose
    # with the backend: BU_NAME namespaces the harness daemon (its IPC
    # socket, log, and pid), and on provider backends the name additionally
    # keys its own cloud browser — so concurrent sessions stop clobbering
    # each other's daemon (#86894). Browser Use direct-API cloud configs
    # are the one exception: the CLI manages named cloud browsers natively,
    # and _resolve_backend_cdp skips provider resolution for them.
    backend_err = _resolve_backend_cdp(env, task_id, session_name=effective_session)
    if backend_err:
        return tool_error(backend_err)

    # On a SHARED browser (local Chrome / CDP override) a fresh named daemon
    # attaches to the first existing page — the same page a sibling daemon
    # may hold. Pin each named session to a tab it created before running
    # the model's code. Private per-name browsers (provider-keyed or BU
    # cloud) skip this: no one to collide with, and the extra tab would leak.
    private_browser = env.pop(_PRIVATE_BROWSER_SENTINEL, None)
    if effective_session and not private_browser:
        code = _OWN_TAB_PREAMBLE + code

    workspace = _workspace_dir(task_id)
    if workspace:
        env["BH_AGENT_WORKSPACE"] = workspace

    # BU_AUTOSPAWN makes the CLI start a Browser Use cloud browser when no
    # local Chrome/CDP endpoint is reachable (their API key authenticates it)
    if "BU_AUTOSPAWN" not in env and is_legacy_browser_use_cloud_config(_read_browser_cfg()):
        env["BU_AUTOSPAWN"] = "1"

    try:
        timeout = max(_MIN_TIMEOUT_S, min(int(timeout_s), _MAX_TIMEOUT_S))
    except (TypeError, ValueError):
        timeout = _DEFAULT_TIMEOUT_S

    # Windows: hide the console the .cmd shim would flash (as browser_tool does)
    popen_extra: dict = {}
    if os.name == "nt":
        try:
            from hermes_cli._subprocess_compat import windows_hide_flags

            popen_extra["creationflags"] = windows_hide_flags()
            _si = subprocess.STARTUPINFO()
            _si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            popen_extra["startupinfo"] = _si
        except Exception as e:
            logger.debug("Windows hide-flags unavailable: %s", e)

    started = time.time()
    global _ORPHAN_REAPED
    if not _ORPHAN_REAPED:
        with _OWNED_DAEMONS_LOCK:
            should_reap = not _ORPHAN_REAPED
            _ORPHAN_REAPED = True
        if should_reap:
            reap_owned_browser_use_orphans()
    try:
        proc = subprocess.run(
            cmd,
            input=code,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            **popen_extra,
        )
    except subprocess.TimeoutExpired:
        return tool_error(
            f"browser-use exec timed out after {timeout}s. The daemon may "
            "still be working; retry with a larger timeout_s (max "
            f"{_MAX_TIMEOUT_S}), or split the work into several calls that "
            "append to workspace files — anything already written to the "
            "workspace is preserved."
        )
    except OSError as e:
        return tool_error(f"Failed to launch browser-use CLI: {e}")

    result = {
        "success": proc.returncode == 0,
        "exit_code": proc.returncode,
        "output": proc.stdout,
    }
    if proc.returncode == 0 and effective_session:
        _register_owned_daemon(effective_session, task_id)
    if task_id or session:
        clean_output, probe_payload = _extract_native_auth_probe_output(proc.stdout or "")
        result["output"] = clean_output
        if _privileged_native_auth_probe and probe_payload is not None:
            auth_context = _native_auth_context_from_probe(
                probe_payload,
                task_id=task_id,
                session=effective_session or "default",
            )
            if auth_context is not None:
                try:
                    from tools.native_auth_runtime import native_auth_runtime

                    native_auth_runtime.notify_component(
                        auth_context["context_id"],
                        task_id=str(task_id or ""),
                    )
                except Exception:
                    logger.debug("native auth component callback failed", exc_info=True)
                result["auth_context"] = auth_context
        if task_id and not _internal_native_auth and not _disable_native_auth_probe:
            post_probe_ok, post_auth_context, _post_probe_result = _run_privileged_native_auth_probe(
                session=session,
                task_id=task_id,
                timeout_s=timeout_s,
                local=local,
            )
            if post_auth_context is not None:
                return tool_result({
                    "success": True,
                    "exit_code": 0,
                    "output": "",
                    "auth_boundary_required": True,
                    "auth_context": post_auth_context,
                    "session": session,
                })
            if not post_probe_ok and _browser_code_requires_interaction(model_code):
                return tool_error(
                    "Native auth browser post-probe is unavailable; withholding "
                    "the browser interaction result until the active page can be verified."
                )
    if workspace:
        result["workspace"] = workspace
    if requested_session:
        result["session"] = requested_session
    stderr = (proc.stderr or "").strip()
    if stderr:
        if len(stderr) > _STDERR_CAP_CHARS:
            stderr = stderr[:_STDERR_CAP_CHARS] + "\n… (stderr truncated)"
        result["stderr"] = stderr

    screenshot = _find_screenshot(proc.stdout, started)
    if screenshot:
        result["screenshot_path"] = screenshot
        native = _native_screenshot_result(result, screenshot)
        if native is not None:
            return native
    return tool_result(result)


# The tool description is the CLI's skill, fetched from browser-use skill
_HEADER_BASE = (
    "Drive a real web browser via the Browser Use CLI: `code` runs as full "
    "Python (stdlib available) with pre-imported browser helpers; stdout "
    "comes back in the result. Start `code` with a one-line comment "
    "describing the step for the user in plain language, max 60 chars "
    "(e.g. `# Searching Amazon for paper towels`) — the UI shows it as the "
    "step label.\n\n"
    "STATE: the browser session and workspace persist across calls; Python "
    "variables do NOT (fresh interpreter each call). The workspace dir is "
    "$BH_AGENT_WORKSPACE (also `workspace` in every result); functions "
    "defined in agent_helpers.py there are auto-imported into every call. "
    "For multi-item tasks ('all N products / every entry'), append each "
    "batch to a JSON/CSV file in the workspace, then read it back and "
    "aggregate in code — dedupe/count/sort with Python, not in your head — "
    "and verify the collected count against what was asked before "
    "answering.\n\n"
    "Navigation/target changes and actions must use separate calls. End a "
    "call immediately after navigation or target switching; Hermes performs "
    "a trusted auth probe before the next browser call. Within a non-navigation "
    "phase, batch related actions, and for long extractions prefer "
    "several medium calls that append to workspace files over one giant "
    "call, so progress survives timeouts."
)

_HEADER_VISION = (
    " Screenshots are attached to your context automatically: when the exec "
    "output contains a capture_screenshot() path, the image arrives with "
    "this tool's result and you inspect it directly with your own vision — "
    "never send browser screenshots to a separate vision tool."
)

_HEADER_TEXT_ONLY = (
    " Your model cannot view images, so work text-first: page_info() for "
    "state, js() for reading/extracting DOM text, fill_input(selector, "
    "text) for inputs, and js(\"document.querySelector('…').click()\") for "
    "clicks — skip the screenshot-driven workflow described below."
)

_DESCRIPTION_HEADER = _HEADER_BASE  # back-compat alias for external imports

# NOTE: browser_exec is additionally gated at tool-definition time — sessions
# whose resolved toolsets do not include ``terminal`` never see it (see
# model_tools._compute_tool_definitions). The check_fn registered below only
# answers "is Browser Use mode configured"; surface policy lives with the
# session, not in the process-wide TTL-cached check_fn.


def _description_header() -> str:
    """Header tailored to whether the active model can see images natively"""
    try:
        from tools.vision_tools import _should_use_native_vision_fast_path

        if _should_use_native_vision_fast_path():
            return _HEADER_BASE + _HEADER_VISION
    except Exception:
        pass
    return _HEADER_BASE + _HEADER_TEXT_ONLY

_skill_text_cache: Optional[str] = None
_skill_text_fetched = False

# Pinned quick-reference for the CLI's pre-imported helpers. Replaces the
# live ``browser-use skill`` fetch: embedding whatever text the installed CLI
# version prints would ship uncontrolled third-party content into every
# session's system-side schema (version drift across machines, supply-chain
# exposure, and a byte-unstable prompt). A/B benchmarked Aug 2026 (108 runs,
# opus-4.8 + kimi-k3, 6 multi-step tasks x 3 reps): header-only schema went
# 36/36 vs 36/36 for the full skill dump at ~equal tokens (-60% vs the
# legacy browser_* toolset either way). The pinned digest below keeps the
# first-call reliability of the helper names without the 7.7KB dump.
_HELPERS_DIGEST = (
    "\n\nHELPERS (pre-imported): new_tab(url) opens/navigates (use for the "
    "FIRST navigation), goto_url(url) navigates the current tab, "
    "wait_for_load() runs in the next call after navigation, page_info() "
    "summarizes the current "
    "page state, js(expr) evaluates a JS expression and returns its value "
    "(js('document.title'); wrap function bodies as js('(() => {...})()') — "
    "a bare '() => {...}' returns the function itself, uncalled), "
    "fill_input(selector, text) types into inputs, click_at_xy(x, y) clicks "
    "viewport coordinates, capture_screenshot() saves and prints a "
    "screenshot path, cdp('Domain.method', **kwargs) is raw CDP — "
    "cdp('Accessibility.getFullAXTree')['nodes'] lists every element's "
    "role/name/backendDOMNodeId (filter in Python before printing; it is "
    "thousands of nodes), then cdp('DOM.getBoxModel', backendNodeId=n) gives "
    "click coordinates. ensure_real_tab() recovers from a stale/internal "
    "tab. If an auth wall appears, stop using fill_input, js, or keyboard "
    "actions for credentials. The browser result may include an `auth_context` "
    "with opaque component IDs. Emit exactly one bounded "
    "`<semreh.native-component>` metadata marker using the context ID "
    "(presentation text only; do not invent selectors, URLs, HTML, JavaScript, "
    "or values), then wait for the native component state before continuing. "
    "Never guess, request, or transmit credentials, OTPs, cookies, tokens, or "
    "form values."
)


def _cli_skill_text() -> str:
    """Deprecated: always returns "" — the schema uses the pinned header.

    Kept so tests and any external callers keep importing a stable symbol;
    see _HELPERS_DIGEST for the rationale (benchmark-backed removal of the
    live ``browser-use skill`` fetch).
    """
    return _skill_text_cache or ""


def _dynamic_schema_overrides() -> dict:
    overrides: dict = {"description": _description_header() + _HELPERS_DIGEST}
    # The ``local`` argument exists ONLY when the user consented to
    # real-profile browsing — everyone else's schema carries zero extra
    # surface. get_definitions() applies this at schema-build time, and the
    # caller memoizes on config.yaml mtime, so toggling consent changes the
    # schema on the next session rather than mid-conversation.
    if _real_profile_consented():
        props = dict(BROWSER_EXEC_SCHEMA["parameters"]["properties"])
        props["local"] = {
            "type": "boolean",
            "description": (
                "Drive the user's own local browser (a Hermes-managed copy of "
                "their real default-Chromium profile, logins/cookies included) "
                "instead of the configured cloud browser backend. Use when the "
                "user asks to act as themselves — their accounts, their "
                "sessions. No-op when the backend is already local. Default "
                "false."
            ),
            "default": False,
        }
        overrides["parameters"] = {**BROWSER_EXEC_SCHEMA["parameters"], "properties": props}
    return overrides


BROWSER_EXEC_SCHEMA = {
    "name": "browser_exec",
    # Static fallback, used only when the CLI (and uvx) is unavailable
    "description": (
        _HEADER_BASE
        + _HELPERS_DIGEST
        + "\n\n(The browser-use CLI is not installed yet. Install it with "
        "`uv tool install browser-use`.)"
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "code": {
                "type": "string",
                "description": "Python code to execute using the pre-imported browser helpers. Use print(...) for any data you need back.",
            },
            "session": {
                "type": "string",
                "description": "Named isolated browser session — its own daemon and (on cloud backends) own browser, so concurrent tasks don't share tabs. Reuse the same name on every related call; omit for the shared default session.",
            },
            "timeout_s": {
                "type": "integer",
                "description": f"Max seconds to wait for the code to finish (default {_DEFAULT_TIMEOUT_S}, max {_MAX_TIMEOUT_S}).",
                "default": _DEFAULT_TIMEOUT_S,
            },
        },
        "required": ["code"],
    },
}


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------
from tools.registry import registry

registry.register(
    name="browser_exec",
    toolset="browser-use",
    schema=BROWSER_EXEC_SCHEMA,
    handler=lambda args, **kw: browser_exec(
        code=args.get("code", ""),
        session=args.get("session", "") or "",
        timeout_s=args.get("timeout_s", _DEFAULT_TIMEOUT_S),
        task_id=kw.get("task_id"),
        local=bool(args.get("local", False)),
    ),
    check_fn=is_browser_use_cli_mode,
    dynamic_schema_overrides=_dynamic_schema_overrides,
    emoji="🌐",
)

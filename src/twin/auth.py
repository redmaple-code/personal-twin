"""Master-password handling, unlock sessions and opt-in autounlock.

Two rules drive this module:

1. A secret never arrives through ``argv``. It comes from a TTY prompt, from
   stdin, or from a locally protected store.
2. There is no silent fallback. If no password source is available, the command
   fails with an explanation instead of reading an environment variable that
   was never opted into.
"""

from __future__ import annotations

import base64
import getpass
import io
import json
import os
import sys
import time
from pathlib import Path

from .errors import AuthError, PolicyError, UnsupportedError
from .vault import secure_path

_IS_WINDOWS = os.name == "nt"


# --------------------------------------------------------------------------
# DPAPI (Windows only): protects a blob with the current user's logon secret.
# --------------------------------------------------------------------------
def dpapi_available() -> bool:
    return _IS_WINDOWS


def _dpapi(data: bytes, protect: bool) -> bytes:
    if not _IS_WINDOWS:
        raise UnsupportedError(
            "DPAPI is Windows-only; unlock sessions and autounlock are disabled "
            "on this platform"
        )
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data)
    blob_in = DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    fn = ctypes.windll.crypt32.CryptProtectData if protect else ctypes.windll.crypt32.CryptUnprotectData
    ok = fn(
        ctypes.byref(blob_in),
        "personal-twin" if protect else None,
        None,
        None,
        None,
        0,
        ctypes.byref(blob_out),
    )
    if not ok:
        raise UnsupportedError("DPAPI call failed")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


# --------------------------------------------------------------------------
# Password sources
# --------------------------------------------------------------------------
def read_password_from_stdin() -> str | None:
    line = sys.stdin.readline()
    return line.rstrip("\r\n") if line else None


def prompt_password(confirm: bool = False) -> str | None:
    if not (sys.stdin.isatty() and sys.stderr.isatty()):
        return None
    pw = getpass.getpass("Master password: ")
    if not pw:
        return None
    if confirm:
        again = getpass.getpass("Repeat master password: ")
        if again != pw:
            raise AuthError("passwords did not match")
    return pw


def _decode_session(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if int(data.get("exp", 0)) <= time.time():
            path.unlink(missing_ok=True)
            return None
        return _dpapi(base64.b64decode(data["blob"]), protect=False).decode("utf-8")
    except Exception:
        # A corrupt or foreign session file is simply ignored; it must never
        # become an error path that leaks file contents into a traceback.
        return None


def _decode_autounlock(path: Path) -> str | None:
    if not path.exists():
        return None
    try:
        return _dpapi(path.read_bytes(), protect=False).decode("utf-8")
    except Exception:
        return None


def acquire(
    *,
    vault_path: Path,
    session_file: Path,
    autounlock_file: Path,
    pw_stdin: bool = False,
    allow_session: bool = True,
    allow_autounlock: bool = True,
    allow_env: bool = False,
    interactive: bool = True,
    confirm: bool = False,
) -> str:
    """Resolve a master password using the documented precedence order."""
    if pw_stdin:
        pw = read_password_from_stdin()
        if not pw:
            raise AuthError("no password on stdin")
        return pw

    if allow_session:
        pw = _decode_session(session_file)
        if pw:
            return pw

    if allow_autounlock:
        pw = _decode_autounlock(autounlock_file)
        if pw:
            return pw

    if allow_env:
        env_pw = os.environ.get("TWIN_PASSWORD")
        if env_pw:
            return env_pw

    if interactive:
        pw = prompt_password(confirm=confirm)
        if pw:
            return pw

    raise AuthError(
        "no master password source available: run in a terminal, pipe it with "
        "`--pw-stdin`, or enable `twin autounlock on`"
    )


def verify(vault_path: Path, password: str) -> None:
    from pykeepass import PyKeePass
    from pykeepass.exceptions import CredentialsError

    try:
        PyKeePass(str(vault_path), password=password)
    except CredentialsError as exc:
        raise AuthError("master password is wrong") from exc
    except Exception as exc:
        raise AuthError(f"cannot open vault: {type(exc).__name__}") from exc


# --------------------------------------------------------------------------
# Session lifecycle
# --------------------------------------------------------------------------
def create_session(session_file: Path, password: str, ttl: int) -> None:
    if not dpapi_available():
        raise UnsupportedError(
            "unlock sessions need DPAPI (Windows). On other platforms the "
            "password is requested for each command."
        )
    blob = _dpapi(password.encode("utf-8"), protect=True)
    session_file.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "v": 1,
        "exp": time.time() + max(1, ttl),
        "blob": base64.b64encode(blob).decode("ascii"),
    }
    fd = os.open(session_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with io.open(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    secure_path(session_file)


def clear_session(session_file: Path) -> bool:
    if session_file.exists():
        session_file.unlink()
        return True
    return False


def session_active(session_file: Path) -> bool:
    return _decode_session(session_file) is not None


# --------------------------------------------------------------------------
# Autounlock
# --------------------------------------------------------------------------
def autounlock_enable(autounlock_file: Path, password: str) -> None:
    if not dpapi_available():
        raise UnsupportedError("autounlock needs DPAPI (Windows)")
    blob = _dpapi(password.encode("utf-8"), protect=True)
    autounlock_file.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(autounlock_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with io.open(fd, "wb") as f:
        f.write(blob)
    secure_path(autounlock_file)


def autounlock_disable(autounlock_file: Path) -> bool:
    if autounlock_file.exists():
        autounlock_file.unlink()
        return True
    return False


def autounlock_status(autounlock_file: Path) -> bool:
    return _decode_autounlock(autounlock_file) is not None


def autounlock_password(autounlock_file: Path) -> str | None:
    """Password held by autounlock, if enabled. Used by the local form."""
    return _decode_autounlock(autounlock_file)


# --------------------------------------------------------------------------
# Reveal gate
# --------------------------------------------------------------------------
class RevealGate:
    """Policy gate for printing a secret value.

    This is a speed bump, not a sandbox: an agent that controls a real PTY and
    the config file can pass it. The enforceable controls are OS-level (separate
    account/file ACLs) — see SECURITY.md.
    """

    def __init__(self, *, allow_reveal: bool, block_agents: bool, agent_env: str = "TWIN_AGENT"):
        self.allow_reveal = allow_reveal
        self.block_agents = block_agents
        self.agent_env = agent_env

    def check(self, *, stdin_tty: bool | None = None, stdout_tty: bool | None = None) -> None:
        stdin_tty = sys.stdin.isatty() if stdin_tty is None else stdin_tty
        stdout_tty = sys.stdout.isatty() if stdout_tty is None else stdout_tty

        if not self.allow_reveal:
            raise PolicyError(
                "revealing secrets is disabled (set [security] allow_reveal = true "
                "in the policy file to enable it for interactive use)"
            )
        if self.block_agents and os.environ.get(self.agent_env):
            raise PolicyError(
                f"reveal is blocked because {self.agent_env} is set; "
                "unset it in a human terminal to proceed"
            )
        if not (stdin_tty and stdout_tty):
            raise PolicyError(
                "reveal requires an interactive terminal on both stdin and stdout "
                "(it is not available to scripts, pipelines or agents)"
            )

    def confirm(self, label: str) -> None:
        answer = input(f"Type REVEAL to print {label}: ").strip()
        if answer != "REVEAL":
            raise PolicyError("reveal cancelled")

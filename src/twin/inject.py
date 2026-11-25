"""Secret injection into a child process.

The value is handed over out-of-band — stdin by default, an environment
variable only when the caller asks for it — and never printed by this process.

stdin is the default because on most systems a process environment is readable
by other processes running as the same user (``/proc/<pid>/environ`` on Linux,
process explorers on Windows), and it is captured by crash reports.
"""

from __future__ import annotations

import os
import subprocess

from .errors import PolicyError

# Keep the child's environment small so an unrelated parent variable cannot
# smuggle data into the tools we spawn.
_MINIMAL_KEYS = (
    "PATH",
    "PATHEXT",
    "SYSTEMROOT",
    "SystemRoot",
    "WINDIR",
    "COMSPEC",
    "TEMP",
    "TMP",
    "TMPDIR",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SHELL",
)


def minimal_env() -> dict[str, str]:
    return {k: os.environ[k] for k in _MINIMAL_KEYS if k in os.environ}


def run(
    cmd: list[str],
    value: str,
    *,
    env_name: str | None = None,
    inherit_env: bool = False,
    allow_env: bool = True,
) -> int:
    """Run ``cmd`` with ``value`` delivered via stdin or ``env_name``."""
    if not cmd:
        raise PolicyError("inject needs a command after `--`")

    if env_name:
        if not allow_env:
            raise PolicyError(
                "environment injection is disabled by policy; drop --env to use stdin"
            )
        env = dict(os.environ) if inherit_env else minimal_env()
        env[env_name] = value
        completed = subprocess.run(cmd, env=env)
        return completed.returncode

    completed = subprocess.run(cmd, input=value.encode("utf-8"))
    return completed.returncode

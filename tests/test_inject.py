import os
import sys

import pytest

from twin import inject
from twin.errors import PolicyError


def _read_stdin_expect(value: str) -> list[str]:
    return [sys.executable, "-c", "import sys; sys.exit(0 if sys.stdin.read() == %r else 3)" % value]


def test_stdin_is_the_default_channel():
    assert inject.run(_read_stdin_expect("s3cr3t"), "s3cr3t") == 0


def test_stdin_mismatch_propagates_exit_code():
    assert inject.run(_read_stdin_expect("expected"), "other") == 3


def test_env_channel(tmp_path):
    out = tmp_path / "out.txt"
    cmd = [
        sys.executable,
        "-c",
        "import os, pathlib, sys; pathlib.Path(sys.argv[1]).write_text(os.environ['TWIN_TEST'])",
        str(out),
    ]
    assert inject.run(cmd, "from-env", env_name="TWIN_TEST") == 0
    assert out.read_text() == "from-env"


def test_env_channel_can_be_disabled():
    with pytest.raises(PolicyError):
        inject.run([sys.executable, "-c", "pass"], "v", env_name="TWIN_TEST", allow_env=False)


def test_minimal_env_does_not_leak_parent_variables(tmp_path, monkeypatch):
    monkeypatch.setenv("TWIN_PARENT_ONLY", "should-not-appear")
    out = tmp_path / "env.txt"
    cmd = [
        sys.executable,
        "-c",
        "import os, pathlib, sys; pathlib.Path(sys.argv[1]).write_text(os.environ.get('TWIN_PARENT_ONLY', 'absent'))",
        str(out),
    ]
    inject.run(cmd, "v", env_name="TWIN_TEST")
    assert out.read_text() == "absent"


def test_inject_requires_a_command():
    with pytest.raises(PolicyError):
        inject.run([], "v")

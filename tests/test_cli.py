import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

MASTER = "cli-master-pw"
SECRET = "s3cr3t-cli-value"


def _env(tmp_path, **extra):
    env = dict(os.environ)
    for key in ("TWIN_VAULT", "TWIN_BACKUP_DIR", "TWIN_PASSWORD", "TWIN_AGENT"):
        env.pop(key, None)
    env.update({
        "TWIN_HOME": str(tmp_path / "data"),
        "TWIN_CONFIG": str(tmp_path / "policy.toml"),
        "PYTHONIOENCODING": "utf-8",
    })
    env.update(extra)
    return env


def run_cli(tmp_path, args, *, stdin="", env_extra=None):
    return subprocess.run(
        [sys.executable, "-m", "twin", *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        env=_env(tmp_path, **(env_extra or {})),
        timeout=120,
    )


@pytest.fixture()
def ready(tmp_path):
    r = run_cli(tmp_path, ["init"], stdin=MASTER + "\n")
    assert r.returncode == 0, r.stderr
    r = run_cli(
        tmp_path,
        ["--pw-stdin", "add", "work-mail", "--type", "person",
         "--field", "username=alice@example.com", "--field", "phone=13800138000",
         "--secret-field", "api_key"],
        stdin=MASTER + "\n" + SECRET + "\n",
    )
    assert r.returncode == 0, r.stderr
    return tmp_path


def test_init_and_list_are_masked(ready):
    r = run_cli(ready, ["--pw-stdin", "list"], stdin=MASTER + "\n")
    assert r.returncode == 0, r.stderr
    assert "alice@example.com" not in r.stdout
    assert "13800138000" not in r.stdout
    assert "a***@example.com" in r.stdout
    assert SECRET not in r.stdout


def test_show_is_masked(ready):
    r = run_cli(ready, ["--pw-stdin", "show", "work-mail"], stdin=MASTER + "\n")
    assert r.returncode == 0, r.stderr
    assert SECRET not in r.stdout
    assert "[hidden]" in r.stdout
    assert "1**" != "" and "138" in r.stdout


def test_export_json_never_contains_secrets(ready):
    r = run_cli(ready, ["--pw-stdin", "export", "--format", "json"], stdin=MASTER + "\n")
    assert r.returncode == 0, r.stderr
    data = json.loads(r.stdout)
    blob = json.dumps(data)
    assert SECRET not in blob
    assert "alice@example.com" not in blob
    assert data[0]["fields"]["api_key"]["value"] == "[hidden]"


def test_reveal_is_blocked_by_default(ready):
    r = run_cli(ready, ["--pw-stdin", "reveal", "work-mail", "--field", "api_key"], stdin=MASTER + "\n")
    assert r.returncode == 7
    assert SECRET not in r.stdout
    assert "disabled" in r.stderr


def test_reveal_is_blocked_without_tty_even_when_enabled(ready):
    (ready / "policy.toml").write_text("[security]\nallow_reveal = true\n", encoding="utf-8")
    r = run_cli(ready, ["--pw-stdin", "reveal", "work-mail", "--field", "api_key"], stdin=MASTER + "\n")
    assert r.returncode == 7
    assert SECRET not in r.stdout
    assert "interactive terminal" in r.stderr


def test_reveal_is_blocked_for_agents(ready):
    (ready / "policy.toml").write_text("[security]\nallow_reveal = true\n", encoding="utf-8")
    r = run_cli(
        ready,
        ["--pw-stdin", "reveal", "work-mail", "--field", "api_key"],
        stdin=MASTER + "\n",
        env_extra={"TWIN_AGENT": "1"},
    )
    assert r.returncode == 7
    assert SECRET not in r.stdout


def test_inject_hands_value_to_child_without_printing(ready):
    r = run_cli(
        ready,
        ["--pw-stdin", "inject", "work-mail", "--field", "api_key", "--",
         sys.executable, "-c", "import sys;sys.exit(0 if sys.stdin.read()=='" + SECRET + "' else 9)"],
        stdin=MASTER + "\n",
    )
    assert r.returncode == 0, r.stdout + r.stderr
    assert SECRET not in r.stdout


def test_doctor_reports_posture(ready):
    r = run_cli(ready, ["doctor"])
    assert r.returncode == 0, r.stdout + r.stderr
    assert "reveal allowed" in r.stdout
    assert "False" in r.stdout


def test_unknown_record_exits_nonzero(ready):
    r = run_cli(ready, ["--pw-stdin", "show", "does-not-exist"], stdin=MASTER + "\n")
    assert r.returncode == 5


def test_secret_values_are_rejected_on_argv(ready):
    r = run_cli(ready, ["--pw-stdin", "add", "sneaky", "--field", "password=hunter2"],
                stdin=MASTER + "\n")
    assert r.returncode == 1
    assert "hunter2" not in r.stdout
    assert "hunter2" not in r.stderr
    assert "--secret-field" in r.stderr


def test_explicit_secret_sensitivity_is_rejected_on_argv(ready):
    r = run_cli(ready, ["--pw-stdin", "add", "sneaky", "--field", "note=hunter2:secret"],
                stdin=MASTER + "\n")
    assert r.returncode == 1
    assert "hunter2" not in r.stdout
    assert "hunter2" not in r.stderr

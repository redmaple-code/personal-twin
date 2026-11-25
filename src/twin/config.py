"""Configuration and path resolution.

Nothing in this module points at a machine-specific location. Defaults live
under the current user's profile so a fresh install works without editing a
file, and every path can be overridden by config, CLI flag or environment
variable.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError

APP_NAME = "twin"


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def default_config_path() -> Path:
    override = os.environ.get("TWIN_CONFIG")
    if override:
        return Path(os.path.expanduser(override))
    if os.name == "nt":
        base = os.environ.get("APPDATA") or str(_home() / "AppData" / "Roaming")
        return Path(base) / APP_NAME / "policy.toml"
    base = os.environ.get("XDG_CONFIG_HOME") or str(_home() / ".config")
    return Path(base) / APP_NAME / "policy.toml"


def default_data_dir() -> Path:
    override = os.environ.get("TWIN_HOME")
    if override:
        return Path(os.path.expanduser(override))
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or str(_home() / "AppData" / "Local")
        return Path(base) / APP_NAME
    base = os.environ.get("XDG_DATA_HOME") or str(_home() / ".local" / "share")
    return Path(base) / APP_NAME


def _expand(value: object, base: Path) -> Path:
    p = Path(os.path.expanduser(str(value)))
    if not p.is_absolute():
        p = base / p
    return p


@dataclass
class SecurityConfig:
    # Never print a secret value unless this is true.
    allow_reveal: bool = False
    # Seconds an unlock session stays valid.
    session_ttl: int = 900
    # Allow passing the master password via TWIN_PASSWORD. Off by default:
    # process environments leak on many platforms.
    allow_env_password: bool = False
    # Allow injecting a secret into a child process environment.
    allow_env_inject: bool = True
    # When true, refuse every secret-revealing action if TWIN_AGENT is set.
    block_agents: bool = True
    # Minimum seconds between failed form master-password attempts is enforced
    # by the form itself; this caps total attempts before shutdown.
    form_max_attempts: int = 5


@dataclass
class AuditConfig:
    roots: list[str] = field(default_factory=list)
    detectors: str = ""
    report: str = ""
    max_file_bytes: int = 5 << 20


@dataclass
class Config:
    path: Path
    data_dir: Path
    vault: Path
    backup_dir: Path
    security: SecurityConfig
    audit: AuditConfig

    def session_file(self) -> Path:
        return self.data_dir / "session.json"

    def autounlock_file(self) -> Path:
        return self.data_dir / "autounlock.bin"


def load(path: Path | None = None, vault: Path | None = None) -> Config:
    cfg_path = path or default_config_path()
    data = {}
    if cfg_path.exists():
        try:
            data = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            raise ConfigError(f"cannot read config {cfg_path}: {exc}") from exc

    data_dir = default_data_dir()
    base = data_dir

    vault_cfg = data.get("vault", {})
    vault_path = vault or _expand(
        os.environ.get("TWIN_VAULT", vault_cfg.get("path", "secrets.kdbx")), base
    )

    backup_cfg = data.get("backup", {})
    backup_dir = _expand(os.environ.get("TWIN_BACKUP_DIR", backup_cfg.get("dir", "backups")), data_dir)

    sec_raw = data.get("security", {})
    security = SecurityConfig(
        allow_reveal=bool(sec_raw.get("allow_reveal", False)),
        session_ttl=int(sec_raw.get("session_ttl", 900)),
        allow_env_password=bool(sec_raw.get("allow_env_password", False)),
        allow_env_inject=bool(sec_raw.get("allow_env_inject", True)),
        block_agents=bool(sec_raw.get("block_agents", True)),
        form_max_attempts=int(sec_raw.get("form_max_attempts", 5)),
    )

    audit_raw = data.get("audit", {})
    audit = AuditConfig(
        roots=[str(r) for r in audit_raw.get("roots", [])],
        detectors=str(audit_raw.get("detectors", "")),
        report=str(audit_raw.get("report", "")),
        max_file_bytes=int(audit_raw.get("max_file_bytes", 5 << 20)),
    )

    return Config(
        path=cfg_path,
        data_dir=data_dir,
        vault=vault_path,
        backup_dir=backup_dir,
        security=security,
        audit=audit,
    )

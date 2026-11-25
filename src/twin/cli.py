"""Command-line interface.

Safety model, in one sentence: every command except ``reveal`` is safe to run
from an AI session, because they either print masked data or hand a secret to
another process without printing it.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import auth, backup, config as config_mod, inject, leakscan, masking, model
from .errors import TwinError
from .forms import FormField, FormSession
from .vault import Vault, secure_dir, secure_path

DEFAULT_GROUP = "Default"


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------
def _out(text: str = "") -> None:
    print(text, flush=True)


def _json_out(payload) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2), flush=True)


def _cfg(args) -> config_mod.Config:
    cfg_path = Path(args.config) if getattr(args, "config", None) else None
    vault = Path(args.vault) if getattr(args, "vault", None) else None
    return config_mod.load(cfg_path, vault)


def _password(
    cfg: config_mod.Config,
    args,
    *,
    allow_session: bool = True,
    allow_autounlock: bool = True,
    interactive: bool = True,
    confirm: bool = False,
) -> str:
    return auth.acquire(
        vault_path=cfg.vault,
        session_file=cfg.session_file(),
        autounlock_file=cfg.autounlock_file(),
        pw_stdin=bool(getattr(args, "pw_stdin", False)),
        allow_session=allow_session,
        allow_autounlock=allow_autounlock,
        allow_env=cfg.security.allow_env_password,
        interactive=interactive,
        confirm=confirm,
    )


def _open(cfg: config_mod.Config, args, **kwargs) -> Vault:
    return Vault.open(cfg.vault, _password(cfg, args, **kwargs))


def _parse_field_spec(spec: str) -> tuple[str, str, str | None]:
    """Parse ``name=value[:sensitivity]``."""
    name, sep, rest = spec.partition("=")
    if not sep:
        raise TwinError(f"--field needs name=value, got {spec!r}")
    name = name.strip()
    if not name:
        raise TwinError("field name cannot be empty")
    sens = None
    value = rest
    head, _, tail = rest.rpartition(":")
    if head and tail.strip().lower() in masking.SENSITIVITIES:
        value, sens = head, tail.strip().lower()
    return name, value, sens


def _read_secret(prompt: str) -> str:
    import getpass

    if sys.stdin.isatty():
        return getpass.getpass(prompt)
    line = sys.stdin.readline()
    return line.rstrip("\r\n") if line else ""


def _masked_table(records: list[model.Record], redactor: masking.Redactor) -> str:
    header = ("group", "title", "type", "primary", "secrets")
    rows: list[tuple[str, ...]] = []
    for r in records:
        primary = r.value("username") or r.value("email") or ""
        primary_masked = masking.mask_field(primary, masking.IDENTIFYING) if primary else "-"
        secret_count = sum(1 for f in r.fields.values() if f.sensitivity == masking.SECRET and f.value)
        rows.append(
            (
                redactor.scrub(r.group) or "-",
                redactor.scrub(r.title),
                r.type,
                primary_masked,
                str(secret_count),
            )
        )
    if not rows:
        return "no records"
    widths = [max(len(x[i]) for x in rows + [header]) for i in range(len(header))]
    lines = ["  ".join(h.ljust(widths[i]) for i, h in enumerate(header))]
    lines.append("  ".join("-" * w for w in widths))
    for row in rows:
        lines.append("  ".join(c.ljust(widths[i]) for i, c in enumerate(row)))
    return "\n".join(lines)


_SECRET_NAMES = {
    "password", "passwd", "pass", "secret", "token", "apikey", "api_key", "api-key",
    "private_key", "privatekey", "key", "credential", "cookie",
}
_SECRET_SUFFIXES = (
    "_key", "-key", ".key", "_token", "-token", "_secret", "-secret", "_password", "-password",
)


def _looks_secret(name: str) -> bool:
    n = name.strip().lower()
    return n in _SECRET_NAMES or n.endswith(_SECRET_SUFFIXES)


def _collect_values(args, rtype: str) -> tuple[dict[str, str], dict[str, str]]:
    values: dict[str, str] = {}
    sens: dict[str, str] = {}

    for spec in args.field or []:
        name, value, explicit = _parse_field_spec(spec)
        if explicit == masking.SECRET:
            raise TwinError(
                f"refusing to take {name!r} on the command line: use --secret-field {name}"
            )
        if explicit is None and _looks_secret(name):
            raise TwinError(
                f"{name!r} looks like a secret: use --secret-field {name} "
                f"(or pass --field {name}=VALUE:public to override)"
            )
        values[name] = value
        if explicit:
            sens[name] = explicit

    for name in args.secret_field or []:
        name = name.strip()
        if not name:
            continue
        value = _read_secret(f"value for {name}: ")
        if value:
            values[name] = value
        sens[name] = masking.SECRET

    for spec in args.sensitivity or []:
        name, sep, level = spec.partition("=")
        if not sep:
            raise TwinError("--sensitivity needs name=level")
        level = level.strip().lower()
        if level not in masking.SENSITIVITIES:
            raise TwinError(f"unknown sensitivity {level!r}")
        sens[name.strip()] = level

    if rtype == model.TYPE_CREDENTIAL and values:
        sens.setdefault("password", masking.SECRET)
        sens.setdefault("username", masking.IDENTIFYING)
        sens.setdefault("url", masking.IDENTIFYING)
    return values, sens


def _safe_dict(record: model.Record, redactor: masking.Redactor) -> dict:
    payload = record.masked_dict()
    payload["title"] = redactor.scrub(payload["title"])
    payload["group"] = redactor.scrub(payload["group"])
    payload["fields"] = {
        name: {"value": redactor.scrub(f["value"]), "sensitivity": f["sensitivity"]}
        for name, f in payload["fields"].items()
    }
    return payload


# --------------------------------------------------------------------------
# vault lifecycle
# --------------------------------------------------------------------------
def cmd_init(args) -> int:
    cfg = _cfg(args)
    if cfg.vault.exists() and not args.force:
        raise TwinError(f"vault already exists: {cfg.vault} (use --force to replace)")
    secure_dir(cfg.data_dir)
    password = _read_secret("Choose a master password: ")
    if not password:
        raise TwinError("master password cannot be empty")
    if sys.stdin.isatty():
        again = _read_secret("Repeat master password: ")
        if again != password:
            raise TwinError("passwords did not match")
    if cfg.vault.exists():
        cfg.vault.unlink()
    Vault.create(cfg.vault, password)
    secure_path(cfg.vault)
    _out(f"created vault: {cfg.vault}")
    _out("next: `twin add` for non-secret metadata, or `twin form` to enter secrets by hand")
    return 0


def cmd_unlock(args) -> int:
    cfg = _cfg(args)
    password = _password(cfg, args, allow_session=False, allow_autounlock=False)
    auth.verify(cfg.vault, password)
    auth.create_session(cfg.session_file(), password, args.ttl)
    _out(f"session created, valid for {args.ttl}s")
    return 0


def cmd_lock(args) -> int:
    cfg = _cfg(args)
    removed = auth.clear_session(cfg.session_file())
    _out("session cleared" if removed else "no active session")
    if auth.autounlock_status(cfg.autounlock_file()):
        _out("note: autounlock is still enabled; run `twin autounlock off` for a hard lock")
    return 0


def cmd_autounlock(args) -> int:
    cfg = _cfg(args)
    path = cfg.autounlock_file()
    if args.op == "status":
        enabled = auth.autounlock_status(path)
        _out("autounlock: enabled" if enabled else "autounlock: disabled")
        if enabled:
            _out("boundary: any process running as this OS user can open the vault")
        return 0
    if args.op == "on":
        password = _password(cfg, args, allow_session=False, allow_autounlock=False)
        auth.verify(cfg.vault, password)
        auth.autounlock_enable(path, password)
        _out("autounlock enabled (DPAPI, bound to the current Windows user)")
        _out("warning: this lowers the boundary to the OS user account")
        return 0
    removed = auth.autounlock_disable(path)
    _out("autounlock disabled" if removed else "autounlock was not enabled")
    return 0


# --------------------------------------------------------------------------
# read commands (masked)
# --------------------------------------------------------------------------
def cmd_list(args) -> int:
    cfg = _cfg(args)
    vault = _open(cfg, args)
    records = vault.records(args.group)
    redactor = masking.Redactor(vault.secret_values())
    if args.json:
        _json_out([_safe_dict(r, redactor) for r in records])
    else:
        _out(_masked_table(records, redactor))
        _out(f"{len(records)} record(s)")
    return 0


def cmd_show(args) -> int:
    cfg = _cfg(args)
    vault = _open(cfg, args)
    record = vault.require(args.title)
    redactor = masking.Redactor(vault.secret_values())
    if args.json:
        _json_out(_safe_dict(record, redactor))
        return 0
    _out(f"title: {redactor.scrub(record.title)}")
    _out(f"group: {redactor.scrub(record.group) or '-'}")
    _out(f"type:  {record.type}")
    for name, f in record.fields.items():
        if not f.value:
            continue
        _out(f"  {name} [{f.sensitivity}]: {redactor.scrub(f.masked())}")
    return 0


def cmd_export(args) -> int:
    """Masked dump of everything: the AI-readable view of the records."""
    cfg = _cfg(args)
    vault = _open(cfg, args)
    records = vault.records(args.group)
    redactor = masking.Redactor(vault.secret_values())

    if args.format == "json":
        _json_out([_safe_dict(r, redactor) for r in records])
        return 0

    lines = ["# Personal records (masked)", ""]
    for r in records:
        lines.append(f"## {redactor.scrub(r.title)}")
        lines.append("")
        lines.append(f"- group: {redactor.scrub(r.group) or '-'}")
        lines.append(f"- type: {r.type}")
        for name, f in r.fields.items():
            if not f.value:
                continue
            lines.append(f"- {name} ({f.sensitivity}): {redactor.scrub(f.masked())}")
        lines.append("")
    _out("\n".join(lines).rstrip())
    return 0


# --------------------------------------------------------------------------
# write commands
# --------------------------------------------------------------------------
def cmd_add(args) -> int:
    cfg = _cfg(args)
    vault = _open(cfg, args)
    values, sens = _collect_values(args, args.type)
    record = vault.add(args.title, group=args.group, rtype=args.type, values=values, sensitivities=sens)
    _out(f"added: {record.title} ({record.type}, group {record.group})")
    _out("stored fields: " + ", ".join(sorted(values)) if values else "stored fields: none")
    return 0


def cmd_set(args) -> int:
    cfg = _cfg(args)
    vault = _open(cfg, args)
    values, sens = _collect_values(args, args.type or model.TYPE_CREDENTIAL)
    if not values and not args.remove and not args.type and not sens:
        raise TwinError("nothing to change")
    record = vault.update(args.title, values=values, sensitivities=sens,
                          rtype=args.type, remove=args.remove)
    _out(f"updated: {record.title}")
    return 0


def cmd_rm(args) -> int:
    cfg = _cfg(args)
    vault = _open(cfg, args)
    record = vault.require(args.title)
    if not args.yes:
        answer = input(f"Delete record {record.title!r} permanently? Type yes: ").strip()
        if answer != "yes":
            _out("cancelled")
            return 0
    vault.delete(args.title)
    _out(f"deleted: {record.title}")
    return 0


def cmd_reveal(args) -> int:
    cfg = _cfg(args)
    gate = auth.RevealGate(allow_reveal=cfg.security.allow_reveal,
                           block_agents=cfg.security.block_agents)
    gate.check()
    vault = _open(cfg, args)
    record = vault.require(args.title)
    field = record.get(args.field)
    if field is None:
        raise TwinError(f"record has no field {args.field!r}")
    if not field.value:
        raise TwinError(f"field {args.field!r} is empty")
    gate.confirm(f"{record.title}.{field.name}")
    print(field.value, flush=True)
    return 0


def cmd_inject(args) -> int:
    if not args.cmd:
        raise TwinError("inject needs a command after `--`")
    cfg = _cfg(args)
    vault = _open(cfg, args)
    record = vault.require(args.title)
    field = record.get(args.field)
    if field is None or not field.value:
        raise TwinError(f"record {record.title!r} has no value for {args.field!r}")
    code = inject.run(
        args.cmd,
        field.value,
        env_name=args.env,
        inherit_env=args.inherit_env,
        allow_env=cfg.security.allow_env_inject,
    )
    _out(f"[inject] {record.title}/{field.name} -> "
         f"{'env ' + args.env if args.env else 'stdin'}; exit {code}")
    return code


# --------------------------------------------------------------------------
# form
# --------------------------------------------------------------------------
def _form_fields(args) -> list[FormField]:
    fields: list[FormField] = []
    for spec in args.field or []:
        name, _, rest = spec.partition("=")
        name = name.strip()
        label = (rest or name).strip()
        secret = False
        if label.endswith(":secret"):
            label, secret = label[: -len(":secret")], True
        if any(token in name.lower() for token in ("pass", "secret", "token", "key")):
            secret = True
        fields.append(FormField(name=name, label=label.strip(), secret=secret))
    if not fields:
        if args.type == model.TYPE_PERSON:
            fields = [
                FormField("name", "Full name"),
                FormField("email", "Email"),
                FormField("phone", "Phone"),
            ]
        else:
            fields = [
                FormField("username", "Username"),
                FormField("password", "Password", secret=True),
            ]
    if args.mode == "batch" and not any(f.name == "title" for f in fields):
        fields.insert(0, FormField("title", "Record name"))
    return fields


def cmd_form(args) -> int:
    cfg = _cfg(args)
    if not cfg.vault.exists():
        raise TwinError(f"vault not found: {cfg.vault} (run `twin init`)")

    def open_vault(password: str) -> Vault:
        return Vault.open(cfg.vault, password)

    def resolve_password() -> str | None:
        return auth.autounlock_password(cfg.autounlock_file())

    try:
        session = FormSession(
            title=args.title,
            group=args.group,
            fields=_form_fields(args),
            mode=args.mode,
            open_vault=open_vault,
            resolve_password=resolve_password,
            port=args.port,
            wait=args.wait,
            max_attempts=cfg.security.form_max_attempts,
        )
        url = session.start()
    except OSError as exc:
        raise TwinError(f"cannot listen on 127.0.0.1:{args.port}: {exc.strerror or exc}") from exc
    _out(f"[form] {url}")
    _out(f"[form] open this URL in a browser within {args.wait}s; values are not returned here")
    result = session.wait()
    _json_out(result.as_json())
    return 0 if result.ok else 1


# --------------------------------------------------------------------------
# audit / backup / restore
# --------------------------------------------------------------------------
def cmd_audit(args) -> int:
    cfg = _cfg(args)
    detectors: list[leakscan.Detector] = []
    if args.detectors:
        detectors.extend(leakscan.load_detector_file(Path(args.detectors)))
    elif cfg.audit.detectors:
        detectors.extend(leakscan.load_detector_file(Path(os.path.expanduser(cfg.audit.detectors))))
    if args.from_vault:
        vault = _open(cfg, args)
        detectors.extend(leakscan.detectors_from_vault(vault))
    if not detectors:
        raise TwinError("no detectors: pass --detectors FILE or --from-vault")

    roots = [Path(os.path.expanduser(p)) for p in (args.path or cfg.audit.roots)]
    if not roots:
        raise TwinError("no scan roots: pass --path DIR or set [audit] roots")

    allowlist: set[str] = set()
    if args.allowlist:
        allow_path = Path(args.allowlist)
        if allow_path.exists():
            allowlist = {
                line.strip()
                for line in allow_path.read_text(encoding="utf-8").splitlines()
                if line.strip() and not line.strip().startswith("#")
            }

    hits = leakscan.scan(roots, detectors, max_file_bytes=cfg.audit.max_file_bytes, allowlist=allowlist)
    report = args.report or cfg.audit.report
    if report:
        leakscan.write_report(Path(os.path.expanduser(report)), hits, len(roots))
    if args.json:
        _json_out({"scanned": len(roots), "hits": [h.as_dict() for h in hits]})
    else:
        _out(leakscan.render_text(hits, len(roots)))
    return 1 if hits else 0


def cmd_backup(args) -> int:
    cfg = _cfg(args)
    vault_path = Path(args.vault) if args.vault else cfg.vault
    password = _password(cfg, args)
    auth.verify(vault_path, password)
    result = backup.create(
        vault_path,
        Path(os.path.expanduser(args.out)) if args.out else cfg.backup_dir,
        password,
        include=[Path(os.path.expanduser(p)) for p in (args.include or [])],
    )
    _out(f"backup written to {result.directory}")
    _out(f"  vault copy: {result.vault_copy.name}")
    if result.extras:
        _out(f"  extras:     {result.extras.name}")
    _out(f"  manifest:   {result.manifest.name}")
    return 0


def cmd_restore(args) -> int:
    cfg = _cfg(args)
    password = _password(cfg, args, allow_session=False, allow_autounlock=False)
    dest = Path(os.path.expanduser(args.dest)) if args.dest else cfg.vault
    extras_to = Path(os.path.expanduser(args.extras)) if args.extras else None
    backup.restore(
        Path(os.path.expanduser(args.source)),
        dest,
        password,
        extras_to=extras_to,
        overwrite=args.force,
    )
    _out(f"restored vault to {dest}")
    if extras_to:
        _out(f"restored extras to {extras_to}")
    return 0


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------
def cmd_doctor(args) -> int:
    cfg = _cfg(args)
    checks: list[tuple[str, str]] = []
    checks.append(("python", sys.version.split()[0]))
    checks.append(("config", str(cfg.path) + ("" if cfg.path.exists() else " (defaults)")))
    checks.append(("vault", str(cfg.vault) + ("" if cfg.vault.exists() else " (missing)")))
    if cfg.vault.exists():
        try:
            mode = oct(cfg.vault.stat().st_mode & 0o777)
        except OSError:
            mode = "?"
        if os.name == "nt":
            mode += " (Windows: ACL-based, chmod is advisory)"
        checks.append(("vault mode", mode))
    checks.append(("session", "active" if auth.session_active(cfg.session_file()) else "none"))
    checks.append(("autounlock", "enabled" if auth.autounlock_status(cfg.autounlock_file()) else "disabled"))
    checks.append(("dpapi", "available" if auth.dpapi_available() else "unavailable (non-Windows)"))
    checks.append(("reveal allowed", str(cfg.security.allow_reveal)))
    checks.append(("TWIN_AGENT", os.environ.get("TWIN_AGENT") or "unset"))

    for name, value in checks:
        _out(f"{name:16s} {value}")

    problems: list[str] = []
    if not cfg.vault.exists():
        problems.append("vault missing: run `twin init`")
    elif os.name != "nt":
        mode = cfg.vault.stat().st_mode & 0o777
        if mode & 0o077:
            problems.append(f"vault permissions are {oct(mode)}; run `chmod 600 {cfg.vault}`")
    if cfg.security.allow_reveal and cfg.security.block_agents and not os.environ.get("TWIN_AGENT"):
        problems.append("reveal is enabled and TWIN_AGENT is unset: agent sessions could reveal secrets")

    if problems:
        _out("")
        for p in problems:
            _out("warning: " + p)
        return 1
    _out("")
    _out("doctor: ok")
    return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="twin",
        description="Local personal-record vault with masked views and secret injection.",
    )
    parser.add_argument("--config", help="policy file (default: per-user app config dir)")
    parser.add_argument("--vault", help="vault path (default: from config)")
    parser.add_argument("--pw-stdin", action="store_true", help="read the master password from stdin")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("init", help="create a new vault")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_init)

    p = sub.add_parser("unlock", help="cache the master password in a DPAPI-protected session")
    p.add_argument("--ttl", type=int, default=900)
    p.set_defaults(fn=cmd_unlock)

    p = sub.add_parser("lock", help="drop the unlock session")
    p.set_defaults(fn=cmd_lock)

    p = sub.add_parser("autounlock", help="opt-in passwordless operation for the current OS user")
    p.add_argument("op", choices=["on", "off", "status"])
    p.set_defaults(fn=cmd_autounlock)

    p = sub.add_parser("list", help="list records with masked identifiers")
    p.add_argument("--group")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_list)

    p = sub.add_parser("show", help="show one record with masked values")
    p.add_argument("title")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_show)

    p = sub.add_parser("export", help="masked dump of all records")
    p.add_argument("--group")
    p.add_argument("--format", choices=["md", "json"], default="md")
    p.set_defaults(fn=cmd_export)

    p = sub.add_parser("add", help="add a record (non-secret fields on argv, secrets via prompt/stdin)")
    p.add_argument("title")
    p.add_argument("--type", choices=model.TYPES, default=model.TYPE_CREDENTIAL)
    p.add_argument("--group", default=DEFAULT_GROUP)
    p.add_argument("--field", action="append", metavar="NAME=VALUE[:SENSITIVITY]")
    p.add_argument("--secret-field", action="append", metavar="NAME")
    p.add_argument("--sensitivity", action="append", metavar="NAME=LEVEL")
    p.set_defaults(fn=cmd_add)

    p = sub.add_parser("set", help="update fields on a record")
    p.add_argument("title")
    p.add_argument("--type", choices=model.TYPES)
    p.add_argument("--field", action="append", metavar="NAME=VALUE[:SENSITIVITY]")
    p.add_argument("--secret-field", action="append", metavar="NAME")
    p.add_argument("--sensitivity", action="append", metavar="NAME=LEVEL")
    p.add_argument("--remove", action="append", metavar="NAME")
    p.set_defaults(fn=cmd_set)

    p = sub.add_parser("rm", help="delete a record")
    p.add_argument("title")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_rm)

    p = sub.add_parser("reveal", help="print a secret (interactive terminal only, policy-gated)")
    p.add_argument("title")
    p.add_argument("--field", required=True)
    p.set_defaults(fn=cmd_reveal)

    p = sub.add_parser("inject", help="hand a secret to a child process without printing it")
    p.add_argument("title")
    p.add_argument("--field", default="password")
    p.add_argument("--env", metavar="VAR", help="pass via environment variable instead of stdin")
    p.add_argument("--inherit-env", action="store_true", help="with --env, keep the full parent env")
    p.set_defaults(fn=cmd_inject)

    p = sub.add_parser("form", help="one-time local web form for hand-entered secrets")
    p.add_argument("title")
    p.add_argument("--group", default=DEFAULT_GROUP)
    p.add_argument("--type", choices=model.TYPES, default=model.TYPE_CREDENTIAL)
    p.add_argument("--field", action="append", metavar="NAME=LABEL[:secret]")
    p.add_argument("--mode", choices=["single", "batch"], default="single")
    p.add_argument("--port", type=int, default=8340)
    p.add_argument("--wait", type=int, default=600)
    p.set_defaults(fn=cmd_form)

    p = sub.add_parser("audit", help="scan directories for stored personal values")
    p.add_argument("--path", action="append", metavar="DIR")
    p.add_argument("--detectors", metavar="FILE")
    p.add_argument("--from-vault", action="store_true", help="use vault values as detectors")
    p.add_argument("--allowlist", metavar="FILE")
    p.add_argument("--report", metavar="FILE")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_audit)

    p = sub.add_parser("backup", help="copy the vault and optionally encrypt extra files")
    p.add_argument("--out", metavar="DIR")
    p.add_argument("--include", action="append", metavar="PATH")
    p.set_defaults(fn=cmd_backup)

    p = sub.add_parser("restore", help="restore a vault from a backup")
    p.add_argument("source")
    p.add_argument("--dest", metavar="FILE")
    p.add_argument("--extras", metavar="DIR")
    p.add_argument("--force", action="store_true")
    p.set_defaults(fn=cmd_restore)

    p = sub.add_parser("doctor", help="show configuration and security posture")
    p.set_defaults(fn=cmd_doctor)

    return parser


def _extract_inject_command(argv: list[str]) -> tuple[list[str], list[str] | None]:
    """Split ``inject ... -- cmd args`` without letting argparse eat flags."""
    if "inject" not in argv:
        return argv, None
    idx = argv.index("inject")
    if "--" not in argv[idx:]:
        return argv, None
    sep = argv.index("--", idx)
    return argv[:sep], argv[sep + 1:]


def main(argv: list[str] | None = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

    raw = list(sys.argv[1:] if argv is None else argv)
    head, inject_cmd = _extract_inject_command(raw)
    parser = build_parser()
    args = parser.parse_args(head)
    if args.command == "inject":
        args.cmd = inject_cmd

    try:
        return int(args.fn(args) or 0)
    except TwinError as exc:
        print(f"error: {exc}", file=sys.stderr, flush=True)
        return getattr(exc, "exit_code", 1)
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr, flush=True)
        return 130
    except Exception as exc:  # never dump a traceback that may hold values
        if os.environ.get("TWIN_DEBUG"):
            raise
        print(f"error: unexpected {type(exc).__name__}", file=sys.stderr, flush=True)
        print("set TWIN_DEBUG=1 for a traceback", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

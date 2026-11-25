"""Thin, explicit wrapper around the KDBX file.

Only this module talks to ``pykeepass``. Everything above it deals in
:class:`twin.model.Record` objects and never sees a raw entry, which keeps the
masking contract in one place.
"""

from __future__ import annotations

import os
from pathlib import Path

from . import model
from .errors import AmbiguousMatchError, AuthError, NotFoundError, VaultError


def secure_path(path: Path, mode: int = 0o600) -> None:
    """Best-effort owner-only permissions.

    POSIX honours the mode. On Windows ``chmod`` only toggles the read-only bit,
    so the real control there is the user-profile ACL inherited from
    ``%LOCALAPPDATA%`` plus disk encryption. Documented in SECURITY.md.
    """
    try:
        os.chmod(path, mode)
    except OSError:
        pass


def secure_dir(path: Path) -> None:
    try:
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, 0o700)
    except OSError:
        pass


def _group_path(entry) -> str:
    """Path without the database root group, e.g. ``Work/Clients``."""
    parts: list[str] = []
    g = getattr(entry, "group", None)
    while g is not None and getattr(g, "parentgroup", None) is not None:
        parts.append(g.name or "")
        g = g.parentgroup
    return "/".join(reversed([p for p in parts if p]))


class Vault:
    """An opened KDBX vault."""

    def __init__(self, kp, path: Path):
        self._kp = kp
        self.path = path

    # -- lifecycle ---------------------------------------------------------
    @classmethod
    def create(cls, path: Path, password: str) -> "Vault":
        from pykeepass import create_database

        if path.exists():
            raise VaultError(f"vault already exists: {path}")
        secure_dir(path.parent)
        kp = create_database(str(path), password=password)
        kp.save()
        secure_path(path)
        return cls(kp, path)

    @classmethod
    def open(cls, path: Path, password: str) -> "Vault":
        from pykeepass import PyKeePass
        from pykeepass.exceptions import CredentialsError

        if not path.exists():
            raise VaultError(f"vault not found: {path} (run `twin init`)")
        try:
            kp = PyKeePass(str(path), password=password)
        except CredentialsError as exc:
            raise AuthError("master password is wrong") from exc
        except Exception as exc:  # corrupted file, unsupported version, ...
            raise VaultError(f"cannot open vault: {type(exc).__name__}") from exc
        return cls(kp, path)

    def save(self) -> None:
        self._kp.save()
        secure_path(self.path)

    @property
    def entry_count(self) -> int:
        return len(self._kp.entries)

    def groups(self) -> list[str]:
        return sorted({_group_path(e) for e in self._kp.entries})

    # -- read --------------------------------------------------------------
    def records(self, group: str | None = None) -> list[model.Record]:
        out = []
        for entry in self._kp.entries:
            gp = _group_path(entry)
            if group and group.lower() not in gp.lower():
                continue
            out.append(model.record_from_entry(entry, gp))
        return sorted(out, key=lambda r: (r.group, r.title.lower()))

    def find(self, title: str) -> list[model.Record]:
        return [model.record_from_entry(e, _group_path(e)) for e in self._match_entries(title)]

    def require(self, title: str) -> model.Record:
        entries = self._match_entries(title)
        if not entries:
            raise NotFoundError(f"no record matched {title!r}")
        if len(entries) > 1:
            names = ", ".join(sorted({e.title or "" for e in entries}))
            raise AmbiguousMatchError(f"{title!r} matched several records: {names}")
        return model.record_from_entry(entries[0], _group_path(entries[0]))

    def secret_values(self) -> list[str]:
        return model.all_secret_values(self.records())

    # -- write -------------------------------------------------------------
    def add(
        self,
        title: str,
        group: str = "Default",
        rtype: str = model.TYPE_CREDENTIAL,
        values: dict[str, str] | None = None,
        sensitivities: dict[str, str] | None = None,
    ) -> model.Record:
        if self._match_entries(title):
            raise VaultError(f"record already exists: {title}")
        target = self._resolve_group(group)
        entry = self._kp.add_entry(target, title=title, username="", password="", url="", notes="")
        self._write(entry, rtype, values or {}, sensitivities or {})
        self.save()
        return model.record_from_entry(entry, _group_path(entry))

    def update(
        self,
        title: str,
        values: dict[str, str] | None = None,
        sensitivities: dict[str, str] | None = None,
        rtype: str | None = None,
        remove: list[str] | None = None,
    ) -> model.Record:
        entry = self._unique_entry(title)
        current = model.read_meta(entry)
        new_type = rtype or current["type"]
        merged_sens = dict(current["fields"])
        merged_sens.update(sensitivities or {})
        for name in remove or []:
            model.remove_field(entry, name)
            merged_sens.pop(name, None)
        self._write(entry, new_type, values or {}, merged_sens)
        self.save()
        return model.record_from_entry(entry, _group_path(entry))

    def delete(self, title: str) -> None:
        entry = self._unique_entry(title)
        self._kp.delete_entry(entry)
        self.save()

    # -- internals ---------------------------------------------------------
    def _write(self, entry, rtype: str, values: dict[str, str], sensitivities: dict[str, str]) -> None:
        merged = dict(model.read_meta(entry)["fields"])
        merged.update({k: v for k, v in sensitivities.items()})
        for name in values:
            if name not in merged:
                merged[name] = model._DEFAULTS.get(name, "identifying")
        for name, value in values.items():
            model.apply_field(entry, name, value, protect=merged.get(name) == "secret")
        model.write_meta(entry, rtype, merged)

    def _unique_entry(self, title: str):
        entries = self._match_entries(title)
        if not entries:
            raise NotFoundError(f"no record matched {title!r}")
        if len(entries) > 1:
            names = ", ".join(sorted({e.title or "" for e in entries}))
            raise AmbiguousMatchError(f"{title!r} matched several records: {names}")
        return entries[0]

    def _match_entries(self, title: str) -> list:
        needle = title.strip().lower()
        exact = [e for e in self._kp.entries if (e.title or "").lower() == needle]
        if exact:
            return exact
        return [e for e in self._kp.entries if needle and needle in (e.title or "").lower()]

    def _resolve_group(self, name: str):
        for group in self._kp.root_group.subgroups:
            if group.name == name:
                return group
        return self._kp.add_group(self._kp.root_group, name)

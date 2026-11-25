"""Record model on top of KeePass entries.

A *record* is a KDBX entry plus a small amount of metadata stored in a custom
property called ``twin.meta``:

    {"type": "credential", "fields": {"email": "identifying", "api_key": "secret"}}

Native KeePass fields (title/username/password/url/notes) and arbitrary custom
fields are all exposed as :class:`Field` objects with an explicit sensitivity,
so masking never has to guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field as dc_field

from . import masking

META_KEY = "twin.meta"

TYPE_CREDENTIAL = "credential"
TYPE_PERSON = "person"
TYPE_NOTE = "note"
TYPES = (TYPE_CREDENTIAL, TYPE_PERSON, TYPE_NOTE)

NATIVE_FIELDS = ("username", "password", "url", "notes")

_DEFAULTS = {
    "password": masking.SECRET,
    "username": masking.IDENTIFYING,
    # URLs are masked by default because query strings routinely carry tokens.
    "url": masking.IDENTIFYING,
    "notes": masking.IDENTIFYING,
}


@dataclass
class Field:
    name: str
    value: str
    sensitivity: str
    native: bool = False

    def masked(self) -> str:
        if self.name == "notes":
            return masking.mask_notes(self.value)
        return masking.mask_field(self.value, self.sensitivity)


@dataclass
class Record:
    title: str
    group: str
    type: str = TYPE_CREDENTIAL
    fields: dict[str, Field] = dc_field(default_factory=dict)

    # -- accessors ---------------------------------------------------------
    def get(self, name: str) -> Field | None:
        return self.fields.get(name)

    def value(self, name: str) -> str:
        f = self.fields.get(name)
        return f.value if f else ""

    def sensitivity(self, name: str) -> str:
        f = self.fields.get(name)
        return f.sensitivity if f else masking.SECRET

    def secret_values(self) -> list[str]:
        return [f.value for f in self.fields.values() if f.sensitivity == masking.SECRET and f.value]

    def masked_dict(self) -> dict:
        return {
            "title": self.title,
            "group": self.group,
            "type": self.type,
            "fields": {
                name: {
                    "value": f.masked(),
                    "sensitivity": f.sensitivity,
                }
                for name, f in self.fields.items()
            },
        }

    def public_label(self) -> str:
        """A one-line label that contains no identifying information."""
        return f"{self.title} ({self.type}, {len(self.fields)} fields)"


def read_meta(entry) -> dict:
    try:
        raw = entry.get_custom_property(META_KEY)
    except Exception:
        raw = None
    if not raw:
        return {"type": TYPE_CREDENTIAL, "fields": {}}
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        return {"type": TYPE_CREDENTIAL, "fields": {}}
    if not isinstance(data, dict):
        return {"type": TYPE_CREDENTIAL, "fields": {}}
    rtype = data.get("type")
    if rtype not in TYPES:
        rtype = TYPE_CREDENTIAL
    fields = data.get("fields") if isinstance(data.get("fields"), dict) else {}
    clean = {}
    for name, sens in fields.items():
        try:
            clean[str(name)] = masking.normalize_sensitivity(str(sens))
        except ValueError:
            continue
    return {"type": rtype, "fields": clean}


def write_meta(entry, rtype: str, sensitivities: dict[str, str]) -> None:
    entry.set_custom_property(
        META_KEY,
        json.dumps(
            {"type": rtype, "fields": sensitivities}, separators=(",", ":"), sort_keys=True
        ),
    )


def record_from_entry(entry, group_path: str) -> Record:
    meta = read_meta(entry)
    rtype = meta["type"]
    sens_map = meta["fields"]
    fields: dict[str, Field] = {}

    for name in NATIVE_FIELDS:
        value = getattr(entry, name, "") or ""
        sens = sens_map.get(name) or _DEFAULTS.get(name, masking.IDENTIFYING)
        fields[name] = Field(name=name, value=value, sensitivity=sens, native=True)

    for name, value in (entry.custom_properties or {}).items():
        if name == META_KEY:
            continue
        sens = sens_map.get(name) or masking.IDENTIFYING
        fields[name] = Field(name=name, value=value or "", sensitivity=sens, native=False)

    return Record(title=entry.title or "", group=group_path, type=rtype, fields=fields)


def apply_field(entry, name: str, value: str, protect: bool = False) -> None:
    if name in NATIVE_FIELDS:
        setattr(entry, name, value)
    else:
        # ``protect=True`` keeps the value in KeePass' protected stream rather
        # than plain XML text inside the database.
        entry.set_custom_property(name, value, protect=protect)


def remove_field(entry, name: str) -> None:
    if name in NATIVE_FIELDS:
        setattr(entry, name, "")
    else:
        try:
            entry.delete_custom_property(name)
        except Exception:
            pass


def all_secret_values(records: list[Record]) -> list[str]:
    out: list[str] = []
    for r in records:
        out.extend(r.secret_values())
    return out

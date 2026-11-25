"""Sensitivity levels and masking.

The masking layer is the only place allowed to decide what a caller sees.
Every read path goes through :func:`mask_field`, and the result of a masked
read is safe to print, log or hand to a language model.

Design rule: masking is *lossy by construction*. There is no "unmask"
function here; unmasking is a separate, policy-gated operation in
``twin.reveal``.
"""

from __future__ import annotations

import re

PUBLIC = "public"
IDENTIFYING = "identifying"
SECRET = "secret"

SENSITIVITIES = (PUBLIC, IDENTIFYING, SECRET)

HIDDEN = "[hidden]"
MASKED = "***"

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_PHONE_RE = re.compile(r"^\+?[\d\s\-().]{6,}$")
_URL_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")


def normalize_sensitivity(value: str | None, default: str = IDENTIFYING) -> str:
    if not value:
        return default
    v = value.strip().lower()
    if v in SENSITIVITIES:
        return v
    raise ValueError(f"unknown sensitivity {value!r}; expected one of {', '.join(SENSITIVITIES)}")


def mask_field(value: str | None, sensitivity: str) -> str:
    """Return a display-safe rendering of ``value``."""
    if not value:
        return ""
    if sensitivity == PUBLIC:
        return value
    if sensitivity == SECRET:
        return HIDDEN
    return mask_identifying(value)


def mask_identifying(value: str) -> str:
    """Partial mask that keeps the value recognisable to its owner only."""
    v = value.strip()
    if not v:
        return ""

    if _EMAIL_RE.match(v):
        local, _, domain = v.partition("@")
        if len(local) <= 1:
            return f"{MASKED}@{domain}"
        return f"{local[0]}{MASKED}@{domain}"

    if _URL_RE.match(v):
        # Query strings and fragments routinely carry tokens.
        return v.split("?", 1)[0].split("#", 1)[0] + ("?…" if ("?" in v or "#" in v) else "")

    digits = re.sub(r"\D", "", v)
    if _PHONE_RE.match(v) and 7 <= len(digits) <= 15:
        if len(digits) <= 7:
            return f"{digits[:2]}{MASKED}{digits[-2:]}"
        return f"{digits[:3]}{MASKED}{digits[-4:]}"

    # Long opaque identifiers (IDs, account numbers): keep a crude shape.
    if len(v) > 12 and not any(c.isspace() for c in v):
        return f"{v[:2]}{MASKED}{v[-2:]}"

    if len(v) <= 2:
        return MASKED
    if len(v) <= 6:
        return f"{v[0]}{MASKED}"
    return f"{v[:2]}{MASKED}"


def mask_notes(value: str | None) -> str:
    """Notes are multi-line and may embed anything; only the first line survives."""
    if not value:
        return ""
    first = value.strip().splitlines()[0]
    if len(first) > 40:
        first = first[:40] + "…"
    return f"{first} …" if len(value.strip().splitlines()) > 1 else first


class Redactor:
    """Scrubs known secret values out of arbitrary text.

    Defence in depth: if a secret ends up in a title, an error message or a
    child process traceback, the redactor keeps it out of the transcript.
    """

    def __init__(self, values: list[str]):
        # Longest first so a secret that contains another is replaced wholesale.
        self._values = sorted({v for v in values if v and len(v) >= 4}, key=len, reverse=True)

    def scrub(self, text: str | None) -> str:
        if not text:
            return ""
        out = text
        for v in self._values:
            if v in out:
                out = out.replace(v, HIDDEN)
        return out

    def __bool__(self) -> bool:
        return bool(self._values)

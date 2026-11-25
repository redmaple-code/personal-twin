"""Encrypted, integrity-protected backups.

The vault file is already encrypted by KeePass, so it is copied as-is. Anything
else (notes, exports, attachments) is packed into a tar and encrypted with
AES-256-GCM under a key derived from the master password with scrypt — unlike a
bare AES-CBC stream, GCM refuses to decrypt tampered data.

No git commits, no cloud destinations and no assumptions about which files a
user keeps: callers pass the list explicitly.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import AuthError, TwinError
from .vault import secure_dir, secure_path

MAGIC = b"TWINBAK1"
SALT_LEN = 16
NONCE_LEN = 12
SCRYPT_N = 1 << 15
SCRYPT_R = 8
SCRYPT_P = 1


@dataclass
class BackupResult:
    directory: Path
    vault_copy: Path
    extras: Path | None
    manifest: Path


def _derive(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive(password, salt)
    return MAGIC + salt + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def decrypt_bytes(blob: bytes, password: str) -> bytes:
    if not blob.startswith(MAGIC):
        raise TwinError("not a twin backup file")
    body = blob[len(MAGIC):]
    if len(body) < SALT_LEN + NONCE_LEN + 16:
        raise TwinError("backup file is truncated")
    salt = body[:SALT_LEN]
    nonce = body[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = body[SALT_LEN + NONCE_LEN:]
    key = _derive(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except InvalidTag as exc:
        raise AuthError("backup password is wrong or the file was tampered with") from exc


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def create(
    vault_path: Path,
    backup_dir: Path,
    password: str,
    include: list[Path] | None = None,
) -> BackupResult:
    if not vault_path.exists():
        raise TwinError(f"vault not found: {vault_path}")
    secure_dir(backup_dir)
    stamp = time.strftime("%Y%m%d-%H%M%S")

    vault_copy = backup_dir / f"vault-{stamp}.kdbx"
    shutil.copy2(vault_path, vault_copy)
    secure_path(vault_copy)
    latest = backup_dir / "latest.kdbx"
    shutil.copy2(vault_path, latest)
    secure_path(latest)

    files = [
        {"name": vault_copy.name, "sha256": _sha256(vault_copy)},
        {"name": latest.name, "sha256": _sha256(latest)},
    ]

    extras_path: Path | None = None
    if include:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
            for item in include:
                p = Path(item)
                if not p.exists():
                    raise TwinError(f"cannot include missing path: {p}")
                tar.add(p, arcname=p.name)
        blob = encrypt_bytes(buffer.getvalue(), password)
        extras_path = backup_dir / f"extras-{stamp}.tar.enc"
        fd = os.open(extras_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with io.open(fd, "wb") as f:
            f.write(blob)
        secure_path(extras_path)
        files.append({"name": extras_path.name, "sha256": _sha256(extras_path)})

    manifest = backup_dir / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "format": "twin-backup-1",
                "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                "files": files,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    secure_path(manifest)

    return BackupResult(directory=backup_dir, vault_copy=vault_copy, extras=extras_path, manifest=manifest)


def restore(
    source: Path,
    dest_vault: Path,
    password: str,
    *,
    extras_to: Path | None = None,
    overwrite: bool = False,
) -> Path:
    """Restore a vault (and optionally the encrypted extras) from a backup dir."""
    src = Path(source)
    if src.is_dir():
        vault_src = src / "latest.kdbx"
        if not vault_src.exists():
            candidates = sorted(src.glob("vault-*.kdbx"))
            if not candidates:
                raise TwinError(f"no vault backup found in {src}")
            vault_src = candidates[-1]
        extras = sorted(src.glob("extras-*.tar.enc"))
        extras_src = extras[-1] if extras else None
    else:
        vault_src = src
        extras_src = None

    if dest_vault.exists() and not overwrite:
        raise TwinError(f"destination already exists: {dest_vault} (use --force)")

    # Prove the backup opens before touching the destination: a wrong password
    # must not leave a half-restored file behind.
    from .auth import verify

    verify(vault_src, password)

    secure_dir(dest_vault.parent)
    shutil.copy2(vault_src, dest_vault)
    secure_path(dest_vault)

    if extras_to and extras_src:
        blob = extras_src.read_bytes()
        plain = decrypt_bytes(blob, password)
        secure_dir(extras_to)
        base = extras_to.resolve()
        with tarfile.open(fileobj=io.BytesIO(plain), mode="r:gz") as tar:
            for member in tar.getmembers():
                target = (base / member.name).resolve()
                if base != target and base not in target.parents:
                    raise TwinError(f"unsafe path in archive: {member.name}")
            try:
                tar.extractall(base, filter="data")
            except TypeError:  # Python < 3.11.12 has no extraction filters
                tar.extractall(base)
    return dest_vault

import pytest

from twin import backup
from twin.errors import AuthError, TwinError
from twin.vault import Vault

PASSWORD = "backup-master-pw"


@pytest.fixture()
def vault_path(tmp_path):
    path = tmp_path / "vault.kdbx"
    v = Vault.create(path, PASSWORD)
    v.add("demo", values={"username": "alice", "password": "s3cret"})
    return path


def test_backup_and_restore_roundtrip(vault_path, tmp_path):
    out = tmp_path / "backups"
    result = backup.create(vault_path, out, PASSWORD)
    assert result.vault_copy.exists()
    assert (out / "latest.kdbx").exists()
    manifest = (out / "manifest.json").read_text()
    assert "latest.kdbx" in manifest
    assert "s3cret" not in manifest

    dest = tmp_path / "restored" / "vault.kdbx"
    backup.restore(out, dest, PASSWORD)
    assert Vault.open(dest, PASSWORD).require("demo").value("password") == "s3cret"


def test_restore_refuses_to_overwrite(vault_path, tmp_path):
    out = tmp_path / "backups"
    backup.create(vault_path, out, PASSWORD)
    with pytest.raises(TwinError):
        backup.restore(out, vault_path, PASSWORD)


def test_restore_with_wrong_password_fails(vault_path, tmp_path):
    out = tmp_path / "backups"
    backup.create(vault_path, out, PASSWORD)
    dest = tmp_path / "restored.kdbx"
    with pytest.raises(AuthError):
        backup.restore(out, dest, "wrong-password")


def test_extras_are_encrypted_and_restorable(vault_path, tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("some private note")
    out = tmp_path / "backups"
    result = backup.create(vault_path, out, PASSWORD, include=[notes])
    assert result.extras is not None
    blob = result.extras.read_bytes()
    assert b"some private note" not in blob

    dest = tmp_path / "restored.kdbx"
    extras_dir = tmp_path / "extras-out"
    backup.restore(out, dest, PASSWORD, extras_to=extras_dir)
    assert (extras_dir / "notes.txt").read_text() == "some private note"


def test_tampered_extras_are_rejected(tmp_path):
    blob = backup.encrypt_bytes(b"payload", PASSWORD)
    tampered = bytearray(blob)
    tampered[-1] ^= 0x01
    with pytest.raises(AuthError):
        backup.decrypt_bytes(bytes(tampered), PASSWORD)


def test_wrong_magic_is_rejected():
    with pytest.raises(TwinError):
        backup.decrypt_bytes(b"NOTABACKUP" + b"0" * 64, PASSWORD)

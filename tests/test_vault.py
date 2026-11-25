import pytest

from twin import masking, model
from twin.errors import AmbiguousMatchError, NotFoundError, VaultError
from twin.vault import Vault

PASSWORD = "correct horse battery staple"


@pytest.fixture()
def vault(tmp_path):
    return Vault.create(tmp_path / "test.kdbx", PASSWORD)


def test_create_and_reopen(tmp_path):
    path = tmp_path / "test.kdbx"
    Vault.create(path, PASSWORD)
    v = Vault.open(path, PASSWORD)
    assert v.entry_count == 0


def test_add_record_and_mask(vault):
    vault.add(
        "home",
        group="Personal",
        rtype=model.TYPE_PERSON,
        values={"username": "alice@example.com", "phone": "13800138000", "password": "s3cret"},
        sensitivities={"phone": masking.IDENTIFYING, "password": masking.SECRET},
    )
    rec = vault.require("home")
    assert rec.type == model.TYPE_PERSON
    assert rec.value("phone") == "13800138000"
    masked = rec.masked_dict()
    assert masked["fields"]["phone"]["value"] == "138***8000"
    assert masked["fields"]["password"]["value"] == masking.HIDDEN
    assert "s3cret" not in str(masked)


def test_custom_field_roundtrip(vault):
    vault.add("bank", values={"account_no": "1234567890123456"}, sensitivities={"account_no": masking.SECRET})
    rec = Vault.open(vault.path, PASSWORD).require("bank")
    assert rec.value("account_no") == "1234567890123456"
    assert rec.sensitivity("account_no") == masking.SECRET


def test_update_and_remove_field(vault):
    vault.add("site", values={"username": "bob"})
    rec = vault.update("site", values={"username": "bob2"})
    assert rec.value("username") == "bob2"
    rec = vault.update("site", remove=["username"])
    assert rec.value("username") == ""


def test_duplicate_add_is_rejected(vault):
    vault.add("dup")
    with pytest.raises(VaultError):
        vault.add("dup")


def test_ambiguous_and_missing(vault):
    vault.add("mail-work", values={"username": "work@example.com"})
    vault.add("mail-home", values={"username": "home@example.com"})
    with pytest.raises(AmbiguousMatchError):
        vault.require("mail")
    with pytest.raises(NotFoundError):
        vault.require("nope")


def test_delete(vault):
    vault.add("temp")
    vault.delete("temp")
    assert vault.entry_count == 0


def test_secret_values_feed_the_redactor(vault):
    vault.add("api", values={"password": "token-abcdef-123"})
    red = masking.Redactor(vault.secret_values())
    assert red.scrub("leaked token-abcdef-123 here") == f"leaked {masking.HIDDEN} here"


def test_secret_custom_fields_use_the_protected_stream(vault):
    vault.add("api", values={"api_key": "abcdef123456"}, sensitivities={"api_key": masking.SECRET})
    entry = vault._kp.entries[0]
    assert entry.is_custom_property_protected("api_key") is True


def test_non_secret_custom_fields_are_not_protected(vault):
    vault.add("api", values={"team": "platform"})
    entry = vault._kp.entries[0]
    assert entry.is_custom_property_protected("team") is False

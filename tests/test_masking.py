import pytest

from twin import masking


@pytest.mark.parametrize(
    "value, expected",
    [
        ("alice@example.com", "a***@example.com"),
        ("a@example.com", "***@example.com"),
        ("+1 415 555 0100", "141***0100"),
        ("13800138000", "138***8000"),
        ("https://example.com/path?token=abc#frag", "https://example.com/path?…"),
        ("short", "s***"),
        ("ab", "***"),
        ("", ""),
    ],
)
def test_mask_identifying(value, expected):
    assert masking.mask_identifying(value) == expected


def test_public_and_secret_are_distinct():
    assert masking.mask_field("example.com", masking.PUBLIC) == "example.com"
    assert masking.mask_field("hunter2", masking.SECRET) == masking.HIDDEN
    assert masking.mask_field("hunter2", masking.SECRET) != "hunter2"


def test_secret_never_survives_masking():
    secret = "s3cr3t-value"
    out = masking.mask_field(secret, masking.SECRET)
    assert secret not in out


def test_notes_only_first_line():
    assert masking.mask_notes("first line\nsecond line with token") == "first line …"


def test_redactor_removes_longest_value_first():
    red = masking.Redactor(["abcdef", "abcdefghij"])
    assert red.scrub("x abcdefghij y") == f"x {masking.HIDDEN} y"


def test_redactor_ignores_short_values_to_avoid_false_positives():
    red = masking.Redactor(["abc"])
    assert red.scrub("abc") == "abc"
    assert not red


def test_normalize_sensitivity_rejects_junk():
    with pytest.raises(ValueError):
        masking.normalize_sensitivity("top-secret")

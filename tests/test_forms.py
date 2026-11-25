import json
import urllib.error
import urllib.request

import pytest

from twin import masking
from twin.forms import FORM_HEADER, MAX_BODY, FormField, FormSession
from twin.vault import Vault

PASSWORD = "test-master-pw"


@pytest.fixture()
def vault_path(tmp_path):
    path = tmp_path / "vault.kdbx"
    Vault.create(path, PASSWORD)
    return path


def _session(vault_path, **kwargs):
    defaults = dict(
        title="demo",
        group="Group",
        fields=[FormField("username", "Username"), FormField("password", "Password", secret=True)],
        mode="single",
        open_vault=lambda pw: Vault.open(vault_path, pw),
        resolve_password=lambda: None,
        port=0,
        wait=10,
    )
    defaults.update(kwargs)
    return FormSession(**defaults)


def _post(url, payload, headers=None, raw=None):
    body = raw if raw is not None else json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", FORM_HEADER: "1"}
    hdrs.update(headers or {})
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    return urllib.request.urlopen(req, timeout=10)


def test_form_saves_record_and_returns_only_status(vault_path):
    s = _session(vault_path)
    url = s.start()
    page = urllib.request.urlopen(url, timeout=10).read().decode()
    assert "demo" in page
    assert "Content-Security-Policy" not in page  # header, not body

    with _post(url, {"username": "alice", "password": "s3cret-value", "__master__": PASSWORD}) as resp:
        payload = json.loads(resp.read())
        assert resp.headers["Cache-Control"].startswith("no-store")
    assert payload == {"ok": True, "entry": "demo"}

    result = s.wait(timeout=5)
    assert result.ok

    record = Vault.open(vault_path, PASSWORD).require("demo")
    assert record.value("password") == "s3cret-value"
    assert record.masked_dict()["fields"]["password"]["value"] == masking.HIDDEN


def test_wrong_master_password_is_reported_without_detail(vault_path):
    s = _session(vault_path)
    url = s.start()
    with _post(url, {"username": "alice", "password": "x", "__master__": "wrong"}) as resp:
        assert json.loads(resp.read()) == {"ok": False, "error": "master password wrong"}
    s.stop()


def test_missing_master_password(vault_path):
    s = _session(vault_path)
    url = s.start()
    with _post(url, {"username": "alice"}) as resp:
        assert json.loads(resp.read())["error"] == "master password required"
    s.stop()


def test_missing_custom_header_is_rejected(vault_path):
    s = _session(vault_path)
    url = s.start()
    req = urllib.request.Request(
        url,
        data=json.dumps({"username": "a"}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=10)
    assert exc.value.code == 415
    s.stop()


def test_wrong_path_is_404(vault_path):
    s = _session(vault_path)
    s.start()
    bad = s.url.replace(s.token, "x" * len(s.token))
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(bad, timeout=10)
    assert exc.value.code == 404
    s.stop()


def test_oversized_body_is_rejected(vault_path):
    s = _session(vault_path)
    url = s.start()
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(url, None, raw=b"{" + b"a" * (MAX_BODY + 10) + b"}")
    assert exc.value.code == 413
    s.stop()


def test_page_is_single_use(vault_path):
    s = _session(vault_path)
    url = s.start()
    with _post(url, {"username": "alice", "__master__": PASSWORD}) as resp:
        assert json.loads(resp.read())["ok"] is True
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(url, {"username": "bob", "__master__": PASSWORD})
    assert exc.value.code == 410
    s.wait(timeout=2)


def test_attempt_limit_shuts_down(vault_path):
    s = _session(vault_path, max_attempts=2)
    url = s.start()
    for _ in range(2):
        try:
            _post(url, {"username": "a", "__master__": "bad"})
        except urllib.error.HTTPError as exc:
            assert exc.code in (200, 429)
    with pytest.raises(urllib.error.HTTPError) as exc:
        _post(url, {"username": "a", "__master__": "bad"})
    assert exc.value.code in (410, 429)
    s.wait(timeout=2)


def test_title_is_html_escaped(vault_path):
    s = _session(vault_path, title='<script>alert(1)</script>')
    url = s.start()
    page = urllib.request.urlopen(url, timeout=10).read().decode()
    assert "<script>alert(1)</script>" not in page
    assert "&lt;script&gt;" in page
    s.stop()


def test_batch_mode_saves_multiple_records(vault_path):
    fields = [
        FormField("title", "Record name"),
        FormField("username", "Username"),
        FormField("password", "Password", secret=True),
    ]
    s = _session(vault_path, mode="batch", fields=fields)
    url = s.start()
    payload = {
        "__master__": PASSWORD,
        "items": [
            {"title": "one", "username": "a@example.com", "password": "p1"},
            {"title": "two", "username": "b@example.com", "password": "p2"},
            {"title": "", "username": "ignored"},
        ],
    }
    with _post(url, payload) as resp:
        result = json.loads(resp.read())
    assert len(result["results"]) == 3
    assert [r["ok"] for r in result["results"]] == [True, True, False]
    s.wait(timeout=5)
    v = Vault.open(vault_path, PASSWORD)
    assert v.require("one").value("password") == "p1"
    assert v.require("two").value("password") == "p2"


def test_duplicate_title_in_batch_is_reported_not_overwritten(vault_path):
    v = Vault.open(vault_path, PASSWORD)
    v.add("existing", values={"username": "keep"})
    fields = [FormField("title", "Record name"), FormField("username", "Username")]
    s = _session(vault_path, mode="batch", fields=fields)
    url = s.start()
    with _post(url, {"__master__": PASSWORD, "items": [{"title": "existing", "username": "new"}]}) as resp:
        result = json.loads(resp.read())
    assert result["results"][0]["ok"] is False
    s.wait(timeout=5)
    assert Vault.open(vault_path, PASSWORD).require("existing").value("username") == "keep"


def test_autounlock_removes_master_field(vault_path):
    s = _session(vault_path, resolve_password=lambda: PASSWORD)
    url = s.start()
    page = urllib.request.urlopen(url, timeout=10).read().decode()
    assert 'id="__master__"' not in page
    with _post(url, {"username": "alice", "password": "pw"}) as resp:
        assert json.loads(resp.read())["ok"] is True
    s.wait(timeout=5)

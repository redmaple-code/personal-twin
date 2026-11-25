import json

from twin import leakscan
from twin.vault import Vault

PASSWORD = "audit-master-pw"


def _detectors(tmp_path, values):
    path = tmp_path / "detectors.txt"
    path.write_text("\n".join(values), encoding="utf-8")
    return leakscan.load_detector_file(path)


def test_clean_tree_has_no_hits(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("nothing sensitive here")
    detectors = _detectors(tmp_path, ["alice@example.com"])
    hits = leakscan.scan([tmp_path / "docs"], detectors)
    assert hits == []


def test_hit_reports_location_not_value(tmp_path):
    target = tmp_path / "docs"
    target.mkdir()
    (target / "a.md").write_text("line one\nalice@example.com is in here\n")
    detectors = _detectors(tmp_path, ["alice@example.com"])
    hits = leakscan.scan([target], detectors)
    assert len(hits) == 1
    assert hits[0].line == 2
    rendered = leakscan.render_text(hits, 1)
    assert "alice@example.com" not in rendered
    assert "a.md:2" in rendered


def test_detector_file_supports_labels(tmp_path):
    path = tmp_path / "det.txt"
    path.write_text("email\talice@example.com\n", encoding="utf-8")
    det = leakscan.load_detector_file(path)
    assert det[0].label == "email"


def test_short_detectors_are_ignored(tmp_path):
    path = tmp_path / "det.txt"
    path.write_text("ab\nalice@example.com\n", encoding="utf-8")
    det = leakscan.load_detector_file(path)
    assert [d.value for d in det] == ["alice@example.com"]


def test_allowlist_and_binary_skip(tmp_path):
    target = tmp_path / "docs"
    target.mkdir()
    allowed = target / "allowed.md"
    allowed.write_text("alice@example.com")
    (target / "blob.md").write_bytes(b"\x00\x01alice@example.com")
    detectors = _detectors(tmp_path, ["alice@example.com"])
    hits = leakscan.scan([target], detectors, allowlist={str(allowed)})
    assert hits == []


def test_detectors_from_vault(tmp_path):
    vault = Vault.create(tmp_path / "v.kdbx", PASSWORD)
    vault.add("me", rtype="person", values={"email": "alice@example.com", "username": "alice"})
    det = leakscan.detectors_from_vault(vault)
    values = {d.value for d in det}
    assert "alice@example.com" in values
    # the label is the field name, never the record title
    assert all("me" != d.label for d in det)


def test_report_json_has_no_values(tmp_path):
    target = tmp_path / "docs"
    target.mkdir()
    (target / "a.md").write_text("alice@example.com")
    detectors = _detectors(tmp_path, ["alice@example.com"])
    hits = leakscan.scan([target], detectors)
    report = tmp_path / "report.json"
    leakscan.write_report(report, hits, 1)
    text = report.read_text()
    data = json.loads(text)
    assert data["hits"][0]["line"] == 1
    assert "alice@example.com" not in text

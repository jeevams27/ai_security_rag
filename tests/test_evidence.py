"""Unit tests for the evidence validator."""

from analysis.evidence_validator import EvidenceValidator


def _repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        "import os\n"
        "\n"
        "def run(cmd):\n"
        "    os.system(cmd)\n"
    )
    return repo


def test_valid_evidence_passes(tmp_path):
    repo = _repo(tmp_path)
    v = EvidenceValidator(repo)
    item = v.validate({
        "file": "app.py", "line": 4, "function": "run",
        "code": "os.system(cmd)", "reason": "user input into shell",
    })
    assert item.valid is True
    assert item.file == "app.py"
    assert item.validation_reason == "verified against repository"


def test_missing_file_rejected(tmp_path):
    repo = _repo(tmp_path)
    v = EvidenceValidator(repo)
    item = v.validate({
        "file": "ghost.py", "line": 1, "function": "x",
        "code": "os.system(x)", "reason": "invented",
    })
    assert item.valid is False
    assert "not found" in item.validation_reason


def test_line_out_of_range_rejected(tmp_path):
    repo = _repo(tmp_path)
    v = EvidenceValidator(repo)
    item = v.validate({
        "file": "app.py", "line": 99, "function": "run",
        "code": "os.system(cmd)", "reason": "bad line",
    })
    assert item.valid is False
    assert "out of range" in item.validation_reason


def test_fabricated_code_rejected(tmp_path):
    repo = _repo(tmp_path)
    v = EvidenceValidator(repo)
    item = v.validate({
        "file": "app.py", "line": 4, "function": "run",
        "code": "os.system('rm -rf /')", "reason": "not in file",
    })
    assert item.valid is False
    assert "does not appear" in item.validation_reason


def test_basename_match_resolves_file(tmp_path):
    repo = _repo(tmp_path)
    v = EvidenceValidator(repo)
    item = v.validate({
        "file": "src/deep/app.py", "line": 4, "function": "run",
        "code": "os.system(cmd)", "reason": "suffix path match",
    })
    assert item.valid is True
    assert item.file == "app.py"

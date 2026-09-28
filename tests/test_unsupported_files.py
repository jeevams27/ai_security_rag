"""Skipped-file visibility: unsupported uploads must be counted, not hidden."""

from ingestion.indexer import Indexer


def _write(path, content=b"x = 1\n"):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def test_only_unsupported_file_reports_skip(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "legacy_auth.php", b"<?php echo 'x'; ?>\n")

    stats = Indexer(embedder, store).index_repository(repo)

    assert stats.files == 0
    assert stats.code_units == 0
    assert stats.files_skipped == 1
    assert stats.skipped_files == ["legacy_auth.php"]
    d = stats.to_dict()
    assert d["files_skipped"] == 1 and d["skipped_files"] == ["legacy_auth.php"]


def test_mixed_repo_counts_supported_and_skipped(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "app.py", b"def f():\n    return 1\n")
    _write(repo / "server.rb", b"puts 'hi'\n")
    _write(repo / "main.rs", b"fn main() {}\n")

    stats = Indexer(embedder, store).index_repository(repo)

    assert stats.files == 1
    assert stats.languages == {"python": 1}
    assert stats.files_skipped == 2
    assert stats.skipped_files == ["main.rs", "server.rb"]


def test_supported_only_repo_has_no_skips(embedder, store, tmp_path):
    repo = tmp_path / "repo"
    _write(repo / "app.py", b"def f():\n    return 1\n")

    stats = Indexer(embedder, store).index_repository(repo)

    assert stats.files == 1
    assert stats.files_skipped == 0
    assert stats.skipped_files == []

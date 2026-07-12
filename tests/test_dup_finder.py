import pytest
import yaml
from click.testing import CliRunner

from dup_finder import DuplicateFinder, FileSize, main


def write_file(path, content: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


class TestConvertSize:
    def test_converts_bytes_to_kb_mb_gb(self):
        assert DuplicateFinder._convert_size(5 * 1024 * 1024) == FileSize(
            kb=5120, mb=5, gb=0
        )

    def test_zero_bytes(self):
        assert DuplicateFinder._convert_size(0) == FileSize(kb=0, mb=0, gb=0)


class TestIsImage:
    @pytest.fixture
    def finder(self, tmp_path):
        return DuplicateFinder(source_path=tmp_path, target_path=tmp_path)

    @pytest.mark.parametrize(
        "name", ["photo.jpg", "photo.JPG", "scan.PDF", "icon.png"]
    )
    def test_recognizes_image_extensions(self, finder, tmp_path, name):
        assert finder._is_image(tmp_path / name) is True

    @pytest.mark.parametrize("name", ["notes.txt", "archive.zip", "noext"])
    def test_rejects_non_image_extensions(self, finder, tmp_path, name):
        assert finder._is_image(tmp_path / name) is False


class TestCleanResults:
    def test_removes_entries_without_duplicates(self):
        source = {
            "hash-with-dupe": {"file": "a", "size": 1, "duplicate": ["b"]},
            "hash-without-dupe": {"file": "c", "size": 1, "duplicate": []},
        }

        assert list(DuplicateFinder._clean_results(source)) == ["hash-with-dupe"]


class TestFindDuplicates:
    def test_identical_files_are_flagged(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        write_file(target / "copy.txt", b"hello world")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        (details,) = finder.results.values()
        assert details["file"] == (source / "one.txt").absolute()
        assert details["duplicate"] == [(target / "copy.txt").absolute()]

    def test_same_size_different_content_not_flagged(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "a.bin", b"A" * 5000)
        write_file(target / "b.bin", b"B" * 5000)

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        assert finder.results == {}

    def test_unmatched_size_is_never_hashed(self, tmp_path, monkeypatch):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "unique.txt", b"nothing on the other side")
        write_file(target / "other.txt", b"different size!")

        finder = DuplicateFinder(source_path=source, target_path=target)

        def fail(*args, **kwargs):
            raise AssertionError("should not hash files with unmatched sizes")

        monkeypatch.setattr(finder, "_partial_hash", fail)
        finder.find_duplicates()

        assert finder.results == {}

    def test_large_identical_files_use_full_hash(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        payload = bytes(range(256)) * (DuplicateFinder.PARTIAL_HASH_SIZE // 128)
        assert len(payload) > DuplicateFinder.PARTIAL_HASH_SIZE
        write_file(source / "big.bin", payload)
        write_file(target / "big_copy.bin", payload)

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        assert len(finder.results) == 1

    def test_large_files_matching_prefix_but_differing_tail_not_flagged(
        self, tmp_path
    ):
        # Same size and same first PARTIAL_HASH_SIZE bytes, but differing
        # tail -- must be caught by the full-hash confirmation pass, not
        # accepted on the partial-hash match alone.
        source, target = tmp_path / "source", tmp_path / "target"
        prefix = b"x" * DuplicateFinder.PARTIAL_HASH_SIZE
        write_file(source / "big.bin", prefix + b"AAAA")
        write_file(target / "big.bin", prefix + b"BBBB")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        assert finder.results == {}

    def test_finds_nested_duplicates_by_default(self, tmp_path):
        # Directories are always searched recursively now -- no flag needed.
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "nested" / "deep.txt", b"deep content")
        write_file(target / "other" / "deep_copy.txt", b"deep content")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        assert len(finder.results) == 1

    def test_images_only_filters_non_image_files(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "photo.jpg", b"same bytes")
        write_file(source / "notes.txt", b"same bytes")
        write_file(target / "photo_copy.jpg", b"same bytes")
        write_file(target / "notes_copy.txt", b"same bytes")

        finder = DuplicateFinder(
            source_path=source, target_path=target, images_only=True
        )
        finder.find_duplicates()

        (details,) = finder.results.values()
        assert details["file"].name == "photo.jpg"
        assert details["duplicate"] == [(target / "photo_copy.jpg").absolute()]

    def test_single_file_source_against_directory_target(self, tmp_path):
        source_file, target = tmp_path / "source.txt", tmp_path / "target"
        write_file(source_file, b"shared content")
        write_file(target / "copy.txt", b"shared content")
        write_file(target / "irrelevant.txt", b"something else")

        finder = DuplicateFinder(source_path=source_file, target_path=target)
        finder.find_duplicates()

        (details,) = finder.results.values()
        assert details["duplicate"] == [(target / "copy.txt").absolute()]

    def test_multiple_duplicates_for_one_source_file(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"repeated content")
        write_file(target / "copy1.txt", b"repeated content")
        write_file(target / "copy2.txt", b"repeated content")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        (details,) = finder.results.values()
        assert sorted(p.name for p in details["duplicate"]) == [
            "copy1.txt",
            "copy2.txt",
        ]

    def test_delete_removes_only_confirmed_duplicates(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        content = b"repeated content"
        write_file(source / "one.txt", content)
        dup_target = target / "copy.txt"
        write_file(dup_target, content)
        # Same size as `content` but different bytes -- must survive deletion.
        same_size_target = target / "same_size.bin"
        write_file(same_size_target, b"x" * len(content))

        finder = DuplicateFinder(source_path=source, target_path=target, delete=True)
        finder.find_duplicates()

        assert not dup_target.exists()
        assert same_size_target.exists()


class TestSummary:
    def test_reports_file_and_duplicate_counts(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        write_file(target / "copy.txt", b"hello world")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()

        assert finder.summary() == {
            "files_with_duplicates": 1,
            "duplicate_count": 1,
            "duplicate_size_mb": 0,
        }


class TestPrintSummary:
    def test_prints_summary_as_yaml(self, tmp_path, capsys):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        write_file(target / "copy.txt", b"hello world")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()
        finder.print_summary()

        parsed = yaml.safe_load(capsys.readouterr().out)
        assert parsed == finder.summary()


class TestPrintResults:
    def test_prints_results_as_yaml(self, tmp_path, capsys):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        write_file(target / "copy.txt", b"hello world")

        finder = DuplicateFinder(source_path=source, target_path=target)
        finder.find_duplicates()
        finder.print_results()

        parsed = yaml.safe_load(capsys.readouterr().out)
        assert len(parsed) == 1
        (details,) = parsed.values()
        assert details["file"] == str((source / "one.txt").absolute())
        assert details["duplicate"] == [str((target / "copy.txt").absolute())]


class TestCli:
    def test_finds_duplicates_and_prints_yaml(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        write_file(target / "copy.txt", b"hello world")

        result = CliRunner().invoke(main, [str(source), str(target)])

        assert result.exit_code == 0
        parsed_docs = list(yaml.safe_load_all(result.stdout))
        results, summary = parsed_docs
        assert len(results) == 1
        assert summary["duplicate_count"] == 1

    def test_source_must_exist(self, tmp_path):
        missing_source = tmp_path / "does-not-exist"
        target = tmp_path / "target"
        target.mkdir()

        result = CliRunner().invoke(main, [str(missing_source), str(target)])

        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_delete_requires_confirmation(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        dup_target = target / "copy.txt"
        write_file(dup_target, b"hello world")

        result = CliRunner().invoke(
            main, [str(source), str(target), "--delete"], input="n\n"
        )

        assert result.exit_code != 0
        assert dup_target.exists()

    def test_delete_removes_duplicate_after_confirmation(self, tmp_path):
        source, target = tmp_path / "source", tmp_path / "target"
        write_file(source / "one.txt", b"hello world")
        dup_target = target / "copy.txt"
        write_file(dup_target, b"hello world")

        result = CliRunner().invoke(
            main, [str(source), str(target), "--delete"], input="y\n"
        )

        assert result.exit_code == 0
        assert not dup_target.exists()

import hashlib
import os
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

import click
import yaml
from tqdm import tqdm

__all__ = ["DuplicateFinder"]


@dataclass
class FileSize:
    kb: int
    mb: int
    gb: int


class DuplicateFinder:
    # Files at or under this size are hashed once; the "partial" hash already
    # covers the whole file, so no separate full-hash pass is needed for them.
    PARTIAL_HASH_SIZE = 64 * 1024

    def __init__(
        self,
        source_path: Path,
        target_path: Path,
        hash_algorithm: str = "blake2b",
        images_only: bool = False,
        delete: bool = False,
    ):
        self.source_path = Path(source_path)
        self.target_path = Path(target_path)
        self.hash_algorithm = hash_algorithm
        self.images_only = images_only
        self.delete = delete
        self.image_file_types = {"bmp", "jpg", "jpeg", "png", "gif", "pdf", "svg"}
        self.results = {}

    @staticmethod
    def _convert_size(size_in_bytes: int) -> FileSize:
        size_kb = size_in_bytes / 1024
        size_mb = size_kb / 1024
        size_gb = size_mb / 1024

        return FileSize(round(size_kb), round(size_mb), round(size_gb))

    @staticmethod
    def _clean_results(source_list: dict) -> dict:
        """Remove items where no duplicates were found."""
        return {k: v for k, v in source_list.items() if v.get("duplicate")}

    @staticmethod
    def _delete_duplicates(files: list[Path]) -> bool:
        """Delete the files in the list."""
        for file in tqdm(files, desc="Deleting duplicates..."):
            file.unlink()

        return True

    def _is_image(self, f: Path) -> bool:
        """Low effort attempt to identify an image file."""

        return f.suffix.lstrip(".").lower() in self.image_file_types

    def summary(self) -> dict:
        duplicate_counter = sum(len(v["duplicate"]) for v in self.results.values())
        total_dup_size = sum(v["size"] for v in self.results.values())

        return {
            "files_with_duplicates": len(self.results),
            "duplicate_count": duplicate_counter,
            "duplicate_size_mb": self._convert_size(total_dup_size).mb,
        }

    def print_summary(self) -> None:
        click.echo(yaml.safe_dump(self.summary(), sort_keys=False))

    def print_results(self) -> None:
        serializable = {
            file_hash: {
                "file": str(details["file"]),
                "size": details["size"],
                "duplicate": [str(p) for p in details["duplicate"]],
            }
            for file_hash, details in self.results.items()
        }
        click.echo(yaml.safe_dump(serializable, sort_keys=False, width=1000))

    def _new_hash(self):
        # A 32-byte digest is already far more collision-resistant than this
        # use case needs, and keeps the resulting hex key under YAML's
        # 128-character simple-key limit so results render as plain
        # `key: value` mappings instead of the verbose `? key` / `: value`
        # explicit-key form.
        kwargs = {"digest_size": 32} if self.hash_algorithm.startswith("blake2") else {}
        return hashlib.new(self.hash_algorithm, usedforsecurity=False, **kwargs)

    def _partial_hash(self, file_obj: Path) -> str:
        """Hash just the leading chunk of a file, to cheaply rule out mismatches."""

        h = self._new_hash()
        with open(file_obj, "rb") as fb:
            h.update(fb.read(self.PARTIAL_HASH_SIZE))

        return h.hexdigest()

    def _full_hash(self, file_obj: Path) -> str:
        """Hash the entire contents of a file, reading in fixed-size chunks."""

        h = self._new_hash()
        with open(file_obj, "rb") as fb:
            while block := fb.read(1024 * 1024):
                h.update(block)

        return h.hexdigest()

    def _walk(self, directory: Path):
        """
        Recursively yield (path, size) for every file under directory.

        Uses os.scandir directly instead of Path.rglob + a separate os.stat
        call, so each entry's type and size come from a single cached stat
        result (one syscall per entry) rather than two.
        """

        with os.scandir(directory) as it:
            for entry in it:
                if entry.is_dir(follow_symlinks=False):
                    yield from self._walk(Path(entry.path))
                elif entry.is_file():
                    path = Path(entry.path)
                    if self.images_only and not self._is_image(path):
                        continue
                    yield path, entry.stat().st_size

    def _build_file_list(self, src_dir: Path) -> list[dict]:
        """Build a list of {file, size} entries for a directory, unhashed."""

        if src_dir.is_file():
            return [{"file": src_dir, "size": src_dir.stat().st_size}]

        return [
            {"file": path, "size": size}
            for path, size in tqdm(
                list(self._walk(src_dir)), colour="#d3d3d3", desc=f"Scanning {src_dir}"
            )
        ]

    def _compute_partial_hashes(self, files: list[dict], desc: str) -> list[dict]:
        """Compute partial hashes for a list of candidate files, in parallel."""

        def work(entry: dict) -> dict:
            entry["partial_hash"] = self._partial_hash(entry["file"])
            entry["is_complete"] = entry["size"] <= self.PARTIAL_HASH_SIZE
            return entry

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(work, f) for f in files]
            for _ in tqdm(
                as_completed(futures), total=len(futures), colour="cyan", desc=desc
            ):
                pass

        return files

    def _compute_full_hashes(self, files: list[dict]) -> None:
        """Confirm candidates with a full-file hash, in parallel."""

        def work(entry: dict) -> None:
            entry["final_hash"] = self._full_hash(entry["file"])

        with ThreadPoolExecutor() as executor:
            futures = [executor.submit(work, f) for f in files]
            for _ in tqdm(
                as_completed(futures),
                total=len(futures),
                colour="yellow",
                desc="Confirming duplicates",
            ):
                pass

    def find_duplicates(self) -> None:
        source_files = self._build_file_list(self.source_path)
        target_files = self._build_file_list(self.target_path)

        # A file can only have a duplicate on the other side if some file
        # there shares its size, so files with a unique size never need to
        # be read at all.
        source_sizes = {f["size"] for f in source_files}
        target_sizes = {f["size"] for f in target_files}
        candidate_sizes = source_sizes & target_sizes

        source_candidates = [f for f in source_files if f["size"] in candidate_sizes]
        target_candidates = [f for f in target_files if f["size"] in candidate_sizes]

        source_candidates = self._compute_partial_hashes(
            source_candidates, desc="Partial hashing source"
        )
        target_candidates = self._compute_partial_hashes(
            target_candidates, desc="Partial hashing target"
        )

        source_by_partial = defaultdict(list)
        for entry in source_candidates:
            source_by_partial[(entry["size"], entry["partial_hash"])].append(entry)

        target_by_partial = defaultdict(list)
        for entry in target_candidates:
            target_by_partial[(entry["size"], entry["partial_hash"])].append(entry)

        confirm_keys = source_by_partial.keys() & target_by_partial.keys()

        to_full_hash = []
        for key in confirm_keys:
            for entry in source_by_partial[key] + target_by_partial[key]:
                if entry["is_complete"]:
                    entry["final_hash"] = entry["partial_hash"]
                else:
                    to_full_hash.append(entry)

        if to_full_hash:
            self._compute_full_hashes(to_full_hash)

        results = {}
        for key in confirm_keys:
            for entry in source_by_partial[key]:
                results.setdefault(
                    entry["final_hash"],
                    {
                        "file": entry["file"].absolute(),
                        "size": entry["size"],
                        "duplicate": [],
                    },
                )

        to_delete = []
        for key in confirm_keys:
            for entry in target_by_partial[key]:
                match = results.get(entry["final_hash"])
                if match is None:
                    continue

                file: Path = entry["file"]
                match["duplicate"].append(file.absolute())
                if self.delete:
                    to_delete.append(file)

        self.results = self._clean_results(results)

        if self.delete:
            click.echo("Deleting duplicates...")
            self._delete_duplicates(to_delete)


@click.command()
@click.argument("source", type=click.Path(exists=True, path_type=Path))
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option(
    "-i",
    "--images",
    "images_only",
    is_flag=True,
    help="Only search for image files.",
)
@click.option(
    "-d",
    "--delete",
    is_flag=True,
    help="Delete duplicates found in TARGET. Confirmation required.",
)
def main(source: Path, target: Path, images_only: bool, delete: bool) -> None:
    """
    Find files in TARGET that duplicate files in SOURCE.

    SOURCE and TARGET may each be a single file or a directory, and
    directories are always searched recursively.
    """

    if delete:
        click.confirm(
            "This will delete duplicate files in the target path. Are you sure?",
            abort=True,
        )

    duplicate_finder = DuplicateFinder(
        source_path=source,
        target_path=target,
        images_only=images_only,
        delete=delete,
    )
    duplicate_finder.find_duplicates()

    duplicate_finder.print_results()
    click.echo("---")
    duplicate_finder.print_summary()


if __name__ == "__main__":
    main()

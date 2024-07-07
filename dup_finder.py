import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path

from tqdm import tqdm

__all__ = ["DuplicateFinder"]


@dataclass
class FileSize:
    kb: int
    mb: int
    gb: int


class DuplicateFinder:
    def __init__(
        self,
        source_path: Path,
        target_path: Path,
        hash_algorithm: str = "sha256",
        images_only: bool = False,
        recursive: bool = False,
        delete: bool = False,
    ):
        self.source_path = source_path
        self.target_path = target_path
        self.recursive = recursive
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

        original = source_list.copy()

        for k, v in tqdm(
            original.items(),
            colour="green",
            desc="Cleaning up results",
            total=len(original),
        ):
            if len(v.get("duplicate")) == 0:
                source_list.pop(k)

        return source_list

    @staticmethod
    def _delete_duplicates(files: list[Path]) -> bool:
        """Delete the files in the list."""
        for file in tqdm(files, desc="Deleting duplicates..."):
            file.unlink()

        return True

    def _is_image(self, f: Path) -> bool:
        """
        Low effort attempt to identify an image file.

        Args:
            f:

        Returns:

        """

        return (
            False
            if not f.suffix.split(".")[-1].lstrip(".").lower() in self.image_file_types
            else True
        )

    def print_summary(self):
        duplicate_counter = 0
        total_dup_size = 0
        for file_hash, file_details in self.results.items():
            duplicate_counter += len(file_details["duplicate"])
            total_dup_size += file_details["size"]

        if duplicate_counter > 0:
            print(json.dumps(self.results, indent=2, default=str))

        print(
            f"{len(self.results)} {'file' if len(self.results) < 2 else 'files'}, {duplicate_counter} duplicates (--print for details)"
        )
        print(f"Size of all duplicates: {self._convert_size(total_dup_size).mb} MB")

    def _get_hash(self, file_obj: Path) -> dict:
        """
        Read a file bytes and generate a hash.

        Args:
            file_obj:

        Returns:

        """

        if file_obj.is_dir():
            pass

        h = hashlib.new(self.hash_algorithm)
        file_stat = file_obj.stat()
        pbar = tqdm(
            total=file_stat.st_size,
            desc=f"Checking {file_obj.name}",
            leave=False,
        )
        with open(file_obj, "rb") as fb:
            block = fb.read()
            while block:
                h.update(block)
                pbar.update(len(block))
                block = fb.read()

        pbar.close()

        return {"file": file_obj, "hash": h.hexdigest()}

    def _read_dir(
        self,
        source_dir: Path,
    ) -> list[Path]:
        """
        Read everything in a directory.

        Args:
            source_dir: Source file or path

        Returns:

        """

        if self.recursive:
            file_list = [path for path in source_dir.rglob("*")]

            return file_list

        return [path for path in source_dir.iterdir()]

    def _build_file_list(self, src_dir: str | Path, images: bool) -> list[dict]:
        """
        Build a list of files for a given directory.

        Args:
            src_dir: Directory to scan
            images: Only look for image files

        Returns:

        """

        file_list = []

        if src_dir.is_file():
            return [self._get_hash(src_dir)]

        dir_files = self._read_dir(src_dir)

        with tqdm(
            enumerate(dir_files), colour="#d3d3d3", total=len(dir_files)
        ) as progress_bar:
            for idx, obj in progress_bar:
                if obj.is_dir():
                    continue

                if images:
                    if obj.is_file() and self._is_image(obj):
                        progress_bar.set_description(f"Reading: {src_dir}")
                        file_list.append(self._get_hash(obj))
                else:
                    progress_bar.set_description(f"Reading {src_dir}")
                    file_list.append(self._get_hash(obj))

        return file_list

    def find_duplicates(self):
        """

        Args:

        Returns:
            dict

        """

        source_list: list[dict] = self._build_file_list(
            Path(self.source_path), images=self.images_only
        )
        target_list: list[dict] = self._build_file_list(
            Path(self.target_path), images=self.images_only
        )

        source_list: dict = {
            source_file.get("hash"): {
                "file": source_file.get("file").absolute(),
                "size": os.stat(source_file.get("file")).st_size,
                "duplicate": [],
            }
            for source_file in source_list
        }

        source_list_hashes = source_list.keys()
        to_delete = []

        for target_file in tqdm(
            target_list, colour="yellow", desc="Identifying duplicates"
        ):
            if target_file.get("hash") in source_list_hashes:
                if self.delete:
                    to_delete.append(target_file.get("file"))
                file: Path = target_file.get("file")
                source_list[target_file.get("hash")]["duplicate"].append(
                    file.absolute()
                )

        self.results = self._clean_results(source_list)

        if self.delete:
            print("Deleting duplicates...")
            self._delete_duplicates(to_delete)


def run_with_args(runtime_args: argparse.Namespace):
    if runtime_args.delete:
        confirm = input(
            "This will delete duplicate files in the target path. Are you sure? (y|N)"
        )
        if not confirm.lower() in ["y", "yes"]:
            raise SystemExit(
                f"Operation cancelled by user. Delete answer was: {confirm}"
            )

    duplicate_finder = DuplicateFinder(
        source_path=runtime_args.source,
        target_path=runtime_args.target,
        recursive=runtime_args.recursive,
        images_only=runtime_args.images,
        delete=runtime_args.delete,
    )

    duplicate_finder.find_duplicates()

    if runtime_args.print_summary:
        duplicate_finder.print_summary()


def parse_arguments():
    """Parse arguments and return the results."""

    parser = argparse.ArgumentParser(description="Find duplicate files")
    parser.set_defaults(func=run_with_args)
    parser.add_argument(
        "-s",
        "--source",
        type=str,
        help="File or path of original files",
        required=True,
    )
    parser.add_argument(
        "-t",
        "--target",
        type=str,
        help="Directory to search",
        required=True,
    )
    parser.add_argument(
        "-r",
        "--recursive",
        help="Recurse into subdirectories",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-f",
        "--fast",
        help="Read a small portion of files, faster but potentially less accurate",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-i",
        "--images",
        help="Only search for image files",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-p",
        "--print",
        dest="print_summary",
        help="Print results to stdout",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-d",
        "--delete",
        help="Delete duplicates. Confirmation required.",
        default=False,
        action="store_true",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()
    args.func(args)

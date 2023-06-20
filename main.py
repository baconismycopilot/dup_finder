import argparse
import json
import os
from dataclasses import dataclass
from hashlib import sha1
from pathlib import Path

from tqdm import tqdm

file_types = ["bmp", "jpg", "jpeg", "png", "gif", "pdf", "svg"]


@dataclass
class FileSize:
    kb: int
    mb: int
    gb: int


def get_hash(file_obj: Path) -> str:
    """
    Read a file and generate a hash.

    :param file_obj: Path object
    :type file_obj: :class:`Path`

    :return: SHA1 hash
    :rtype: :class:`str`
    """

    if not file_obj.is_file():
        pass

    b = file_obj.read_bytes()
    h = sha1(b).hexdigest()

    del b

    return h


def read_dir(source_dir: Path, recursive: bool) -> list[Path]:
    """
    Read everything in a directory.

    :param source_dir: Directory of the source files
    :type source_dir: :class:`Path`
    :param recursive: Read subdirectories
    :type recursive: :class:`bool`

    :return: List of :class:`Path` objects
    :rtype: :class:`list[Path]`
    """

    files = []
    if isinstance(source_dir, Path):
        if recursive:
            files = list(source_dir.rglob("*"))
        else:
            files = list(source_dir.iterdir())

    return files


def is_image(f: Path) -> bool:
    """
    Low effort attempt to identify an image file.

    :param f: :class:`Path` object
    :type f: :class:`Path`

    :rtype: :class:`bool`
    """

    if not f.suffix.split(".")[-1].lstrip(".").lower() in file_types:
        return False

    return True


def delete_duplicates(file_list: list):
    """
    Takes a list of file paths to delete.

    :param file_list:
    :return:
    """
    # trash = os.path.expanduser('~/.Trash')
    for idx, file in tqdm(enumerate(file_list), colour="red", total=len(file_list), desc="Deleting duplicates"):
        Path(file).unlink(missing_ok=True)


def build_file_list(src_dir: str | Path, recursive: bool, images: bool) -> list[dict]:
    """
    Build a list of files for a given directory.

    :param src_dir: Directory to scan
    :type src_dir: :class:`str | Path`
    :param recursive: Scan subdirectories
    :type recursive: :class:`bool`
    :param images: Only look for images
    :type images: :class:`bool`

    :return:
    :rtype: :class:`list[dict`
    """

    file_list = []
    dir_files = read_dir(src_dir, recursive=recursive)
    pbar = tqdm(enumerate(dir_files), colour="#d3d3d3", total=len(dir_files))

    for idx, obj in pbar:
        if obj.is_dir():
            continue
        if not images:
            pbar.set_description(f"Reading {src_dir}")
            file_list.append(
                {"file": obj, "size": obj.stat().st_size, "hash": get_hash(obj)}
            )
        else:
            if obj.is_file() and is_image(obj):
                pbar.set_description(f"Reading {src_dir}")
                file_list.append(
                    {"file": obj, "size": obj.stat().st_size, "hash": get_hash(obj)}
                )

    pbar.close()

    return file_list


def find_duplicates(
        src_list: str, target_list: str, recursive: bool, remove_zero: bool, images: bool, delete: bool
) -> dict:
    """
    Find duplicates of files in `src_list` in `dup_list`.

    :param src_list: Directory of originals
    :type src_list: :class:`str`
    :param target_list: Directory to search for duplicates
    :type: :class:`str`
    :param recursive: Recurse into subdirectories
    :param remove_zero: Remove items from results without duplicates
    :type remove_zero: :class:`bool`
    :param images: Only search for image files
    :type images: :class:`bool`
    :param delete: Delete duplicates
    :type delete: :class:`bool`

    :return: Original ``dict`` of files with respective duplicates
    or ``dict`` of files with only duplicates [remove_zero]
    :rtype: :class:`dict`
    """

    source_path: list[dict] = build_file_list(
        Path(src_list), recursive=recursive, images=images
    )
    target_path: list[dict] = build_file_list(
        Path(target_list), recursive=recursive, images=images
    )
    duplicates: dict = {
        k.get("hash"): {
            "file": k.get("file"),
            "size": os.stat(k.get("file")).st_size,
            "duplicates": [],
        }
        for k in source_path
    }

    for dup in tqdm(target_path, colour="yellow", desc="Identifying duplicates"):
        if dup.get("hash") in duplicates.keys():
            duplicate_file: Path = dup.get("file")
            duplicates[dup.get("hash")]["duplicates"].append(
                {"path": duplicate_file.absolute(), "size": duplicate_file.stat().st_size}
            )

    if remove_zero:
        no_dups = []

        for k, v in duplicates.items():
            if len(v.get("duplicates")) == 0:
                no_dups.append(k)

        if len(no_dups) == 0:
            return duplicates

        for x in tqdm(
                no_dups,
                colour="green",
                desc="Removing items with no matches",
                total=len(no_dups),
        ):
            duplicates.pop(x)

    if delete:
        to_delete = []
        for key, value in duplicates.items():
            for file in value['duplicates']:
                to_delete.append(file['path'])

        delete_duplicates(to_delete)

    return duplicates


def pretty_dump(data: list | list[dict] | dict):
    print(json.dumps(data, indent=2, default=str))


def convert_size(size_in_bytes: int):
    size_kb = size_in_bytes / 1024
    size_mb = size_kb / 1024
    size_gb = size_mb / 1024

    return FileSize(round(size_kb), round(size_mb), round(size_gb))


def print_summary(data: list | list[dict] | dict):
    dc = 0
    total_dup_size = 0
    for file, result in dups.items():
        if len(result["duplicates"]) > 0:
            dc += len(result["duplicates"])
            total_dup_size += result["size"]

    if args.print and dc > 0:
        print(f"Duplicate Count: {dc}")
        pretty_dump(dups)

    print(
        f"{len(data)} {'file' if len(data) < 2 else 'files'}, {dc} duplicates, Size of all duplicates: {convert_size(total_dup_size).mb} MB"
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Find duplicate files")
    parser.add_argument(
        "--source",
        metavar="source",
        type=str,
        help="Directory of original files",
        required=True,
    )
    parser.add_argument(
        "--target",
        metavar="target",
        type=str,
        help="Directory to search",
        required=True,
    )
    parser.add_argument(
        "--recursive",
        help="Recurse into subdirectories",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--reduce",
        help="Omit files from results with no duplicates",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--images", help="Search only for images", default=False, action="store_true"
    )
    parser.add_argument(
        "--print",
        help="Print results to stdout, defaults is summary output",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "--delete",
        help="Delete duplicates",
        default=False,
        action="store_true",
    )

    args = parser.parse_args()

    dups = find_duplicates(
        src_list=args.source,
        target_list=args.target,
        recursive=args.recursive,
        remove_zero=args.reduce,
        images=args.images,
        delete=args.delete
    )

    print_summary(data=dups)

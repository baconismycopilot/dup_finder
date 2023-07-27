import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Callable

from tqdm import tqdm

FILE_TYPES = ["bmp", "jpg", "jpeg", "png", "gif", "pdf", "svg"]


@dataclass
class FileSize:
    kb: int
    mb: int
    gb: int


def get_hash(file_obj: Path, alg: str | None = "sha256") -> dict:
    """
    Read a file bytes and generate a hash.

    :param file_obj: Path object
    :type file_obj: :class:`Path`
    :param alg: Hash algorithm to use, refer to `hashlib` docs
    :type alg: :class:`str`

    :return: :class:`dict` with :class:`Path` object and :class:`hash` object
    :rtype: :class:`dict`
    """

    if file_obj.is_dir():
        pass

    h = hashlib.new(alg)
    pbar = tqdm(total=file_obj.stat().st_size, desc=f"Checking {file_obj.name}", leave=False)
    with open(file_obj.absolute(), 'rb') as fb:
        if args.fast:
            block = fb.read(4096)
            h.update(block)
            return {"file": file_obj, "hash": h.hexdigest()}

        block = fb.read(512)
        while block:
            h.update(block)
            pbar.update(len(block))
            block = fb.read(512)

    pbar.close()

    return {"file": file_obj, "hash": h.hexdigest()}


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

    if not f.suffix.split(".")[-1].lstrip(".").lower() in FILE_TYPES:
        return False

    return True


def do_big_task(func_name: Callable, func_args: list):
    """Take advantage of multiprocessing and use half
    of the available cores to perform this task."""

    cpus = int(cpu_count() / 2)

    with Pool(cpus) as pool:
        res = pool.map(func_name, func_args)

    pool.join()

    return res


def delete_duplicates(files: list[Path]) -> bool:
    """Delete the files in the list."""
    for file in tqdm(files, desc="Deleting duplicates..."):
        file.unlink()

    return True


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
    :rtype: :class:`list[dict]`
    """

    to_hash = []
    file_list = []

    if src_dir.is_file():
        return [get_hash(src_dir)]

    dir_files = read_dir(src_dir, recursive=recursive)

    with tqdm(enumerate(dir_files), colour="#d3d3d3", total=len(dir_files)) as pb:
        for idx, obj in pb:
            if obj.is_dir():
                continue
            if images:
                if obj.is_file() and is_image(obj):
                    pb.set_description(f"Reading: {src_dir}")
                    if args.multithread:
                        to_hash.append(obj)
                    else:
                        file_list.append(get_hash(obj))
            else:
                pb.set_description(f"Reading {src_dir}")
                if args.multithread:
                    to_hash.append(obj)
                else:
                    file_list.append(get_hash(obj))

    if args.multithread:
        res = do_big_task(get_hash, to_hash)

        return res

    return file_list


def clean_results(source_list: dict) -> dict:
    """Remove items where no duplicates were found."""

    original = source_list.copy()

    for k, v in tqdm(original.items(), colour="green", desc="Cleaning up results", total=len(original)):
        if len(v.get("duplicate")) == 0:
            source_list.pop(k)

    return source_list


def find_duplicates(
        src_list: str, target_list: str, recursive: bool, images: bool, delete: bool = False
) -> dict:
    """
    Find duplicates of files from `src_list` in `dup_list`.

    :param src_list: File or path of originals
    :type src_list: :class:`str`
    :param target_list: Directory to search for duplicates
    :type: :class:`str`
    :param recursive: Recurse into subdirectories
    :param images: Only search for image files
    :type images: :class:`bool`
    :param delete: Delete duplicates in the target path
    :type delete: :class:`bool`

    :return: Original ``dict`` of files with respective duplicates
    :rtype: :class:`dict`
    """

    source_path: list[dict] = build_file_list(
        Path(src_list), recursive=recursive, images=images
    )
    target_path: list[dict] = build_file_list(
        Path(target_list), recursive=recursive, images=images
    )

    source_list: dict = {
        k.get("hash"): {
            "file": k.get("file").absolute(),
            "size": os.stat(k.get("file")).st_size,
            "duplicate": []} for k in source_path
    }

    source_list_hashes = source_list.keys()
    to_delete = []

    for target_file in tqdm(target_path, colour="yellow", desc="Identifying duplicates"):
        if target_file.get("hash") in source_list_hashes:
            if delete:
                to_delete.append(target_file.get("file"))
            t: Path = target_file.get("file")
            source_list[target_file.get("hash")]["duplicate"].append(t.absolute())

    results = clean_results(source_list)
    delete_duplicates(to_delete)

    return results


def convert_size(size_in_bytes: int):
    size_kb = size_in_bytes / 1024
    size_mb = size_kb / 1024
    size_gb = size_mb / 1024

    return FileSize(round(size_kb), round(size_mb), round(size_gb))


def pretty_dump(data: list | list[dict] | dict):
    print(json.dumps(data, indent=2, default=str))


def print_summary(data: list | list[dict] | dict):
    duplicate_counter = 0
    total_dup_size = 0
    for file_hash, file_details in duplicates.items():
        duplicate_counter += len(file_details["duplicate"])
        total_dup_size += file_details["size"]

    if args.print:
        pretty_dump(duplicates)

    print(f"{len(data)} {'file' if len(data) < 2 else 'files'}, {duplicate_counter} duplicates (--print for details)")
    print(f"Size of all duplicates: {convert_size(total_dup_size).mb} MB")


def parse_arguments():
    """Parse arguments and return the results."""

    parser = argparse.ArgumentParser(description="Find duplicate files")
    parser.add_argument(
        "-s", "--source",
        type=str,
        help="File or path of original files",
        required=True,
    )
    parser.add_argument(
        "-t", "--target",
        type=str,
        help="Directory to search",
        required=True,
    )
    parser.add_argument(
        "-r", "--recursive",
        help="Recurse into subdirectories",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-f", "--fast",
        help="Read a small portion of files, faster but potentially less accurate",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-i", "--images", help="Only search for image files",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-m", "--multithread",
        help="Use multiprocessing for large batches, defaults to half of available cores",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-p", "--print",
        help="Print results to stdout",
        default=False,
        action="store_true",
    )
    parser.add_argument(
        "-d", "--delete",
        help="Delete duplicates. This is irreversible. You will need to confirm.",
        default=False,
        action="store_true"
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    if args.delete:
        confirm = input("This will delete duplicate files in the target path. Are you sure? (y|N)")
        if not confirm.lower() in ['y', 'yes']:
            raise RuntimeError(f"Operation cancelled by user. Delete answer was: {confirm}")

    duplicates = find_duplicates(
        src_list=args.source,
        target_list=args.target,
        recursive=args.recursive,
        images=args.images,
        delete=args.delete
    )

    print_summary(data=duplicates)

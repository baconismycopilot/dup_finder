import argparse
import json
from hashlib import sha1
from multiprocessing import Pool, cpu_count
from pathlib import Path
from typing import Callable

from tqdm import tqdm

FILE_TYPES = ["bmp", "jpg", "jpeg", "png", "gif", "pdf", "svg"]


def get_hash(file_obj: list[Path]) -> list[dict]:
    """
    Read a file and generate a hash.

    :param file_obj: Path object
    :type file_obj: :class:`Path`

    :return: SHA1 hash
    :rtype: :class:`list[dict]`
    """

    results = []

    for f in file_obj:
        if not f.is_file():
            pass

        with open(f, 'rb') as fb:
            if args.quick:
                b = fb.read(4096)
            else:
                b = fb.read()

            h = sha1(b).hexdigest()

        results.append({"file": f, "hash": h})

    return results


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


def do_big_task(func_name: Callable, func_args):
    """Use half of available CPUs to perform this task."""

    cpus = int(cpu_count() / 2)
    with Pool(cpus) as pool:
        res = pool.map(func_name, func_args)

    return res


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
                        file_list.append(get_hash([obj])[0])
            else:
                pb.set_description(f"Reading {src_dir}")
                if args.multithread:
                    to_hash.append(obj)
                else:
                    file_list.append(get_hash([obj])[0])

    if args.multithread:
        res = do_big_task(get_hash, [to_hash])
        return res[0]

    return file_list


def find_duplicates(
        src_list: str, dup_list: str, recursive: bool, images: bool
) -> dict:
    """
    Find duplicates of files in `src_list` in `dup_list`.

    :param src_list: Directory of originals
    :type src_list: :class:`str`
    :param dup_list: Directory to search for duplicates
    :type: :class:`str`
    :param recursive: Recurse into subdirectories
    :param images: Only search for image files
    :type images: :class:`bool`

    :return: Original ``dict`` of files with respective duplicates
    :rtype: :class:`dict`
    """

    list_one: list[dict] = build_file_list(
        Path(src_list), recursive=recursive, images=images
    )
    list_two: list[dict] = build_file_list(
        Path(dup_list), recursive=recursive, images=images
    )

    source_list: dict = {
        k.get("hash"): {"file": k.get("file"), "duplicate": []} for k in list_one
    }

    source_list_hashes = source_list.keys()

    for target_file in tqdm(list_two, colour="yellow", desc="Identifying duplicates"):
        if target_file.get("hash") in source_list_hashes:
            t: Path = target_file.get("file")
            source_list[target_file.get("hash")]["duplicate"].append(t.absolute())

    no_dups = []

    for k, v in source_list.items():
        if len(v.get("duplicate")) == 0:
            no_dups.append(k)

    if len(no_dups) == 0:
        return source_list

    for x in tqdm(no_dups, colour="green", desc="Cleaning up results.", total=len(no_dups)):
        source_list.pop(x)

    return source_list


def pretty_dump(data: list | list[dict] | dict):
    print(json.dumps(data, indent=2, default=str))


def print_summary(data: list | list[dict] | dict, dup_count: int):
    print(f"{len(data)} {'file' if len(data) < 2 else 'files'}, {dup_count} duplicates (--print for details)")


def parse_arguments():
    """Parse arguments and return the results."""

    parser = argparse.ArgumentParser(description="Find duplicate files")
    parser.add_argument(
        "-s", "--source",
        type=str,
        help="Directory of original files",
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
        "-q", "--quick",
        help="Read a small portion of files, faster but potentially less accurate",
        default=False,
        action="store_true"
    )
    parser.add_argument(
        "-i", "--images", help="Only search for image files", default=False, action="store_true"
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

    return parser.parse_args()


if __name__ == "__main__":
    args = parse_arguments()

    dups = find_duplicates(
        src_list=args.source,
        dup_list=args.target,
        recursive=args.recursive,
        images=args.images,
    )

    dc = 0
    for file, result in dups.items():
        if len(result["duplicate"]) > 0:
            dc += len(result["duplicate"])

    if args.print and dc > 0:
        pretty_dump(dups)

    print_summary(data=dups, dup_count=dc)

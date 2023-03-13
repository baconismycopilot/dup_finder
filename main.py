import json
import sys
from hashlib import sha1
from pathlib import Path

from tqdm import tqdm


def get_hash(file_obj: Path) -> str:
    if not file_obj.is_file():
        pass

    b = file_obj.read_bytes()
    h = sha1(b).hexdigest()

    del b

    return h


def read_dir(_dir: Path) -> list[Path]:
    files = []

    if isinstance(_dir, Path):
        files = _dir.rglob("*")

    return files


def is_image(f: Path) -> bool:
    file_types = ['bmp', 'jpg', 'jpeg', 'png', 'gif', 'pdf', 'svg']

    if not f.suffix.split('.')[-1].lstrip('.').lower() in file_types:
        return False

    return True


def build_file_list(src_dir: str | Path) -> list[dict]:
    file_list = []

    for idx, obj in tqdm(list(enumerate(read_dir(src_dir))), colour='yellow', miniters=1, desc=f"Reading files in {src_dir}"):
        if obj.is_file() and is_image(obj):
            file_list.append({"file": obj, "hash": get_hash(obj)})

    return file_list


def find_duplicates(src_list: str, dup_list: str):
    list_one: list[dict] = build_file_list(Path(src_list))
    list_two: list[dict] = build_file_list(Path(dup_list))
    duplicates: dict = {k.get('hash'): {'file': k.get('file'), 'duplicate': []} for k in list_one}
    # print(json.dumps(duplicates, indent=2, default=str))

    for file in tqdm(list_one, desc="Looking for duplicates"):
        for dup in list_two:
            if file.get('hash') == dup.get('hash'):
                t: Path = dup.get('file')
                duplicates[file.get('hash')]['duplicate'].append(t.absolute())

    return duplicates


if __name__ == '__main__':
    dupes = find_duplicates(src_list=sys.argv[1], dup_list=sys.argv[2])

    if len(dupes) > 0:
        print(json.dumps(dupes, indent=2, default=str))
        print(f"Found {len(dupes)} duplicate files.")

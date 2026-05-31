#!/usr/bin/env python3
"""
dupfinder - Terminal-native duplicate file finder with visual progress.
Refactored to use Click for CLI handling and modular ETL pipeline functions.
"""

import csv
import hashlib
import json
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Tuple

import click

# --- Configuration ---
CHUNK_SIZE = 65536
FIRST_CHUNK_SIZE = 1024


class ProgressBar:
    """Simple ANSI-based progress bar that updates in place."""

    def __init__(self, total: int, label: str, width: int = 40) -> None:
        self.total = total
        self.current = 0
        self.label = label
        self.width = width
        self.enabled = sys.stdout.isatty() and sys.stdout.encoding is not None
        self._update_display()

    def _update_display(self) -> None:
        """Render the progress bar."""
        if not self.enabled or self.total == 0:
            return

        percent = min(100.0, (self.current / self.total) * 100)
        filled = int(self.width * (self.current / self.total))
        bar = "=" * filled + "-" * (self.width - filled)

        label = self.label[:15] if len(self.label) > 15 else self.label
        output = f"\r{label:<16} [{bar}] {percent:5.1f}% ({self.current}/{self.total})"

        sys.stdout.write(output)
        sys.stdout.flush()

    def update(self, n: int = 1) -> None:
        """Increment progress."""
        self.current += n
        if self.enabled:
            self._update_display()

    def finish(self) -> None:
        """Finalize and move to next line."""
        if self.enabled:
            sys.stdout.write("\r\033[K")
            percent = 100.0
            bar = "=" * self.width
            label = self.label[:15] if len(self.label) > 15 else self.label
            sys.stdout.write(
                f"\r{label:<16} [{bar}] {percent:5.1f}% ({self.current}/{self.total})\n"
            )
            sys.stdout.flush()
        else:
            sys.stderr.write(f"{self.label}: Complete ({self.current}/{self.total})\n")


def get_hash(path: Path, full: bool = True) -> Optional[str]:
    """Compute hash. Returns None on error."""
    algo = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            if full:
                while chunk := f.read(CHUNK_SIZE):
                    algo.update(chunk)
            else:
                algo.update(f.read(FIRST_CHUNK_SIZE))
        return algo.hexdigest()
    except (OSError, IOError, PermissionError):
        return None


def get_size(path: Path) -> int:
    """Get file size. Returns -1 on error."""
    try:
        return path.stat().st_size
    except (OSError, IOError):
        return -1


def collect_files(
    root: Path, min_size: int, max_size: Optional[int], exclude_exts: set
) -> List[Path]:
    """Walk directory and filter files."""
    total_count = sum(1 for p in root.rglob("*") if p.is_file())

    pb = ProgressBar(total_count, "Scanning files")
    files: List[Path] = []

    for p in root.rglob("*"):
        if not p.is_file():
            pb.update()
            continue
        if p.name.startswith("."):
            pb.update()
            continue
        if p.suffix.lower() in exclude_exts:
            pb.update()
            continue

        sz = get_size(p)
        if sz < 0 or sz == 0:
            pb.update()
            continue
        if sz < min_size:
            pb.update()
            continue
        if max_size and sz > max_size:
            pb.update()
            continue

        files.append(p)
        pb.update()

    pb.finish()
    return files


# --- ETL Pipeline Stages ---

def stage_extract(
    root: Path, min_size: int, max_size: Optional[int], exclude_exts: set
) -> Tuple[List[Path], int]:
    """
    STAGE 1: EXTRACT
    Collect all valid files from the directory tree.
    Returns: (List of files, total count)
    """
    all_files = collect_files(root, min_size, max_size, exclude_exts)
    return all_files, len(all_files)


def stage_transform_size(all_files: List[Path]) -> List[List[Path]]:
    """
    STAGE 2: TRANSFORM (Size)
    Group files by size. Filter to keep only groups with 2+ files.
    Returns: List of file lists (candidates)
    """
    size_map: dict[int, List[Path]] = defaultdict(list)
    for f in all_files:
        sz = get_size(f)
        if sz > 0:
            size_map[sz].append(f)

    size_candidates = [flist for flist in size_map.values() if len(flist) >= 2]
    return size_candidates


def stage_transform_partial_hash(
    candidates: List[List[Path]], workers: int
) -> List[List[Path]]:
    """
    STAGE 3: TRANSFORM (Partial Hash)
    Hash first 1KB of candidates. Filter to keep only groups with 2+ matches.
    Returns: List of file lists (candidates)
    """
    flat_candidates = [f for flist in candidates for f in flist]
    pb = ProgressBar(len(flat_candidates), "Partial Hashing (1KB)")
    partial_map: dict[str, List[Path]] = defaultdict(list)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(get_hash, f, False): f for f in flat_candidates}
        for fut in as_completed(futures):
            h = fut.result()
            if h:
                f = futures[fut]
                partial_map[h].append(f)
            pb.update()
    pb.finish()

    partial_candidates = [flist for flist in partial_map.values() if len(flist) >= 2]
    return partial_candidates


def stage_transform_full_hash(
    candidates: List[List[Path]], workers: int
) -> dict[str, List[str]]:
    """
    STAGE 4: TRANSFORM (Full Hash)
    Hash full content of candidates.
    Returns: Dictionary mapping hash to list of file paths.
    """
    flat_candidates = [f for flist in candidates for f in flist]
    pb = ProgressBar(len(flat_candidates), "Full Hashing")
    full_map: dict[str, List[str]] = defaultdict(list)

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(get_hash, f, True): f for f in flat_candidates}
        for fut in as_completed(futures):
            h = fut.result()
            if h:
                f = futures[fut]
                full_map[h].append(str(f))
            pb.update()
    pb.finish()

    return full_map


def stage_load(full_map: dict[str, List[str]]) -> List[Tuple[str, List[str]]]:
    """
    STAGE 5: LOAD
    Aggregate final groups and sort by wasted space (descending).
    Returns: List of (hash, paths) tuples.
    """
    results: List[Tuple[str, List[str]]] = []
    for _h, paths in full_map.items():
        if len(paths) >= 2:
            results.append((_h, sorted(paths)))

    results.sort(key=lambda x: (-len(x[1]), x[0]))
    return results


def find_duplicates(
    root: Path,
    min_size: int,
    max_size: Optional[int],
    exclude_exts: set,
    workers: int,
) -> Tuple[List[Tuple[str, List[str]]], int]:
    """
    Orchestrate the ETL pipeline to find duplicates.
    """
    # Stage 1: Extract
    all_files, total_scanned = stage_extract(root, min_size, max_size, exclude_exts)
    if total_scanned < 2:
        return [], total_scanned

    # Stage 2: Transform (Size)
    size_candidates = stage_transform_size(all_files)
    if not size_candidates:
        return [], total_scanned

    # Stage 3: Transform (Partial Hash)
    partial_candidates = stage_transform_partial_hash(size_candidates, workers)
    if not partial_candidates:
        return [], total_scanned

    # Stage 4: Transform (Full Hash)
    full_map = stage_transform_full_hash(partial_candidates, workers)

    # Stage 5: Load
    results = stage_load(full_map)

    return results, total_scanned


def print_stats(
    start_time: float,
    total_files: int,
    dup_groups: int,
    dup_files: int,
    wasted: int,
) -> None:
    """Print summary to stderr."""
    end_time = datetime.now().timestamp()
    duration = end_time - start_time

    click.echo("\nSCAN COMPLETE", err=True)
    click.echo(f"Time: {duration:.2f}s", err=True)
    click.echo(f"Files Scanned: {total_files}", err=True)
    click.echo(f"Duplicate Groups: {dup_groups}", err=True)
    click.echo(f"Duplicate Files: {dup_files}", err=True)
    click.echo(f"Wasted Space: {wasted} bytes", err=True)


def output_console(groups: List[Tuple[str, List[str]]]) -> None:
    """Human readable output to stdout."""
    if not groups:
        click.echo("No duplicates found.")
        return

    click.echo(f"Found {len(groups)} duplicate groups:")
    for i, (h, paths) in enumerate(groups, 1):
        click.echo(f"\nGroup {i} ({len(paths)} files, hash: {h[:16]}...)")
        for p in paths:
            click.echo(f"  {p}")


def output_json(groups: List[Tuple[str, List[str]]], out_path: Path) -> None:
    """JSON output."""
    data = {
        "groups": [{"hash": h, "files": paths} for h, paths in groups]
    }
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)
    click.echo(f"JSON report saved to: {out_path}", err=True)


def output_csv(groups: List[Tuple[str, List[str]]], out_path: Path) -> None:
    """CSV output."""
    with open(out_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Group_ID", "Hash", "FilePath"])
        for i, (h, paths) in enumerate(groups, 1):
            for p in paths:
                writer.writerow([i, h, p])
    click.echo(f"CSV report saved to: {out_path}", err=True)


@click.command()
@click.argument(
    "path", type=click.Path(exists=True, file_okay=False, dir_okay=True, readable=True)
)
@click.option("-m", "--min-size", type=int, default=0, help="Min file size in bytes")
@click.option("-M", "--max-size", type=int, default=None, help="Max file size in bytes")
@click.option(
    "-e",
    "--exclude",
    type=str,
    default="",
    help="Comma-separated extensions (e.g. .tmp,.log)",
)
@click.option("-j", "--jobs", type=int, default=4, help="Parallel workers")
@click.option("-o", "--output", type=click.Path(), default=None, help="Output file path")
@click.option(
    "--format",
    type=click.Choice(["console", "json", "csv"]),
    default="console",
    help="Output format",
)
@click.option("-v", "--verbose", is_flag=True, help="Show stats on stderr")
@click.version_option(version="1.0.0", prog_name="dupfinder")
def main(
    path: str,
    min_size: int,
    max_size: Optional[int],
    exclude: str,
    jobs: int,
    output: Optional[str],
    format: str,
    verbose: bool,
) -> None:
    """
    Find duplicate files in a directory.

    PATH: The directory to scan.
    """
    root = Path(path).resolve()
    exclude_exts = set(e.strip().lstrip(".") for e in exclude.split(",") if e.strip())

    start_time = datetime.now().timestamp()
    groups, total_scanned = find_duplicates(
        root, min_size, max_size, exclude_exts, jobs
    )

    dup_groups = len(groups)
    dup_files = sum(len(g[1]) for g in groups)
    wasted = 0

    # Calculate wasted space
    if groups:
        for _h, paths in groups:
            if paths:
                try:
                    sz = get_size(Path(paths[0]))
                    if sz > 0:
                        wasted += sz * (len(paths) - 1)
                except Exception:
                    pass

    if verbose:
        print_stats(start_time, total_scanned, dup_groups, dup_files, wasted)

    if format == "console":
        output_console(groups)
    elif format == "json":
        if not output:
            click.echo("Error: --output required for JSON format", err=True)
            sys.exit(2)
        output_json(groups, Path(output))
    elif format == "csv":
        if not output:
            click.echo("Error: --output required for CSV format", err=True)
            sys.exit(2)
        output_csv(groups, Path(output))

    sys.exit(0 if dup_groups == 0 else 1)


if __name__ == "__main__":
    main()

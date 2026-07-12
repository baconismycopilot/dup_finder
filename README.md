# Find duplicate files

## Description

Find duplicate files and optionally delete duplicates.


## Setup

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```shell
uv sync
```

## Usage

Run via `uv run`:

```shell
uv run dup-finder SOURCE TARGET
```

`SOURCE` and `TARGET` may each be a single file or a directory; directories
are always searched recursively. Results (which files in `TARGET` duplicate
files in `SOURCE`) and a summary are always printed to stdout as YAML.

```text
Usage: dup-finder [OPTIONS] SOURCE TARGET

  Find files in TARGET that duplicate files in SOURCE.

  SOURCE and TARGET may each be a single file or a directory, and directories
  are always searched recursively.

Options:
  -i, --images  Only search for image files.
  -d, --delete  Delete duplicates found in TARGET. Confirmation required.
  --help        Show this message and exit.
```

## Examples

### Find duplicate files

```shell
uv run dup-finder ~/Pictures/originals ~/Downloads
```

### Only compare images, and delete confirmed duplicates in TARGET

```shell
uv run dup-finder --images --delete ~/Pictures/originals ~/Downloads
```

## Development

Run the test suite with:

```shell
make test
```

or directly:

```shell
uv run pytest tests/
```


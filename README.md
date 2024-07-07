# Find duplicate files

## Description

Find duplicate files and optionally delete duplicates.


## Usage

```text
usage: dup_finder.py [-h] -s SOURCE -t TARGET [-r] [-f] [-i] [-p] [-d]

Find duplicate files

options:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        File or path of original files
  -t TARGET, --target TARGET
                        Directory to search
  -r, --recursive       Recurse into subdirectories
  -f, --fast            Read a small portion of files, faster but potentially less accurate
  -i, --images          Only search for image files
  -p, --print           Print results to stdout
  -d, --delete          Delete duplicates. Confirmation required.
```

## Examples

### Find Duplicate Files
    



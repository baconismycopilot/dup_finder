# dupfinder

**Terminal-native duplicate file finder with visual progress and ETL-style architecture.**

`dupfinder` is a high-performance Python utility designed to scan directories for duplicate files. It utilizes a multi-stage filtering pipeline (Size → Partial Hash → Full Hash) combined with parallel processing to maximize speed while minimizing disk I/O.

Built with a "real engineer" mindset, it features:
- **Modern Tooling**: Managed entirely with `uv` for instant installs and reproducible environments.
- **Zero Bloat**: Minimal dependencies (`click`).
- **Visual Feedback**: Real-time ANSI progress bars for every stage of the scan.
- **Pipeline Architecture**: Modular ETL (Extract, Transform, Load) design for clarity and testability.
- **Scriptable**: Clean exit codes and machine-readable output formats (JSON/CSV) for CI/CD integration.

## Features

### 🚀 Performance Optimizations
- **Multi-Stage Filtering**:
  1.  **Size Grouping**: Instantly eliminates files with unique sizes.
  2.  **Partial Hashing**: Compares only the first 1KB of remaining candidates.
  3.  **Full Hashing**: Only computes full SHA-256 hashes for files that match both size and partial hash.
- **Parallel Processing**: Uses `ThreadPoolExecutor` to hash multiple files simultaneously.
- **Smart Caching**: Efficient memory usage via `defaultdict` and generator-based file walking.

### 🎨 User Experience
- **Real-time Progress Bars**: Visual feedback for scanning, partial hashing, and full hashing stages.
- **Graceful Degradation**: Automatically disables progress bars when output is piped.
- **Colored Output**: Leverages `click` for clean, formatted terminal output.

### 🛠️ Capabilities
- **Flexible Filtering**:
  - Minimum/Maximum file size constraints.
  - Exclude specific file extensions (e.g., `.log`, `.tmp`).
  - Ignore hidden files (dotfiles).
- **Multiple Output Formats**:
  - **Console**: Human-readable summary and file lists.
  - **JSON**: Structured data for programmatic analysis.
  - **CSV**: Spreadsheet-ready format for reporting.
- **Wasted Space Calculation**: Estimates total storage wasted by duplicates.

## Installation & Setup

We use **`uv`**, the extremely fast Python package installer and resolver, to manage the project environment.

### Prerequisites
- Python 3.10+
- `uv` installed (`curl -LsSf https://astral.sh/uv/install.sh | sh`)

### Project Setup

1. **Initialize the project** (creates `pyproject.toml` and virtual environment):
   ```bash
   uv init
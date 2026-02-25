# TARE — Forensic Analysis of Digital Footprints and Secure Data Deletion

A Streamlit-based tool that demonstrates how digital traces persist after
data deletion and how forensic techniques recover them. It also implements
secure deletion methods that overwrite data before removal to prevent
recovery.

## Quick Start

```bash
# Install dependencies (inside a venv recommended)
pip install -r requirements.txt

# Run the app
streamlit run main.py
```

---

## Navigation Pages

### 1. Overview

Project dashboard showing platform information, file count in the test
environment, number of evidence entries, and deletion history. Includes a
step-by-step workflow explaining the intended usage sequence.

### 2. Perform User Activities

Creates a realistic digital footprint inside the test environment:

- **File Activities** — Generates text documents, confidential reports,
  image files, temporary/swap files. Files are read, renamed, and moved to
  leave metadata traces.
- **Browser Activities** — Creates simulated Chrome and Firefox profiles
  with browsing history, cookies, and cached pages.

### 3. File Management

Browse and inspect every file in the forensic test environment. Select any
file to view its full metadata: size, creation/modification/access
timestamps, SHA-256 hash, and absolute path.

### 4. Data Deletion

Delete files using one of three methods and compare their forensic
implications:

| Method       | What Happens                                | Recoverable? |
|-------------|---------------------------------------------|-------------|
| **Normal**   | Moves file to Recycle Bin / Trash           | ✅ Yes — fully intact |
| **Permanent**| Bypasses trash, removes file reference      | ⚠️ Likely — data blocks remain on disk |
| **Secure**   | Overwrites content with random/zero/dummy data, then deletes | ❌ No — original data destroyed |

### 5. Forensic Analysis

Four analysis tabs:

- **Browser Artifacts** — Parses and displays recovered browser history,
  cookies, and cache. Can also normal-delete browser data to demonstrate
  recovery.
- **System Metadata** — Collects timestamps, permissions, ownership, and
  system logs for every file in the test environment.
- **Residual Data** — Scans for leftover derivative files: swap files, lock
  files, temp copies, and access logs referencing deleted files.
- **Recovery Verification** — Runs a multi-check forensic analysis on any
  previously deleted file to determine if it is recoverable:
  1. Checks if the file still exists at its original path
  2. Analyses the deletion method used
  3. Scans trash, test environment, and evidence directories for matching
     files (by name, hash, and content signature)
  4. Checks for residual traces (swap files, access logs, metadata
     references)

### 6. Timeline Reconstruction

Aggregates all forensic findings (browser artifacts, file metadata,
residual data) into a unified, chronological event timeline. Detects
anomalies such as file access timestamps that occur after deletion.
Exportable as a text report.

### 7. Evidence Report

Centralized log of every forensic finding from all modules. Supports:

- Filtering by severity (INFO / WARNING / FINDING / ALERT) and by module
- Color-coded log display
- Export as HTML, JSON, or PDF report

---

## Project Structure

```
TARE_proj/
├── main.py                    # Unified Streamlit application (all 7 pages)
├── requirements.txt
├── environment_setup.py       # Initial environment bootstrapper
├── src/
│   ├── Deletion/              # Member 2: Deletion & Mitigation modules
│   │   ├── deletion_techniques.py   # Normal / permanent / secure delete
│   │   ├── secure_deletion.py       # Overwrite engine (zeros/dummy/random)
│   │   ├── post_deletion_verification.py  # Recovery verification checks
│   │   ├── forensic_logger.py       # Deletion-specific logging
│   │   └── environment_setup.py     # Test environment setup
│   └── recovery/              # Member 1: Recovery & Analysis modules
│       ├── activity_simulation.py   # User file activity simulator
│       ├── browser_cache.py         # Browser data simulator & parser
│       ├── evidence_logger.py       # Central evidence logging engine
│       ├── system_metadata.py       # File metadata & system log collector
│       ├── residual_data.py         # Residual/derivative file scanner
│       ├── reconstruction.py        # Timeline reconstruction engine
│       └── shared_constants.py      # Shared paths and config
└── forensic_project/          # Runtime test environment (auto-generated)
    ├── test_environment/
    │   ├── user_files/        # Simulated user documents
    │   ├── browser_data/      # Simulated browser profiles
    │   ├── system_logs/       # System logs
    │   ├── temp_files/        # Temporary files
    │   └── deleted_files/     # Simulated trash (normal deletes)
    ├── evidence/              # Collected forensic evidence
    ├── reports/               # Generated reports
    └── config/                # Configuration
```

---

## Requirements

- Python 3.10+
- streamlit ≥ 1.24.0
- pandas ≥ 1.5.0
- send2trash ≥ 1.8.0
- reportlab ≥ 4.0

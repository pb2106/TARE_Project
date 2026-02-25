#!/usr/bin/env python3
"""
Module 4 – Residual Data Identification (Member 1)
====================================================
After files are deleted (by Member 2's deletion module), this module
scans the working directory, temp paths, and OS-specific locations for
leftover artifacts that could aid forensic recovery.
"""

import os
import platform
import fnmatch
from pathlib import Path
from datetime import datetime

from .shared_constants import (
    TEST_ENV, USER_FILES_DIR, BROWSER_DATA_DIR, TEMP_FILES_DIR,
    SYSTEM_LOGS_DIR, DELETED_FILES_DIR,
    SEVERITY_FINDING,
)


class ResidualDataScanner:
    """
    Scans for residual forensic artifacts left behind after file
    deletion.
    """

    _PATTERNS = [
        ("Thumbs.db",       "thumbnail_db"),
        (".DS_Store",       "macos_metadata"),
        ("desktop.ini",     "windows_metadata"),
        ("*.swp",           "swap_file"),
        ("*.swo",           "swap_file"),
        (".*.swp",          "swap_file"),
        ("~$*",             "office_lock"),
        ("~*",              "temp_backup"),
        ("*.tmp",           "temp_file"),
        ("*.temp",          "temp_file"),
        ("*.log",           "log_fragment"),
        ("*.bak",           "backup_file"),
        ("*.cache",         "cache_file"),
        ("recently_opened*","recent_registry"),
        ("recently-used*",  "recent_registry"),
        ("*.lnk",           "shortcut"),
    ]

    def __init__(self, evidence_logger=None):
        self.evidence_logger = evidence_logger
        self._results = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, extra_dirs=None, callback=None):
        """
        Scan all relevant directories for residual artifacts.

        Returns:
            list of dicts with keys: path, name, size, modified, classification
        """
        self._results = []
        scan_dirs = self._build_scan_dirs(extra_dirs)

        for scan_dir in scan_dirs:
            if not scan_dir.exists():
                continue
            self._notify(callback, f"Scanning: {scan_dir}")
            try:
                for root, dirs, files in os.walk(scan_dir):
                    for fname in files:
                        fpath = Path(root) / fname
                        classification = self._classify(fname)
                        if classification:
                            try:
                                st = fpath.stat()
                                self._results.append({
                                    "path": str(fpath),
                                    "name": fname,
                                    "size": st.st_size,
                                    "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                                    "classification": classification,
                                })
                                if self.evidence_logger:
                                    self.evidence_logger.log(
                                        "residual_data", "artifact_found",
                                        f"{classification}: {fpath.name} ({st.st_size} bytes)",
                                        SEVERITY_FINDING,
                                    )
                            except (PermissionError, OSError):
                                continue
            except PermissionError:
                self._notify(callback, f"[Permission Denied] Skipping: {scan_dir}")

        self._notify(callback, f"Scan complete — {len(self._results)} residual artifacts found")
        return self._results

    def get_results(self):
        return self._results

    def get_summary(self):
        """Return a type-grouped summary of scan results."""
        summary = {}
        for r in self._results:
            cls = r["classification"]
            summary.setdefault(cls, {"count": 0, "total_size": 0})
            summary[cls]["count"] += 1
            summary[cls]["total_size"] += r["size"]
        return summary

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_scan_dirs(self, extra_dirs=None):
        dirs = [TEST_ENV, USER_FILES_DIR, BROWSER_DATA_DIR, TEMP_FILES_DIR,
                SYSTEM_LOGS_DIR, DELETED_FILES_DIR]

        system = platform.system()
        home = Path.home()

        if system in ("Linux", "Darwin"):
            dirs.extend([Path("/tmp"), home / ".cache", home / ".local" / "share"])
            xbel = home / ".local" / "share" / "recently-used.xbel"
            if xbel.exists():
                dirs.append(xbel.parent)
        elif system == "Windows":
            temp = os.environ.get("TEMP", os.environ.get("TMP", ""))
            if temp:
                dirs.append(Path(temp))
            appdata = os.environ.get("APPDATA", "")
            if appdata:
                dirs.append(Path(appdata))
            recent = home / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Recent"
            if recent.exists():
                dirs.append(recent)

        if extra_dirs:
            dirs.extend([Path(d) for d in extra_dirs])

        seen, unique = set(), []
        for d in dirs:
            key = str(d.resolve())
            if key not in seen:
                seen.add(key)
                unique.append(d)
        return unique

    def _classify(self, filename):
        for pattern, cls in self._PATTERNS:
            if fnmatch.fnmatch(filename, pattern) or fnmatch.fnmatch(filename.lower(), pattern.lower()):
                return cls
        return None

    def _notify(self, callback, msg):
        if callback:
            ts = datetime.now().strftime("%H:%M:%S")
            callback(f"[{ts}] {msg}")


# ════════════════════════════════════════════════════════════════════
#  Self-test
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=== Residual Data Scanner Self-Test ===\n")
    rds = ResidualDataScanner()
    results = rds.scan(callback=lambda m: print(f"  {m}"))
    print(f"\nTotal artifacts: {len(results)}")
    for r in results[:10]:
        print(f"  [{r['classification']:15s}] {r['name']:30s} {r['size']:>8} bytes")
    summary = rds.get_summary()
    if summary:
        print("\nSummary:")
        for cls, info in summary.items():
            print(f"  {cls}: {info['count']} files ({info['total_size']} bytes)")
    print("\n✓ Residual Data Scanner self-test passed.")

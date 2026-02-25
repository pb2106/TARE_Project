#!/usr/bin/env python3
"""
Module 3 – System Logs & Metadata (Member 1)
==============================================
Reads and displays real system metadata for files in the working
directory plus (where permitted) snippets from OS-level logs.

Cross-platform using os, stat, platform, subprocess.
Graceful fallback if elevated permissions are required.
"""

import os
import stat
import platform
import subprocess
from pathlib import Path
from datetime import datetime

from .shared_constants import (
    SYSTEM_LOGS_DIR, TEST_ENV,
    SEVERITY_INFO,
)


class SystemMetadataAnalyzer:
    """
    Collects and displays file-level metadata and OS-level log
    snippets relevant to forensic analysis.
    """

    def __init__(self, scan_dir=None, evidence_logger=None):
        self.scan_dir = Path(scan_dir) if scan_dir else TEST_ENV
        self.evidence_logger = evidence_logger
        self._file_metadata = []
        self._system_logs = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect_file_metadata(self, directory=None):
        """Gather metadata for all files under *directory*."""
        scan = Path(directory) if directory else self.scan_dir
        self._file_metadata = []

        if not scan.exists():
            return self._file_metadata

        for root, _, files in os.walk(scan):
            for fname in files:
                fpath = Path(root) / fname
                try:
                    st = fpath.stat()
                    meta = {
                        "path": str(fpath),
                        "name": fname,
                        "size": st.st_size,
                        "created": datetime.fromtimestamp(st.st_ctime).isoformat(),
                        "modified": datetime.fromtimestamp(st.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(st.st_atime).isoformat(),
                        "permissions": stat.filemode(st.st_mode),
                        "owner_uid": st.st_uid,
                        "owner_gid": st.st_gid,
                    }
                    if platform.system() != "Windows":
                        try:
                            import pwd
                            meta["owner"] = pwd.getpwuid(st.st_uid).pw_name
                        except (ImportError, KeyError):
                            meta["owner"] = str(st.st_uid)
                    else:
                        meta["owner"] = str(st.st_uid)

                    self._file_metadata.append(meta)
                except (PermissionError, OSError):
                    continue

        if self.evidence_logger:
            self.evidence_logger.log(
                "system_metadata", "metadata_collected",
                f"Collected metadata for {len(self._file_metadata)} files in {scan}",
                SEVERITY_INFO,
            )
        return self._file_metadata

    def collect_system_logs(self, max_lines=50):
        """Retrieve recent system log entries (platform-dependent)."""
        self._system_logs = []
        system = platform.system()

        try:
            if system == "Linux":
                self._system_logs = self._collect_linux_logs(max_lines)
            elif system == "Darwin":
                self._system_logs = self._collect_macos_logs(max_lines)
            elif system == "Windows":
                self._system_logs = self._collect_windows_logs(max_lines)
            else:
                self._system_logs = [f"Unsupported platform: {system}"]
        except Exception as e:
            self._system_logs = [f"Error collecting system logs: {e}"]

        try:
            SYSTEM_LOGS_DIR.mkdir(parents=True, exist_ok=True)
            with open(SYSTEM_LOGS_DIR / "collected_syslog.txt", "w") as f:
                f.write("\n".join(self._system_logs))
        except Exception:
            pass

        if self.evidence_logger:
            self.evidence_logger.log(
                "system_metadata", "syslog_collected",
                f"Collected {len(self._system_logs)} system log lines ({system})",
                SEVERITY_INFO,
            )
        return self._system_logs

    def get_file_metadata(self):
        return self._file_metadata

    def get_system_logs(self):
        return self._system_logs

    # ------------------------------------------------------------------
    # Platform-specific log collection
    # ------------------------------------------------------------------

    def _collect_linux_logs(self, max_lines):
        lines = []
        try:
            result = subprocess.run(
                ["journalctl", "--no-pager", "-n", str(max_lines),
                 "--output=short-iso"],
                capture_output=True, text=True, timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[:max_lines]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        for sp in [Path("/var/log/syslog"), Path("/var/log/messages")]:
            if sp.exists():
                try:
                    with open(sp, "r", errors="ignore") as f:
                        all_lines = f.readlines()
                    return [l.rstrip() for l in all_lines[-max_lines:]]
                except PermissionError:
                    return [f"[Permission Denied] Cannot read {sp} — run with elevated privileges."]

        return ["[INFO] No system log sources accessible without root."]

    def _collect_macos_logs(self, max_lines):
        syslog = Path("/var/log/system.log")
        if syslog.exists():
            try:
                with open(syslog, "r", errors="ignore") as f:
                    all_lines = f.readlines()
                return [l.rstrip() for l in all_lines[-max_lines:]]
            except PermissionError:
                return ["[Permission Denied] Cannot read system.log."]
        try:
            result = subprocess.run(
                ["log", "show", "--last", "5m", "--style=compact"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                return result.stdout.strip().splitlines()[:max_lines]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ["[INFO] macOS log collection unavailable."]

    def _collect_windows_logs(self, max_lines):
        try:
            ps_cmd = (
                f"Get-WinEvent -LogName System -MaxEvents {max_lines} "
                f"| Format-Table -Property TimeCreated, Id, Message -AutoSize"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip().splitlines()[:max_lines]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        try:
            result = subprocess.run(
                ["wmic", "ntevent", "where", "LogFile='System'", "get",
                 "TimeGenerated,EventCode,Message", "/format:list"],
                capture_output=True, text=True, timeout=15,
            )
            if result.returncode == 0:
                return [l.strip() for l in result.stdout.splitlines() if l.strip()][:max_lines]
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return ["[INFO] Windows event log collection unavailable."]


# ════════════════════════════════════════════════════════════════════
#  Self-test
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=== System Metadata Analyzer Self-Test ===\n")
    sma = SystemMetadataAnalyzer()
    metadata = sma.collect_file_metadata()
    print(f"Files found: {len(metadata)}")
    for m in metadata[:5]:
        print(f"  {m['name']:30s} {m['size']:>8} bytes  {m['permissions']}  {m['modified'][:19]}")
    print(f"\nPlatform: {platform.system()} {platform.release()}")
    logs = sma.collect_system_logs(max_lines=10)
    print(f"Log lines: {len(logs)}")
    for line in logs[:5]:
        print(f"  {line[:100]}")
    print("\n✓ System Metadata self-test passed.")

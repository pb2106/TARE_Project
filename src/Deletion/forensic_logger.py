#!/usr/bin/env python3
"""
Forensic Logger Module
Centralized structured logging for all forensic operations.

Logs are stored as JSON entries in forensic_project/reports/forensic_log.json
and also kept in-memory for real-time GUI display.
"""

import os
import json
from pathlib import Path
from datetime import datetime


class ForensicLogger:
    """Structured JSON logger for forensic actions."""

    def __init__(self, log_dir="forensic_project/reports"):
        self.log_dir = Path(log_dir).absolute()
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / "forensic_log.json"
        self._entries = []

        # Load existing log if present
        if self.log_file.exists():
            try:
                with open(self.log_file, "r") as f:
                    self._entries = json.load(f)
            except (json.JSONDecodeError, Exception):
                self._entries = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, action, category="general", details=None, status="info"):
        """
        Record a forensic action.

        Args:
            action:   Short description of the action.
            category: Category tag (e.g., 'deletion', 'verification',
                      'simulation', 'analysis').
            details:  Optional dict with extra information.
            status:   'info', 'success', 'warning', or 'error'.

        Returns:
            The log entry dict.
        """
        entry = {
            "id": len(self._entries) + 1,
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "category": category,
            "status": status,
            "details": details or {},
        }
        self._entries.append(entry)
        self._persist()
        return entry

    def log_deletion(self, filepath, method, result_details):
        """Convenience: log a file deletion action."""
        return self.log(
            action=f"Deleted '{Path(filepath).name}' using {method} method",
            category="deletion",
            details={
                "filepath": str(filepath),
                "method": method,
                **result_details,
            },
            status="success" if result_details.get("status") != "failed" else "error",
        )

    def log_verification(self, filepath, verification_result):
        """Convenience: log a verification action."""
        recoverable = verification_result.get("recoverable", False)
        return self.log(
            action=f"Verified '{Path(filepath).name}' – {'RECOVERABLE' if recoverable else 'NOT RECOVERABLE'}",
            category="verification",
            details=verification_result,
            status="warning" if recoverable else "success",
        )

    def log_simulation(self, action_desc, files_created=None):
        """Convenience: log a simulation activity."""
        return self.log(
            action=action_desc,
            category="simulation",
            details={"files_created": files_created or []},
            status="success",
        )

    def log_analysis(self, action_desc, findings=None):
        """Convenience: log a forensic analysis action."""
        return self.log(
            action=action_desc,
            category="analysis",
            details={"findings": findings or {}},
            status="success",
        )

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    def get_logs(self, category=None, last_n=None):
        """
        Retrieve log entries, optionally filtered.

        Args:
            category: Filter by category (or None for all).
            last_n:   Return only the last N entries.

        Returns:
            List of log entry dicts.
        """
        entries = self._entries
        if category:
            entries = [e for e in entries if e["category"] == category]
        if last_n:
            entries = entries[-last_n:]
        return entries

    def get_log_text(self, category=None, last_n=None):
        """Return logs as a formatted multiline string (for GUI display)."""
        entries = self.get_logs(category=category, last_n=last_n)
        lines = []
        for e in entries:
            ts = e["timestamp"][:19].replace("T", " ")
            status_icon = {"info": "ℹ", "success": "✓", "warning": "⚠", "error": "✗"}.get(
                e["status"], "•"
            )
            lines.append(f"[{ts}] {status_icon} [{e['category'].upper()}] {e['action']}")
        return "\n".join(lines) if lines else "(no log entries)"

    def get_entry_count(self):
        return len(self._entries)

    # ------------------------------------------------------------------
    # Export / Clear
    # ------------------------------------------------------------------

    def export_logs(self, filepath=None):
        """
        Export logs to a JSON file.

        Args:
            filepath: Destination path (defaults to the main log file).

        Returns:
            Path to the exported file.
        """
        dest = Path(filepath) if filepath else self.log_file
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w") as f:
            json.dump(self._entries, f, indent=2)
        return str(dest)

    def clear_logs(self):
        """Clear all in-memory and on-disk logs."""
        self._entries = []
        self._persist()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _persist(self):
        """Write current entries to disk."""
        try:
            with open(self.log_file, "w") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass  # best-effort persistence


# ------------------------------------------------------------------
# Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Forensic Logger Self-Test ===\n")
    logger = ForensicLogger()
    logger.clear_logs()

    logger.log("Environment initialized", category="general", status="info")
    logger.log_deletion("secret.txt", "secure", {"status": "success", "mode": "random", "passes": 3})
    logger.log_verification("secret.txt", {"recoverable": False, "recovery_risk": "NONE"})
    logger.log_simulation("Generated 5 test files", files_created=["a.txt", "b.txt"])

    print(logger.get_log_text())
    print(f"\nTotal entries: {logger.get_entry_count()}")
    print(f"Log file: {logger.export_logs()}")

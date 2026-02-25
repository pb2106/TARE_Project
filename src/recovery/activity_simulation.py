#!/usr/bin/env python3
"""
Module 1 – User Activity Simulation (Member 1)
================================================
Simulates realistic user activity inside the forensic test environment:
  • Creates text, image-placeholder, and document files
  • Writes content, reads files, renames and moves them
  • Logs every action with timestamps
  • Stores simulation metadata in a JSON file for other modules
"""

import os
import json
import shutil
import random
from pathlib import Path
from datetime import datetime

from .shared_constants import (
    USER_FILES_DIR, EVIDENCE_DIR, TEMP_FILES_DIR,
    SEVERITY_INFO,
)


class ActivitySimulator:
    """
    Simulates realistic user file activity and records every action
    with timestamps for forensic reconstruction.
    """

    # Sample content templates
    _TEXT_CONTENT = [
        "Meeting notes: Discussed Q4 targets. Action items pending.\n",
        "TODO: Review expense reports, submit by Friday.\n",
        "Personal: Flight confirmation for Bangalore, 14-Mar.\n",
        "Draft: Proposal for network audit — version 2.\n",
        "Credentials backup: server admin / P@ssw0rd!23\n",
    ]

    _DOC_CONTENT = (
        "CONFIDENTIAL REPORT\n"
        "=" * 40 + "\n"
        "Employee Performance Review — FY 2025\n"
        "Rating: Exceeds Expectations\n"
        "Manager Notes: Strong contribution to the forensics module.\n"
        "Salary Revision: +12%\n"
    )

    _IMAGE_HEADER = (
        b'\x89PNG\r\n\x1a\n'  # PNG magic bytes (simulated)
        + b'\x00' * 256       # Placeholder pixel data
    )

    def __init__(self, working_dir=None, evidence_dir=None, evidence_logger=None):
        """
        Args:
            working_dir:     Directory to create user files in.
            evidence_dir:    Directory for metadata JSON output.
            evidence_logger: Shared :class:`EvidenceLogger` instance.
        """
        self.working_dir = Path(working_dir) if working_dir else USER_FILES_DIR
        self.evidence_dir = Path(evidence_dir) if evidence_dir else EVIDENCE_DIR
        self.evidence_logger = evidence_logger

        self.working_dir.mkdir(parents=True, exist_ok=True)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        self.metadata_file = self.evidence_dir / "simulation_metadata.json"
        self._actions = []

        # Load existing metadata if present
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, "r") as f:
                    self._actions = json.load(f)
            except (json.JSONDecodeError, Exception):
                self._actions = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def run_simulation(self, callback=None):
        """
        Execute the full simulation sequence.

        Args:
            callback: Optional callable(str) invoked with each log line.

        Returns:
            list of action dicts recorded during the simulation.
        """
        self._actions = []
        steps = [
            self._step_create_text_files,
            self._step_create_document,
            self._step_create_image_file,
            self._step_read_files,
            self._step_rename_file,
            self._step_move_file,
            self._step_create_temp_files,
        ]
        for step_fn in steps:
            step_fn(callback)

        self._save_metadata()
        self._log_action(
            "simulation_complete",
            f"Simulation finished — {len(self._actions)} actions recorded",
            callback,
        )
        return self._actions

    def get_actions(self):
        """Return the list of recorded simulation actions."""
        return self._actions

    # ------------------------------------------------------------------
    # Simulation steps
    # ------------------------------------------------------------------

    def _step_create_text_files(self, cb):
        for i, content in enumerate(self._TEXT_CONTENT, 1):
            fname = f"user_note_{i}.txt"
            fpath = self.working_dir / fname
            with open(fpath, "w") as f:
                f.write(content * random.randint(1, 5))
            self._log_action(
                "file_created",
                f"Created text file: {fname} ({fpath.stat().st_size} bytes)",
                cb, filepath=str(fpath),
            )

    def _step_create_document(self, cb):
        fname = "confidential_review.doc"
        fpath = self.working_dir / fname
        with open(fpath, "w") as f:
            f.write(self._DOC_CONTENT * 3)
        self._log_action(
            "file_created",
            f"Created document: {fname} ({fpath.stat().st_size} bytes)",
            cb, filepath=str(fpath),
        )

    def _step_create_image_file(self, cb):
        fname = "screenshot_desktop.png"
        fpath = self.working_dir / fname
        with open(fpath, "wb") as f:
            f.write(self._IMAGE_HEADER)
            f.write(os.urandom(1024))
        self._log_action(
            "file_created",
            f"Created image file: {fname} ({fpath.stat().st_size} bytes)",
            cb, filepath=str(fpath),
        )

    def _step_read_files(self, cb):
        for fpath in sorted(self.working_dir.iterdir()):
            if fpath.is_file():
                try:
                    with open(fpath, "rb") as f:
                        _ = f.read(512)
                    self._log_action(
                        "file_accessed", f"Read file: {fpath.name}",
                        cb, filepath=str(fpath),
                    )
                except Exception:
                    pass

    def _step_rename_file(self, cb):
        src = self.working_dir / "user_note_1.txt"
        dst = self.working_dir / "important_notes_FINAL.txt"
        if src.exists():
            shutil.move(str(src), str(dst))
            self._log_action(
                "file_renamed", f"Renamed: {src.name} → {dst.name}",
                cb, filepath=str(dst),
            )

    def _step_move_file(self, cb):
        src = self.working_dir / "user_note_2.txt"
        dst_dir = TEMP_FILES_DIR
        dst_dir.mkdir(parents=True, exist_ok=True)
        dst = dst_dir / "moved_note.txt"
        if src.exists():
            shutil.move(str(src), str(dst))
            self._log_action(
                "file_moved", f"Moved: {src.name} → temp_files/moved_note.txt",
                cb, filepath=str(dst),
            )

    def _step_create_temp_files(self, cb):
        temp_dir = TEMP_FILES_DIR
        temp_dir.mkdir(parents=True, exist_ok=True)

        # Swap file
        swap_path = temp_dir / ".user_note_3.txt.swp"
        with open(swap_path, "w") as f:
            f.write("b0VIM 8.2\x00" + "swap file content fragment\n" * 5)
        self._log_action("file_created", f"Created swap file: {swap_path.name}",
                         cb, filepath=str(swap_path))

        # Lock file
        lock_path = temp_dir / "~$confidential_review.doc"
        with open(lock_path, "w") as f:
            f.write("lock" + "\x00" * 20)
        self._log_action("file_created", f"Created lock file: {lock_path.name}",
                         cb, filepath=str(lock_path))

        # Recent-use log
        recent_path = temp_dir / "recently_opened.log"
        lines = []
        for fpath in sorted(self.working_dir.iterdir()):
            if fpath.is_file():
                lines.append(f"{datetime.now().isoformat()} OPEN {fpath.name}\n")
        with open(recent_path, "w") as f:
            f.writelines(lines)
        self._log_action("file_created", f"Created recent-use log: {recent_path.name}",
                         cb, filepath=str(recent_path))

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log_action(self, event_type, detail, callback=None, filepath=None):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "detail": detail,
            "filepath": filepath or "",
        }
        self._actions.append(entry)
        if self.evidence_logger:
            self.evidence_logger.log(
                "activity_simulation", event_type, detail, SEVERITY_INFO,
            )
        if callback:
            ts = entry["timestamp"][:19].replace("T", " ")
            callback(f"[{ts}] {event_type}: {detail}")

    def _save_metadata(self):
        try:
            with open(self.metadata_file, "w") as f:
                json.dump(self._actions, f, indent=2)
        except Exception:
            pass


# ════════════════════════════════════════════════════════════════════
#  Self-test
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=== Activity Simulation Self-Test ===\n")
    sim = ActivitySimulator()
    actions = sim.run_simulation(callback=lambda line: print(f"  {line}"))
    print(f"\nTotal actions: {len(actions)}")
    print(f"Metadata file: {sim.metadata_file}")
    print("\n✓ Activity Simulation self-test passed.")

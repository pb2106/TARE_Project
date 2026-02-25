#!/usr/bin/env python3
"""
Deletion Techniques Module
Provides three deletion strategies through a common interface:

1. Normal Delete   – moves file to Recycle Bin (Windows) or OS trash
2. Permanent Delete – bypasses trash; directly removes the file
3. Secure Delete   – overwrites contents, then removes the file
"""

import os
import shutil
from pathlib import Path
from datetime import datetime

from secure_deletion import SecureDeletion


class DeletionTechniques:
    """Unified interface for multiple file deletion strategies."""

    METHODS = ["normal", "permanent", "secure"]

    # Default simulated-trash folder (inside forensic_project)
    _SIMULATED_TRASH = (
        Path(__file__).resolve().parent.parent.parent
        / "forensic_project" / "test_environment" / "deleted_files"
    )

    def __init__(self):
        """
        Initialize deletion techniques.
        No backup copies are made — only metadata (name, size, hash,
        timestamps) is recorded in the result dict for logging.
        """
        self.secure_engine = SecureDeletion()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def delete_file(self, filepath, method="normal", secure_mode="random",
                    secure_passes=1, progress_callback=None):
        """
        Delete a file using the specified method.

        Args:
            filepath:          Path to the target file.
            method:            'normal', 'permanent', or 'secure'.
            secure_mode:       Overwrite mode for secure delete ('zeros',
                               'dummy', 'random').
            secure_passes:     Number of overwrite passes for secure delete.
            progress_callback: Optional callable(percent: int).

        Returns:
            dict with deletion result details.
        """
        filepath = Path(filepath)
        result = {
            "status": "failed",
            "filepath": str(filepath),
            "method": method,
            "timestamp": datetime.now().isoformat(),
            "file_size": 0,
            "error": None,
            "details": {},
        }

        if not filepath.exists():
            result["error"] = "File does not exist"
            return result

        if not filepath.is_file():
            result["error"] = "Path is not a regular file"
            return result

        stat = filepath.stat()
        result["file_size"] = stat.st_size

        # Capture metadata BEFORE deletion (for logging, not file copy)
        result["metadata"] = {
            "filename": filepath.name,
            "size_bytes": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
            "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
        }

        try:
            if method == "normal":
                result["details"] = self._normal_delete(filepath)
            elif method == "permanent":
                result["details"] = self._permanent_delete(filepath)
            elif method == "secure":
                result["details"] = self._secure_delete(
                    filepath, secure_mode, secure_passes, progress_callback
                )
            else:
                result["error"] = (
                    f"Unknown method '{method}'. "
                    f"Choose from: {self.METHODS}"
                )
                return result

            result["status"] = "success"

        except PermissionError:
            result["error"] = "Permission denied – file may be in use"
        except Exception as e:
            result["error"] = str(e)

        return result

    def get_available_methods(self):
        """Return list of supported deletion methods with descriptions."""
        return [
            {
                "name": "normal",
                "label": "Normal Delete",
                "description": (
                    "Sends the file to the OS trash / Recycle Bin. "
                    "Data remains easily recoverable."
                ),
            },
            {
                "name": "permanent",
                "label": "Permanent Delete",
                "description": (
                    "Bypasses the trash and removes the file directly. "
                    "Data may still be recoverable from disk."
                ),
            },
            {
                "name": "secure",
                "label": "Secure Delete",
                "description": (
                    "Overwrites the file contents before deletion. "
                    "Prevents standard forensic recovery."
                ),
            },
        ]

    # ------------------------------------------------------------------
    # Internal deletion strategies
    # ------------------------------------------------------------------

    def _normal_delete(self, filepath):
        """Move the file to the OS trash or a simulated trash directory."""
        filepath = Path(filepath).resolve()
        details = {"technique": "normal", "trash_used": False, "trash_path": None}
        try:
            # Try send2trash for proper Recycle Bin / system-trash integration
            from send2trash import send2trash
            send2trash(str(filepath))
            details["trash_used"] = True
            details["note"] = "File moved to system Recycle Bin / Trash"
        except (ImportError, Exception):
            # Fallback: move to a simulated trash directory so the file
            # is preserved and can be found by the recovery scanner.
            trash_dir = self._SIMULATED_TRASH
            trash_dir.mkdir(parents=True, exist_ok=True)
            dest = trash_dir / filepath.name
            # Avoid overwriting an existing file in simulated trash
            if dest.exists():
                stem, suffix = dest.stem, dest.suffix
                counter = 1
                while dest.exists():
                    dest = trash_dir / f"{stem}_{counter}{suffix}"
                    counter += 1
            shutil.move(str(filepath), str(dest))
            details["trash_used"] = True
            details["trash_path"] = str(dest)
            details["note"] = (
                "send2trash unavailable — file moved to simulated trash "
                f"({dest})"
            )
        return details

    def _permanent_delete(self, filepath):
        """Remove file directly, bypassing trash."""
        os.remove(filepath)
        return {
            "technique": "permanent",
            "note": "File permanently removed (bypassed trash)",
        }

    def _secure_delete(self, filepath, mode, passes, progress_callback):
        """Overwrite then delete using SecureDeletion engine."""
        sd_result = self.secure_engine.secure_delete(
            filepath, mode=mode, passes=passes, progress_callback=progress_callback
        )
        return {
            "technique": "secure",
            "overwrite_mode": mode,
            "overwrite_passes": passes,
            "bytes_overwritten": sd_result.get("bytes_overwritten", 0),
            "time_taken": sd_result.get("time_taken", 0),
            "hash_before": sd_result.get("hash_before"),
            "hash_after": sd_result.get("hash_after"),
            "note": "File overwritten then deleted",
        }




# ------------------------------------------------------------------
# Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    print("=== Deletion Techniques Self-Test ===\n")
    dt = DeletionTechniques()

    for method in DeletionTechniques.METHODS:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
        tmp.write(f"Test data for {method} delete\n".encode() * 50)
        tmp.close()
        print(f"--- {method.upper()} DELETE ---")
        print(f"  File: {tmp.name}  Size: {os.path.getsize(tmp.name)} bytes")
        res = dt.delete_file(tmp.name, method=method, secure_mode="random", secure_passes=1)
        print(f"  Status: {res['status']}")
        print(f"  Details: {res['details']}")
        print(f"  File exists after: {os.path.exists(tmp.name)}\n")

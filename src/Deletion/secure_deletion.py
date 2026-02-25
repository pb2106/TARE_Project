#!/usr/bin/env python3
"""
Secure Deletion Module
Overwrites file contents before deletion to prevent forensic recovery.

Overwrite Modes:
  - zeros  : Fills with 0x00 bytes
  - dummy  : Fills with 0xAA bytes
  - random : Fills with cryptographically random bytes (os.urandom)

Pass Count:
  - 1 (single-pass, fast)
  - 3 (DoD-style, thorough)
"""

import os
import time
import hashlib
from pathlib import Path
from datetime import datetime


class SecureDeletion:
    """Engine for securely overwriting and deleting files."""

    MODES = {
        "zeros": b"\x00",
        "dummy": b"\xAA",
        "random": None,  # handled dynamically via os.urandom
    }

    # Standards context (useful for Viva)
    STANDARDS = {
        "zeros": "Simple Overwrite (1-pass): Effective for mechanical drives; fast.",
        "random": "DoD 5220.22-M (concept): Uses random data to mask previous bit patterns.",
        "SSD_WARNING": "Note: Wear leveling and over-provisioning on SSDs can prevent standard software overwriting from reaching all physical blocks."
    }

    def __init__(self):
        self.last_result = None

    def get_viva_explanation(self, topic):
        """Provide technical explanations for viva questions."""
        explanations = {
            "why_recoverable": "When a file is normally deleted, the OS only removes the pointer in the file system table (e.g., MFT in NTFS). The actual bits remain on the disk in 'unallocated space' until overwritten by new data.",
            "overwriting": "Secure overwriting replaces the original bit patterns with new data (zeros/random). This physically changes the state of the storage medium, making original recovery impossible for standard software tools.",
            "ssd_diff": "SSDs use 'Wear Leveling' which moves data around to extend life. When you overwrite a 'file', the SSD controller might write a new block elsewhere, leaving the old 'deleted' block intact until 'TRIM' or 'Garbage Collection' runs.",
            "unallocated_space": "This is disk area marked by the file system as available for new data, but which may still contain residual data from 'deleted' files."
        }
        return explanations.get(topic, "Topic not found.")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def secure_delete(self, filepath, mode="random", passes=1, progress_callback=None):
        """
        Securely overwrite a file and then delete it.

        Args:
            filepath:  Path to the file to delete.
            mode:      Overwrite mode – 'zeros', 'dummy', or 'random'.
            passes:    Number of overwrite passes (1 or 3 recommended).
            progress_callback: Optional callable(percent: int) for UI updates.

        Returns:
            dict with keys: status, filepath, mode, passes,
                            bytes_overwritten, time_taken, hash_before, hash_after,
                            error (if any).
        """
        filepath = Path(filepath)
        result = {
            "status": "failed",
            "filepath": str(filepath),
            "mode": mode,
            "passes": passes,
            "bytes_overwritten": 0,
            "time_taken": 0.0,
            "hash_before": None,
            "hash_after": None,
            "timestamp": datetime.now().isoformat(),
            "error": None,
        }

        # Validation
        if not filepath.exists():
            result["error"] = "File does not exist"
            self.last_result = result
            return result

        if not filepath.is_file():
            result["error"] = "Path is not a regular file"
            self.last_result = result
            return result

        if mode not in self.MODES:
            result["error"] = f"Invalid mode '{mode}'. Choose from: {list(self.MODES.keys())}"
            self.last_result = result
            return result

        try:
            file_size = filepath.stat().st_size

            # Hash BEFORE overwrite (for verification later)
            result["hash_before"] = self._hash_file(filepath)

            start = time.time()

            # Overwrite passes
            for current_pass in range(1, passes + 1):
                self._overwrite_file(filepath, mode, file_size)
                if progress_callback:
                    pct = int((current_pass / passes) * 100)
                    progress_callback(pct)

            # Hash AFTER overwrite – should differ from hash_before
            result["hash_after"] = self._hash_file(filepath)

            elapsed = time.time() - start

            # Delete the file
            os.remove(filepath)

            result["status"] = "success"
            result["bytes_overwritten"] = file_size * passes
            result["time_taken"] = round(elapsed, 4)

        except PermissionError:
            result["error"] = "Permission denied – file may be in use"
        except Exception as e:
            result["error"] = str(e)

        self.last_result = result
        return result

    def overwrite_only(self, filepath, mode="random", passes=1, progress_callback=None):
        """
        Overwrite file contents WITHOUT deleting it.
        Useful for demonstrating that overwrite changes the data.

        Returns the same result dict as secure_delete (but file still exists).
        """
        filepath = Path(filepath)
        result = {
            "status": "failed",
            "filepath": str(filepath),
            "mode": mode,
            "passes": passes,
            "bytes_overwritten": 0,
            "time_taken": 0.0,
            "hash_before": None,
            "hash_after": None,
            "timestamp": datetime.now().isoformat(),
            "error": None,
        }

        if not filepath.exists() or not filepath.is_file():
            result["error"] = "File does not exist or is not a regular file"
            self.last_result = result
            return result

        try:
            file_size = filepath.stat().st_size
            result["hash_before"] = self._hash_file(filepath)

            start = time.time()
            for current_pass in range(1, passes + 1):
                self._overwrite_file(filepath, mode, file_size)
                if progress_callback:
                    progress_callback(int((current_pass / passes) * 100))

            result["hash_after"] = self._hash_file(filepath)
            elapsed = time.time() - start

            result["status"] = "success"
            result["bytes_overwritten"] = file_size * passes
            result["time_taken"] = round(elapsed, 4)

        except Exception as e:
            result["error"] = str(e)

        self.last_result = result
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _overwrite_file(self, filepath, mode, file_size):
        """Write overwrite data to an existing file, matching its size."""
        chunk_size = 4096
        with open(filepath, "r+b") as f:
            written = 0
            while written < file_size:
                to_write = min(chunk_size, file_size - written)
                if mode == "random":
                    data = os.urandom(to_write)
                else:
                    data = self.MODES[mode] * to_write
                f.write(data)
                written += to_write
            f.flush()
            os.fsync(f.fileno())

    @staticmethod
    def _hash_file(filepath, algorithm="sha256"):
        """Compute hash of a file's contents."""
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()


# ------------------------------------------------------------------
# Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    import tempfile

    print("=== Secure Deletion Self-Test ===\n")
    sd = SecureDeletion()

    # Create a temp file with known content
    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".txt")
    tmp.write(b"CONFIDENTIAL DATA - TOP SECRET INFORMATION\n" * 100)
    tmp.close()

    print(f"Created test file: {tmp.name}")
    print(f"Size: {os.path.getsize(tmp.name)} bytes")

    result = sd.secure_delete(tmp.name, mode="random", passes=3)

    print(f"\nResult: {result['status']}")
    print(f"Mode: {result['mode']}, Passes: {result['passes']}")
    print(f"Bytes overwritten: {result['bytes_overwritten']}")
    print(f"Time taken: {result['time_taken']}s")
    print(f"Hash before: {result['hash_before'][:16]}...")
    print(f"Hash after:  {result['hash_after'][:16]}...")
    print(f"File exists after delete: {os.path.exists(tmp.name)}")

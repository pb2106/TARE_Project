#!/usr/bin/env python3
"""
Post-Deletion Verification Module
Determines whether a deleted file is recoverable by checking:

1. File path existence (trivially recoverable if still present)
2. Backup / Recycle Bin copies
3. Residual data in temp / cache directories
4. Content-signature match in leftover artifacts
"""

import os
import hashlib
from pathlib import Path
from datetime import datetime


class PostDeletionVerification:
    """
    Verify whether deleted data can be recovered.
    Works with the forensic_project directory structure created by
    environment_setup.py.
    """

    def __init__(self, project_base="forensic_project"):
        self.project_base = Path(project_base).absolute()
        self.scan_directories = [
            self.project_base / "test_environment" / "deleted_files",
            self.project_base / "test_environment" / "temp_files",
            self.project_base / "test_environment" / "browser_data",
            self.project_base / "test_environment" / "system_logs",
            self.project_base / "evidence",
        ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def verify(self, original_path, original_hash=None, original_content_sample=None):
        """
        Run a full verification check for a previously deleted file.

        Args:
            original_path:           Original file path (may no longer exist).
            original_hash:           SHA-256 hash of the original content
                                     (obtained before deletion).
            original_content_sample: First N bytes of the original file
                                     (hex string) for signature scanning.

        Returns:
            dict – verification report.
        """
        original_path = Path(original_path)
        report = {
            "filepath": str(original_path),
            "filename": original_path.name,
            "timestamp": datetime.now().isoformat(),
            "checks": {},
            "recoverable": False,
            "recovery_risk": "NONE",
            "summary": "",
            "found_artifacts": [],
        }

        # Check 1: Does the original path still exist?
        path_exists = original_path.exists()
        report["checks"]["path_exists"] = path_exists
        if path_exists:
            report["recoverable"] = True
            report["found_artifacts"].append({
                "type": "original_file",
                "location": str(original_path),
                "note": "Original file was NOT deleted",
            })

        # Check 2: Look for copies / residual files by name
        name_matches = self._scan_by_filename(original_path.name)
        report["checks"]["name_matches"] = len(name_matches)
        if name_matches:
            report["recoverable"] = True
            for m in name_matches:
                report["found_artifacts"].append({
                    "type": "name_match",
                    "location": str(m),
                    "note": "File with matching name found in scan directories",
                })

        # Check 3: Hash-based scan (if original hash provided)
        if original_hash:
            hash_matches = self._scan_by_hash(original_hash)
            report["checks"]["hash_matches"] = len(hash_matches)
            if hash_matches:
                report["recoverable"] = True
                for m in hash_matches:
                    report["found_artifacts"].append({
                        "type": "hash_match",
                        "location": str(m),
                        "note": "File with identical content hash found",
                    })
        else:
            report["checks"]["hash_matches"] = "skipped (no hash provided)"

        # Check 4: Content-signature scan (if content sample provided)
        if original_content_sample:
            sig_matches = self._scan_by_signature(original_content_sample)
            report["checks"]["signature_matches"] = len(sig_matches)
            if sig_matches:
                report["recoverable"] = True
                for m in sig_matches:
                    report["found_artifacts"].append({
                        "type": "signature_match",
                        "location": str(m),
                        "note": "Partial content signature found in artifact",
                    })
        else:
            report["checks"]["signature_matches"] = "skipped (no sample provided)"

        # Determine risk level
        if report["recoverable"]:
            artifact_count = len(report["found_artifacts"])
            if artifact_count >= 3:
                report["recovery_risk"] = "HIGH"
            elif artifact_count >= 1:
                report["recovery_risk"] = "MEDIUM"
        else:
            report["recovery_risk"] = "NONE"

        # Human-readable summary
        report["summary"] = self._build_summary(report)

        return report

    def quick_verify(self, original_path):
        """
        Lightweight check – only tests path existence and name scan.
        Useful for rapid UI feedback.
        """
        original_path = Path(original_path)
        exists = original_path.exists()
        name_matches = self._scan_by_filename(original_path.name)
        recoverable = exists or len(name_matches) > 0
        return {
            "filepath": str(original_path),
            "recoverable": recoverable,
            "path_exists": exists,
            "copies_found": len(name_matches),
            "recovery_risk": "HIGH" if exists else ("MEDIUM" if name_matches else "NONE"),
            "timestamp": datetime.now().isoformat(),
        }

    # ------------------------------------------------------------------
    # Comparison helper (normal vs secure delete)
    # ------------------------------------------------------------------

    def compare_deletion_methods(self, normal_result, secure_result):
        """
        Compare two verification reports and produce a side-by-side summary.

        Args:
            normal_result: Verification report after normal delete.
            secure_result: Verification report after secure delete.

        Returns:
            dict with comparison details.
        """
        return {
            "timestamp": datetime.now().isoformat(),
            "normal_delete": {
                "recoverable": normal_result.get("recoverable", False),
                "risk": normal_result.get("recovery_risk", "UNKNOWN"),
                "artifacts_found": len(normal_result.get("found_artifacts", [])),
            },
            "secure_delete": {
                "recoverable": secure_result.get("recoverable", False),
                "risk": secure_result.get("recovery_risk", "UNKNOWN"),
                "artifacts_found": len(secure_result.get("found_artifacts", [])),
            },
            "conclusion": self._comparison_conclusion(normal_result, secure_result),
        }

    # ------------------------------------------------------------------
    # Internal scanning methods
    # ------------------------------------------------------------------

    def _scan_by_filename(self, filename):
        """Search scan directories for files with matching name."""
        matches = []
        for scan_dir in self.scan_directories:
            if not scan_dir.exists():
                continue
            for root, _, files in os.walk(scan_dir):
                for f in files:
                    if f == filename:
                        matches.append(Path(root) / f)
        return matches

    def _scan_by_hash(self, target_hash):
        """Search scan directories for files with matching SHA-256 hash."""
        matches = []
        for scan_dir in self.scan_directories:
            if not scan_dir.exists():
                continue
            for root, _, files in os.walk(scan_dir):
                for f in files:
                    fpath = Path(root) / f
                    try:
                        if self._hash_file(fpath) == target_hash:
                            matches.append(fpath)
                    except Exception:
                        continue
        return matches

    def _scan_by_signature(self, hex_signature):
        """Search scan directories for files containing the given byte signature."""
        try:
            sig_bytes = bytes.fromhex(hex_signature)
        except ValueError:
            return []

        matches = []
        for scan_dir in self.scan_directories:
            if not scan_dir.exists():
                continue
            for root, _, files in os.walk(scan_dir):
                for f in files:
                    fpath = Path(root) / f
                    try:
                        with open(fpath, "rb") as fp:
                            content = fp.read()
                            if sig_bytes in content:
                                matches.append(fpath)
                    except Exception:
                        continue
        return matches

    @staticmethod
    def _hash_file(filepath, algorithm="sha256"):
        h = hashlib.new(algorithm)
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()

    # ------------------------------------------------------------------
    # Summary builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_summary(report):
        if not report["recoverable"]:
            return (
                f"✓ File '{report['filename']}' appears to be securely deleted. "
                f"No recoverable artifacts found."
            )
        artifact_count = len(report["found_artifacts"])
        return (
            f"✗ File '{report['filename']}' is POTENTIALLY RECOVERABLE. "
            f"{artifact_count} artifact(s) found. "
            f"Recovery risk: {report['recovery_risk']}."
        )

    @staticmethod
    def _comparison_conclusion(normal_result, secure_result):
        normal_rec = normal_result.get("recoverable", False)
        secure_rec = secure_result.get("recoverable", False)
        if normal_rec and not secure_rec:
            return (
                "Normal deletion left recoverable artifacts, while secure deletion "
                "successfully prevented recovery. This demonstrates why secure "
                "overwriting is essential for data privacy."
            )
        elif not normal_rec and not secure_rec:
            return (
                "Neither method left recoverable artifacts in the scanned directories. "
                "However, normal deletion typically leaves data on disk that "
                "specialized tools can recover."
            )
        elif normal_rec and secure_rec:
            return (
                "Both methods left some artifacts. The secure deletion may need "
                "additional passes or the scan directories still contain copies."
            )
        else:
            return "Unexpected result – manual review recommended."


# ------------------------------------------------------------------
# Quick self-test
# ------------------------------------------------------------------
if __name__ == "__main__":
    print("=== Post-Deletion Verification Self-Test ===\n")
    pdv = PostDeletionVerification()

    # Test with a non-existent file
    report = pdv.verify("some_deleted_file.txt")
    print(f"Recoverable: {report['recoverable']}")
    print(f"Risk: {report['recovery_risk']}")
    print(f"Summary: {report['summary']}")

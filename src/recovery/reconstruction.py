#!/usr/bin/env python3
"""
Module 5 – Activity Reconstruction (Member 1)
===============================================
Aggregates all artifacts collected by Modules 1–4 and Member 2's
forensic logs to build a unified, chronological timeline of events.

Features:
  • Merges simulation metadata, browser artifacts, system metadata,
    residual data findings, and Member 2's forensic log entries
  • Sorts everything by timestamp
  • Highlights suspicious gaps or anomalies
  • Exports the full timeline to a readable text report
"""

import json
from pathlib import Path
from datetime import datetime

from .shared_constants import (
    EVIDENCE_DIR, REPORTS_DIR, PROJECT_BASE,
    SEVERITY_INFO,
)


class ActivityReconstructor:
    """
    Aggregates forensic artifacts from all sources and builds a
    unified event timeline.
    """

    def __init__(self, evidence_dir=None, reports_dir=None, evidence_logger=None):
        self.evidence_dir = Path(evidence_dir) if evidence_dir else EVIDENCE_DIR
        self.reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
        self.evidence_logger = evidence_logger
        self._timeline = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reconstruct(self, simulation_data=None, browser_artifacts=None,
                    file_metadata=None, residual_results=None):
        """
        Build a unified timeline from all available data sources.

        Returns:
            list of timeline event dicts sorted by timestamp.
        """
        self._timeline = []

        # Source 1: Simulation metadata
        if simulation_data:
            for a in simulation_data:
                self._add_event(
                    a.get("timestamp", ""), a.get("event_type", "unknown"),
                    "Activity Simulation", a.get("detail", ""),
                    a.get("filepath", ""),
                )
        else:
            meta_file = self.evidence_dir / "simulation_metadata.json"
            if meta_file.exists():
                try:
                    with open(meta_file, "r") as f:
                        for a in json.load(f):
                            self._add_event(
                                a.get("timestamp", ""), a.get("event_type", "unknown"),
                                "Activity Simulation", a.get("detail", ""),
                                a.get("filepath", ""),
                            )
                except Exception:
                    pass

        # Source 2: Browser artifacts
        if browser_artifacts:
            for a in browser_artifacts:
                self._add_event(
                    a.get("timestamp", ""),
                    f"browser_{a.get('type', 'artifact')}",
                    f"Browser ({a.get('browser', 'Unknown')})",
                    a.get("detail", ""), a.get("path", ""),
                )

        # Source 3: File metadata
        if file_metadata:
            for m in file_metadata:
                self._add_event(
                    m.get("created", ""), "file_created", "System Metadata",
                    f"{m.get('name', '')} ({m.get('size', 0)} bytes)",
                    m.get("path", ""),
                )
                if m.get("modified", "") != m.get("created", ""):
                    self._add_event(
                        m.get("modified", ""), "file_modified", "System Metadata",
                        f"{m.get('name', '')} modified", m.get("path", ""),
                    )
                if m.get("accessed", "") and m.get("accessed") != m.get("modified"):
                    self._add_event(
                        m.get("accessed", ""), "file_accessed", "System Metadata",
                        f"{m.get('name', '')} accessed", m.get("path", ""),
                    )

        # Source 4: Residual data findings
        if residual_results:
            for r in residual_results:
                self._add_event(
                    r.get("modified", ""), "residual_found", "Residual Scanner",
                    f"[{r.get('classification', 'unknown')}] {r.get('name', '')}",
                    r.get("path", ""),
                )

        # Source 5: Member 2's forensic log
        m2_log = PROJECT_BASE / "reports" / "forensic_log.json"
        if m2_log.exists():
            try:
                with open(m2_log, "r") as f:
                    for e in json.load(f):
                        self._add_event(
                            e.get("timestamp", ""), e.get("category", "unknown"),
                            "Member 2 – Deletion Logs", e.get("action", ""),
                            e.get("details", {}).get("filepath", ""),
                        )
            except Exception:
                pass

        # Source 6: Evidence logger entries
        evidence_json = self.evidence_dir / "forensic_report.json"
        if evidence_json.exists():
            try:
                with open(evidence_json, "r") as f:
                    for e in json.load(f):
                        self._add_event(
                            e.get("timestamp", ""), e.get("event_type", "unknown"),
                            f"Evidence ({e.get('module', 'unknown')})",
                            e.get("detail", ""),
                        )
            except Exception:
                pass

        self._timeline.sort(key=lambda x: x["timestamp"])
        self._detect_anomalies()

        if self.evidence_logger:
            self.evidence_logger.log(
                "reconstruction", "timeline_built",
                f"Reconstructed timeline with {len(self._timeline)} events",
                SEVERITY_INFO,
            )
        return self._timeline

    def export_timeline(self, filepath=None):
        """Export the timeline to a readable text report."""
        dest = Path(filepath) if filepath else self.reports_dir / "timeline_report.txt"
        dest.parent.mkdir(parents=True, exist_ok=True)

        lines = [
            "=" * 70,
            "  FORENSIC ACTIVITY RECONSTRUCTION – TIMELINE REPORT",
            "=" * 70,
            f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Total Events: {len(self._timeline)}",
            "=" * 70, "",
        ]

        for e in self._timeline:
            ts = e["timestamp"][:19].replace("T", " ") if e["timestamp"] else "N/A"
            flag = " ⚠ ANOMALY" if e.get("flag") else ""
            lines.append(f"[{ts}] {e['event']:20s} | {e['source']:25s} | {e['detail']}{flag}")
            if e.get("flag"):
                lines.append(f"         └── FLAG: {e['flag']}")

        lines.extend(["", "=" * 70, "  END OF REPORT", "=" * 70])

        with open(dest, "w") as f:
            f.write("\n".join(lines))
        return str(dest)

    def get_timeline(self):
        return self._timeline

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _add_event(self, timestamp, event, source, detail, filepath=""):
        self._timeline.append({
            "timestamp": timestamp, "event": event, "source": source,
            "detail": detail, "filepath": filepath, "flag": "",
        })

    def _detect_anomalies(self):
        """Flag files accessed/modified after deletion."""
        deleted = {}
        for e in self._timeline:
            if "delet" in e["event"].lower():
                fp = e.get("filepath", "")
                if fp:
                    deleted[fp] = e["timestamp"]

        for e in self._timeline:
            if e["event"] in ("file_accessed", "file_modified"):
                fp = e.get("filepath", "")
                if fp in deleted and e["timestamp"] > deleted[fp]:
                    e["flag"] = (
                        f"File accessed/modified AFTER deletion "
                        f"(deleted at {deleted[fp][:19]})"
                    )

        for e in self._timeline:
            if e["event"] == "residual_found":
                for fp, del_ts in deleted.items():
                    if Path(fp).name in e["detail"]:
                        e["flag"] = (
                            f"Residual trace of deleted file '{Path(fp).name}' found"
                        )
                        break


# ════════════════════════════════════════════════════════════════════
#  Self-test
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=== Activity Reconstruction Self-Test ===\n")
    ar = ActivityReconstructor()
    timeline = ar.reconstruct()
    print(f"Timeline events: {len(timeline)}")
    for e in timeline[:10]:
        ts = e["timestamp"][:19].replace("T", " ") if e["timestamp"] else "N/A"
        flag = " ⚠" if e.get("flag") else ""
        print(f"  [{ts}] {e['event']:20s} | {e['source']:20s} | {e['detail'][:40]}{flag}")
    report = ar.export_timeline()
    print(f"\nTimeline exported to: {report}")
    print("\n✓ Activity Reconstruction self-test passed.")

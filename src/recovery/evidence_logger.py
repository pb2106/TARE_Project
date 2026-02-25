#!/usr/bin/env python3
"""
Module 6 – Evidence Logging (Member 1)
=======================================
Central logging module used by all other Member 1 modules.

Features:
  • Writes structured log entries (timestamp, module, event_type,
    severity, detail) to ``forensic_evidence.log`` and optionally
    ``forensic_report.json``
  • Export compiled report to HTML, JSON, or PDF (reportlab)
"""

import os
import json
from pathlib import Path
from datetime import datetime

# ── Local imports ───────────────────────────────────────────────────
from .shared_constants import (
    EVIDENCE_DIR, REPORTS_DIR,
    SEVERITY_INFO, SEVERITY_WARNING, SEVERITY_FINDING, SEVERITY_ALERT,
    SEVERITY_COLOURS, ACCENT_BLUE, ACCENT_GREEN, ACCENT_RED, ACCENT_ORANGE,
)


class EvidenceLogger:
    """
    Centralized evidence logger for all Member 1 forensic modules.

    Every call to :meth:`log` persists a structured entry to both an
    in-memory list and on-disk files (``forensic_evidence.log`` text
    file and ``forensic_report.json`` JSON array).
    """

    def __init__(self, evidence_dir=None, reports_dir=None):
        """
        Initialise the evidence logger.

        Args:
            evidence_dir: Directory for log/report files.
                          Defaults to ``forensic_project/evidence``.
            reports_dir:  Directory for exported reports.
                          Defaults to ``forensic_project/reports``.
        """
        self.evidence_dir = Path(evidence_dir) if evidence_dir else EVIDENCE_DIR
        self.reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR

        # Ensure directories exist
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)

        # File paths
        self.log_file = self.evidence_dir / "forensic_evidence.log"
        self.json_file = self.evidence_dir / "forensic_report.json"

        # In-memory entries
        self._entries = []

        # Load existing JSON entries if present
        if self.json_file.exists():
            try:
                with open(self.json_file, "r") as f:
                    self._entries = json.load(f)
            except (json.JSONDecodeError, Exception):
                self._entries = []

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def log(self, module_name, event_type, detail, severity=SEVERITY_INFO):
        """
        Record a forensic evidence entry.

        Args:
            module_name: Name of the originating module.
            event_type:  Short event tag (e.g. ``'file_created'``).
            detail:      Human-readable description string.
            severity:    One of INFO, WARNING, FINDING, ALERT.

        Returns:
            The log entry dict.
        """
        entry = {
            "id": len(self._entries) + 1,
            "timestamp": datetime.now().isoformat(),
            "module": module_name,
            "event_type": event_type,
            "severity": severity,
            "detail": detail,
        }
        self._entries.append(entry)
        self._persist()
        return entry

    def get_entries(self, module=None, severity=None, last_n=None):
        """
        Retrieve log entries with optional filters.

        Args:
            module:   Filter by module name.
            severity: Filter by severity level.
            last_n:   Return only the last *n* entries.

        Returns:
            List of entry dicts.
        """
        entries = self._entries
        if module:
            entries = [e for e in entries if e["module"] == module]
        if severity:
            entries = [e for e in entries if e["severity"] == severity]
        if last_n:
            entries = entries[-last_n:]
        return entries

    def get_formatted_text(self, module=None, severity=None, last_n=None):
        """Return entries as a formatted multiline string for display."""
        entries = self.get_entries(module=module, severity=severity, last_n=last_n)
        lines = []
        for e in entries:
            ts = e["timestamp"][:19].replace("T", " ")
            sev = e["severity"]
            icon = {"INFO": "ℹ", "WARNING": "⚠", "FINDING": "🔍", "ALERT": "🚨"}.get(sev, "•")
            lines.append(
                f"[{ts}] {icon} [{sev}] [{e['module']}] "
                f"{e['event_type']}: {e['detail']}"
            )
        return "\n".join(lines) if lines else "(no evidence entries)"

    def get_entry_count(self):
        """Return total number of logged entries."""
        return len(self._entries)

    def clear(self):
        """Clear all in-memory and on-disk entries."""
        self._entries = []
        self._persist()

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_report(self, filepath=None, fmt="html"):
        """
        Compile all findings into a formatted report.

        Args:
            filepath: Destination path.
            fmt:      ``'html'``, ``'json'``, or ``'pdf'``.

        Returns:
            Path to the exported file.
        """
        if fmt == "json":
            return self._export_json(filepath)
        elif fmt == "pdf":
            return self._export_pdf(filepath)
        else:
            return self._export_html(filepath)

    def _export_json(self, filepath=None):
        """Export entries as a JSON file."""
        dest = Path(filepath) if filepath else self.reports_dir / "forensic_report.json"
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open(dest, "w") as f:
            json.dump(self._entries, f, indent=2)
        return str(dest)

    def _export_html(self, filepath=None):
        """Export entries as a styled HTML report."""
        dest = Path(filepath) if filepath else self.reports_dir / "forensic_report.html"
        dest.parent.mkdir(parents=True, exist_ok=True)

        sev_css = {
            SEVERITY_INFO: "#00adb5", SEVERITY_WARNING: "#ff9800",
            SEVERITY_FINDING: "#00e676", SEVERITY_ALERT: "#ff5252",
        }

        rows = ""
        for e in self._entries:
            colour = sev_css.get(e["severity"], "#e0e0e0")
            ts = e["timestamp"][:19].replace("T", " ")
            rows += (
                f'<tr><td>{e["id"]}</td><td>{ts}</td>'
                f'<td style="color:{colour};font-weight:bold">{e["severity"]}</td>'
                f'<td>{e["module"]}</td><td>{e["event_type"]}</td>'
                f'<td>{e["detail"]}</td></tr>\n'
            )

        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>Forensic Evidence Report</title>
<style>
  body {{ background:#1a1a2e; color:#e0e0e0; font-family:'Segoe UI',sans-serif; padding:30px; }}
  h1 {{ color:#00adb5; }}
  table {{ width:100%; border-collapse:collapse; margin-top:20px; }}
  th {{ background:#0f3460; color:#e0e0e0; padding:10px; text-align:left; }}
  td {{ padding:8px 10px; border-bottom:1px solid #16213e; }}
  tr:hover {{ background:#16213e; }}
  .footer {{ margin-top:30px; color:#8899aa; font-size:0.9em; }}
</style></head><body>
<h1>🔍 Forensic Evidence Report</h1>
<p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
<p>Total entries: {len(self._entries)}</p>
<table><tr><th>#</th><th>Timestamp</th><th>Severity</th><th>Module</th>
<th>Event</th><th>Detail</th></tr>{rows}</table>
<div class="footer"><p>Digital Forensics Analysis Tool</p></div>
</body></html>"""

        with open(dest, "w") as f:
            f.write(html)
        return str(dest)

    def _export_pdf(self, filepath=None):
        """Export entries as a PDF (falls back to HTML if reportlab missing)."""
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer,
            )
            from reportlab.lib.styles import getSampleStyleSheet
        except ImportError:
            dest = filepath or str(self.reports_dir / "forensic_report.html")
            result = self._export_html(dest)
            return result + " (PDF unavailable – exported as HTML)"

        dest = Path(filepath) if filepath else self.reports_dir / "forensic_report.pdf"
        dest.parent.mkdir(parents=True, exist_ok=True)

        doc = SimpleDocTemplate(str(dest), pagesize=A4)
        styles = getSampleStyleSheet()
        elements = [
            Paragraph("Forensic Evidence Report", styles["Title"]),
            Spacer(1, 12),
            Paragraph(
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | "
                f"Total entries: {len(self._entries)}", styles["Normal"],
            ),
            Spacer(1, 20),
        ]

        data = [["#", "Timestamp", "Severity", "Module", "Event", "Detail"]]
        for e in self._entries:
            ts = e["timestamp"][:19].replace("T", " ")
            data.append([str(e["id"]), ts, e["severity"],
                         e["module"], e["event_type"], e["detail"][:60]])

        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f3460")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.HexColor("#1a1a2e"), colors.HexColor("#16213e")]),
            ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#e0e0e0")),
        ]))
        elements.append(table)
        doc.build(elements)
        return str(dest)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _persist(self):
        """Write current entries to disk (log + JSON)."""
        try:
            if self._entries:
                latest = self._entries[-1]
                ts = latest["timestamp"][:19].replace("T", " ")
                line = (
                    f"[{ts}] [{latest['severity']}] [{latest['module']}] "
                    f"{latest['event_type']}: {latest['detail']}\n"
                )
                with open(self.log_file, "a") as f:
                    f.write(line)
            with open(self.json_file, "w") as f:
                json.dump(self._entries, f, indent=2)
        except Exception:
            pass  # best-effort persistence


# ════════════════════════════════════════════════════════════════════
#  Self-test
# ════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=== Evidence Logger Self-Test ===\n")
    el = EvidenceLogger()
    el.clear()

    el.log("self_test", "init", "Evidence logger initialised", SEVERITY_INFO)
    el.log("self_test", "file_created", "Created test.txt in user_files", SEVERITY_INFO)
    el.log("self_test", "artifact_found", "Residual thumbnail database detected", SEVERITY_FINDING)
    el.log("self_test", "anomaly", "File accessed 3 min after deletion timestamp", SEVERITY_WARNING)
    el.log("self_test", "critical", "Unencrypted credentials found in swap", SEVERITY_ALERT)

    print(el.get_formatted_text())
    print(f"\nTotal entries: {el.get_entry_count()}")
    print(f"HTML report: {el.export_report(fmt='html')}")
    print(f"JSON report: {el.export_report(fmt='json')}")
    print(f"PDF report:  {el.export_report(fmt='pdf')}")
    print("\n✓ Evidence Logger self-test passed.")

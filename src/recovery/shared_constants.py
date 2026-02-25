#!/usr/bin/env python3
"""
Shared Constants – Recovery & Analysis Modules (Member 1)
=========================================================
Centralized colour palette, font definitions, and project paths
used by all Member 1 modules.  Values are kept identical to the
colour scheme defined in Member 2's main_gui.py for visual
consistency across the entire application.
"""

from pathlib import Path

# ── Colour Palette (matches Member 2) ──────────────────────────────
BG_DARK      = "#1a1a2e"
BG_PANEL     = "#16213e"
BG_CARD      = "#0f3460"
FG_TEXT      = "#e0e0e0"
FG_DIM       = "#8899aa"
ACCENT_BLUE  = "#00adb5"
ACCENT_GREEN = "#00e676"
ACCENT_RED   = "#ff5252"
ACCENT_ORANGE = "#ff9800"
ACCENT_PURPLE = "#bb86fc"
BTN_BG       = "#0f3460"
BTN_ACTIVE   = "#1a5276"
ENTRY_BG     = "#222244"

# ── Fonts ───────────────────────────────────────────────────────────
FONT_HEADING  = ("Segoe UI", 14, "bold")
FONT_SUBHEAD  = ("Segoe UI", 12, "bold")
FONT_LABEL    = ("Segoe UI", 10)
FONT_DIM      = ("Segoe UI", 10)
FONT_MONO     = ("Consolas", 10)
FONT_MONO_SM  = ("Consolas", 9)

# ── Project Paths ───────────────────────────────────────────────────
PROJECT_BASE     = Path("forensic_project").absolute()
TEST_ENV         = PROJECT_BASE / "test_environment"
USER_FILES_DIR   = TEST_ENV / "user_files"
BROWSER_DATA_DIR = TEST_ENV / "browser_data"
SYSTEM_LOGS_DIR  = TEST_ENV / "system_logs"
TEMP_FILES_DIR   = TEST_ENV / "temp_files"
DELETED_FILES_DIR = TEST_ENV / "deleted_files"
EVIDENCE_DIR     = PROJECT_BASE / "evidence"
REPORTS_DIR      = PROJECT_BASE / "reports"
CONFIG_DIR       = PROJECT_BASE / "config"

# ── Severity / Event constants ──────────────────────────────────────
SEVERITY_INFO    = "INFO"
SEVERITY_WARNING = "WARNING"
SEVERITY_FINDING = "FINDING"
SEVERITY_ALERT   = "ALERT"

SEVERITY_COLOURS = {
    SEVERITY_INFO:    ACCENT_BLUE,
    SEVERITY_WARNING: ACCENT_ORANGE,
    SEVERITY_FINDING: ACCENT_GREEN,
    SEVERITY_ALERT:   ACCENT_RED,
}

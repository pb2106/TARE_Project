#!/usr/bin/env python3
"""
Forensic Analysis of Digital Footprints and Secure Data Deletion
=================================================================
Unified Streamlit interface connecting Recovery & Analysis (Member 1)
and Secure Deletion & Mitigation (Member 2) modules.

Run with:  streamlit run main.py
"""

# ── Standard Library ────────────────────────────────────────────────
import sys
import os
import json
import platform
import hashlib
from pathlib import Path
from datetime import datetime

# ── Path Setup ──────────────────────────────────────────────────────
ROOT = Path(__file__).parent.resolve()
os.chdir(ROOT)
sys.path.insert(0, str(ROOT / "src" / "Deletion"))
sys.path.insert(0, str(ROOT / "src"))

# ── Third-party ─────────────────────────────────────────────────────
import streamlit as st
import pandas as pd

# ── Member 1 Modules (Recovery & Analysis) ──────────────────────────
from recovery.evidence_logger import EvidenceLogger
from recovery.activity_simulation import ActivitySimulator
from recovery.browser_cache import BrowserCacheSimulator
from recovery.system_metadata import SystemMetadataAnalyzer
from recovery.residual_data import ResidualDataScanner
from recovery.reconstruction import ActivityReconstructor

# ── Member 2 Modules (Deletion & Mitigation) ───────────────────────
from deletion_techniques import DeletionTechniques
from secure_deletion import SecureDeletion
from post_deletion_verification import PostDeletionVerification
from forensic_logger import ForensicLogger
from environment_setup import EnvironmentSetup


# ════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ════════════════════════════════════════════════════════════════════

st.set_page_config(
    page_title="Digital Forensics Analysis Tool",
    page_icon="magnifying_glass_tilted_left",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; }
    h1, h2, h3 { font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg, #16213e 0%, #1a1a2e 100%);
    }
    [data-testid="stSidebar"] hr { border-color: #0f3460; }

    [data-testid="stMetric"] {
        background: #0f3460;
        border-radius: 8px;
        padding: 14px 18px;
        border: 1px solid rgba(0,173,181,0.15);
    }

    .log-container {
        background: #222244;
        border-radius: 6px;
        padding: 14px;
        font-family: 'Consolas', 'Courier New', monospace;
        font-size: 0.85rem;
        color: #e0e0e0;
        max-height: 420px;
        overflow-y: auto;
        line-height: 1.6;
    }
    .sev-info    { color: #00adb5; }
    .sev-warning { color: #ff9800; }
    .sev-finding { color: #00e676; }
    .sev-alert   { color: #ff5252; }

    .stTabs [data-baseweb="tab-list"] { gap: 4px; }
    .stTabs [data-baseweb="tab"] { border-radius: 6px 6px 0 0; padding: 8px 20px; }
</style>
""", unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════
#  INITIALISATION
# ════════════════════════════════════════════════════════════════════

PROJECT_DIR = Path("forensic_project").absolute()
TEST_ENV = PROJECT_DIR / "test_environment"
USER_FILES = TEST_ENV / "user_files"
BROWSER_DATA = TEST_ENV / "browser_data"


@st.cache_resource
def init_environment():
    env = EnvironmentSetup("forensic_project")
    env.setup_environment()
    return env


@st.cache_resource
def get_modules():
    return {
        "evidence_logger": EvidenceLogger(),
        "forensic_logger": ForensicLogger(),
        "deleter": DeletionTechniques(),
        "verifier": PostDeletionVerification(),
        "secure_eng": SecureDeletion(),
    }


init_environment()
mods = get_modules()
el = mods["evidence_logger"]
fl = mods["forensic_logger"]

_DEFAULTS = {
    "deletion_history": [],
    "pre_delete_hashes": {},
    "deletion_records": {},
    "activity_log": [],
    "browser_artifacts": [],
    "file_metadata": [],
    "residual_results": [],
    "timeline": [],
    "system_logs": [],
}
for k, v in _DEFAULTS.items():
    if k not in st.session_state:
        st.session_state[k] = v


# ════════════════════════════════════════════════════════════════════
#  HELPERS
# ════════════════════════════════════════════════════════════════════

def _human_size(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024.0:
            return f"{n:3.1f} {unit}"
        n /= 1024.0
    return f"{n:3.1f} TB"


def _hash_file(filepath):
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return "N/A"


def _list_files(directory):
    p = Path(directory)
    if not p.exists():
        return []
    files = []
    try:
        for item in sorted(p.iterdir()):
            if item.is_file():
                stat = item.stat()
                files.append({
                    "Name": item.name,
                    "Size": _human_size(stat.st_size),
                    "Size_bytes": stat.st_size,
                    "Modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "Path": str(item),
                })
    except PermissionError:
        pass
    return files


def _collect_all_test_files():
    """List every file under the test environment."""
    if not TEST_ENV.exists():
        return []
    files = []
    try:
        for item in sorted(TEST_ENV.rglob("*")):
            if item.is_file():
                stat = item.stat()
                rel = item.relative_to(TEST_ENV)
                files.append({
                    "Name": item.name,
                    "Location": str(rel.parent),
                    "Size": _human_size(stat.st_size),
                    "Size_bytes": stat.st_size,
                    "Modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "Path": str(item),
                })
    except PermissionError:
        pass
    return files


# ════════════════════════════════════════════════════════════════════
#  RECOVERY ANALYSIS ENGINE
# ════════════════════════════════════════════════════════════════════

def _get_trash_directories():
    """Return platform-specific trash/recycle-bin directories."""
    dirs = []
    system = platform.system()
    home = Path.home()
    if system == "Linux":
        # FreeDesktop trash spec
        dirs.append(home / ".local" / "share" / "Trash" / "files")
        dirs.append(home / ".local" / "share" / "Trash" / "info")
        dirs.append(Path("/tmp"))
    elif system == "Darwin":
        dirs.append(home / ".Trash")
    elif system == "Windows":
        # C:\$Recycle.Bin is not directly accessible, but we can check
        for drive in ["C", "D", "E"]:
            rb = Path(f"{drive}:\\$Recycle.Bin")
            if rb.exists():
                dirs.append(rb)
        temp = os.environ.get("TEMP", os.environ.get("TMP", ""))
        if temp:
            dirs.append(Path(temp))
    return [d for d in dirs if d.exists()]


def _scan_for_file(filename, target_hash=None, content_sample_hex=None):
    """
    Scan the test environment, trash, and common temp dirs for traces
    of a file by name, hash, or content signature.

    Returns list of evidence dicts.
    """
    evidence = []
    scan_dirs = [
        TEST_ENV,
        PROJECT_DIR / "evidence",
    ] + _get_trash_directories()

    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        try:
            for root, _, files in os.walk(scan_dir):
                for fname in files:
                    fpath = Path(root) / fname

                    # Name match
                    if fname == filename:
                        evidence.append({
                            "type": "Name Match",
                            "detail": f"File with same name found at: {fpath}",
                        })

                    # Hash match
                    if target_hash and target_hash != "N/A":
                        try:
                            if _hash_file(str(fpath)) == target_hash:
                                evidence.append({
                                    "type": "Content Match (Hash)",
                                    "detail": (
                                        f"Identical content (SHA-256) found at: "
                                        f"{fpath}"
                                    ),
                                })
                        except Exception:
                            pass

                    # Content signature match
                    if content_sample_hex and len(content_sample_hex) >= 16:
                        try:
                            sig = bytes.fromhex(content_sample_hex[:64])
                            with open(fpath, "rb") as f:
                                head = f.read(256)
                            if sig in head:
                                # Avoid duplicate if already matched by hash
                                if not any(
                                    "Content Match" in e["type"]
                                    and str(fpath) in e["detail"]
                                    for e in evidence
                                ):
                                    evidence.append({
                                        "type": "Content Signature Match",
                                        "detail": (
                                            f"Matching byte signature found "
                                            f"in: {fpath}"
                                        ),
                                    })
                        except Exception:
                            pass
        except PermissionError:
            continue

    return evidence


def _check_residual_traces(filename):
    """
    Check for derivative files — swap files, lock files, temp copies,
    recent-use logs — that reference the deleted file.
    """
    evidence = []
    stem = Path(filename).stem
    patterns_to_check = [
        f".{filename}.swp",       # Vim swap
        f".{filename}.swo",
        f"~${filename}",          # Office lock
        f"{filename}.tmp",
        f"{filename}.bak",
        f"{stem}.tmp",
    ]

    scan_dirs = [TEST_ENV]
    for scan_dir in scan_dirs:
        if not scan_dir.exists():
            continue
        for root, _, files in os.walk(scan_dir):
            for fname in files:
                fpath = Path(root) / fname
                if fname in patterns_to_check:
                    evidence.append({
                        "type": "Residual Trace",
                        "detail": f"Related file found: {fpath}",
                    })

    # Check recently_opened.log for references
    recent_log = TEST_ENV / "temp_files" / "recently_opened.log"
    if recent_log.exists():
        try:
            content = recent_log.read_text()
            if filename in content:
                evidence.append({
                    "type": "Access Log Reference",
                    "detail": (
                        f"File '{filename}' is referenced in the recent "
                        f"access log: {recent_log}"
                    ),
                })
        except Exception:
            pass

    # Check simulation metadata for references
    meta_file = PROJECT_DIR / "evidence" / "simulation_metadata.json"
    if meta_file.exists():
        try:
            with open(meta_file) as f:
                entries = json.load(f)
            for entry in entries:
                if filename in entry.get("detail", "") or filename in entry.get("filepath", ""):
                    evidence.append({
                        "type": "Metadata Reference",
                        "detail": (
                            f"File '{filename}' is recorded in simulation "
                            f"metadata ({entry.get('event_type', 'unknown')} "
                            f"at {entry.get('timestamp', 'N/A')[:19]})"
                        ),
                    })
                    break  # one reference is enough
        except Exception:
            pass

    return evidence


def _run_recovery_analysis(filepath):
    """
    Comprehensive forensic recovery analysis for a deleted file.

    Logic:
      - NORMAL delete (trash):    Data is moved to Recycle Bin, fully
        intact. RECOVERABLE — simply restore from trash.
      - PERMANENT delete (unlink): File reference removed, but actual
        data blocks remain on disk until overwritten. RECOVERABLE
        with forensic tools.
      - SECURE delete (overwrite): Content overwritten with random/zero
        data BEFORE deletion. NOT RECOVERABLE — original data destroyed.
    """
    filepath = str(Path(filepath).absolute())
    record = st.session_state.deletion_records.get(filepath, {})
    method = record.get("method", "unknown")
    filename = record.get("filename", Path(filepath).name)
    orig_hash = record.get("hash", st.session_state.pre_delete_hashes.get(filepath))
    content_sample = record.get("content_sample", "")
    original_exists = Path(filepath).exists()

    checks = []
    evidence = []
    recoverable = False
    risk = "NONE"

    # ── Check 1: Original path existence ────────────────────────────
    checks.append({
        "name": "Original Path Existence",
        "passed": original_exists,
        "detail": (
            f"File still exists at original path"
            if original_exists else
            f"File removed from original path"
        ),
    })
    if original_exists:
        recoverable = True
        evidence.append({
            "type": "Original File",
            "detail": f"File still exists at: {filepath}",
        })

    # ── Check 2: Deletion method analysis ───────────────────────────
    if method == "normal":
        checks.append({
            "name": "Deletion Method Analysis",
            "passed": True,
            "detail": (
                "NORMAL DELETE — File was moved to Recycle Bin / Trash. "
                "The data is intact and can be restored by the user."
            ),
        })
        recoverable = True
        evidence.append({
            "type": "Recycle Bin / Trash",
            "detail": (
                "Normal deletion only moves the file to the system trash. "
                "Full content is preserved and can be restored."
            ),
        })

    elif method == "permanent":
        checks.append({
            "name": "Deletion Method Analysis",
            "passed": True,
            "detail": (
                "PERMANENT DELETE — File reference (inode/MFT entry) removed, "
                "but actual data blocks remain on disk in unallocated space. "
                "Recoverable with forensic tools until sectors are reused."
            ),
        })
        recoverable = True
        evidence.append({
            "type": "Unallocated Disk Space",
            "detail": (
                "Permanent deletion removes the file system reference but "
                "does NOT erase the data blocks. Content remains on disk "
                "and is recoverable with forensic tools (e.g., Autopsy, "
                "FTK, PhotoRec)."
            ),
        })

    elif method == "secure":
        secure_mode = record.get("secure_mode", "random")
        secure_passes = record.get("secure_passes", 1)
        checks.append({
            "name": "Deletion Method Analysis",
            "passed": False,
            "detail": (
                f"SECURE DELETE — File content was overwritten with "
                f"'{secure_mode}' data ({secure_passes} pass"
                f"{'es' if secure_passes != 1 else ''}) before deletion. "
                f"Original data has been destroyed."
            ),
        })
        # Secure delete should NOT be recoverable (data was overwritten)
        # We don't set recoverable=True here

    else:
        checks.append({
            "name": "Deletion Method Analysis",
            "passed": True,
            "detail": "Unknown deletion method — assuming data may be recoverable.",
        })
        recoverable = True

    # ── Check 3: Scan trash and test environment ────────────────────
    scan_evidence = _scan_for_file(filename, orig_hash, content_sample)
    if scan_evidence:
        checks.append({
            "name": "File System Scan",
            "passed": True,
            "detail": f"Found {len(scan_evidence)} matching file(s) in scan directories.",
        })
        evidence.extend(scan_evidence)
        recoverable = True
    else:
        checks.append({
            "name": "File System Scan",
            "passed": False,
            "detail": "No matching files found in trash, test environment, or evidence directories.",
        })

    # ── Check 4: Residual traces ────────────────────────────────────
    residual = _check_residual_traces(filename)
    if residual:
        checks.append({
            "name": "Residual Trace Analysis",
            "passed": True,
            "detail": (
                f"Found {len(residual)} residual trace(s) — swap files, "
                f"access logs, or metadata referencing the deleted file."
            ),
        })
        evidence.extend(residual)
        # Residual traces alone indicate activity but not full recovery
        # They support the case that the file existed
    else:
        checks.append({
            "name": "Residual Trace Analysis",
            "passed": False,
            "detail": "No residual traces (swap, temp, log references) found.",
        })

    # ── Determine risk level ────────────────────────────────────────
    if recoverable:
        if method == "normal":
            risk = "HIGH"
        elif method == "permanent":
            risk = "MEDIUM"
        elif len(evidence) >= 3:
            risk = "HIGH"
        else:
            risk = "MEDIUM"
    else:
        risk = "NONE"

    # ── Build summary ───────────────────────────────────────────────
    if method == "normal":
        summary = (
            f"File '{filename}' was moved to the Recycle Bin / Trash. "
            f"It is FULLY RECOVERABLE. The user can simply restore it, "
            f"or forensic tools can extract it. "
            f"{len(evidence)} piece(s) of evidence found."
        )
    elif method == "permanent":
        summary = (
            f"File '{filename}' was permanently deleted (reference removed). "
            f"However, the actual data remains on disk in unallocated space "
            f"and is RECOVERABLE with forensic tools. "
            f"{len(evidence)} piece(s) of evidence found."
        )
    elif method == "secure" and not recoverable:
        summary = (
            f"File '{filename}' was securely overwritten before deletion. "
            f"The original data has been destroyed and is NOT RECOVERABLE. "
            f"This demonstrates proper secure data removal."
        )
    else:
        summary = (
            f"File '{filename}' — {len(evidence)} piece(s) of evidence found. "
            f"Recovery risk: {risk}."
        )

    # Log to evidence logger
    el.log(
        "recovery_verification",
        "recovery_check",
        f"{filename}: method={method}, recoverable={recoverable}, risk={risk}",
        "FINDING" if recoverable else "INFO",
    )

    return {
        "recoverable": recoverable,
        "recovery_risk": risk,
        "method": method,
        "filename": filename,
        "checks": checks,
        "evidence": evidence,
        "summary": summary,
    }


# ════════════════════════════════════════════════════════════════════
#  SIDEBAR
# ════════════════════════════════════════════════════════════════════

with st.sidebar:
    st.markdown("### Digital Forensics")
    st.markdown("##### Analysis Tool")
    st.markdown("---")
    page = st.radio(
        "Navigation",
        [
            "Overview",
            "Perform User Activities",
            "File Management",
            "Data Deletion",
            "Forensic Analysis",
            "Timeline Reconstruction",
            "Evidence Report",
        ],
        label_visibility="collapsed",
    )
    st.markdown("---")
    st.caption(f"Platform: {platform.system()} {platform.release()}")
    st.caption(f"Python {platform.python_version()}")


# ════════════════════════════════════════════════════════════════════
#  PAGE: OVERVIEW
# ════════════════════════════════════════════════════════════════════

def page_overview():
    st.title("Forensic Analysis of Digital Footprints and Secure Data Deletion")
    st.markdown("---")

    st.markdown(
        "This project studies the digital traces that remain on a computer "
        "system even after a user deletes files, clears browser history, or "
        "removes activity. Normally, deleting data does not completely erase "
        "it; instead, the system only removes references to the data while "
        "the actual content remains stored in memory or disk space."
    )
    st.markdown(
        "Normal user activities are performed and then deleted, after which "
        "forensic techniques are used to analyze leftover artifacts such as "
        "cache files, logs, metadata, and unallocated storage. These traces "
        "are used to reconstruct the user's past actions, demonstrating how "
        "investigators recover evidence during digital investigations."
    )
    st.markdown(
        "The project also implements secure deletion methods, where memory "
        "locations are overwritten with dummy or random data before deletion "
        "to prevent recovery. This helps understand both the risks of "
        "improper deletion and the importance of secure data removal in "
        "protecting privacy and security."
    )

    st.markdown("---")
    st.subheader("Project Status")

    file_count = sum(
        1 for _ in TEST_ENV.rglob("*") if _.is_file()
    ) if TEST_ENV.exists() else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Platform", platform.system())
    c2.metric("Files in Environment", file_count)
    c3.metric("Evidence Entries", el.get_entry_count())
    c4.metric("Deletions Tracked", len(st.session_state.deletion_history))

    st.markdown("---")
    st.subheader("Workflow")
    st.markdown(
        "1. **Perform User Activities** — Create files, documents, and "
        "browser data within the test environment\n"
        "2. **Data Deletion** — Delete the created data using normal, "
        "permanent, or secure overwrite methods\n"
        "3. **Forensic Analysis** — Scan for recoverable artifacts: browser "
        "cache, metadata, residual files, system logs\n"
        "4. **Timeline Reconstruction** — Aggregate all findings into a "
        "chronological event timeline\n"
        "5. **Evidence Report** — Review and export the forensic evidence log"
    )


# ════════════════════════════════════════════════════════════════════
#  PAGE: PERFORM USER ACTIVITIES
# ════════════════════════════════════════════════════════════════════

def page_user_activities():
    st.header("Perform User Activities")
    st.caption(
        "Create files, documents, and browser data within the test "
        "environment to establish a digital footprint for forensic analysis."
    )

    tab_files, tab_browser = st.tabs(["File Activities", "Browser Activities"])

    # ── File activities ─────────────────────────────────────────────
    with tab_files:
        st.markdown(
            "Creates text documents, a confidential report, an image file, "
            "and various temporary/swap files in the working directory. "
            "Files are also read, renamed, and moved to leave metadata traces."
        )

        sim = ActivitySimulator(evidence_logger=el)

        if st.button("Execute File Activities", type="primary", key="run_files"):
            log_lines = []
            with st.spinner("Performing user file activities..."):
                actions = sim.run_simulation(callback=lambda l: log_lines.append(l))
            st.session_state.activity_log = log_lines
            st.success(f"Completed — {len(actions)} actions recorded.")
            fl.log_simulation(f"Performed {len(actions)} user file activities")

        if st.session_state.activity_log:
            st.markdown("##### Activity Log")
            st.code("\n".join(st.session_state.activity_log), language="text")

        # Show resulting files
        files = _list_files(str(USER_FILES))
        if files:
            st.markdown("##### Files in Working Directory")
            st.dataframe(
                pd.DataFrame(files)[["Name", "Size", "Modified"]],
                use_container_width=True, hide_index=True,
            )

    # ── Browser activities ──────────────────────────────────────────
    with tab_browser:
        st.markdown(
            "Creates browser history entries, cookies, and cached page content "
            "mimicking Chrome and Firefox profile structures."
        )

        bcs = BrowserCacheSimulator(evidence_logger=el)

        if st.button("Execute Browser Activities", type="primary", key="run_browser"):
            with st.spinner("Creating browser data..."):
                result = bcs.simulate_browsing()
            st.success(
                f"Created {sum(result.values())} artifacts: "
                f"{result['history']} history, {result['cookies']} cookies, "
                f"{result['cache']} cache files."
            )

        # Show what was created
        browser_files = _list_files(str(BROWSER_DATA))
        if browser_files or (BROWSER_DATA / "Chrome").exists():
            st.markdown("##### Browser Data Created")
            all_browser = []
            for bd in BROWSER_DATA.rglob("*"):
                if bd.is_file():
                    all_browser.append({
                        "File": bd.name,
                        "Browser": "Chrome" if "Chrome" in str(bd) else "Firefox",
                        "Location": str(bd.relative_to(BROWSER_DATA)),
                        "Size": _human_size(bd.stat().st_size),
                    })
            if all_browser:
                st.dataframe(pd.DataFrame(all_browser), use_container_width=True,
                             hide_index=True)


# ════════════════════════════════════════════════════════════════════
#  PAGE: FILE MANAGEMENT
# ════════════════════════════════════════════════════════════════════

def page_file_management():
    st.header("File Management")
    st.caption("Browse and inspect all files in the forensic test environment.")

    files = _collect_all_test_files()
    if not files:
        st.info("No files in the test environment. Use 'Perform User Activities' first.")
        return

    st.dataframe(
        pd.DataFrame(files)[["Name", "Location", "Size", "Modified"]],
        use_container_width=True, hide_index=True,
    )

    st.markdown("---")
    st.subheader("File Details")
    file_names = [f"{f['Location']}/{f['Name']}" for f in files]
    selected = st.selectbox("Select a file to inspect", file_names)

    if selected:
        match = next((f for f in files if f"{f['Location']}/{f['Name']}" == selected), None)
        if match:
            fpath = Path(match["Path"])
            if fpath.exists():
                stat = fpath.stat()
                c1, c2, c3 = st.columns(3)
                c1.metric("Size", _human_size(stat.st_size))
                c2.metric("Created", datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M"))
                c3.metric("Last Modified", datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"))

                with st.expander("Full Metadata"):
                    st.json({
                        "name": fpath.name,
                        "absolute_path": str(fpath),
                        "size_bytes": stat.st_size,
                        "sha256": _hash_file(fpath)[:32] + "...",
                        "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                        "accessed": datetime.fromtimestamp(stat.st_atime).isoformat(),
                    })


# ════════════════════════════════════════════════════════════════════
#  PAGE: DATA DELETION
# ════════════════════════════════════════════════════════════════════

def page_deletion():
    st.header("Data Deletion")
    st.caption(
        "Delete files using different methods — normal, permanent, "
        "or secure overwrite — and compare their forensic implications."
    )

    deleter = mods["deleter"]

    # Collect files from the test environment
    files = _collect_all_test_files()

    if not files:
        st.info("No files available for deletion. Use 'Perform User Activities' first.")
        return

    col_ctrl, col_res = st.columns([1, 1])

    with col_ctrl:
        st.subheader("Configure")

        file_options = [f"{f['Location']}/{f['Name']}" for f in files]
        selected_label = st.selectbox("Select File", file_options)
        selected_file = next(
            (f for f in files if f"{f['Location']}/{f['Name']}" == selected_label),
            None,
        )

        if selected_file:
            st.text(f"Path: {selected_file['Path']}")
            st.text(f"Size: {selected_file['Size']}")

        st.markdown("---")
        method = st.radio(
            "Deletion Method",
            ["normal", "permanent", "secure"],
            format_func=lambda m: {
                "normal":    "Normal — Move to Recycle Bin",
                "permanent": "Permanent — Bypass Trash",
                "secure":    "Secure — Overwrite then Delete",
            }[m],
        )

        if method == "secure":
            sc1, sc2 = st.columns(2)
            pattern = sc1.selectbox("Overwrite Pattern", ["random", "zeros", "dummy"])
            passes = sc2.selectbox("Overwrite Passes", [1, 3, 7])
        else:
            pattern, passes = "random", 1

    with col_res:
        st.subheader("Result")

        if st.button("Execute Deletion", type="primary"):
            if not selected_file:
                st.error("No file selected.")
                return

            fpath = selected_file["Path"]
            if not Path(fpath).exists():
                st.error("File no longer exists.")
                return

            # Store pre-delete hash AND content sample for later recovery checks
            abs_path = str(Path(fpath).absolute())
            pre_hash = _hash_file(fpath)
            st.session_state.pre_delete_hashes[abs_path] = pre_hash

            # Read first 256 bytes as hex for content-signature scanning
            try:
                with open(fpath, "rb") as _f:
                    content_sample = _f.read(256).hex()
            except Exception:
                content_sample = ""

            # Store full deletion record
            st.session_state.deletion_records[abs_path] = {
                "filename": Path(fpath).name,
                "method": method,
                "hash": pre_hash,
                "content_sample": content_sample,
                "timestamp": datetime.now().isoformat(),
                "size": selected_file["Size_bytes"],
                "secure_mode": pattern if method == "secure" else None,
                "secure_passes": passes if method == "secure" else None,
            }

            progress = st.progress(0, text="Processing...")

            def _cb(pct):
                progress.progress(pct / 100, text=f"Overwriting... {pct}%")

            result = deleter.delete_file(
                fpath, method=method,
                secure_mode=pattern, secure_passes=passes,
                progress_callback=_cb,
            )
            progress.progress(1.0, text="Complete")

            if result["status"] == "success":
                if abs_path not in st.session_state.deletion_history:
                    st.session_state.deletion_history.append(abs_path)
                st.success(f"{method.upper()} deletion completed successfully.")
                fl.log_deletion(fpath, method, result)
            else:
                st.error(f"Failed: {result.get('error', 'Unknown error')}")

            # Report
            st.markdown(f"**File:** {Path(fpath).name}")
            st.markdown(f"**Method:** {method.upper()}")
            st.markdown(f"**Status:** {result['status'].upper()}")

            if method == "secure" and "details" in result:
                d = result["details"]
                st.markdown(f"**Overwrite:** {d.get('overwrite_mode')} ({d.get('overwrite_passes')} passes)")
                st.markdown(f"**Time:** {d.get('time_taken')}s")
                st.markdown(f"**Hash Before:** `{str(d.get('hash_before',''))[:24]}...`")
                st.markdown(f"**Hash After:** `{str(d.get('hash_after',''))[:24]}...`")

            exists = Path(fpath).exists()
            st.markdown(
                f"**Verification:** {'FAIL — File still exists' if exists else 'PASS — File removed from disk'}"
            )

    # Deletion history
    if st.session_state.deletion_history:
        st.markdown("---")
        st.subheader("Deletion History")
        for i, path in enumerate(st.session_state.deletion_history, 1):
            rec = st.session_state.deletion_records.get(path, {})
            method_label = rec.get("method", "unknown").upper()
            st.text(f"  {i}. [{method_label}] {path}")


# ════════════════════════════════════════════════════════════════════
#  PAGE: FORENSIC ANALYSIS
# ════════════════════════════════════════════════════════════════════

def page_forensic_analysis():
    st.header("Forensic Analysis")
    st.caption(
        "Analyze leftover artifacts after deletion — browser data, "
        "file metadata, residual files, and recovery verification."
    )

    tab_browser, tab_metadata, tab_residual, tab_recovery = st.tabs([
        "Browser Artifacts",
        "System Metadata",
        "Residual Data",
        "Recovery Verification",
    ])

    # ── Browser Artifacts ───────────────────────────────────────────
    with tab_browser:
        bcs = BrowserCacheSimulator(evidence_logger=el)

        c1, c2 = st.columns(2)
        with c1:
            parse = st.button("Parse Browser Artifacts", type="primary")
        with c2:
            delete_br = st.button("Normal-Delete Browser Data")

        if parse:
            with st.spinner("Parsing..."):
                artifacts = bcs.parse_artifacts()
            st.session_state.browser_artifacts = artifacts
            st.success(f"Parsed {len(artifacts)} browser artifacts.")

        if delete_br:
            count = bcs.delete_artifacts()
            st.warning(f"Deleted {count} files (normal delete — data may be recoverable).")
            st.session_state.browser_artifacts = []

        if st.session_state.browser_artifacts:
            df = pd.DataFrame(st.session_state.browser_artifacts)
            if not df.empty:
                st.dataframe(
                    df[["browser", "type", "detail", "size", "timestamp"]],
                    use_container_width=True, hide_index=True,
                )

    # ── System Metadata ─────────────────────────────────────────────
    with tab_metadata:
        sma = SystemMetadataAnalyzer(evidence_logger=el)

        sub_meta, sub_logs = st.tabs(["File Metadata", "System Logs"])

        with sub_meta:
            if st.button("Collect File Metadata", type="primary"):
                with st.spinner("Scanning..."):
                    metadata = sma.collect_file_metadata()
                st.session_state.file_metadata = metadata
                st.success(f"Metadata collected for {len(metadata)} files.")

            if st.session_state.file_metadata:
                display = [{
                    "Name": m["name"],
                    "Size": _human_size(m["size"]),
                    "Created": m["created"][:19].replace("T", " "),
                    "Modified": m["modified"][:19].replace("T", " "),
                    "Accessed": m["accessed"][:19].replace("T", " "),
                    "Permissions": m["permissions"],
                    "Owner": m.get("owner", str(m["owner_uid"])),
                } for m in st.session_state.file_metadata]
                st.dataframe(pd.DataFrame(display), use_container_width=True,
                             hide_index=True)

        with sub_logs:
            if st.button("Collect System Logs"):
                with st.spinner("Collecting..."):
                    logs = sma.collect_system_logs()
                st.session_state.system_logs = logs
                st.success(f"Collected {len(logs)} log lines.")

            if st.session_state.system_logs:
                st.code("\n".join(st.session_state.system_logs), language="text")

    # ── Residual Data ───────────────────────────────────────────────
    with tab_residual:
        scanner = ResidualDataScanner(evidence_logger=el)

        if st.button("Scan for Residual Data", type="primary"):
            log_lines = []
            with st.spinner("Scanning directories..."):
                results = scanner.scan(callback=lambda m: log_lines.append(m))
            st.session_state.residual_results = results
            st.success(f"Found {len(results)} residual artifacts.")
            with st.expander("Scan Log"):
                st.code("\n".join(log_lines), language="text")

        if st.session_state.residual_results:
            results = st.session_state.residual_results

            summary = {}
            for r in results:
                cls = r["classification"]
                summary.setdefault(cls, {"count": 0, "size": 0})
                summary[cls]["count"] += 1
                summary[cls]["size"] += r["size"]

            if summary:
                cols = st.columns(min(len(summary), 4))
                for i, (cls, info) in enumerate(sorted(summary.items())):
                    cols[i % len(cols)].metric(
                        cls.replace("_", " ").title(),
                        f"{info['count']} files",
                        f"{_human_size(info['size'])}",
                    )

            display = [{
                "Name": r["name"],
                "Type": r["classification"],
                "Size": _human_size(r["size"]),
                "Modified": r["modified"][:19].replace("T", " ") if r["modified"] else "",
                "Path": r["path"],
            } for r in results]
            st.dataframe(pd.DataFrame(display), use_container_width=True,
                         hide_index=True)

    # ── Recovery Verification ───────────────────────────────────────
    with tab_recovery:
        history = st.session_state.deletion_history

        if not history:
            st.info("No deletion history yet. Delete files first, then verify recovery.")
            return

        selected = st.selectbox("Select deleted file to verify", history)

        if st.button("Verify Recovery", type="primary"):
            with st.spinner("Running comprehensive recovery analysis..."):
                report = _run_recovery_analysis(selected)

            # Display results
            c1, c2, c3 = st.columns(3)
            c1.metric("Recoverable", "YES" if report["recoverable"] else "NO")
            c2.metric("Risk Level", report["recovery_risk"])
            c3.metric("Evidence Found", len(report["evidence"]))

            st.markdown(f"**Deletion Method Used:** {report['method'].upper()}")
            st.markdown(f"**Summary:** {report['summary']}")

            st.markdown("##### Analysis Checks")
            for check in report["checks"]:
                icon = "PASS" if check["passed"] else "FAIL"
                st.markdown(f"- **[{icon}] {check['name']}:** {check['detail']}")

            if report["evidence"]:
                st.markdown("##### Recovery Evidence Found")
                for ev in report["evidence"]:
                    st.warning(f"**{ev['type']}** — {ev['detail']}")

            if not report["recoverable"]:
                st.success(
                    "Data appears to be securely erased. Overwriting destroyed "
                    "the original content before deletion."
                )


# ════════════════════════════════════════════════════════════════════
#  PAGE: TIMELINE RECONSTRUCTION
# ════════════════════════════════════════════════════════════════════

def page_timeline():
    st.header("Timeline Reconstruction")
    st.caption(
        "Aggregate all forensic findings into a unified chronological "
        "event timeline. Highlights anomalies such as file access after deletion."
    )

    recon = ActivityReconstructor(evidence_logger=el)

    if st.button("Reconstruct Timeline", type="primary"):
        with st.spinner("Aggregating forensic data..."):
            timeline = recon.reconstruct(
                browser_artifacts=st.session_state.browser_artifacts or None,
                file_metadata=st.session_state.file_metadata or None,
                residual_results=st.session_state.residual_results or None,
            )
        st.session_state.timeline = timeline
        anomalies = sum(1 for e in timeline if e.get("flag"))
        st.success(
            f"Timeline built: {len(timeline)} events"
            + (f", {anomalies} anomalies detected." if anomalies else ".")
        )

    if st.session_state.timeline:
        timeline = st.session_state.timeline
        anomalies = [e for e in timeline if e.get("flag")]

        if anomalies:
            st.error(f"{len(anomalies)} Anomalies Detected")
            for a in anomalies:
                st.warning(f"**{a['event']}** — {a['detail']}  \n{a['flag']}")
            st.markdown("---")

        display = [{
            "Timestamp": e["timestamp"][:19].replace("T", " ") if e["timestamp"] else "",
            "Event": e["event"],
            "Source": e["source"],
            "Detail": e["detail"][:60],
            "Flag": e.get("flag", "")[:40],
        } for e in timeline]
        st.dataframe(pd.DataFrame(display), use_container_width=True, hide_index=True)

        st.markdown("---")
        report_path = recon.export_timeline()
        with open(report_path) as f:
            content = f.read()
        st.download_button(
            "Download Timeline Report",
            data=content, file_name="timeline_report.txt", mime="text/plain",
        )


# ════════════════════════════════════════════════════════════════════
#  PAGE: EVIDENCE REPORT
# ════════════════════════════════════════════════════════════════════

def page_evidence_report():
    st.header("Evidence Report")
    st.caption("Centralized forensic evidence log — all findings from every module.")

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Entries", el.get_entry_count())
    c2.metric("Findings", len(el.get_entries(severity="FINDING")))
    c3.metric("Warnings", len(el.get_entries(severity="WARNING")))
    c4.metric("Alerts", len(el.get_entries(severity="ALERT")))

    st.markdown("---")

    # Filters
    fc1, fc2 = st.columns(2)
    filter_sev = fc1.selectbox(
        "Filter by Severity",
        ["All", "INFO", "WARNING", "FINDING", "ALERT"],
    )
    all_modules = sorted(set(e["module"] for e in el.get_entries()))
    filter_mod = fc2.selectbox("Filter by Module", ["All"] + all_modules)

    entries = el.get_entries(
        severity=filter_sev if filter_sev != "All" else None,
        module=filter_mod if filter_mod != "All" else None,
    )

    if entries:
        lines_html = []
        for e in entries:
            ts = e["timestamp"][:19].replace("T", " ")
            sev = e["severity"]
            css = {"INFO": "sev-info", "WARNING": "sev-warning",
                   "FINDING": "sev-finding", "ALERT": "sev-alert"}.get(sev, "")
            lines_html.append(
                f'<span class="{css}">[{ts}] [{sev}] '
                f'[{e["module"]}] {e["event_type"]}: {e["detail"]}</span>'
            )
        st.markdown(
            "<div class='log-container'>" + "<br>".join(lines_html) + "</div>",
            unsafe_allow_html=True,
        )
    else:
        st.info("No evidence entries yet. Perform activities and analysis to generate findings.")

    st.markdown("---")
    st.subheader("Export")
    ec1, ec2, ec3, ec4 = st.columns(4)
    with ec1:
        if st.button("Export HTML Report"):
            path = el.export_report(fmt="html")
            st.success(f"Saved: {path}")
    with ec2:
        if st.button("Export JSON Report"):
            path = el.export_report(fmt="json")
            st.success(f"Saved: {path}")
    with ec3:
        if st.button("Export PDF Report"):
            path = el.export_report(fmt="pdf")
            st.success(f"Saved: {path}")
    with ec4:
        if st.button("Clear Evidence Log"):
            el.clear()
            st.rerun()


# ════════════════════════════════════════════════════════════════════
#  PAGE ROUTING
# ════════════════════════════════════════════════════════════════════

_PAGES = {
    "Overview":                page_overview,
    "Perform User Activities": page_user_activities,
    "File Management":         page_file_management,
    "Data Deletion":           page_deletion,
    "Forensic Analysis":       page_forensic_analysis,
    "Timeline Reconstruction": page_timeline,
    "Evidence Report":         page_evidence_report,
}

_PAGES.get(page, page_overview)()

#!/usr/bin/env python3
"""
Digital Forensics – Member 2: Secure Deletion & Mitigation Lead
==============================================================
Tkinter GUI integrating all Member 2 modules:
  • File Management      (Member 2)
  • Deletion Techniques  (Member 2)
  • Recovery Check       (Member 2 - Post-Delete Verification)
  • Mitigation & Viva Help (Member 2 - Educational section)
  • Logs                 (Member 2)
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime

# ── Local module imports ────────────────────────────────────────────
from environment_setup import EnvironmentSetup
from secure_deletion import SecureDeletion
from deletion_techniques import DeletionTechniques
from post_deletion_verification import PostDeletionVerification
from forensic_logger import ForensicLogger

# ── Colour Palette ──────────────────────────────────────────────────
BG_DARK      = "#1a1a2e"
BG_PANEL     = "#16213e"
BG_CARD      = "#0f3460"
FG_TEXT       = "#e0e0e0"
FG_DIM        = "#8899aa"
ACCENT_BLUE   = "#00adb5"
ACCENT_GREEN  = "#00e676"
ACCENT_RED    = "#ff5252"
ACCENT_ORANGE = "#ff9800"
ACCENT_PURPLE = "#bb86fc"
BTN_BG        = "#0f3460"
BTN_ACTIVE    = "#1a5276"
ENTRY_BG      = "#222244"


# ════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ════════════════════════════════════════════════════════════════════
class ForensicApp(tk.Tk):
    """Main Tkinter application for Member 2."""

    def __init__(self):
        super().__init__()

        self.title("🛡️ Forensic Secure Deletion & Mitigation Tool (Member 2)")
        self.geometry("1100x780")
        self.minsize(950, 700)
        self.configure(bg=BG_DARK)

        # ── Backend initialisation ──────────────────────────────────
        self.env = EnvironmentSetup("forensic_project")
        self.env.setup_environment()

        self.logger       = ForensicLogger()
        self.deleter      = DeletionTechniques()
        self.verifier     = PostDeletionVerification()
        self.secure_eng   = SecureDeletion()

        # Track file hashes before deletion (for verification)
        self._pre_delete_hashes = {}
        # Currently browsed folder
        self._current_folder = str(Path.home() / "Desktop")
        # History of deleted files for recovery checking
        self._deletion_history = []

        self.logger.log("Application started - Member 2 Lead Role", category="general")

        # ── Style ───────────────────────────────────────────────────
        self._configure_style()

        # ── Header ──────────────────────────────────────────────────
        self._build_header()

        # ── Tabs ────────────────────────────────────────────────────
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=(0, 10))

        self._build_tab_files()
        self._build_tab_deletion()
        self._build_tab_verification()
        self._build_tab_mitigation()
        self._build_tab_logs()

        # ── Status bar ──────────────────────────────────────────────
        self.status_var = tk.StringVar(value="Ready")
        status_bar = tk.Label(
            self, textvariable=self.status_var, bg=BG_PANEL,
            fg=FG_DIM, anchor="w", padx=10, pady=5,
            font=("Consolas", 10),
        )
        status_bar.pack(fill="x", side="bottom")

    # ────────────────────────────────────────────────────────────────
    #  STYLING
    # ────────────────────────────────────────────────────────────────
    def _configure_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("TNotebook",        background=BG_DARK)
        style.configure("TNotebook.Tab",    background=BG_PANEL, foreground=FG_TEXT,
                         padding=[16, 8], font=("Segoe UI", 10, "bold"))
        style.map("TNotebook.Tab",
                  background=[("selected", BG_CARD)],
                  foreground=[("selected", ACCENT_BLUE)])

        style.configure("TFrame",           background=BG_DARK)
        style.configure("TLabel",           background=BG_DARK, foreground=FG_TEXT,
                         font=("Segoe UI", 10))
        style.configure("Header.TLabel",    font=("Segoe UI", 13, "bold"),
                         foreground=ACCENT_BLUE, background=BG_DARK)

        style.configure("Accent.TButton",   background=ACCENT_BLUE, foreground="#ffffff",
                         font=("Segoe UI", 10, "bold"), padding=[12, 6])
        style.map("Accent.TButton", background=[("active", BTN_ACTIVE)])

        style.configure("Danger.TButton",   background=ACCENT_RED, foreground="#ffffff",
                         font=("Segoe UI", 10, "bold"), padding=[12, 6])
        style.map("Danger.TButton", background=[("active", "#c62828")])

        style.configure("Success.TButton",  background=ACCENT_GREEN, foreground="#1a1a2e",
                         font=("Segoe UI", 10, "bold"), padding=[12, 6])
        style.map("Success.TButton", background=[("active", "#00c853")])

        style.configure("TRadiobutton",     background=BG_DARK, foreground=FG_TEXT,
                         font=("Segoe UI", 10))
        style.configure("TCombobox",        fieldbackground=ENTRY_BG, foreground=FG_TEXT,
                         background=BG_PANEL, arrowcolor=ACCENT_BLUE)
        
        # Fixing Combobox Popdown (Dropdown List) colors for dark theme
        self.option_add("*TCombobox*Listbox.background", ENTRY_BG)
        self.option_add("*TCombobox*Listbox.foreground", FG_TEXT)
        self.option_add("*TCombobox*Listbox.selectBackground", ACCENT_BLUE)
        self.option_add("*TCombobox*Listbox.selectForeground", "#ffffff")

        style.configure("Horizontal.TProgressbar", troughcolor=BG_PANEL,
                         background=ACCENT_BLUE)

    # ────────────────────────────────────────────────────────────────
    #  HEADER
    # ────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG_PANEL, pady=12)
        hdr.pack(fill="x", padx=10, pady=(10, 5))
        tk.Label(
            hdr, text="🛡️  Forensic Secure Deletion & Mitigation Tool",
            bg=BG_PANEL, fg=ACCENT_BLUE,
            font=("Segoe UI", 18, "bold"),
        ).pack(side="left", padx=15)
        tk.Label(
            hdr, text="MEMBER 2: Secure Deletion & UI Lead",
            bg=BG_PANEL, fg=ACCENT_PURPLE,
            font=("Segoe UI", 11, "bold"),
        ).pack(side="right", padx=15)

    # ════════════════════════════════════════════════════════════════
    #  TAB 1 – FILE MANAGEMENT
    # ════════════════════════════════════════════════════════════════
    def _build_tab_files(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="  📁 File Management  ")

        top = tk.Frame(frame, bg=BG_DARK)
        top.pack(fill="x", padx=16, pady=(16, 8))
        tk.Label(top, text="Browse and Inspect Files", bg=BG_DARK, fg=ACCENT_BLUE,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(top, text="Select files to view their metadata before choosing a deletion technique.",
                 bg=BG_DARK, fg=FG_DIM, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 5))

        # Folder selection
        folder_row = tk.Frame(frame, bg=BG_DARK)
        folder_row.pack(fill="x", padx=16, pady=5)
        self.folder_var = tk.StringVar(value=self._current_folder)
        tk.Entry(folder_row, textvariable=self.folder_var, bg=ENTRY_BG, fg=FG_TEXT,
                 insertbackground=FG_TEXT, font=("Consolas", 10), width=80).pack(side="left", padx=(0, 10))
        ttk.Button(folder_row, text="📂 Open Folder", style="Accent.TButton",
                   command=self._on_browse_folder).pack(side="left")

        # Content: Treeview + Preview
        content = tk.Frame(frame, bg=BG_DARK)
        content.pack(fill="both", expand=True, padx=16, pady=10)

        # Treeview
        tree_frame = tk.Frame(content, bg=BG_DARK)
        tree_frame.pack(side="left", fill="both", expand=True)
        cols = ("Name", "Size", "Modified")
        self.tree = ttk.Treeview(tree_frame, columns=cols, show="headings", height=15)
        self.tree.heading("Name", text="File Name")
        self.tree.heading("Size", text="Size")
        self.tree.heading("Modified", text="Last Modified")
        self.tree.column("Name", width=350)
        self.tree.column("Size", width=100, anchor="e")
        self.tree.column("Modified", width=180)
        
        vsb = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        # Info Panel
        info_panel = tk.Frame(content, bg=BG_PANEL, width=300)
        info_panel.pack(side="right", fill="y", padx=(10, 0))
        info_panel.pack_propagate(False)
        tk.Label(info_panel, text="File Metadata", bg=BG_PANEL, fg=ACCENT_BLUE,
                 font=("Segoe UI", 12, "bold")).pack(pady=10)
        self.file_info = scrolledtext.ScrolledText(info_panel, bg=ENTRY_BG, fg=FG_TEXT,
                                                  font=("Consolas", 9), wrap="word", state="disabled")
        self.file_info.pack(fill="both", expand=True, padx=8, pady=8)

        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self._update_file_list()

    def _on_browse_folder(self):
        folder = filedialog.askdirectory(initialdir=self._current_folder)
        if folder:
            self._current_folder = folder
            self.folder_var.set(folder)
            self._update_file_list()

    def _update_file_list(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
        p = Path(self._current_folder)
        if not p.exists(): return
        
        try:
            for item in sorted(p.iterdir()):
                if item.is_file():
                    stat = item.stat()
                    mod = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M")
                    self.tree.insert("", "end", values=(item.name, self._human_size(stat.st_size), mod))
        except PermissionError:
            self._set_status("Permission Denied for folder")

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        name = self.tree.item(sel[0], "values")[0]
        fpath = Path(self._current_folder) / name
        stat = fpath.stat()
        info = (
            f"NAME: {name}\n"
            f"SIZE: {self._human_size(stat.st_size)}\n"
            f"HASH (SHA256): {self.secure_eng._hash_file(fpath)[:16]}...\n\n"
            f"CREATED: {datetime.fromtimestamp(stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"MODIFIED: {datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')}\n"
        )
        self._write_to(self.file_info, info)

    # ════════════════════════════════════════════════════════════════
    #  TAB 2 – DELETION
    # ════════════════════════════════════════════════════════════════
    def _build_tab_deletion(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="  🗑 Deletion  ")

        # Layout: Control Panel + Result Display
        content = tk.Frame(frame, bg=BG_DARK)
        content.pack(fill="both", expand=True, padx=20, pady=20)

        # Controls (Left)
        ctrl = tk.Frame(content, bg=BG_PANEL, padx=20, pady=20, width=450)
        ctrl.pack(side="left", fill="both")
        ctrl.pack_propagate(False)

        tk.Label(ctrl, text="Configure Deletion", bg=BG_PANEL, fg=ACCENT_BLUE,
                 font=("Segoe UI", 14, "bold")).pack(anchor="w", pady=(0, 15))

        # File Selection
        tk.Label(ctrl, text="Target File:", bg=BG_PANEL, fg=FG_DIM).pack(anchor="w")
        self.del_path_var = tk.StringVar()
        tk.Entry(ctrl, textvariable=self.del_path_var, bg=ENTRY_BG, fg=FG_TEXT, width=40).pack(fill="x", pady=5)
        ttk.Button(ctrl, text="Browse File", style="Accent.TButton", command=self._on_browse_del_file).pack(anchor="e")

        # Method
        tk.Label(ctrl, text="\nDeletion Method:", bg=BG_PANEL, fg=FG_DIM).pack(anchor="w")
        self.method_var = tk.StringVar(value="normal")
        for m in ["normal", "permanent", "secure"]:
            ttk.Radiobutton(ctrl, text=m.capitalize() + " Delete", variable=self.method_var, value=m).pack(anchor="w", padx=10, pady=2)

        # Secure Options
        self.secure_opt_frame = tk.LabelFrame(ctrl, text="Secure Overwrite Details", bg=BG_PANEL, fg=ACCENT_ORANGE, font=("Segoe UI", 9, "bold"))
        self.secure_opt_frame.pack(fill="x", pady=15, padx=5)
        
        tk.Label(self.secure_opt_frame, text="Pattern:", bg=BG_PANEL).pack(side="left", padx=5)
        self.pattern_var = tk.StringVar(value="random")
        ttk.Combobox(self.secure_opt_frame, textvariable=self.pattern_var, values=["random", "zeros", "dummy"], width=8, state="readonly").pack(side="left", padx=5)
        
        tk.Label(self.secure_opt_frame, text="Passes:", bg=BG_PANEL).pack(side="left", padx=5)
        self.pass_var = tk.StringVar(value="1")
        ttk.Combobox(self.secure_opt_frame, textvariable=self.pass_var, values=["1", "3", "7"], width=3, state="readonly").pack(side="left", padx=5)

        # Progress
        self.progress = ttk.Progressbar(ctrl, style="Horizontal.TProgressbar", mode="determinate")
        self.progress.pack(fill="x", pady=20)

        ttk.Button(ctrl, text="🔥  EXECUTE DELETION", style="Danger.TButton", command=self._on_delete).pack(fill="x")

        # Results (Right)
        res = tk.Frame(content, bg=BG_DARK, padx=20)
        res.pack(side="right", fill="both", expand=True)
        tk.Label(res, text="Standard Deletion vs Secure Overwrite", bg=BG_DARK, fg=FG_DIM).pack(anchor="w")
        self.del_output = scrolledtext.ScrolledText(res, bg=ENTRY_BG, fg=FG_TEXT, font=("Consolas", 10))
        self.del_output.pack(fill="both", expand=True, pady=10)

    def _on_browse_del_file(self):
        f = filedialog.askopenfilename()
        if f: self.del_path_var.set(f)

    def _on_delete(self):
        fpath = self.del_path_var.get()
        if not fpath or not Path(fpath).exists():
            messagebox.showerror("Error", "Please select a valid file.")
            return

        method = self.method_var.get()
        confirm = messagebox.askyesno("Confirm", f"Are you sure you want to perform a {method.upper()} deletion?")
        if not confirm: return

        self.progress["value"] = 0
        self._set_status(f"Executing {method} delete...")
        
        # Preserve hash for verification demo
        tag_path = str(Path(fpath).absolute())
        self._pre_delete_hashes[tag_path] = self.secure_eng._hash_file(fpath)

        def cb(p):
            self.progress["value"] = p
            self.update_idletasks()

        result = self.deleter.delete_file(
            fpath, method=method, 
            secure_mode=self.pattern_var.get(), 
            secure_passes=int(self.pass_var.get()),
            progress_callback=cb
        )
        self.progress["value"] = 100
        
        # Display Result
        out = (
            f"DELETION REPORT\n"
            f"{'='*30}\n"
            f"FILE: {Path(fpath).name}\n"
            f"METHOD: {method.upper()}\n"
            f"STATUS: {result['status'].upper()}\n"
        )
        if method == "secure" and "details" in result:
            d = result["details"]
            out += f"OVERWRITE: {d.get('overwrite_mode')} ({d.get('overwrite_passes')} passes)\n"
            out += f"TIME: {d.get('time_taken')}s\n"
            out += f"HASH BEFORE: {d.get('hash_before')[:24]}...\n"
            out += f"HASH AFTER:  {d.get('hash_after')[:24]}...\n"
        
        out += f"\nVERIFICATION: File existence check -> {'FAIL (Still Exists)' if Path(fpath).exists() else 'SUCCESS (Removed from Path)'}"
        
        # Add to history if successful
        if result["status"] == "success":
            abs_path = str(Path(fpath).absolute())
            if abs_path not in self._deletion_history:
                self._deletion_history.append(abs_path)
                self.verify_path_combo["values"] = self._deletion_history
                self.verify_path_var.set(abs_path) # Auto-select for next tab

        self._write_to(self.del_output, out)
        self.logger.log_deletion(fpath, method, result)
        self._set_status("Operation completed.")
        self._update_file_list()

    # ════════════════════════════════════════════════════════════════
    #  TAB 3 – RECOVERY CHECK (Verification)
    # ════════════════════════════════════════════════════════════════
    def _build_tab_verification(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="  ✅ Recovery Check  ")

        top = tk.Frame(frame, bg=BG_DARK, padx=30, pady=20)
        top.pack(fill="x")
        tk.Label(top, text="Post-Deletion Verification", bg=BG_DARK, fg=ACCENT_BLUE,
                 font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(top, text="Prove that normal deletion is reversible and secure overwriting is not.",
                 bg=BG_DARK, fg=FG_DIM, font=("Segoe UI", 10)).pack(anchor="w")

        # Input
        inp = tk.Frame(frame, bg=BG_PANEL, padx=20, pady=20)
        inp.pack(fill="x", padx=30, pady=10)
        tk.Label(inp, text="Deleted File History:", bg=BG_PANEL).pack(side="left")
        self.verify_path_var = tk.StringVar()
        self.verify_path_combo = ttk.Combobox(inp, textvariable=self.verify_path_var, width=60, values=self._deletion_history)
        self.verify_path_combo.pack(side="left", padx=10)
        ttk.Button(inp, text="Check Recovery Trace", style="Success.TButton", command=self._on_verify).pack(side="left")

        # Results
        self.verify_res = scrolledtext.ScrolledText(frame, bg=ENTRY_BG, fg=FG_TEXT, font=("Consolas", 11), padx=10, pady=10)
        self.verify_res.pack(fill="both", expand=True, padx=30, pady=20)

    def _on_verify(self):
        path = self.verify_path_var.get()
        if not path:
            messagebox.showwarning("No Path", "Select or enter the path of a deleted file.")
            return
        
        orig_hash = self._pre_delete_hashes.get(str(Path(path).absolute()))
        report = self.verifier.verify(path, original_hash=orig_hash)
        
        out = f"RECOVERY VERIFICATION REPORT\n{'='*40}\n"
        out += f"FILE: {Path(path).name}\n"
        out += f"RECOVERABLE: {report['recoverable']}\n"
        out += f"RISK LEVEL: {report['recovery_risk']}\n"
        out += f"SUMMARY: {report['summary']}\n\n"
        
        out += "DETAILED CHECKS:\n"
        for k, v in report['checks'].items():
            out += f" - {k.replace('_', ' ').title()}: {v}\n"
            
        if report['found_artifacts']:
            out += "\nARTIFACT TRACKS DETECTED:\n"
            for a in report['found_artifacts']:
                out += f" [!] {a['type'].upper()} @ {a['location']}\n"
        else:
            out += "\n[✓] No bit-streams or metadata matching the original file found."

        self._write_to(self.verify_res, out)
        self.logger.log_verification(path, report)

    # ════════════════════════════════════════════════════════════════
    #  TAB 4 – MITIGATION & VIVA HELP
    # ════════════════════════════════════════════════════════════════
    def _build_tab_mitigation(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="  💡 Mitigation & Help  ")
        
        # Left side: Viva Questions list
        # Right side: Detail display
        paned = tk.PanedWindow(frame, orient="horizontal", bg=BG_DARK, borderwidth=0)
        paned.pack(fill="both", expand=True, padx=10, pady=10)

        # Left: Listbox
        list_f = tk.Frame(paned, bg=BG_DARK, padx=10)
        tk.Label(list_f, text="Digital Forensics Viva Q&A", bg=BG_DARK, fg=ACCENT_PURPLE, font=("Segoe UI", 12, "bold")).pack(pady=10)
        
        self.viva_list = tk.Listbox(list_f, bg=BG_PANEL, fg=FG_TEXT, font=("Segoe UI", 10), 
                                    selectbackground=ACCENT_BLUE, borderwidth=0, highlightthickness=0)
        questions = [
            "Why is normally deleted data recoverable?",
            "How does overwriting prevent recovery?",
            "What is unallocated space?",
            "How do SSDs handle deletion differently?",
            "Difference between 1-pass and multi-pass?",
            "What happens to the Master File Table (MFT)?"
        ]
        for q in questions: self.viva_list.insert("end", q)
        self.viva_list.pack(fill="both", expand=True)
        self.viva_list.bind("<<ListboxSelect>>", self._on_viva_select)
        
        paned.add(list_f, width=350)

        # Right: Answer area
        ans_f = tk.Frame(paned, bg=BG_PANEL, padx=20, pady=20)
        tk.Label(ans_f, text="Technical Explanation", bg=BG_PANEL, fg=ACCENT_BLUE, font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.viva_ans = scrolledtext.ScrolledText(ans_f, bg=BG_PANEL, fg=FG_TEXT, font=("Segoe UI", 11), 
                                                 wrap="word", borderwidth=0, highlightthickness=0)
        self.viva_ans.pack(fill="both", expand=True, pady=10)
        paned.add(ans_f)

    def _on_viva_select(self, event):
        idx = self.viva_list.curselection()
        if not idx: return
        q = self.viva_list.get(idx[0])
        
        mapping = {
            "Why is normally deleted data recoverable?": "why_recoverable",
            "How does overwriting prevent recovery?": "overwriting",
            "What is unallocated space?": "unallocated_space",
            "How do SSDs handle deletion differently?": "ssd_diff",
            "Difference between 1-pass and multi-pass?": "passes",
            "What happens to the Master File Table (MFT)?": "mft"
        }
        
        topic = mapping.get(q)
        expl = self.secure_eng.get_viva_explanation(topic)
        
        # Add local overrides for specific UI questions
        if topic == "passes":
            expl = "1-pass is usually enough for modern drives. Multi-pass (like 3-7 passes) was a standard for older magnetic media to ensure no 'bit-ghosting' occurred. For modern SSDs, a single overwrite session is sufficient if it bypasses the mapping layer."
        elif topic == "mft":
            expl = "The Master File Table (MFT) is a database where Windows stores file info. Normal delete just sets a flag in the MFT; secure delete must ideally clear the MFT record and the data blocks."

        self._write_to(self.viva_ans, f"TOPIC: {q}\n\n{expl}")

    # ════════════════════════════════════════════════════════════════
    #  TAB 5 – LOGS
    # ════════════════════════════════════════════════════════════════
    def _build_tab_logs(self):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text="  📜 Action Logs  ")

        btn_row = tk.Frame(frame, bg=BG_DARK, padx=20, pady=10)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="🔄 Refresh Logs", command=self._refresh_logs).pack(side="left", padx=5)
        ttk.Button(btn_row, text="📤 Export to JSON", command=self._on_export).pack(side="left", padx=5)
        ttk.Button(btn_row, text="🗑 Clear Records", style="Danger.TButton", command=self._on_clear).pack(side="right")

        self.log_text = scrolledtext.ScrolledText(frame, bg=ENTRY_BG, fg=FG_TEXT, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=20, pady=10)
        self._refresh_logs()

    def _refresh_logs(self):
        txt = self.logger.get_log_text()
        self._write_to(self.log_text, txt)

    def _on_export(self):
        f = filedialog.asksaveasfilename(defaultextension=".json")
        if f: self.logger.export_logs(f)

    def _on_clear(self):
        if messagebox.askyesno("Clear", "Clear all action logs?"):
            self.logger.clear_logs()
            self._refresh_logs()

    # ────────────────────────────────────────────────────────────────
    #  UTILS
    # ────────────────────────────────────────────────────────────────
    def _write_to(self, widget, text):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", text)
        widget.configure(state="disabled")

    def _set_status(self, msg):
        self.status_var.set(f"  STATUS: {msg}  |  {datetime.now().strftime('%H:%M:%S')}")

    def _human_size(self, n):
        for unit in ['B', 'KB', 'MB', 'GB']:
            if n < 1024.0: return f"{n:3.1f} {unit}"
            n /= 1024.0
        return f"{n:3.1f} TB"


if __name__ == "__main__":
    app = ForensicApp()
    app.mainloop()

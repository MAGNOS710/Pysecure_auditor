"""
gui.py
Tkinter desktop GUI for PySecure Auditor.

Features:
  - Pick a folder (or file) to scan
  - Toggle AST / Regex / Bandit engines
  - Progress bar while scanning
  - Results table, color-coded by severity, sortable by clicking headers
  - Detail panel showing description + recommendation for the selected finding
  - Export to JSON / HTML / PDF
"""

import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from report_generator import generate_html_report, generate_json_report, generate_pdf_report
from scanner import Scanner

SEVERITY_TAGS = {
    "CRITICAL": "#8B0000",
    "HIGH": "#E74C3C",
    "MEDIUM": "#E67E22",
    "LOW": "#F1C40F",
    "INFO": "#3498DB",
}


class PySecureAuditorGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PySecure Auditor")
        self.geometry("1080x650")
        self.minsize(860, 520)
        self.configure(bg="#0f1115")

        self.target_path = tk.StringVar()
        self.use_ast = tk.BooleanVar(value=True)
        self.use_regex = tk.BooleanVar(value=True)
        self.use_bandit = tk.BooleanVar(value=True)
        self.status_text = tk.StringVar(value="Ready.")

        self.scan_result = None
        self._build_style()
        self._build_layout()

    # ------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background="#0f1115")
        style.configure("TLabel", background="#0f1115", foreground="#e7e9ee")
        style.configure("TCheckbutton", background="#0f1115", foreground="#e7e9ee")
        style.configure("TButton", padding=6)
        style.configure("Treeview", background="#171a21", fieldbackground="#171a21",
                         foreground="#e7e9ee", rowheight=24, bordercolor="#262b36")
        style.configure("Treeview.Heading", background="#1d212b", foreground="#9aa2b1")
        style.map("Treeview", background=[("selected", "#2a3040")])

    # ------------------------------------------------------------------
    def _build_layout(self):
        top = ttk.Frame(self, padding=12)
        top.pack(fill="x")

        ttk.Label(top, text="Target:").grid(row=0, column=0, sticky="w")
        entry = ttk.Entry(top, textvariable=self.target_path, width=70)
        entry.grid(row=0, column=1, padx=6, sticky="we")
        ttk.Button(top, text="Choose Folder", command=self._choose_folder).grid(row=0, column=2, padx=4)
        ttk.Button(top, text="Choose File", command=self._choose_file).grid(row=0, column=3, padx=4)

        opts = ttk.Frame(top)
        opts.grid(row=1, column=0, columnspan=4, sticky="w", pady=(8, 0))
        ttk.Checkbutton(opts, text="AST Analysis", variable=self.use_ast).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Regex Analysis", variable=self.use_regex).pack(side="left", padx=4)
        ttk.Checkbutton(opts, text="Bandit", variable=self.use_bandit).pack(side="left", padx=4)
        self.scan_btn = ttk.Button(opts, text="Run Scan", command=self._start_scan)
        self.scan_btn.pack(side="left", padx=16)

        top.columnconfigure(1, weight=1)

        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=12)

        # Summary cards
        self.summary_frame = ttk.Frame(self, padding=(12, 8))
        self.summary_frame.pack(fill="x")
        self.summary_labels = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "TOTAL"):
            f = tk.Frame(self.summary_frame, bg="#171a21", padx=14, pady=8)
            f.pack(side="left", padx=6)
            num = tk.Label(f, text="0", font=("Helvetica", 16, "bold"),
                            bg="#171a21", fg=SEVERITY_TAGS.get(sev, "#e7e9ee"))
            num.pack()
            tk.Label(f, text=sev, font=("Helvetica", 9), bg="#171a21", fg="#9aa2b1").pack()
            self.summary_labels[sev] = num

        # Findings table
        mid = ttk.Frame(self, padding=(12, 4))
        mid.pack(fill="both", expand=True)

        columns = ("severity", "vulnerability", "location", "engine")
        self.tree = ttk.Treeview(mid, columns=columns, show="headings", selectmode="browse")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("vulnerability", text="Vulnerability")
        self.tree.heading("location", text="Location")
        self.tree.heading("engine", text="Engine")
        self.tree.column("severity", width=90, anchor="center")
        self.tree.column("vulnerability", width=280)
        self.tree.column("location", width=320)
        self.tree.column("engine", width=80, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        for sev, color in SEVERITY_TAGS.items():
            self.tree.tag_configure(sev, foreground=color)

        scrollbar = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="left", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Detail panel
        detail = ttk.Frame(mid, padding=(12, 0))
        detail.pack(side="left", fill="both", expand=True)
        ttk.Label(detail, text="Details", font=("Helvetica", 12, "bold")).pack(anchor="w")
        self.detail_text = tk.Text(detail, wrap="word", bg="#171a21", fg="#e7e9ee",
                                    insertbackground="#e7e9ee", relief="flat", padx=10, pady=10)
        self.detail_text.pack(fill="both", expand=True, pady=6)
        self.detail_text.configure(state="disabled")

        # Bottom bar: export + status
        bottom = ttk.Frame(self, padding=12)
        bottom.pack(fill="x")
        ttk.Button(bottom, text="Export JSON", command=lambda: self._export("json")).pack(side="left", padx=4)
        ttk.Button(bottom, text="Export HTML", command=lambda: self._export("html")).pack(side="left", padx=4)
        ttk.Button(bottom, text="Export PDF", command=lambda: self._export("pdf")).pack(side="left", padx=4)
        ttk.Label(bottom, textvariable=self.status_text).pack(side="right")

    # ------------------------------------------------------------------
    def _choose_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.target_path.set(path)

    def _choose_file(self):
        path = filedialog.askopenfilename(filetypes=[("Python files", "*.py")])
        if path:
            self.target_path.set(path)

    def _start_scan(self):
        path = self.target_path.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showerror("PySecure Auditor", "Please choose a valid file or folder first.")
            return

        self.scan_btn.configure(state="disabled")
        self.status_text.set("Scanning...")
        self.progress["value"] = 0
        for row in self.tree.get_children():
            self.tree.delete(row)

        thread = threading.Thread(target=self._run_scan_thread, args=(path,), daemon=True)
        thread.start()

    def _run_scan_thread(self, path):
        scanner = Scanner(path, use_bandit=self.use_bandit.get(),
                           use_ast=self.use_ast.get(), use_regex=self.use_regex.get())

        def progress_cb(done, total, _fname):
            pct = (done / total * 100) if total else 100
            self.after(0, lambda: self.progress.configure(value=pct))

        result = scanner.run(progress_callback=progress_cb)
        self.after(0, lambda: self._on_scan_done(result))

    def _on_scan_done(self, result):
        self.scan_result = result
        self.scan_btn.configure(state="normal")
        self.progress["value"] = 100

        summary = result.summary
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            self.summary_labels[sev].configure(text=str(summary[sev]))
        self.summary_labels["TOTAL"].configure(text=str(len(result.findings)))

        for idx, f in enumerate(result.findings):
            self.tree.insert("", "end", iid=str(idx),
                              values=(str(f.severity), f.vulnerability,
                                      f"{f.file}:{f.line}", f.source),
                              tags=(str(f.severity),))

        msg = f"Scanned {result.files_scanned} file(s). {len(result.findings)} finding(s)."
        if not result.bandit_available and self.use_bandit.get():
            msg += " (Bandit unavailable - install with `pip install bandit`)"
        self.status_text.set(msg)

    def _on_select(self, _event):
        sel = self.tree.selection()
        if not sel or not self.scan_result:
            return
        f = self.scan_result.findings[int(sel[0])]
        text = (f"Vulnerability: {f.vulnerability}\n"
                f"Severity: {f.severity}\n"
                f"Location: {f.file}:{f.line}\n"
                f"Detected by: {f.source}\n\n"
                f"Why it matters:\n{f.description}\n\n"
                f"Recommendation:\n{f.recommendation}\n\n"
                f"Code:\n{f.code_snippet}")
        self.detail_text.configure(state="normal")
        self.detail_text.delete("1.0", "end")
        self.detail_text.insert("1.0", text)
        self.detail_text.configure(state="disabled")

    def _export(self, fmt):
        if not self.scan_result:
            messagebox.showwarning("PySecure Auditor", "Run a scan first.")
            return
        ext = {"json": ".json", "html": ".html", "pdf": ".pdf"}[fmt]
        path = filedialog.asksaveasfilename(defaultextension=ext,
                                             initialfile=f"pysecure_report{ext}")
        if not path:
            return
        try:
            if fmt == "json":
                generate_json_report(self.scan_result.findings, self.scan_result.target_path, path)
            elif fmt == "html":
                generate_html_report(self.scan_result.findings, self.scan_result.target_path, path)
            elif fmt == "pdf":
                generate_pdf_report(self.scan_result.findings, self.scan_result.target_path, path)
            self.status_text.set(f"Report saved: {path}")
        except Exception as exc:  # surface any export error to the user
            messagebox.showerror("Export failed", str(exc))


def launch_gui():
    app = PySecureAuditorGUI()
    app.mainloop()


if __name__ == "__main__":
    launch_gui()

"""
utils.py
Shared data structures and helper functions for PySecure Auditor.
"""

import os
from dataclasses import dataclass, field
from enum import Enum


class Severity(Enum):
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0

    def __str__(self):
        return self.name

    @property
    def color(self):
        return {
            Severity.CRITICAL: "#8B0000",
            Severity.HIGH: "#E74C3C",
            Severity.MEDIUM: "#E67E22",
            Severity.LOW: "#F1C40F",
            Severity.INFO: "#3498DB",
        }[self]


@dataclass
class Finding:
    """A single security finding discovered in a source file."""
    file: str
    line: int
    vulnerability: str
    severity: Severity
    description: str
    recommendation: str
    source: str  # which engine found it: AST / Regex / Bandit
    code_snippet: str = ""

    def to_dict(self):
        return {
            "file": self.file,
            "line": self.line,
            "vulnerability": self.vulnerability,
            "severity": str(self.severity),
            "description": self.description,
            "recommendation": self.recommendation,
            "source": self.source,
            "code_snippet": self.code_snippet,
        }


def find_python_files(root_path):
    """Recursively find all .py files under root_path, skipping venvs/caches."""
    skip_dirs = {".git", "__pycache__", "venv", ".venv", "env",
                 "node_modules", "site-packages", ".tox", "build", "dist"}
    py_files = []
    if os.path.isfile(root_path) and root_path.endswith(".py"):
        return [root_path]
    for dirpath, dirnames, filenames in os.walk(root_path):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        for fname in filenames:
            if fname.endswith(".py"):
                py_files.append(os.path.join(dirpath, fname))
    return py_files


def get_line_snippet(filepath, lineno, context=0):
    """Return the stripped source line (with optional context) for a finding."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        idx = lineno - 1
        if 0 <= idx < len(lines):
            return lines[idx].strip()
    except (OSError, IndexError):
        pass
    return ""


def dedupe_findings(findings):
    """Remove duplicate findings (same file/line/vulnerability) keeping the
    highest-confidence one (AST/Regex findings are considered equal rank;
    we just keep the first occurrence)."""
    seen = set()
    unique = []
    for f in findings:
        key = (f.file, f.line, f.vulnerability)
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_findings(findings):
    return sorted(findings, key=lambda f: (-f.severity.value, f.file, f.line))

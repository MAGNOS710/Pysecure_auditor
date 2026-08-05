"""
scanner.py
Orchestrates the AST, Regex, and Bandit engines across a project directory
and merges the results into a single, deduplicated, sorted findings list.
"""

from ast_analyzer import ASTAnalyzer
from bandit_runner import BanditRunner
from regex_analyzer import RegexAnalyzer
from utils import dedupe_findings, find_python_files, sort_findings


class ScanResult:
    def __init__(self, target_path):
        self.target_path = target_path
        self.findings = []
        self.files_scanned = 0
        self.bandit_available = True
        self.bandit_error = None

    @property
    def summary(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in self.findings:
            counts[str(f.severity)] += 1
        return counts


class Scanner:
    """
    Usage:
        scanner = Scanner(target_path, use_bandit=True)
        result = scanner.run(progress_callback=lambda done, total, fname: ...)
    """

    def __init__(self, target_path, use_bandit=True, use_ast=True, use_regex=True):
        self.target_path = target_path
        self.use_bandit = use_bandit
        self.use_ast = use_ast
        self.use_regex = use_regex

    def run(self, progress_callback=None):
        result = ScanResult(self.target_path)
        py_files = find_python_files(self.target_path)
        result.files_scanned = len(py_files)
        all_findings = []

        total_steps = len(py_files) + (1 if self.use_bandit else 0)
        done_steps = 0

        for filepath in py_files:
            if self.use_ast:
                all_findings.extend(ASTAnalyzer(filepath).analyze())
            if self.use_regex:
                all_findings.extend(RegexAnalyzer(filepath).analyze())
            done_steps += 1
            if progress_callback:
                progress_callback(done_steps, total_steps, filepath)

        if self.use_bandit:
            runner = BanditRunner(self.target_path)
            bandit_findings = runner.run()
            all_findings.extend(bandit_findings)
            result.bandit_available = runner.available
            result.bandit_error = runner.error
            done_steps += 1
            if progress_callback:
                progress_callback(done_steps, total_steps, "bandit")

        all_findings = dedupe_findings(all_findings)
        result.findings = sort_findings(all_findings)
        return result

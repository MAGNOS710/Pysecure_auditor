"""
bandit_runner.py
Runs Bandit (https://bandit.readthedocs.io) against a target path and
converts its JSON output into our common Finding objects.

Bandit is optional: if it isn't installed, run() returns an empty list and
sets `available = False` so callers can note it in the report instead of
crashing.
"""

import json
import shutil
import subprocess

from utils import Finding, Severity


BANDIT_SEVERITY_MAP = {
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNDEFINED": Severity.INFO,
}


class BanditRunner:
    def __init__(self, target_path):
        self.target_path = target_path
        self.findings = []
        self.available = shutil.which("bandit") is not None
        self.error = None

    def run(self):
        if not self.available:
            self.error = "Bandit is not installed (pip install bandit)."
            return self.findings

        try:
            proc = subprocess.run(
                ["bandit", "-r", self.target_path, "-f", "json"],
                capture_output=True, text=True, timeout=120,
            )
            # bandit exits non-zero when it finds issues, that's expected
            stdout = proc.stdout.strip()
            if not stdout:
                self.error = proc.stderr.strip() or "Bandit produced no output."
                return self.findings
            data = json.loads(stdout)
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as exc:
            self.error = f"Bandit run failed: {exc}"
            return self.findings

        for item in data.get("results", []):
            sev = BANDIT_SEVERITY_MAP.get(item.get("issue_severity", "UNDEFINED"),
                                           Severity.INFO)
            self.findings.append(Finding(
                file=item.get("filename", "?"),
                line=item.get("line_number", 0),
                vulnerability=f"[{item.get('test_id', '?')}] {item.get('test_name', 'Bandit finding')}",
                severity=sev,
                description=item.get("issue_text", "").strip(),
                recommendation="See Bandit docs for this check: "
                                f"https://bandit.readthedocs.io/en/latest/plugins/"
                                f"index.html#{item.get('test_id', '').lower()}",
                source="Bandit",
                code_snippet=item.get("code", "").strip().splitlines()[0]
                if item.get("code") else "",
            ))
        return self.findings

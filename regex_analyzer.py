"""
regex_analyzer.py
Regex-based static analysis. Complements the AST analyzer by catching
patterns that are easier (or only possible) to spot as raw text - such as
hardcoded secrets that span multiple styles of assignment, dict literals,
function defaults, or connection strings embedded in URLs.
"""

import re

from utils import Finding, Severity, get_line_snippet


# Each rule: (compiled regex, vulnerability, severity, description, recommendation)
RULES = [
    (
        re.compile(
            r'(?i)\b(password|passwd|pwd)\s*[:=]\s*["\']([^"\'\s]{3,})["\']'
        ),
        "Hardcoded Password", Severity.HIGH,
        "A password value is hardcoded directly in source code.",
        "Store credentials in environment variables or a secrets manager, "
        "never in source code.",
    ),
    (
        re.compile(
            r'(?i)\b(api[_-]?key|secret[_-]?key|access[_-]?key|auth[_-]?token|'
            r'client[_-]?secret)\s*[:=]\s*["\']([A-Za-z0-9_\-/+=]{8,})["\']'
        ),
        "Hardcoded API Key / Secret", Severity.HIGH,
        "An API key or secret token is hardcoded directly in source code.",
        "Load API keys and tokens from environment variables or a secrets "
        "manager (e.g. python-dotenv, AWS Secrets Manager, Vault).",
    ),
    (
        re.compile(r'(?i)://[^:\s/]+:[^@\s/]+@'),
        "Hardcoded Credentials in Connection String", Severity.HIGH,
        "A username/password pair is embedded directly in a connection URL "
        "(e.g. a database or service URI).",
        "Pull the connection string from an environment variable or "
        "secrets manager instead of hardcoding credentials in the URL.",
    ),
    (
        re.compile(r'(?i)-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----'),
        "Hardcoded Private Key", Severity.CRITICAL,
        "A private key appears to be embedded directly in source code.",
        "Remove the private key from source control immediately, rotate the "
        "key, and load key material from a secure secrets store at runtime.",
    ),
    (
        re.compile(r'\bassert\s'),
        "Use of assert for Validation", Severity.LOW,
        "assert statements are stripped out when Python is run with the -O "
        "optimization flag, so using them for security/validation checks can "
        "silently disable the check in production.",
        "Use explicit if-checks that raise exceptions instead of assert for "
        "any security- or logic-critical validation.",
    ),
    (
        re.compile(r'\bverify\s*=\s*False\b'),
        "TLS Certificate Verification Disabled", Severity.HIGH,
        "verify=False disables TLS/SSL certificate verification (commonly "
        "seen with the requests library), exposing the connection to "
        "man-in-the-middle attacks.",
        "Keep certificate verification enabled. If a custom CA is needed, "
        "pass verify='/path/to/ca-bundle.pem' instead of disabling it.",
    ),
    (
        re.compile(r'\.execute\s*\(\s*(?:f["\']|["\'][^"\']*["\']\s*(?:\+|%|\.format))'),
        "Possible SQL Injection (string building)", Severity.CRITICAL,
        "A SQL query appears to be built via string concatenation, an "
        "f-string, or .format() rather than parameter placeholders.",
        "Use parameterized queries with placeholders (e.g. '?' or '%s') and "
        "pass values as a separate tuple/list argument to .execute().",
    ),
]


class RegexAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []

    def analyze(self):
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return self.findings

        for lineno, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            for pattern, vuln, sev, desc, rec in RULES:
                if pattern.search(line):
                    self.findings.append(Finding(
                        file=self.filepath,
                        line=lineno,
                        vulnerability=vuln,
                        severity=sev,
                        description=desc,
                        recommendation=rec,
                        source="Regex",
                        code_snippet=get_line_snippet(self.filepath, lineno),
                    ))
        return self.findings

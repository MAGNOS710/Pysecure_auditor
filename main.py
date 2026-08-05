#!/usr/bin/env python3
"""
main.py
Command-line entry point for PySecure Auditor.

Examples:
    python main.py scan ./my_project
    python main.py scan ./my_project --format html --output reports/out.html
    python main.py scan ./my_project --no-bandit
    python main.py gui
"""

import argparse
import os
import sys

from report_generator import generate_html_report, generate_json_report, generate_pdf_report
from scanner import Scanner


SEVERITY_COLOR_CODES = {
    "CRITICAL": "\033[41m\033[97m",  # white on red
    "HIGH": "\033[91m",              # red
    "MEDIUM": "\033[93m",            # yellow
    "LOW": "\033[94m",               # blue
    "INFO": "\033[90m",              # grey
}
RESET = "\033[0m"


def print_console_report(result):
    print(f"\nPySecure Auditor - scanned {result.files_scanned} file(s) "
          f"under: {result.target_path}\n")

    if not result.bandit_available and result.bandit_error:
        print(f"[!] {result.bandit_error}\n")

    summary = result.summary
    print("Summary:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        color = SEVERITY_COLOR_CODES[sev]
        print(f"  {color}{sev:<9}{RESET} {summary[sev]}")
    print(f"  {'TOTAL':<9} {len(result.findings)}\n")

    if not result.findings:
        print("No issues found.\n")
        return

    for f in result.findings:
        color = SEVERITY_COLOR_CODES[str(f.severity)]
        print(f"{color}[{f.severity}]{RESET} {f.vulnerability}")
        print(f"  File: {f.file}:{f.line}  (found by {f.source})")
        if f.code_snippet:
            print(f"  Code: {f.code_snippet}")
        print(f"  Why:  {f.description}")
        print(f"  Fix:  {f.recommendation}\n")


def run_scan(args):
    if not os.path.exists(args.path):
        print(f"Error: path does not exist: {args.path}", file=sys.stderr)
        sys.exit(1)

    scanner = Scanner(args.path, use_bandit=not args.no_bandit,
                       use_ast=not args.no_ast, use_regex=not args.no_regex)
    result = scanner.run()

    print_console_report(result)

    if args.format and args.format != "console":
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        if args.format == "json":
            generate_json_report(result.findings, args.path, args.output)
        elif args.format == "html":
            generate_html_report(result.findings, args.path, args.output)
        elif args.format == "pdf":
            generate_pdf_report(result.findings, args.path, args.output)
        print(f"Report written to: {args.output}")

    if args.fail_on and result.findings:
        threshold_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        threshold_idx = threshold_order.index(args.fail_on.upper())
        for f in result.findings:
            if threshold_order.index(str(f.severity)) >= threshold_idx:
                sys.exit(2)


def run_gui(_args):
    from gui import launch_gui
    launch_gui()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="pysecure-auditor",
        description="Static security code review tool for Python projects.")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", help="Path to a .py file or a project directory")
    scan_p.add_argument("--format", choices=["console", "json", "html", "pdf"],
                         default="console", help="Report output format")
    scan_p.add_argument("--output", default="reports/report.html",
                         help="Output file path (for json/html/pdf)")
    scan_p.add_argument("--no-bandit", action="store_true",
                         help="Skip the Bandit static analyzer")
    scan_p.add_argument("--no-ast", action="store_true",
                         help="Skip the AST analyzer")
    scan_p.add_argument("--no-regex", action="store_true",
                         help="Skip the regex analyzer")
    scan_p.add_argument("--fail-on", choices=["low", "medium", "high", "critical"],
                         default=None,
                         help="Exit with code 2 if any finding is >= this severity "
                              "(useful in CI pipelines)")
    scan_p.set_defaults(func=run_scan)

    gui_p = sub.add_parser("gui", help="Launch the Tkinter GUI")
    gui_p.set_defaults(func=run_gui)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

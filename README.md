# PySecure Auditor

A static security code review tool for Python projects. It combines three
detection engines — **AST analysis**, **regex pattern matching**, and
**[Bandit](https://bandit.readthedocs.io)** — to find common vulnerability
classes, then produces a report with location, severity, root cause, and a
concrete fix for each finding.

## What it detects

| Vulnerability                          | Severity |
|-----------------------------------------|----------|
| SQL Injection                            | Critical |
| Command Injection (`os.system`, `subprocess(shell=True)`) | Critical |
| Hardcoded private keys                   | Critical |
| Hardcoded passwords / API keys / tokens  | High     |
| Insecure deserialization (`pickle`, unsafe `yaml.load`) | High |
| `eval()` / `exec()`                      | High     |
| TLS verification disabled (`verify=False`) | High   |
| Weak hash algorithms (MD5 / SHA-1)       | Medium   |
| Weak randomness (`random` for tokens)    | Medium   |
| Use of `assert` for validation           | Low      |
| Debug mode enabled (Flask/Django)        | Low      |

Plus everything Bandit's ~70 built-in checks cover.

## Project layout

```
pysecure-auditor/
├── main.py              # CLI entry point (scan / gui)
├── gui.py                # Tkinter desktop GUI
├── scanner.py             # Orchestrates all engines
├── ast_analyzer.py        # AST-based checks
├── regex_analyzer.py      # Regex-based checks
├── bandit_runner.py       # Wraps the Bandit CLI
├── report_generator.py    # JSON / HTML / PDF report generation
├── utils.py               # Shared Finding/Severity types + helpers
├── samples/
│   ├── vulnerable_login.py  # Intentionally insecure demo file
│   └── secure_login.py      # Corrected version, for comparison
├── reports/                 # Default output folder for generated reports
└── requirements.txt
```

## Install

```bash
pip install -r requirements.txt
```

(`bandit` and `reportlab` are the only external dependencies; `tkinter` ships
with most Python installs — on Debian/Ubuntu install it separately with
`sudo apt install python3-tk` if the GUI reports it's missing.)

## Usage

### Command line

```bash
# Scan a project, print a colored report to the console
python main.py scan ./my_project

# Scan a single file
python main.py scan ./my_project/app.py

# Export a report
python main.py scan ./my_project --format json --output reports/report.json
python main.py scan ./my_project --format html --output reports/report.html
python main.py scan ./my_project --format pdf  --output reports/report.pdf

# Skip an engine
python main.py scan ./my_project --no-bandit

# CI mode: exit with code 2 if anything HIGH or above is found
python main.py scan ./my_project --fail-on high
```

Try it on the bundled samples:

```bash
python main.py scan samples/vulnerable_login.py --format html --output reports/demo.html
python main.py scan samples/secure_login.py       # should report 0 findings
```

### GUI

```bash
python main.py gui
```

Pick a folder or file, toggle which engines to run, click **Run Scan**, click
any row to see the full description and fix, and export to JSON/HTML/PDF from
the bottom bar.

## How it works

```
        User selects folder
                │
                ▼
        Find all .py files
                │
   ┌────────────┼────────────┐
   ▼             ▼            ▼
 AST Scan    Regex Scan    Bandit
   │             │            │
   └─────────────┼────────────┘
                 ▼
        Merge + deduplicate
                 ▼
        Sort by severity
                 ▼
      Console / JSON / HTML / PDF report
```

- **AST analysis** (`ast_analyzer.py`) parses each file into a syntax tree
  and inspects specific call/assignment shapes (e.g. `eval(...)`,
  `hashlib.md5(...)`, `cursor.execute(f"...")`) — this catches issues
  regardless of code style/whitespace and understands actual call structure.
- **Regex analysis** (`regex_analyzer.py`) scans raw lines for patterns AST
  alone can miss or that are simpler to express as text, such as connection
  strings with embedded credentials or PEM-format private keys.
- **Bandit** (`bandit_runner.py`) runs the industry-standard `bandit` CLI and
  folds its JSON output into the same finding format, adding its ~70 checks
  on top.

Findings from all three engines are deduplicated (same file + line +
vulnerability) and sorted by severity before being reported.

## Best practices reference

Every report ends with a checklist of general secure-coding practices
(input validation, secrets management, parameterized queries, secure
hashing, least privilege, safe exception handling, etc.) — see
`report_generator.py::BEST_PRACTICES`.

## Limitations

This is a **static** analyzer: it flags textual/structural patterns, not
confirmed exploits. It doesn't do data-flow/taint tracking, so it cannot
tell whether a flagged value truly originates from untrusted input — treat
findings as a prioritized checklist for manual review, not a certification.
It also only supports Python source (`.py`) files.

## Extending it

- Add a new AST rule: add a case in `ast_analyzer.py::_Visitor.visit_Call`
  or `visit_Assign`.
- Add a new regex rule: append a tuple to `regex_analyzer.py::RULES`.
- Add a new report format: add a `generate_x_report()` function in
  `report_generator.py` and wire it into `main.py` / `gui.py`.
- Support another language: implement an analyzer module with an
  `analyze()` method returning `Finding` objects, matching the interface
  used by `ASTAnalyzer` / `RegexAnalyzer`.

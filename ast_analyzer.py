"""
ast_analyzer.py
AST-based static analysis for detecting insecure Python code patterns.

Detects:
  - eval() / exec()
  - pickle.loads() / pickle.load()
  - yaml.load() without SafeLoader
  - os.system() / subprocess with shell=True
  - Weak hashing (md5 / sha1)
  - Weak randomness for security purposes (random module)
  - Flask/Django debug mode enabled
  - Naive SQL string building (string concat / f-string / % / .format used
    directly inside a .execute(...) call)
  - Hardcoded secrets assigned via literals (delegated mostly to regex, but
    caught here too when it's an assignment inside a function/class)
"""

import ast

from utils import Finding, Severity, get_line_snippet


DANGEROUS_CALLS = {
    "eval": ("Use of eval()", Severity.HIGH,
              "eval() executes arbitrary code and can lead to remote code "
              "execution if fed untrusted input.",
              "Avoid eval(). Use ast.literal_eval() for parsing literals, "
              "or a proper parser/serializer (e.g. json) for structured data."),
    "exec": ("Use of exec()", Severity.HIGH,
             "exec() executes arbitrary code and can lead to remote code "
             "execution if fed untrusted input.",
             "Avoid exec(). Refactor the logic so dynamic execution isn't "
             "required, or strictly sandbox and validate the input."),
}

SQL_EXECUTE_METHODS = {"execute", "executemany", "raw", "executescript"}


class ASTAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.findings = []
        self.source = ""

    def analyze(self):
        try:
            with open(self.filepath, "r", encoding="utf-8", errors="replace") as f:
                self.source = f.read()
            tree = ast.parse(self.source, filename=self.filepath)
        except (SyntaxError, OSError, UnicodeDecodeError):
            return self.findings

        visitor = _Visitor(self.filepath, self.source)
        visitor.visit(tree)
        self.findings = visitor.findings
        return self.findings


class _Visitor(ast.NodeVisitor):
    def __init__(self, filepath, source):
        self.filepath = filepath
        self.source = source
        self.findings = []

    # -- helpers -----------------------------------------------------
    def _add(self, node, vulnerability, severity, description, recommendation):
        self.findings.append(Finding(
            file=self.filepath,
            line=getattr(node, "lineno", 0),
            vulnerability=vulnerability,
            severity=severity,
            description=description,
            recommendation=recommendation,
            source="AST",
            code_snippet=get_line_snippet(self.filepath, getattr(node, "lineno", 0)),
        ))

    @staticmethod
    def _dotted_name(node):
        """Turn an attribute/name chain like os.system into 'os.system'."""
        parts = []
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(node.id)
        return ".".join(reversed(parts))

    def _is_fstring_or_concat(self, node):
        """True if node is a JoinedStr (f-string), string concatenation
        (BinOp Add), or %/format string building - i.e. not a safe
        parameterized literal."""
        if isinstance(node, ast.JoinedStr):
            return True
        if isinstance(node, ast.BinOp):
            return True  # covers 'a' + var  and  'a %s' % var
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr == "format":
                return True
        return False

    # -- visitors ------------------------------------------------------
    def visit_Call(self, node):
        func = node.func
        dotted = self._dotted_name(func)
        simple_name = func.id if isinstance(func, ast.Name) else None

        # eval / exec
        if simple_name in DANGEROUS_CALLS:
            title, sev, desc, rec = DANGEROUS_CALLS[simple_name]
            self._add(node, title, sev, desc, rec)

        # os.system
        if dotted == "os.system":
            self._add(node, "Command Injection (os.system)", Severity.CRITICAL,
                       "os.system() runs a command through the shell; if any "
                       "part of the command string comes from user input, an "
                       "attacker can inject arbitrary shell commands.",
                       "Use subprocess.run([...], shell=False) with a list of "
                       "arguments instead of building a shell command string.")

        # subprocess.* with shell=True
        if dotted.startswith("subprocess."):
            for kw in node.keywords:
                if kw.arg == "shell" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is True:
                    self._add(node, "Command Injection (subprocess shell=True)",
                               Severity.CRITICAL,
                               "Calling subprocess with shell=True passes the "
                               "command through the system shell, allowing "
                               "shell metacharacters/injection if input is "
                               "attacker-controlled.",
                               "Use shell=False and pass the command as a list "
                               "of arguments, e.g. subprocess.run(['ls', path]).")

        # pickle.loads / pickle.load
        if dotted in ("pickle.loads", "pickle.load", "cPickle.loads", "cPickle.load"):
            self._add(node, "Insecure Deserialization (pickle)", Severity.HIGH,
                       "Unpickling data from an untrusted source can execute "
                       "arbitrary code during deserialization.",
                       "Never unpickle untrusted data. Use a safe format such "
                       "as JSON, or cryptographically sign/verify pickled data.")

        # yaml.load without SafeLoader
        if dotted == "yaml.load":
            has_safe_loader = False
            for kw in node.keywords:
                if kw.arg == "Loader":
                    loader_name = self._dotted_name(kw.value) if isinstance(
                        kw.value, (ast.Attribute, ast.Name)) else ""
                    if "SafeLoader" in loader_name or "CSafeLoader" in loader_name:
                        has_safe_loader = True
            if not has_safe_loader:
                self._add(node, "Insecure Deserialization (yaml.load)", Severity.HIGH,
                           "yaml.load() without Loader=yaml.SafeLoader can "
                           "instantiate arbitrary Python objects from the "
                           "YAML document, leading to code execution.",
                           "Use yaml.safe_load(data) or yaml.load(data, "
                           "Loader=yaml.SafeLoader).")

        # hashlib weak hashes
        if dotted in ("hashlib.md5", "hashlib.sha1"):
            algo = dotted.split(".")[1]
            self._add(node, f"Weak Hash Algorithm ({algo})", Severity.MEDIUM,
                       f"{algo.upper()} is cryptographically broken and unsuitable "
                       "for password hashing or integrity-sensitive use cases.",
                       "Use bcrypt, scrypt, or Argon2 for passwords; use "
                       "SHA-256/SHA-3 for general integrity hashing.")

        # weak randomness
        if dotted.startswith("random.") and dotted.split(".")[1] in (
                "random", "randint", "choice", "randrange", "shuffle"):
            self._add(node, "Weak Random Number Generator", Severity.MEDIUM,
                       "The 'random' module is not cryptographically secure and "
                       "is predictable, which is unsafe for tokens, passwords, "
                       "or other security-sensitive values.",
                       "Use the 'secrets' module (e.g. secrets.token_hex(), "
                       "secrets.choice()) for security-sensitive randomness.")

        # Flask/Django debug=True
        if isinstance(func, ast.Attribute) and func.attr == "run":
            for kw in node.keywords:
                if kw.arg == "debug" and isinstance(kw.value, ast.Constant) \
                        and kw.value.value is True:
                    self._add(node, "Debug Mode Enabled", Severity.LOW,
                               "Running the application with debug=True can "
                               "expose an interactive debugger and stack "
                               "traces to end users in production, leaking "
                               "source code and secrets.",
                               "Disable debug mode in production; drive it "
                               "from an environment variable that defaults "
                               "to False.")

        # SQL injection via string building inside .execute()/.raw()
        if isinstance(func, ast.Attribute) and func.attr in SQL_EXECUTE_METHODS \
                and node.args:
            query_arg = node.args[0]
            if self._is_fstring_or_concat(query_arg):
                self._add(node, "SQL Injection", Severity.CRITICAL,
                           "The SQL query is built by concatenating or "
                           "formatting strings (f-string/+/%/.format) instead "
                           "of using parameter placeholders, allowing SQL "
                           "injection if any part comes from user input.",
                           "Use parameterized queries, e.g. "
                           "cursor.execute('SELECT * FROM t WHERE id=%s', "
                           "(user_id,)) instead of building the query string "
                           "yourself.")

        self.generic_visit(node)

    def visit_Assign(self, node):
        # Hardcoded secrets: NAME = "literal" where NAME looks sensitive
        sensitive_keywords = ("password", "passwd", "pwd", "secret", "api_key",
                               "apikey", "access_key", "private_key", "token",
                               "auth_token", "secret_key")
        for target in node.targets:
            name = None
            if isinstance(target, ast.Name):
                name = target.id
            elif isinstance(target, ast.Attribute):
                name = target.attr
            if not name:
                continue
            lname = name.lower()
            if any(k in lname for k in sensitive_keywords):
                if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str) \
                        and node.value.value.strip() != "":
                    self._add(node, "Hardcoded Secret/Credential", Severity.HIGH,
                               f"The variable '{name}' is assigned a hardcoded "
                               "string literal that looks like a secret "
                               "(password/API key/token). Hardcoded secrets "
                               "end up in source control and are easy to leak.",
                               "Load secrets from environment variables or a "
                               "secrets manager (e.g. os.environ['...'], "
                               "python-dotenv, AWS Secrets Manager, Vault).")
        self.generic_visit(node)

"""
secure_login.py
A corrected version of vulnerable_login.py showing secure equivalents for
each issue PySecure Auditor flags.
"""

import os
import secrets
import sqlite3

import bcrypt
import yaml
from flask import Flask

app = Flask(__name__)

# Secrets loaded from the environment instead of hardcoded
DB_PASSWORD = os.environ.get("DB_PASSWORD")
API_KEY = os.environ.get("API_KEY")


def check_login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # Parameterized query - safe from SQL injection
    cursor.execute(
        "SELECT * FROM users WHERE username = ? AND password_hash = ?",
        (username, hash_password(password)),
    )
    return cursor.fetchone()


def hash_password(password):
    # Strong, salted password hashing
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def generate_session_token():
    # Cryptographically secure token
    return secrets.token_hex(32)


def run_diagnostic(host):
    # No shell involved, arguments passed as a list
    import subprocess
    subprocess.run(["ping", "-c", "4", host], shell=False, check=False)


def load_config(path):
    with open(path) as f:
        # Safe YAML loading
        return yaml.safe_load(f)


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(debug=debug_mode)

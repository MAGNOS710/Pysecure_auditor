"""
vulnerable_login.py
INTENTIONALLY INSECURE sample application, used only to demonstrate what
PySecure Auditor detects. Do not use any pattern in this file in real code.
"""

import hashlib
import os
import pickle
import random
import sqlite3

import yaml
from flask import Flask, request

app = Flask(__name__)

DB_PASSWORD = "SuperSecret123"
API_KEY = "sk_live_51Hh2eZAbCdEfGhIjKlMnOpQrStUv"


def check_login(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection: query built with an f-string instead of parameters
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    return cursor.fetchone()


def hash_password(password):
    # Weak hash algorithm
    return hashlib.md5(password.encode()).hexdigest()


def generate_session_token():
    # Weak randomness for a security-sensitive token
    return str(random.randint(100000, 999999))


def run_diagnostic(cmd):
    # Command injection
    os.system("ping " + cmd)


def load_config(path):
    with open(path) as f:
        # Insecure deserialization
        return yaml.load(f)


def load_session(data):
    # Insecure deserialization
    return pickle.loads(data)


def debug_eval(expr):
    return eval(expr)


if __name__ == "__main__":
    app.run(debug=True)

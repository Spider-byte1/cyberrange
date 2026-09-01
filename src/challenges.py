"""
CyberRange Lab - challenge engine.

Each challenge has a VULNERABLE code path and a PATCHED code path. The
defender toggles which one is active per-challenge. This module is the only
place "dangerous-looking" code lives, and even then it's all self-contained:
- SQL injection uses a real local in-memory SQLite DB (safe: your own data).
- XSS reflects input into HTML you view in your own browser (safe: local).
- Command injection is SIMULATED with string matching -- no subprocess is
  ever actually executed, so there is no real command execution risk.
This mirrors how established training tools (DVWA, OWASP Juice Shop,
WebGoat) work: real vulnerability classes, contained entirely inside a
local practice app.
"""
from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

FLAGS = {
    "sqli": "FLAG{sql1_1nj3ct10n_byp4ss3d}",
    "xss": "FLAG{r3fl3ct3d_xss_p0pp3d}",
    "bruteforce": "FLAG{w34k_p4ssw0rd_crack3d}",
    "idor": "FLAG{1d0r_l34k3d_1nv01c3}",
    "cmdi": "FLAG{cmd_1nj3ct10n_s1mul4t3d}",
}

CHALLENGE_META = {
    "sqli": {
        "title": "SQL Injection — Admin Login Bypass",
        "owasp": "A03:2021 Injection",
        "technique": "T1190 Exploit Public-Facing Application",
        "blurb": "The internal admin login builds its SQL query with raw string "
                 "concatenation. Log in as admin without knowing the password.",
        "defense": "Parameterized queries (bound placeholders instead of string building).",
    },
    "xss": {
        "title": "Reflected XSS — Search Box",
        "owasp": "A03:2021 Injection (XSS)",
        "technique": "OWASP: Cross-Site Scripting",
        "blurb": "The search page reflects your query straight into the page HTML. "
                 "Get a <script> payload to appear unescaped in the response.",
        "defense": "Output encoding / auto-escaping of user input in HTML context.",
    },
    "bruteforce": {
        "title": "Brute Force — Weak Service Account",
        "owasp": "A07:2021 Identification & Authentication Failures",
        "technique": "T1110 Brute Force",
        "blurb": "The svc_backup account uses a common password and there's no "
                 "lockout. Guess it from the candidate list.",
        "defense": "Account lockout after repeated failed attempts.",
    },
    "idor": {
        "title": "IDOR — Invoice Viewer",
        "owasp": "A01:2021 Broken Access Control",
        "technique": "OWASP: Insecure Direct Object Reference",
        "blurb": "You're logged in as alice. The invoice viewer trusts the ID in "
                 "the URL with no ownership check. View someone else's invoice.",
        "defense": "Server-side ownership check before returning the record.",
    },
    "cmdi": {
        "title": "Command Injection — Network Diagnostics (simulated)",
        "owasp": "A03:2021 Injection",
        "technique": "T1059 Command and Scripting Interpreter",
        "blurb": "The diagnostics tool builds a shell command from your input. "
                 "Chain in an extra command to leak simulated secret data. "
                 "(No real shell command ever runs — output is simulated.)",
        "defense": "Strict input validation (allowlist characters, no shell metachars).",
    },
}

# ---------------------------------------------------------------------------
# In-memory state (single-process demo app)
# ---------------------------------------------------------------------------

PATCHES: Dict[str, bool] = {name: False for name in CHALLENGE_META}
ACTIVITY_LOG: List[dict] = []

_BRUTEFORCE_ATTEMPTS: Dict[str, int] = {}
_BRUTEFORCE_LOCKED: Dict[str, bool] = {}

_db = sqlite3.connect(":memory:", check_same_thread=False)
_db.row_factory = sqlite3.Row


def _seed_db():
    cur = _db.cursor()
    cur.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, role TEXT)")
    cur.execute("CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner TEXT, amount TEXT, memo TEXT)")
    cur.executemany(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        [
            ("alice", "wonderland1", "user"),
            ("bob", "fishing2024", "user"),
            ("admin", "CorrectHorseBattery!9", "admin"),
            ("svc_backup", "Summer2024!", "service"),
        ],
    )
    cur.executemany(
        "INSERT INTO invoices (id, owner, amount, memo) VALUES (?, ?, ?, ?)",
        [
            (1001, "alice", "$120.00", "Monthly SaaS subscription."),
            (1002, "admin", "$48,000.00", f"Vendor payout approval. Internal note: {FLAGS['idor']}"),
            (1003, "bob", "$76.50", "Office supplies reimbursement."),
        ],
    )
    _db.commit()


_seed_db()

BRUTEFORCE_CANDIDATES = [
    "password1", "welcome123", "admin123", "letmein",
    "qwerty2024", "Summer2024!", "backup2023", "changeme",
]


def log_activity(challenge: str, action: str, payload: str, success: bool, note: str = ""):
    ACTIVITY_LOG.append({
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "challenge": challenge,
        "action": action,
        "payload": payload[:200],
        "patched": PATCHES.get(challenge, False),
        "success": success,
        "note": note,
    })
    if len(ACTIVITY_LOG) > 500:
        del ACTIVITY_LOG[0]


def reset_lab():
    ACTIVITY_LOG.clear()
    for k in PATCHES:
        PATCHES[k] = False
    _BRUTEFORCE_ATTEMPTS.clear()
    _BRUTEFORCE_LOCKED.clear()


# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

def attempt_sqli(username: str, password: str):
    cur = _db.cursor()
    error = None
    row = None
    if PATCHES["sqli"]:
        cur.execute("SELECT * FROM users WHERE username=? AND password=?", (username, password))
        row = cur.fetchone()
    else:
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try:
            cur.execute(query)
            row = cur.fetchone()
        except sqlite3.Error as e:
            error = str(e)

    success = row is not None
    flag = FLAGS["sqli"] if (success and not PATCHES["sqli"]) else None
    log_activity("sqli", "login", f"username={username!r} password={password!r}", success)
    return {
        "success": success,
        "row": dict(row) if row else None,
        "error": error,
        "flag": flag,
    }


# ---------------------------------------------------------------------------
# Reflected XSS
# ---------------------------------------------------------------------------

XSS_MARKERS = re.compile(r"<script|onerror\s*=|onload\s*=|javascript:", re.IGNORECASE)


def attempt_xss(query: str):
    triggered = bool(XSS_MARKERS.search(query or ""))
    success = triggered and not PATCHES["xss"]
    flag = FLAGS["xss"] if success else None
    log_activity("xss", "search", query, success)
    return {"success": success, "flag": flag, "raw_reflected": not PATCHES["xss"]}


# ---------------------------------------------------------------------------
# Brute force
# ---------------------------------------------------------------------------

def attempt_bruteforce(session_id: str, guess: str):
    if _BRUTEFORCE_LOCKED.get(session_id):
        log_activity("bruteforce", "login_attempt", guess, False, note="locked")
        return {"success": False, "locked": True, "flag": None, "attempts": _BRUTEFORCE_ATTEMPTS.get(session_id, 0)}

    _BRUTEFORCE_ATTEMPTS[session_id] = _BRUTEFORCE_ATTEMPTS.get(session_id, 0) + 1
    correct = guess == "Summer2024!"
    success = correct

    if not success and PATCHES["bruteforce"] and _BRUTEFORCE_ATTEMPTS[session_id] >= 3:
        _BRUTEFORCE_LOCKED[session_id] = True

    flag = FLAGS["bruteforce"] if success else None
    log_activity("bruteforce", "login_attempt", guess, success)
    return {
        "success": success,
        "locked": _BRUTEFORCE_LOCKED.get(session_id, False),
        "flag": flag,
        "attempts": _BRUTEFORCE_ATTEMPTS[session_id],
    }


# ---------------------------------------------------------------------------
# IDOR
# ---------------------------------------------------------------------------

def attempt_idor(session_user: str, invoice_id: int):
    cur = _db.cursor()
    cur.execute("SELECT * FROM invoices WHERE id=?", (invoice_id,))
    row = cur.fetchone()
    if row is None:
        log_activity("idor", "view_invoice", str(invoice_id), False, note="not found")
        return {"found": False, "allowed": False, "row": None, "flag": None}

    is_owner = row["owner"] == session_user
    allowed = is_owner or not PATCHES["idor"]
    success = allowed and not is_owner  # "success" = accessed someone else's data
    flag = FLAGS["idor"] if (success and row["owner"] == "admin") else None

    log_activity("idor", "view_invoice", str(invoice_id), success,
                  note=f"owner={row['owner']}, allowed={allowed}")
    return {
        "found": True,
        "allowed": allowed,
        "row": dict(row) if allowed else None,
        "flag": flag,
    }


# ---------------------------------------------------------------------------
# Command injection (SIMULATED -- no real subprocess is ever run)
# ---------------------------------------------------------------------------

SAFE_HOSTNAME_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")
SHELL_META_RE = re.compile(r"[;&|`$()]")


def attempt_cmdi(hostname: str):
    hostname = hostname or ""

    if PATCHES["cmdi"]:
        if not SAFE_HOSTNAME_RE.match(hostname):
            log_activity("cmdi", "ping", hostname, False, note="rejected by input validation")
            return {"output": "Error: invalid hostname format. Only letters, digits, '.', '-' allowed.",
                     "success": False, "flag": None}
        output = f"PING {hostname}: 4 packets transmitted, 4 received, 0% loss (simulated)"
        log_activity("cmdi", "ping", hostname, False, note="patched, clean ping")
        return {"output": output, "success": False, "flag": None}

    # Vulnerable path: naive simulation of "the host shell ran your extra command"
    has_meta = bool(SHELL_META_RE.search(hostname))
    output_lines = [f"PING {hostname.split(';')[0].strip()}: 4 packets transmitted, 4 received, 0% loss (simulated)"]
    leaked = False
    if has_meta:
        injected = re.split(r"[;&|]", hostname, maxsplit=1)[1].strip() if len(re.split(r"[;&|]", hostname, maxsplit=1)) > 1 else ""
        lowered = injected.lower()
        if "whoami" in lowered:
            output_lines.append("svc-network")
        if "cat" in lowered and ("secret" in lowered or "flag" in lowered or "passwd" in lowered):
            output_lines.append(f"-- simulated secret file contents --\n{FLAGS['cmdi']}")
            leaked = True
        if not lowered:
            output_lines.append("(empty injected command)")
        elif "whoami" not in lowered and not leaked:
            output_lines.append(f"(simulated) command not found: {injected}")

    success = leaked
    flag = FLAGS["cmdi"] if success else None
    log_activity("cmdi", "ping", hostname, success)
    return {"output": "\n".join(output_lines), "success": success, "flag": flag}

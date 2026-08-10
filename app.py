#!/usr/bin/env python3
"""
CyberRange Lab - Practice attack & defense in a safe, local, self-contained
web app.

Run with:
    python3 app.py
Then open http://localhost:5000

Educational use only. Everything here (the vulnerable logins, the "system"
being attacked, the injected command output) is simulated inside this one
process -- there is no real database of real users, no real shell command
execution, and nothing here reaches out to the network or to any other
system. Run it locally; don't expose it to the internet.
"""
import os
import sys
import uuid

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import challenges  # noqa: E402
import rag  # noqa: E402

app = Flask(__name__)
app.secret_key = "cyberrange-lab-local-demo-only"


def get_session_id():
    if "sid" not in session:
        session["sid"] = str(uuid.uuid4())
    if "captured_flags" not in session:
        session["captured_flags"] = []
    session.setdefault("user", "alice")
    return session["sid"]


@app.route("/")
def dashboard():
    get_session_id()
    challenges_view = []
    for name, meta in challenges.CHALLENGE_META.items():
        challenges_view.append({
            "name": name,
            "captured": name in session.get("captured_flags", []),
            "patched": challenges.PATCHES[name],
            **meta,
        })
    return render_template(
        "dashboard.html",
        challenges=challenges_view,
        captured_count=len(session.get("captured_flags", [])),
        total=len(challenges.CHALLENGE_META),
        user=session.get("user", "alice"),
    )


def _award(name, flag):
    if flag and name not in session.get("captured_flags", []):
        flags = session.get("captured_flags", [])
        flags.append(name)
        session["captured_flags"] = flags


@app.route("/challenge/sqli", methods=["GET", "POST"])
def challenge_sqli():
    result = None
    if request.method == "POST":
        result = challenges.attempt_sqli(request.form.get("username", ""), request.form.get("password", ""))
        _award("sqli", result.get("flag"))
    return render_template("challenge_sqli.html", meta=challenges.CHALLENGE_META["sqli"],
                            patched=challenges.PATCHES["sqli"], result=result)


@app.route("/challenge/xss", methods=["GET", "POST"])
def challenge_xss():
    query = request.values.get("q", "")
    result = None
    if query:
        result = challenges.attempt_xss(query)
        _award("xss", result.get("flag"))
    return render_template("challenge_xss.html", meta=challenges.CHALLENGE_META["xss"],
                            patched=challenges.PATCHES["xss"], query=query, result=result,
                            reflect_raw=(query and not challenges.PATCHES["xss"]))


@app.route("/challenge/bruteforce", methods=["GET", "POST"])
def challenge_bruteforce():
    sid = get_session_id()
    result = None
    if request.method == "POST":
        result = challenges.attempt_bruteforce(sid, request.form.get("guess", ""))
        _award("bruteforce", result.get("flag"))
    attempts = challenges._BRUTEFORCE_ATTEMPTS.get(sid, 0)
    locked = challenges._BRUTEFORCE_LOCKED.get(sid, False)
    return render_template("challenge_bruteforce.html", meta=challenges.CHALLENGE_META["bruteforce"],
                            patched=challenges.PATCHES["bruteforce"], result=result,
                            attempts=attempts, locked=locked,
                            candidates=challenges.BRUTEFORCE_CANDIDATES)


@app.route("/challenge/idor", methods=["GET"])
@app.route("/challenge/idor/<int:invoice_id>", methods=["GET"])
def challenge_idor(invoice_id=1001):
    sid = get_session_id()
    result = challenges.attempt_idor(session.get("user", "alice"), invoice_id)
    _award("idor", result.get("flag"))
    return render_template("challenge_idor.html", meta=challenges.CHALLENGE_META["idor"],
                            patched=challenges.PATCHES["idor"], result=result,
                            invoice_id=invoice_id, user=session.get("user", "alice"))


@app.route("/challenge/cmdi", methods=["GET", "POST"])
def challenge_cmdi():
    result = None
    hostname = ""
    if request.method == "POST":
        hostname = request.form.get("hostname", "")
        result = challenges.attempt_cmdi(hostname)
        _award("cmdi", result.get("flag"))
    return render_template("challenge_cmdi.html", meta=challenges.CHALLENGE_META["cmdi"],
                            patched=challenges.PATCHES["cmdi"], result=result, hostname=hostname)


@app.route("/toggle_patch/<name>", methods=["POST"])
def toggle_patch(name):
    if name in challenges.PATCHES:
        challenges.PATCHES[name] = not challenges.PATCHES[name]
    return redirect(request.referrer or url_for("dashboard"))


@app.route("/reset", methods=["POST"])
def reset():
    challenges.reset_lab()
    session["captured_flags"] = []
    return redirect(url_for("dashboard"))


@app.route("/blueteam")
def blueteam():
    get_session_id()
    return render_template("blueteam.html", log=list(reversed(challenges.ACTIVITY_LOG))[:100],
                            challenges=challenges.CHALLENGE_META, patches=challenges.PATCHES)


@app.route("/api/ask", methods=["POST"])
def api_ask():
    payload = request.get_json(force=True, silent=True) or {}
    question = (payload.get("question") or "").strip()
    if not question:
        return jsonify({"error": "question is required"}), 400
    return jsonify(rag.ask(question))


@app.route("/api/log")
def api_log():
    return jsonify(list(reversed(challenges.ACTIVITY_LOG))[:100])


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=False)

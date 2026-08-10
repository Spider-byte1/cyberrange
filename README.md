# CyberRange Lab

Practice offensive and defensive security **inside the app itself** — no
external targets, no real network requests, nothing leaves this process.
Five classic vulnerability classes, each with a working exploit and a
working fix you can toggle live, plus a blue-team AI assistant (RAG) that
analyzes your session's activity log and tells you what happened.

**Educational sandbox only.** Everything is simulated locally: the "admin
login" is a local in-memory SQLite table you seed yourself, the XSS target
is a page you view in your own browser, and command injection is
string-pattern **simulated** — no real shell command is ever executed.
This mirrors how established training tools (DVWA, OWASP Juice Shop,
WebGoat) work. Run it locally; don't expose it to the internet; never use
these techniques against systems you don't own or have permission to test.

## The five challenges

| Challenge | Class | You do |
|---|---|---|
| SQL Injection | A03 Injection / T1190 | Log in as `admin` without the password via a raw-concatenated SQL query |
| Reflected XSS | A03 Injection (XSS) | Get a `<script>` payload reflected unescaped into the page |
| Brute Force | A07 Auth Failures / T1110 | Guess a weak service-account password from a candidate list |
| IDOR | A01 Broken Access Control | View another user's invoice by changing an ID in the URL |
| Command Injection (simulated) | A03 Injection / T1059 | Chain a second command onto a hostname field to leak a "secret" |

Each challenge page has a **patch toggle**. Exploit it while vulnerable to
capture the flag, then apply the patch and try the exact same exploit
again — it fails, and you can see exactly what code-level fix stopped it
(parameterized queries, output encoding, lockout, ownership checks, input
allowlisting).

## Blue Team Console

Every attempt across every challenge — yours, patched or not, successful
or not — lands in a live activity log. The **Ask the Assistant** panel runs
a small retrieval-augmented pipeline over that log plus static
technique/defense notes (dependency-free hashing-vectorizer embeddings, no
external calls) and returns a grounded analyst note: Findings, Severity,
Recommended Actions — grounded in your actual log entries, not invented.

Try asking:
- "What attacks succeeded while unpatched?"
- "Summarize all SQL injection attempts"
- "Was the brute force attack blocked?"
- "What should I patch next?"

## Run it

```bash
cd cyberrange-lab
pip install -r requirements.txt   # flask, numpy
python3 app.py
```

Open **http://localhost:5000**. Click into a challenge, try the exploit,
flip the patch toggle, try again, then check the Blue Team Console to see
it in the log and ask the assistant about it.

Use "Reset lab" in the top nav anytime to clear patches, flags, and the
activity log and start over.

## Project structure

```
cyberrange-lab/
├── app.py                    # Flask routes for dashboard, challenges, patches, blue team API
├── src/
│   ├── challenges.py         # vulnerable + patched logic for all 5 challenges, in-memory DB, activity log
│   └── rag.py                 # dependency-free RAG: hashing-vectorizer retrieval + template analyst report
├── templates/                # Jinja2 pages (dashboard, each challenge, blue team console)
├── static/                   # CSS + JS (challenge dashboard styling, blue team chat)
└── requirements.txt
```

## Extending this

- **More challenges**: add a `CHALLENGE_META` entry + `attempt_*` function
  in `challenges.py`, a template, and a route in `app.py`. Ideas: SSRF,
  insecure deserialization, JWT `alg=none`, path traversal, CSRF.
- **Multiplayer / scoreboard**: the activity log already records everything
  needed to build a shared leaderboard across sessions.
- **Real LLM generation**: swap the template-based note in `src/rag.py`
  for a call to a local Ollama model or the Anthropic API for richer
  narrative reports, using the same retrieved context.
- **Difficulty tiers**: add a second, less obvious injection point per
  challenge for players who finish the basic version quickly.

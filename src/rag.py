"""
Blue-team RAG assistant.

Indexes two kinds of documents at query time:
  1. Live activity log entries produced by red-team play in this session.
  2. Static technique/defense knowledge for each challenge (OWASP category,
     ATT&CK-style technique, recommended fix).

Retrieval uses a dependency-free hashing vectorizer (pure numpy) so this
runs with zero external services or downloads. Generation is a template
that turns retrieved, *verified* log lines + technique notes into a
structured analyst note -- it never invents facts not present in the log.
"""
from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import List

import numpy as np

from challenges import ACTIVITY_LOG, CHALLENGE_META, PATCHES

DIM = 256


def _tokenize(text: str) -> List[str]:
    import re
    return re.findall(r"[A-Za-z0-9_./:'=!-]+", text.lower())


def _hash(token: str) -> int:
    return int(hashlib.md5(token.encode("utf-8")).hexdigest(), 16) % DIM


def _vectorize(texts: List[str]) -> np.ndarray:
    doc_freq = Counter()
    tokenized = [_tokenize(t) for t in texts]
    for toks in tokenized:
        for tok in set(toks):
            doc_freq[tok] += 1
    n = len(texts)

    mat = np.zeros((n, DIM), dtype=np.float32)
    for i, toks in enumerate(tokenized):
        counts = Counter(toks)
        for tok, cnt in counts.items():
            idf = math.log((n + 1) / (doc_freq[tok] + 1)) + 1.0
            mat[i, _hash(tok)] += (1 + math.log(cnt)) * idf
        norm = np.linalg.norm(mat[i])
        if norm > 0:
            mat[i] /= norm
    return mat


def _build_corpus():
    docs = []  # list of (text, meta)
    for entry in ACTIVITY_LOG:
        text = (f"[{entry['ts']}] challenge={entry['challenge']} action={entry['action']} "
                f"payload={entry['payload']} patched={entry['patched']} "
                f"success={entry['success']} note={entry['note']}")
        docs.append((text, {"kind": "log", **entry}))

    for name, meta in CHALLENGE_META.items():
        text = (f"{meta['title']} ({meta['owasp']} / {meta['technique']}). {meta['blurb']} "
                f"Defense: {meta['defense']}")
        docs.append((text, {"kind": "technique", "challenge": name, **meta}))

    return docs


def ask(question: str, top_k: int = 8) -> dict:
    corpus = _build_corpus()
    if not corpus:
        return {"answer": "No activity yet. Try a challenge first, then ask again.",
                "sources": []}

    texts = [d[0] for d in corpus]
    vectors = _vectorize(texts + [question])
    doc_vectors, q_vector = vectors[:-1], vectors[-1]

    sims = doc_vectors @ q_vector
    order = np.argsort(-sims)[:top_k]
    retrieved = [corpus[i] for i in order if sims[i] > 0]

    if not retrieved:
        retrieved = corpus[-min(top_k, len(corpus)):]

    log_hits = [d for d in retrieved if d[1]["kind"] == "log"]
    tech_hits = [d for d in retrieved if d[1]["kind"] == "technique"]

    lines = ["Findings:"]
    if log_hits:
        for text, meta in log_hits:
            marker = "SUCCESS" if meta["success"] else "blocked/failed"
            lines.append(f"  - {meta['ts']} · {meta['challenge']} · {meta['action']} "
                         f"(patched={meta['patched']}) -> {marker} · payload={meta['payload']!r}")
    else:
        lines.append("  - No matching activity log entries found for this question.")

    any_unpatched_success = any(m["success"] and not m["patched"] for _, m in log_hits)
    any_success = any(m["success"] for _, m in log_hits)

    if tech_hits:
        lines.append("\nRelated technique / defense notes:")
        for text, meta in tech_hits:
            lines.append(f"  - {meta['title']} [{meta['technique']}]: {meta['blurb']} "
                         f"Fix: {meta['defense']}")

    if any_unpatched_success:
        severity = "High"
    elif any_success:
        severity = "Medium"
    elif log_hits:
        severity = "Low"
    else:
        severity = "N/A"
    lines.append(f"\nSeverity: {severity}")

    lines.append("\nRecommended Actions:")
    unpatched_involved = {m["challenge"] for _, m in log_hits if not m["patched"]}
    if unpatched_involved:
        for c in unpatched_involved:
            fix = CHALLENGE_META.get(c, {}).get("defense", "apply the relevant fix")
            lines.append(f"  - Enable the patch for '{c}': {fix}")
    else:
        lines.append("  - No unpatched exploit activity in the retrieved context.")

    return {
        "answer": "\n".join(lines),
        "severity": severity,
        "sources": [{"kind": m["kind"], "challenge": m.get("challenge"), "text": t} for t, m in retrieved],
    }

const EXAMPLE_QUESTIONS = [
  "What attacks succeeded while unpatched?",
  "Summarize all SQL injection attempts",
  "Was the brute force attack blocked?",
  "What should I patch next?",
];

const streamEl = document.getElementById("stream");
const composer = document.getElementById("composer");
const input = document.getElementById("question-input");

function escapeHtml(str) {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function highlightEntities(escapedText) {
  return escapedText
    .replace(/\bT\d{4}\b/g, (m) => `<span class="entity">${m}</span>`)
    .replace(/\b(sqli|xss|bruteforce|idor|cmdi)\b/g, (m) => `<span class="entity">${m}</span>`);
}

function formatAnswer(rawText) {
  const escaped = escapeHtml(rawText);
  const withLabels = escaped.replace(
    /^(Findings:|Related technique \/ defense notes:|Severity:|Recommended Actions:)/gm,
    '<span class="section-label">$1</span>'
  );
  return highlightEntities(withLabels);
}

function severityClass(sev) {
  const s = (sev || "unknown").toLowerCase();
  if (["high", "medium", "low", "n/a"].includes(s)) return "sev-" + s.replace("/", "");
  return "sev-na";
}

function clearEmpty() {
  const empty = streamEl.querySelector(".assistant-empty");
  if (empty) empty.remove();
}

async function askQuestion(question) {
  clearEmpty();
  const ticket = document.createElement("div");
  ticket.className = "ticket";
  ticket.innerHTML = `
    <div class="ticket-q">${escapeHtml(question)}</div>
    <div class="ticket-a">analyzing…</div>
  `;
  streamEl.appendChild(ticket);
  streamEl.scrollTop = streamEl.scrollHeight;

  try {
    const res = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Request failed");
    ticket.classList.add(severityClass(data.severity));
    ticket.querySelector(".ticket-a").innerHTML = formatAnswer(data.answer);
  } catch (err) {
    ticket.classList.add("sev-high");
    ticket.querySelector(".ticket-a").textContent = "Error: " + err.message;
  }
  streamEl.scrollTop = streamEl.scrollHeight;
}

composer.addEventListener("submit", (e) => {
  e.preventDefault();
  const q = input.value.trim();
  if (!q) return;
  input.value = "";
  askQuestion(q);
});

function renderChips() {
  const container = document.getElementById("example-chips");
  EXAMPLE_QUESTIONS.forEach((q) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "example-chip";
    chip.textContent = q;
    chip.addEventListener("click", () => askQuestion(q));
    container.appendChild(chip);
  });
}

renderChips();

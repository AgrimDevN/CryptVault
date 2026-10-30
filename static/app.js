(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const COLORS = ["#c0392b", "#e67e22", "#d4ac0d", "#27ae60", "#1e8e5a"];

  async function strength(pw) {
    const r = await fetch("/api/strength", {method: "POST",
      headers: {"Content-Type": "application/json", "X-CSRF-Token": csrf},
      body: JSON.stringify({password: pw})});
    return r.json();
  }
  function paint(s) {
    const m = document.getElementById("meter"); if (!m) return;
    m.querySelector(".bar").style.setProperty("--w", ((s.score + 1) * 20) + "%");
    m.querySelector(".bar").style.setProperty("--c", COLORS[s.score]);
    m.querySelector(".label").textContent = s.label + " - ~" + s.entropy_bits + " bits" + (s.policy_passed ? " - meets policy" : "");
    const ul = m.querySelector(".hints"); ul.innerHTML = "";
    s.feedback.forEach(f => { const li = document.createElement("li"); li.textContent = f; ul.appendChild(li); });
  }
  const pw = document.querySelector('[data-strength="meter"]');
  if (pw) { const run = () => pw.value ? strength(pw.value).then(paint) : null; pw.addEventListener("input", run); run(); }

  async function generate(params) {
    const r = await fetch("/api/generate?" + new URLSearchParams(params)); return r.json();
  }
  function genParams() {
    const f = document.getElementById("genform"); if (!f) return {};
    const p = {length: f.length.value};
    ["upper", "lower", "digits", "symbols", "ambiguous"].forEach(k => p[k] = f[k].checked ? "1" : "0");
    return p;
  }
  async function regen() {
    const d = await generate(genParams());
    if (d.error) { document.getElementById("genpw").textContent = d.error; return; }
    document.getElementById("genpw").textContent = d.password; paint(d.strength);
  }
  const gf = document.getElementById("genform");
  if (gf) { gf.addEventListener("input", () => { document.getElementById("lenval").textContent = gf.length.value; regen(); }); regen(); }

  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-action]"); if (!b) return;
    const a = b.dataset.action;
    if (a === "reveal") { const s = b.parentElement.querySelector(".secret");
      const shown = b.textContent === "Hide"; s.textContent = shown ? "•".repeat(8) : s.dataset.secret; b.textContent = shown ? "Show" : "Hide"; }
    if (a === "copy") { await navigator.clipboard.writeText(b.parentElement.querySelector(".secret").dataset.secret);
      b.textContent = "Copied"; setTimeout(() => { b.textContent = "Copy"; navigator.clipboard.writeText(""); }, 15000); }
    if (a === "copy-gen") { await navigator.clipboard.writeText(document.getElementById("genpw").textContent); b.textContent = "Copied"; }
    if (a === "regen") regen();
    if (a === "generate") { const d = await generate({length: 20}); pw.value = d.password; paint(d.strength); }
  });
  document.querySelectorAll("form[data-confirm]").forEach(f => f.addEventListener("submit", e => { if (!confirm(f.dataset.confirm)) e.preventDefault(); }));

  // client-side idle countdown mirrors the server auto-lock
  if (document.body.dataset.unlocked) {
    let left = parseInt(document.body.dataset.timeout, 10); const t = document.getElementById("timer");
    const tick = () => { t.textContent = "Auto-lock in " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0"); };
    tick();
    setInterval(() => { left--; tick(); if (left <= 0) location.href = "/login"; }, 1000);
  }
})();

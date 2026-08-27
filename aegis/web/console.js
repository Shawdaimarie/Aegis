"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const state = { token: "", boundaries: [] };

  const headers = () => ({ "Content-Type": "application/json", Authorization: `Bearer ${state.token}` });

  async function api(path, opts = {}) {
    const res = await fetch(path, { ...opts, headers: headers() });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(body.detail || body.error || `HTTP ${res.status}`);
    return body;
  }

  function setStatus(el, text, cls) { el.textContent = text; el.className = `status ${cls || ""}`; }

  function kv(text) {
    const out = {};
    for (const part of text.split(",")) {
      const [k, v] = part.split("=").map((s) => s.trim());
      if (!k) continue;
      out[k] = v;
    }
    return out;
  }
  const numeric = (obj) => Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, Number(v)]));

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }

  function renderBoundaries(list) {
    const ul = $("boundaries");
    ul.replaceChildren();
    for (const b of list) {
      const li = el("li", b.severity);
      li.append(el("div", "id", b.id));
      li.append(el("div", "sev", `${b.severity} · ${b.checkpoints.join(", ")}`));
      const p = b.predicate;
      li.append(el("div", "pred", p.value === null ? `${p.path} ${p.op}` : `${p.path} ${p.op} ${p.value}`));
      li.append(el("div", "why", b.rationale));
      ul.append(li);
    }
  }

  async function connect() {
    state.token = $("token").value.trim();
    if (!state.token) { setStatus($("conn"), "Not connected"); return; }
    try {
      state.boundaries = await api("/v1/governance/boundaries");
      renderBoundaries(state.boundaries);
      setStatus($("conn"), `Connected · ${state.boundaries.length} boundaries`, "ok");
    } catch (e) {
      setStatus($("conn"), `Connection failed: ${e.message}`, "err");
    }
  }

  function verdict(container, allowed, by, extra) {
    container.replaceChildren();
    const box = el("div", `verdict ${allowed ? "allow" : "deny"}`);
    box.append(el("span", "word", allowed ? "Allowed" : "Denied"));
    if (by) box.append(el("span", "by", by));
    container.append(box);
    if (extra) { const pre = el("pre"); pre.textContent = JSON.stringify(extra, null, 2); container.append(pre); }
  }
  function showError(container, e) { container.replaceChildren(el("div", "err-box", e.message)); }

  async function evaluate() {
    const out = $("ev-out");
    const btn = $("ev-go"); btn.disabled = true;
    try {
      const body = {
        checkpoint: $("ev-checkpoint").value,
        context: {
          run_id: $("ev-run").value, scenario: $("ev-scenario").value, step: Number($("ev-step").value),
          metrics: numeric(kv($("ev-metrics").value)), resources: numeric(kv($("ev-resources").value)),
          tags: kv($("ev-tags").value),
        },
      };
      const d = await api("/v1/governance/evaluate", { method: "POST", body: JSON.stringify(body) });
      const by = d.halted_by ? `HALT · ${d.halted_by}` : d.blocked_by ? `BLOCKING · ${d.blocked_by}`
        : d.advisories.length ? `advisory · ${d.advisories.join(", ")}` : "no boundaries crossed";
      verdict(out, d.allowed, by, d);
    } catch (e) { showError(out, e); } finally { btn.disabled = false; }
  }

  async function simulate() {
    const out = $("sim-out");
    const btn = $("sim-go"); btn.disabled = true;
    try {
      const spec = {
        run_id: $("sim-run").value, scenario: $("sim-scenario").value, root_seed: Number($("sim-seed").value),
        steps: Number($("sim-steps").value), dataset_hash: $("sim-ds").value, egress: $("sim-egress").value,
        git_commit: $("sim-git").value, config_hash: "console", env_lock_hash: "console",
      };
      const body = { spec, loss_decay: Number($("sim-decay").value), gpu_hours_per_step: Number($("sim-gpu").value) };
      const r = await api("/v1/runs/simulate", { method: "POST", body: JSON.stringify(body) });
      verdict(out, r.outcome === "completed", r.outcome === "completed" ? `manifest ${r.manifest_id.slice(0, 22)}…` : r.outcome, r.manifest);
    } catch (e) { showError(out, e); } finally { btn.disabled = false; }
  }

  async function refreshAudit() {
    try {
      const a = await api("/v1/audit?limit=60");
      setStatus($("audit-meta"), `${a.total} records · chain ${a.verified ? "verified" : "BROKEN"}`, a.verified ? "ok" : "err");
      const chain = $("chain"); chain.replaceChildren();
      chain.append(el("span", "genesis", a.records[0]?.seq === 0 ? "genesis" : "…"));
      for (const r of a.records) {
        const seg = el("div", "seg");
        seg.append(el("span", "link"));
        const cls = r.decision === "deny" ? "deny" : r.decision === "crossed" ? "crossed" : "";
        const node = el("span", `node ${cls}`, r.id.slice(7, 13));
        node.title = `${r.seq} · ${r.action} · ${r.decision}`;
        seg.append(node); chain.append(seg);
      }
      const tb = $("audit-table").querySelector("tbody"); tb.replaceChildren();
      for (const r of [...a.records].reverse()) {
        const tr = el("tr");
        const cells = [r.seq, r.at.replace("T", " ").slice(0, 19), r.actor, r.action, r.resource, r.decision];
        cells.forEach((c, i) => { const td = el("td", i === 5 ? (r.decision === "deny" ? "deny" : r.decision === "crossed" ? "crossed" : "") : "", String(c)); tr.append(td); });
        tb.append(tr);
      }
    } catch (e) { setStatus($("audit-meta"), e.message, "err"); }
  }

  document.querySelectorAll(".tabs [role=tab]").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tabs [role=tab]").forEach((t) => t.setAttribute("aria-selected", String(t === tab)));
      document.querySelectorAll("[role=tabpanel]").forEach((p) => { p.hidden = p.id !== `tab-${tab.dataset.tab}`; });
      if (tab.dataset.tab === "audit") refreshAudit();
    });
  });
  $("token").addEventListener("change", connect);
  $("ev-go").addEventListener("click", evaluate);
  $("sim-go").addEventListener("click", simulate);
  $("audit-refresh").addEventListener("click", refreshAudit);
})();

"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const switches = { automation_enabled: $("automation-switch"), require_human_approval: $("approval-switch") };
  let credential = "", current = null, busy = false, generation = 0;

  function render() {
    for (const [name, button] of Object.entries(switches)) {
      button.disabled = busy || !current || !current.permissions.includes(name);
      button.textContent = current ? (current.settings[name] ? "On" : "Off") : "Unknown";
      button.setAttribute("aria-checked", String(current ? current.settings[name] : name === "require_human_approval"));
    }
    $("control-connect").disabled = busy;
    $("control-disconnect").disabled = !credential;
  }
  async function request(path, options = {}) {
    const response = await fetch(path, { ...options, cache: "no-store", headers: {
      "Content-Type": "application/json", Authorization: `Bearer ${credential}`,
    }});
    const body = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(typeof body.detail === "string" ? body.detail : `Request failed (${response.status})`);
    return body;
  }
  function history(events) {
    $("control-history").replaceChildren();
    for (const event of events) {
      const li = document.createElement("li");
      const changed = ["automation_enabled", "require_human_approval"].filter(name => event.before[name] !== event.after[name]);
      const names = { automation_enabled: "Automation", require_human_approval: "Human approval" };
      const details = changed.map(name => `${names[name]} ${event.after[name] ? "on" : "off"}`).join(", ") || "Settings reaffirmed";
      li.textContent = `${event.at} · ${event.actor} (${event.role}) · ${details} · ${event.reason}`;
      $("control-history").append(li);
    }
    if (!events.length) { const li = document.createElement("li"); li.textContent = "No changes recorded."; $("control-history").append(li); }
  }
  async function refreshHistory(epoch) {
    try { const events = await request("/v1/controls/history"); if (epoch === generation) history(events); }
    catch { if (epoch === generation) $("control-history").textContent = "Change history is unavailable. Refresh controls to retry."; }
  }
  async function connect() {
    const epoch = ++generation;
    credential = $("control-token").value.trim(); $("control-token").value = "";
    current = null; busy = true; render();
    try {
      if (!credential) throw new Error("Enter your personal control credential.");
      const data = await request("/v1/controls");
      if (epoch !== generation) return;
      current = data;
      $("control-status").textContent = `${data.subject} · ${data.role} · Tenant: ${data.settings.tenant}`;
      await refreshHistory(epoch);
    } catch (error) {
      if (epoch === generation) { credential = ""; $("control-status").textContent = error.message; }
    } finally { if (epoch === generation) { busy = false; render(); } }
  }
  async function change(name) {
    if (!current || busy || !current.permissions.includes(name)) return;
    const reason = $("control-reason").value.trim();
    if (reason.length < 3) { $("control-status").textContent = "Enter a reason (at least 3 characters)."; $("control-reason").focus(); return; }
    const epoch = generation;
    const payload = { setting: name, enabled: !current.settings[name], expected_revision: current.settings.revision, reason };
    busy = true; render();
    try {
      const data = await request("/v1/controls", { method: "PATCH", body: JSON.stringify(payload) });
      if (epoch !== generation) return;
      current = data; $("control-reason").value = "";
      $("control-status").textContent = "Change saved and recorded.";
      await refreshHistory(epoch);
    } catch (error) {
      if (epoch !== generation) return;
      current = null;
      $("control-status").textContent = `${error.message}. Reconnect to verify the saved state before retrying.`;
    } finally { if (epoch === generation) { busy = false; render(); } }
  }
  function disconnect() {
    generation++; credential = ""; current = null; busy = false;
    $("control-token").value = ""; $("control-reason").value = "";
    $("control-status").textContent = "Disconnected. Settings are unchanged.";
    $("control-history").replaceChildren(); render();
  }
  $("control-connect").addEventListener("click", connect);
  $("control-disconnect").addEventListener("click", disconnect);
  $("control-token").addEventListener("keydown", event => { if (event.key === "Enter" && !busy) connect(); });
  for (const name of Object.keys(switches)) switches[name].addEventListener("click", () => change(name));
  window.addEventListener("pagehide", disconnect);
  render();
})();

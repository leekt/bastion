// Frontend for the Bastion example dashboard.
// Talks ONLY to this app's own /api/* proxy — never to the Bastion bridge
// directly (the browser has no token, and the bridge rejects Origin headers).

const $ = (id) => document.getElementById(id);

async function api(path, opts) {
  const res = await fetch(path, opts);
  let body;
  try {
    body = await res.json();
  } catch {
    body = {};
  }
  return { ok: res.ok, status: res.status, body };
}

function kv(el, pairs) {
  el.replaceChildren();
  for (const [k, v] of pairs) {
    const dt = document.createElement("dt");
    dt.textContent = k;
    const dd = document.createElement("dd");
    dd.textContent = v === undefined || v === null || v === "" ? "—" : String(v);
    el.append(dt, dd);
  }
}

function errorPairs(label, r) {
  return [[label, ""], ["status", r.status], ["error", r.body.error || JSON.stringify(r.body)]];
}

function log(title, payload, kind = "") {
  const stamp = new Date().toLocaleTimeString();
  const text =
    typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
  const el = $("result");
  const prefix = kind === "bad" ? "✗" : kind === "ok" ? "✓" : "•";
  el.textContent = `[${stamp}] ${prefix} ${title}\n${text}\n\n` + el.textContent;
}

async function loadStatus() {
  const r = await api("/api/status");
  if (!r.ok) return kv($("status"), errorPairs("unavailable", r));
  const b = r.body;
  kv($("status"), [
    ["status", b.status || (b.bundleIdentifier ? "running" : "unknown")],
    ["bundle", b.bundleIdentifier],
    ["version", b.version],
    ["mode", b.launchMode],
  ]);
}

async function loadAccount() {
  const r = await api("/api/account");
  if (!r.ok) return kv($("account"), errorPairs("unavailable", r));
  const b = r.body;
  kv($("account"), [
    ["address", b.accountAddress || b.address],
    ["pubkey x", b.x || b.pubkeyX],
    ["pubkey y", b.y || b.pubkeyY],
  ]);
}

async function loadState() {
  const r = await api("/api/state");
  if (!r.ok) return kv($("state"), errorPairs("unavailable", r));
  const b = r.body;
  const pairs = [];
  if (Array.isArray(b.rateLimits)) {
    b.rateLimits.forEach((rl, i) =>
      pairs.push([`rate #${i + 1}`, `${rl.remaining ?? "?"} left / ${rl.windowSeconds ?? "?"}s`])
    );
  }
  if (Array.isArray(b.spendingLimits)) {
    b.spendingLimits.forEach((sl, i) =>
      pairs.push([`spend ${sl.token ?? i}`, `${sl.remaining ?? "?"} / ${sl.windowSeconds ?? "?"}s`])
    );
  }
  kv($("state"), pairs.length ? pairs : [["state", "no active limits"]]);
}

async function loadRules() {
  const r = await api("/api/rules");
  $("rules").textContent = r.ok ? JSON.stringify(r.body, null, 2) : `Error ${r.status}: ${r.body.error || ""}`;
}

async function refresh() {
  $("refresh").disabled = true;
  await Promise.all([loadStatus(), loadAccount(), loadState(), loadRules()]);
  $("refresh").disabled = false;
}

$("refresh").addEventListener("click", refresh);
$("clearLog").addEventListener("click", () => ($("result").textContent = ""));

$("signForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  btn.disabled = true;
  const message = $("message").value;
  log("Sign message → " + JSON.stringify(message), "waiting for Bastion (approval may be required)…");
  const r = await api("/api/sign-message", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message }),
  });
  log(r.ok ? "Signature" : "Sign failed", r.body, r.ok ? "ok" : "bad");
  btn.disabled = false;
  loadState();
});

$("userOpForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const btn = e.target.querySelector("button");
  btn.disabled = true;
  const actions = [{ target: $("target").value, value: $("value").value || "0", data: $("data").value || "0x" }];
  const payload = { actions, send: $("send").checked, chainId: $("chainId").value };
  log("Send UserOp", payload);
  const r = await api("/api/send-userop", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  log(r.ok ? "UserOp result" : "UserOp failed", r.body, r.ok ? "ok" : "bad");
  btn.disabled = false;
  loadState();
});

refresh();

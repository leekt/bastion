// Bastion popup — status + first-run pairing.

const main = document.getElementById("main");

// HTML-escape any dynamic value before it goes into innerHTML. Inputs come from
// our own local native host, but escaping keeps the popup XSS-safe regardless.
function esc(v) {
  return String(v ?? "").replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

function call(payload) {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage({ payload }, (resp) => {
      const err = chrome.runtime.lastError;
      if (err) return resolve({ error: { message: err.message } });
      resolve(resp || {});
    });
  });
}

function row(k, v, cls) {
  return `<div class="row"><span class="k">${k}</span><span class="v ${cls || ""}">${v}</span></div>`;
}

async function renderState() {
  const { result, error } = await call({ kind: "state" });
  if (error) {
    main.innerHTML =
      `<p class="bad">Can't reach the Bastion host.</p>` +
      `<p class="hint">Install the native host (scripts/install-host.sh) and make sure Bastion.app is running.</p>`;
    return;
  }
  const s = result;
  let html = "";
  html += row("Host", s.mcpFound ? '<span class="ok">found</span>' : '<span class="bad">bastion-mcp missing</span>');
  html += row("Network", esc(s.chainId));
  html += row("Status", s.paired ? '<span class="ok">connected</span>' : "not connected");
  if (s.paired) {
    const acct = await call({ kind: "rpc", method: "eth_accounts" });
    if (acct.result?.[0]) html += row("Account", esc(acct.result[0]));
    html += `<button id="rebtn">Re-pair</button>`;
  } else {
    html += `<button id="connect">Connect to Bastion</button>`;
    html += `<p class="hint" style="margin-top:10px">Pairs this browser with your local Bastion wallet. You'll approve a code in the Bastion menu bar.</p>`;
  }
  main.innerHTML = html;
  document.getElementById("connect")?.addEventListener("click", startPairing);
  document.getElementById("rebtn")?.addEventListener("click", startPairing);
}

async function startPairing() {
  main.innerHTML = `<p class="hint">Starting pairing…</p>`;
  const { result, error } = await call({ kind: "pairStart" });
  if (error || !result?.pairingCode) {
    main.innerHTML = `<p class="bad">Pairing failed: ${esc(error?.message || "unknown")}</p>`;
    return;
  }
  main.innerHTML =
    `<p class="hint">Open the <b>Bastion</b> menu-bar app and confirm this code:</p>` +
    `<div class="code">${esc(result.pairingCode)}</div>` +
    `<p class="hint">Waiting for approval…</p>`;
  poll(result.requestId, Date.now() + 5 * 60 * 1000);
}

async function poll(requestId, deadline) {
  if (Date.now() > deadline) {
    main.innerHTML = `<p class="bad">Pairing timed out.</p><button id="connect">Try again</button>`;
    document.getElementById("connect").addEventListener("click", startPairing);
    return;
  }
  const { result } = await call({ kind: "pairPoll", params: { requestId } });
  if (result?.state === "accepted") {
    main.innerHTML =
      `<p class="ok">Connected!</p>` + row("Account", esc(result.account || "(ready)")) +
      `<p class="hint">You can now connect dApps to Bastion from the wallet list.</p>`;
    return;
  }
  if (result?.state === "rejected" || result?.state === "expired") {
    main.innerHTML = `<p class="bad">Pairing ${esc(result.state)}.</p><button id="connect">Try again</button>`;
    document.getElementById("connect").addEventListener("click", startPairing);
    return;
  }
  setTimeout(() => poll(requestId, deadline), 1500);
}

renderState();

// Bastion content script — ISOLATED world.
// Relays EIP-1193 requests between the page's injected provider (MAIN world,
// via window.postMessage) and the extension background service worker
// (via chrome.runtime), and forwards wallet events back to the page.

window.addEventListener("message", (ev) => {
  if (ev.source !== window) return;
  const msg = ev.data;
  if (!msg || msg.__bastion !== "req") return;

  chrome.runtime.sendMessage({ payload: msg.payload }, (resp) => {
    const err = chrome.runtime.lastError;
    if (err) {
      window.postMessage(
        { __bastion: "res", id: msg.id, error: { code: -32603, message: err.message } },
        "*"
      );
      return;
    }
    window.postMessage(
      { __bastion: "res", id: msg.id, result: resp?.result, error: resp?.error },
      "*"
    );
  });
});

// Events pushed from the background (e.g. chainChanged) → page provider.
chrome.runtime.onMessage.addListener((msg) => {
  if (msg && msg.__bastionEvent) {
    window.postMessage({ __bastion: "evt", event: msg.event, data: msg.data }, "*");
  }
});

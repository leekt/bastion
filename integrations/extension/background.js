// Bastion background service worker.
// Owns the native-messaging port to "app.bastion.host", correlates requests,
// and relays them from content scripts (page provider) and the popup.

let port = null;
let nextHostId = 1;
const hostPending = new Map();

function getPort() {
  if (port) return port;
  port = chrome.runtime.connectNative("app.bastion.host");
  port.onMessage.addListener((msg) => {
    const cb = hostPending.get(msg.id);
    if (cb) { hostPending.delete(msg.id); cb(msg); }
  });
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError;
    const message = (err && err.message) || "native host disconnected";
    for (const cb of hostPending.values()) cb({ error: { code: -32603, message } });
    hostPending.clear();
    port = null;
  });
  return port;
}

function callHost(obj) {
  return new Promise((resolve) => {
    const id = nextHostId++;
    hostPending.set(id, resolve);
    try {
      getPort().postMessage({ ...obj, id });
    } catch (e) {
      hostPending.delete(id);
      resolve({ error: { code: -32603, message: e.message || String(e) } });
    }
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const p = msg && msg.payload;
  if (!p) return;
  callHost({ kind: p.kind, method: p.method, params: p.params }).then((resp) => {
    sendResponse({ result: resp.result, error: resp.error });
    // Surface chainChanged to the page after a successful network switch.
    if (
      p.kind === "rpc" &&
      p.method === "wallet_switchEthereumChain" &&
      !resp.error &&
      sender.tab
    ) {
      const chainId = p.params?.[0]?.chainId;
      chrome.tabs.sendMessage(sender.tab.id, {
        __bastionEvent: true,
        event: "chainChanged",
        data: chainId,
      });
    }
  });
  return true; // keep the message channel open for async sendResponse
});

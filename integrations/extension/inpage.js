// Bastion injected provider — runs in the page's MAIN world.
// Exposes an EIP-1193 provider and announces it via EIP-6963 so dApps
// (Uniswap, wagmi, RainbowKit, Web3Modal) discover "Bastion" with no changes.
(function () {
  "use strict";

  const ICON =
    "data:image/svg+xml;base64," +
    btoa(
      '<svg xmlns="http://www.w3.org/2000/svg" width="96" height="96" viewBox="0 0 24 24">' +
        '<rect width="24" height="24" rx="6" fill="#14110d"/>' +
        '<path d="M12 3l7 3v5c0 4.4-3 7.6-7 9-4-1.4-7-4.6-7-9V6l7-3z" fill="#faf7f0"/>' +
        "</svg>"
    );

  let nextId = 1;
  const pending = new Map();
  const listeners = {}; // event -> Set<fn>

  function emit(event, data) {
    (listeners[event] || []).forEach((fn) => {
      try { fn(data); } catch (e) { /* listener threw */ }
    });
  }

  // page → content-script bridge
  window.addEventListener("message", (ev) => {
    if (ev.source !== window) return;
    const msg = ev.data;
    if (!msg || msg.__bastion === undefined) return;
    if (msg.__bastion === "res") {
      const entry = pending.get(msg.id);
      if (!entry) return;
      pending.delete(msg.id);
      if (msg.error) {
        const err = new Error(msg.error.message || "request failed");
        err.code = msg.error.code || -32603;
        entry.reject(err);
      } else {
        entry.resolve(msg.result);
      }
    } else if (msg.__bastion === "evt") {
      if (msg.event === "chainChanged") emit("chainChanged", msg.data);
      else if (msg.event === "accountsChanged") emit("accountsChanged", msg.data);
      else if (msg.event === "connect") emit("connect", msg.data);
      else if (msg.event === "disconnect") emit("disconnect", msg.data);
    }
  });

  function send(kind, method, params) {
    const id = nextId++;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      window.postMessage({ __bastion: "req", id, payload: { kind, method, params } }, "*");
    });
  }

  const provider = {
    isBastion: true,
    // Many dApps still branch on isMetaMask; we do NOT claim to be MetaMask.
    _state: { accounts: [], chainId: null },

    async request({ method, params }) {
      const result = await send("rpc", method, params);
      // Track connection state + surface the standard events.
      if (method === "eth_requestAccounts" || method === "eth_accounts") {
        this._state.accounts = result || [];
        if (method === "eth_requestAccounts") {
          const chainId = await send("rpc", "eth_chainId", []);
          this._state.chainId = chainId;
          emit("connect", { chainId });
          emit("accountsChanged", this._state.accounts);
        }
      }
      if (method === "eth_chainId") this._state.chainId = result;
      if (method === "wallet_switchEthereumChain") {
        const chainId = params?.[0]?.chainId;
        if (chainId) { this._state.chainId = chainId; emit("chainChanged", chainId); }
      }
      return result;
    },

    on(event, fn) {
      (listeners[event] = listeners[event] || new Set()).add(fn);
      return this;
    },
    removeListener(event, fn) {
      listeners[event]?.delete(fn);
      return this;
    },
    // Legacy shims some dApps still call.
    async enable() { return this.request({ method: "eth_requestAccounts" }); },
    isConnected() { return true; },
  };

  // ---- EIP-6963 announcement ----
  const info = {
    uuid: (crypto.randomUUID && crypto.randomUUID()) || "bastion-" + Date.now(),
    name: "Bastion",
    icon: ICON,
    rdns: "app.bastion",
  };
  function announce() {
    window.dispatchEvent(
      new CustomEvent("eip6963:announceProvider", {
        detail: Object.freeze({ info, provider }),
      })
    );
  }
  window.addEventListener("eip6963:requestProvider", announce);
  announce();

  // Legacy fallback: only set window.ethereum if nothing else claimed it.
  try {
    if (!window.ethereum) {
      Object.defineProperty(window, "ethereum", { value: provider, configurable: true });
    }
  } catch (_) { /* a wallet already locked window.ethereum */ }
})();

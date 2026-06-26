# Bastion MCP/REST Bridge — Security Audit Report

**Auditor:** taek <leekt216@gmail.com>
**Date:** 2026-06-26
**Commit:** `390de47` ("Add production Swift MCP bridge")
**Artifacts:** [`attack-surface.md`](attack-surface.md) · [`findings.md`](findings.md) · [`external/codex.md`](external/codex.md) · [`external/gemini.md`](external/gemini.md)

## Executive summary

Commit `390de47` introduces a production Swift bridge (`bastion-mcp`) that speaks MCP-stdio and localhost REST **directly to the XPC signing service**, replacing the Node/Bun server that wrapped `bastion-cli`. The architectural win is a path-bound, per-method trusted-bridge identity. The architectural cost — and the substance of this audit — is that **agent identity attribution moved from a kernel-verified caller code signature to a bridge-supplied string**, gated only by binary identity plus a single shared bearer token.

That shift produced **two Critical findings**: any holder of the one `BASTION_API_TOKEN` (or any process that can reach the stdio bridge) can sign for **every** paired profile by naming its UUID (AC-01), and the XPC server authenticates clients by **PID rather than audit token**, enabling a PID-reuse race that impersonates the trusted bridge (AC-02). A High cross-tenant read disclosure (RE-01) and a High pre-auth DoS on the hand-rolled socket parser (DO-01) follow, plus three Medium read-gate / validation-parity gaps.

**Verdict: do not ship REST mode (and treat stdio multi-profile as unsafe) until Waves 1 and 2 land.** The single-profile-per-bridge stdio configuration with a closed `agentProfileId` allow-set is the minimum safe posture.

## Counts

| Severity | Count |
|----------|-------|
| Critical | 2 |
| High | 2 |
| Medium | 3 |
| Low / Info | 0 |
| **Confirmed total** | **7** |
| Dismissed by verification | 18 |

## Method & confidence

Four parallel streams: per-focus-area subagents, a Codex cold pass, and a cross-cutting pass (Gemini produced no output). Every surviving finding was adversarially refuted by 3 independent skeptics; 18 candidate findings were dismissed (false positives / non-exploitable / out-of-trust-model). All findings are **static-source-traced, not runtime-confirmed** — PoCs are exploit outlines. The two Criticals were independently re-discovered by multiple streams (AC-01 ≡ X-01 ≡ CDX-1; AC-02 found by the XPC-identity focus and cross-cutting passes), which raises confidence.

## What's solid (verified, not findings)

- XPC accept requires Team ID `926A27BQ7W`; bridge identity additionally path-bound to `<host>/Contents/MacOS/bastion-mcp` and unit-tested.
- Each `bridge*` method re-checks `isTrustedAgentBridge`; non-bridge callers get `ruleViolation`.
- `agentProfileId` must resolve to an already-paired profile (fails closed on miss).
- REST: loopback-only bind, `Origin`-present rejection, 128-bit token-entropy gate, 1 MiB body cap, regex validators on addresses/hex/UUIDs, `maxUserOpActions` 16.
- UserOp `sender` must match the resolved profile account; pause/lockdown/revoked block signing.

The gaps are about **which profile** a caller may act as — not about the signing crypto or the SE boundary.

## Remediation plan

See [`findings.md`](findings.md) for the per-finding wave table. Order: **Wave 1 (AC-01, RP-01)** + **Wave 2 (AC-02)** before any release (parallelizable); **Wave 3 (AC-03, AC-04)** and **Wave 4 (DO-01)** independent. Write a regression PoC per wave that flips green on the fix, Criticals first.

## Dismissed (sample rationale)

18 candidates were refuted, including: non-constant-time bearer compare (local loopback + high-entropy token → not practically exploitable; noted, not filed), the path-binding being defeatable by symlink (rejected — `standardizedFileURL` resolves), and several "missing validation" claims where the service already fails closed. Full dismissal set is in the workflow transcript.

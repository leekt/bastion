import Combine
import Foundation

// Lightweight RPC health monitor.
//
// Pings each configured chain's RPC with eth_blockNumber on a slow interval
// (60s) and records latency + status. Surfaces in App Preferences and gates
// the menu bar's "policy status" banner. Stays in-process, no Keychain.

enum RPCStatus: String, Sendable, Codable {
    case unknown, ok, warn, bad
}

struct RPCHealthSample: Sendable, Hashable {
    let chainId: Int
    let status: RPCStatus
    let latencyMs: Int?
    let error: String?
    let probedAt: Date
}

@MainActor
@Observable
final class RPCHealthMonitor {
    static let shared = RPCHealthMonitor()
    nonisolated static let monitoringInterval: Duration = .seconds(60)
    private(set) var samples: [Int: RPCHealthSample] = [:]
    private(set) var isProbing = false
    private var probeTask: Task<Void, Never>?

    private init() {}

    /// Starts a background loop that probes every 60 seconds. Idempotent.
    func startMonitoring() {
        guard probeTask == nil else { return }
        probeTask = Task { [weak self] in
            await Self.runScheduledProbes {
                await self?.probeOnce()
            }
        }
    }

    func stopMonitoring() {
        probeTask?.cancel()
        probeTask = nil
    }

    /// Triggers an immediate probe on demand (e.g. when the user opens
    /// Settings → App preferences). No-op if a probe is already in flight.
    func probeNow() {
        guard !isProbing else { return }
        Task { await probeOnce() }
    }

    @discardableResult
    func probe(
        preferences: BundlerPreferences,
        session: URLSession = .shared
    ) async -> [Int: RPCHealthSample] {
        guard !isProbing else { return samples }
        isProbing = true
        defer { isProbing = false }

        var collected: [Int: RPCHealthSample] = [:]
        for entry in preferences.chainRPCs {
            let sample = await probe(chainId: entry.chainId, url: entry.rpcURL, session: session)
            samples[entry.chainId] = sample
            collected[entry.chainId] = sample
        }
        return collected
    }

    nonisolated static func runScheduledProbes(
        interval: Duration = monitoringInterval,
        sleep: (Duration) async throws -> Void = { interval in
            try await Task.sleep(for: interval)
        },
        probe: () async -> Void
    ) async {
        await probe()
        while !Task.isCancelled {
            do {
                try await sleep(interval)
            } catch {
                break
            }
            guard !Task.isCancelled else {
                break
            }
            await probe()
        }
    }

    private func probeOnce() async {
        let preferences = RuleEngine.shared.config.bundlerPreferences
        await probe(preferences: preferences)
    }

    /// Reject responses larger than this — a misconfigured or hostile RPC
    /// must not be able to balloon Bastion's memory through repeated probes.
    /// 64 KiB is plenty for any sane eth_blockNumber response.
    private static let maxResponseBytes = 64 * 1024

    private func probe(
        chainId: Int,
        url: String,
        session: URLSession = .shared
    ) async -> RPCHealthSample {
        guard let endpoint = URL(string: url),
              let scheme = endpoint.scheme?.lowercased(),
              scheme == "http" || scheme == "https" else {
            return RPCHealthSample(chainId: chainId, status: .bad, latencyMs: nil, error: "Invalid URL", probedAt: Date())
        }
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.timeoutInterval = 5
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = #"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#.data(using: .utf8)
        let start = Date()
        do {
            let (data, response) = try await session.data(for: req)
            let latencyMs = Int(Date().timeIntervalSince(start) * 1000)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return RPCHealthSample(chainId: chainId, status: .bad, latencyMs: latencyMs,
                                       error: "HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)",
                                       probedAt: Date())
            }
            // Bound response size to keep a hostile RPC from filling memory.
            guard data.count <= Self.maxResponseBytes else {
                return RPCHealthSample(chainId: chainId, status: .bad, latencyMs: latencyMs,
                                       error: "Response exceeded \(Self.maxResponseBytes) bytes",
                                       probedAt: Date())
            }
            // Parse a minimal {"jsonrpc":"2.0","id":1,"result":"0x..."}
            guard
                let json = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                json["result"] is String
            else {
                return RPCHealthSample(chainId: chainId, status: .warn, latencyMs: latencyMs, error: "No result", probedAt: Date())
            }
            let status: RPCStatus = latencyMs < 500 ? .ok : (latencyMs < 1500 ? .warn : .bad)
            return RPCHealthSample(chainId: chainId, status: status, latencyMs: latencyMs, error: nil, probedAt: Date())
        } catch {
            return RPCHealthSample(chainId: chainId, status: .bad, latencyMs: nil, error: error.localizedDescription, probedAt: Date())
        }
    }
}

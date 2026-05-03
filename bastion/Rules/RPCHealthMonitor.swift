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
    private(set) var samples: [Int: RPCHealthSample] = [:]
    private var probeTask: Task<Void, Never>?

    private init() {}

    /// Starts a background loop that probes every 60 seconds. Idempotent.
    func startMonitoring() {
        guard probeTask == nil else { return }
        probeTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.probeOnce()
                try? await Task.sleep(for: .seconds(60))
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
        Task { await probeOnce() }
    }

    private func probeOnce() async {
        let preferences = RuleEngine.shared.config.bundlerPreferences
        for entry in preferences.chainRPCs {
            let sample = await probe(chainId: entry.chainId, url: entry.rpcURL)
            samples[entry.chainId] = sample
        }
    }

    private func probe(chainId: Int, url: String) async -> RPCHealthSample {
        guard let endpoint = URL(string: url) else {
            return RPCHealthSample(chainId: chainId, status: .bad, latencyMs: nil, error: "Invalid URL", probedAt: Date())
        }
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.timeoutInterval = 5
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = #"{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}"#.data(using: .utf8)
        let start = Date()
        do {
            let (data, response) = try await URLSession.shared.data(for: req)
            let latencyMs = Int(Date().timeIntervalSince(start) * 1000)
            guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
                return RPCHealthSample(chainId: chainId, status: .bad, latencyMs: latencyMs,
                                       error: "HTTP \((response as? HTTPURLResponse)?.statusCode ?? -1)",
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

import Foundation

final class RuleEngine {
    static let shared = RuleEngine()

    private let keychain: KeychainBackend
    let stateStore: StateStore
    private let authManager = AuthManager.shared
    private let auditLog = AuditLog.shared

    private nonisolated static let configAccount = "config"

    private(set) var config: BastionConfig = .default
    private(set) var configLoaded = false

    private init() {
        self.keychain = SystemKeychainBackend()
        self.stateStore = .shared
    }

    // For testing
    init(keychain: KeychainBackend) {
        self.keychain = keychain
        self.stateStore = StateStore(keychain: keychain)
    }

    // MARK: - Config Management

    nonisolated func loadConfig() -> BastionConfig {
        guard let data = keychain.read(account: Self.configAccount),
              let config = try? JSONDecoder().decode(BastionConfig.self, from: data) else {
            return .default
        }
        return config
    }

    nonisolated func saveConfig(_ newConfig: BastionConfig) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(newConfig)
        keychain.write(account: Self.configAccount, data: data)
    }

    func loadConfigOnStartup() {
        config = loadConfig()
        configLoaded = true
    }

    func updateConfig(_ newConfig: BastionConfig) async throws {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to update Bastion rules"
        )
        try saveConfig(newConfig)
        config = newConfig
        configLoaded = true
    }

    // MARK: - Validation

    enum ValidationResult {
        case allowed
        case denied(reasons: [String])
    }

    /// Validates a signing operation against all configured rules.
    nonisolated func validate(_ request: SignRequest, config: BastionConfig) -> ValidationResult {
        guard config.rules.enabled else {
            return .allowed
        }

        var reasons: [String] = []

        // 0. Client allowlist
        if let allowedClients = config.rules.allowedClients, !allowedClients.isEmpty {
            if let clientId = request.clientBundleId {
                let allowed = allowedClients.contains { $0.bundleId == clientId }
                if !allowed {
                    reasons.append("Client \(clientId) not in allowlist")
                }
            } else {
                reasons.append("Unknown client — allowlist is configured but client identity unavailable")
            }
        }

        // 1. Allowed hours
        if let hours = config.rules.allowedHours {
            let calendar = Calendar.current
            let hour = calendar.component(.hour, from: request.timestamp)
            let inRange: Bool
            if hours.start <= hours.end {
                inRange = hour >= hours.start && hour < hours.end
            } else {
                inRange = hour >= hours.start || hour < hours.end
            }
            if !inRange {
                reasons.append("Outside allowed hours (\(hours.start):00 - \(hours.end):00)")
            }
        }

        // 2. Chain ID check
        if let allowedChains = config.rules.allowedChains,
           let chainId = request.operation.chainId {
            if !allowedChains.contains(chainId) {
                reasons.append("Chain \(ChainConfig.name(for: chainId)) (\(chainId)) not allowed")
            }
        }

        // 3. Target check (direct `to` address filtering)
        if let allowedTargets = config.rules.allowedTargets,
           let chainId = request.operation.chainId,
           let target = request.operation.targetAddress {
            let chainKey = String(chainId)
            if let chainTargets = allowedTargets[chainKey] {
                let normalizedTarget = target.lowercased()
                let allowed = chainTargets.contains { $0.lowercased() == normalizedTarget }
                if !allowed {
                    let short = "\(target.prefix(10))..."
                    reasons.append("Target \(short) not in allowlist for chain \(chainId)")
                }
            }
            // If chain has no target list, all targets are allowed on that chain
        }

        // 4. Rate limit checks
        for rule in config.rules.rateLimits {
            let count = stateStore.rateLimitCount(ruleId: rule.id, windowSeconds: rule.windowSeconds)
            if count >= rule.maxRequests {
                reasons.append("Rate limit exceeded: \(rule.displayDescription) (\(count)/\(rule.maxRequests))")
            }
        }

        // 5. Spending limit checks (ETH value for transactions)
        if let ethValue = request.operation.ethValue, ethValue != "0" {
            for rule in config.rules.spendingLimits {
                if case .eth = rule.token {
                    let spent = stateStore.spentAmount(ruleId: rule.id, windowSeconds: rule.windowSeconds)
                    let allowance = UInt128(rule.allowance) ?? 0
                    let txValue = UInt128(ethValue) ?? 0
                    if spent + txValue > allowance {
                        reasons.append("ETH spending limit exceeded: \(rule.displayDescription)")
                    }
                }
            }
        }

        // TODO: ERC-20 spending limit checks require parsing calldata
        // (transfer/approve selectors) — will be added with ABI decoding

        if reasons.isEmpty {
            return .allowed
        }
        return .denied(reasons: reasons)
    }

    /// Records state after a successful sign (increment counters, track spending).
    nonisolated func recordSuccess(request: SignRequest, config: BastionConfig) {
        // Record rate limit entries
        for rule in config.rules.rateLimits {
            stateStore.recordRequest(ruleId: rule.id, windowSeconds: rule.windowSeconds)
        }

        // Record ETH spending
        if let ethValue = request.operation.ethValue, ethValue != "0" {
            for rule in config.rules.spendingLimits {
                if case .eth = rule.token {
                    stateStore.recordSpend(ruleId: rule.id, amount: ethValue, windowSeconds: rule.windowSeconds)
                }
            }
        }
    }
}

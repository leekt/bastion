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

    private enum OperationInspection {
        case notApplicable
        case known(targets: [String], spending: [SpendObservation])
        case opaque(String)
    }

    private struct SpendObservation {
        let token: TokenIdentifier
        let amount: String
    }

    private enum SpendEvaluation {
        case noMatch
        case amount(UInt128)
        case unsupportedAmount
    }

    /// Validates a signing operation against all configured rules.
    nonisolated func validate(_ request: SignRequest, config: BastionConfig) -> ValidationResult {
        guard config.rules.enabled else {
            return .allowed
        }

        var reasons: [String] = []
        let inspection = inspect(request.operation)

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

        // 3. Target check (verifying contract or decoded inner call targets)
        if let allowedTargets = config.rules.allowedTargets,
           let chainId = request.operation.chainId {
            validateTargets(
                inspection: inspection,
                allowedTargets: allowedTargets,
                chainId: chainId,
                reasons: &reasons
            )
        }

        // 4. Rate limit checks
        for rule in config.rules.rateLimits {
            let count = stateStore.rateLimitCount(ruleId: rule.id, windowSeconds: rule.windowSeconds)
            if count >= rule.maxRequests {
                reasons.append("Rate limit exceeded: \(rule.displayDescription) (\(count)/\(rule.maxRequests))")
            }
        }

        // 5. Spending limit checks (native ETH + direct ERC-20 transfers/approvals)
        validateSpendingLimits(
            inspection: inspection,
            rules: config.rules.spendingLimits,
            reasons: &reasons
        )

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

        guard case .known(_, let observations) = inspect(request.operation) else {
            return
        }

        for rule in config.rules.spendingLimits {
            switch matchedSpendAmount(for: rule, observations: observations) {
            case .amount(let amount) where amount > 0:
                stateStore.recordSpend(
                    ruleId: rule.id,
                    amount: String(amount),
                    windowSeconds: rule.windowSeconds
                )
            default:
                continue
            }
        }
    }

    private func inspect(_ operation: SigningOperation) -> OperationInspection {
        switch operation {
        case .message:
            return .notApplicable
        case .typedData(let data):
            if let verifyingContract = data.domain.verifyingContract {
                return .known(targets: [verifyingContract], spending: [])
            }
            return .known(targets: [], spending: [])
        case .userOperation(let op):
            switch CalldataDecoder.inspect(op) {
            case .decoded(let executions):
                return .known(
                    targets: executions.map(\.to),
                    spending: spendObservations(from: executions, chainId: op.chainId)
                )
            case .opaque(let reason):
                return .opaque(reason)
            }
        }
    }

    private func spendObservations(
        from executions: [CalldataDecoder.DecodedExecution],
        chainId: Int
    ) -> [SpendObservation] {
        var observations: [SpendObservation] = []

        for execution in executions {
            if execution.value != "0" {
                observations.append(SpendObservation(token: .eth, amount: execution.value))
            }

            if let tokenOperation = execution.tokenOperation {
                let token: TokenIdentifier
                if let usdcAddress = USDCAddresses.address(for: chainId),
                   usdcAddress.caseInsensitiveCompare(execution.to) == .orderedSame {
                    token = .usdc
                } else {
                    token = .erc20(address: execution.to, chainId: chainId)
                }
                observations.append(SpendObservation(token: token, amount: tokenOperation.amount))
            }
        }

        return observations
    }

    private func validateTargets(
        inspection: OperationInspection,
        allowedTargets: [String: [String]],
        chainId: Int,
        reasons: inout [String]
    ) {
        let chainKey = String(chainId)
        guard let chainTargets = allowedTargets[chainKey], !chainTargets.isEmpty else {
            return
        }

        let normalizedAllowed = Set(chainTargets.map(normalizedAddress))

        switch inspection {
        case .opaque(let reason):
            reasons.append("Unable to inspect targets for chain \(chainId): \(reason)")
        case .notApplicable:
            reasons.append("No inspectable target found for chain \(chainId)")
        case .known(let targets, _):
            let normalizedTargets = Set(targets.map(normalizedAddress))
            guard !normalizedTargets.isEmpty else {
                reasons.append("No inspectable target found for chain \(chainId)")
                return
            }

            for target in normalizedTargets where !normalizedAllowed.contains(target) {
                reasons.append("Target \(shortAddress(target)) not in allowlist for chain \(chainId)")
            }
        }
    }

    private func validateSpendingLimits(
        inspection: OperationInspection,
        rules: [SpendingLimitRule],
        reasons: inout [String]
    ) {
        guard !rules.isEmpty else { return }

        switch inspection {
        case .opaque(let reason):
            reasons.append("Unable to inspect UserOperation spending: \(reason)")
        case .notApplicable:
            return
        case .known(_, let observations):
            for rule in rules {
                switch matchedSpendAmount(for: rule, observations: observations) {
                case .noMatch:
                    continue
                case .unsupportedAmount:
                    reasons.append("Unable to safely evaluate \(rule.token.displayName) amount for spending limit")
                case .amount(let pendingSpend):
                    guard pendingSpend > 0 else { continue }
                    guard let allowance = UInt128(rule.allowance) else {
                        reasons.append("Invalid allowance configured for \(rule.token.displayName)")
                        continue
                    }

                    let spent = stateStore.spentAmount(ruleId: rule.id, windowSeconds: rule.windowSeconds)
                    let (projectedSpend, overflow) = spent.addingReportingOverflow(pendingSpend)
                    if overflow || projectedSpend > allowance {
                        reasons.append("\(rule.token.displayName) spending limit exceeded: \(rule.displayDescription)")
                    }
                }
            }
        }
    }

    private func matchedSpendAmount(
        for rule: SpendingLimitRule,
        observations: [SpendObservation]
    ) -> SpendEvaluation {
        var total: UInt128 = 0
        var sawMatch = false

        for observation in observations where matches(rule.token, observation.token) {
            sawMatch = true
            guard let amount = UInt128(observation.amount) else {
                return .unsupportedAmount
            }
            let (newTotal, overflow) = total.addingReportingOverflow(amount)
            if overflow {
                return .unsupportedAmount
            }
            total = newTotal
        }

        return sawMatch ? .amount(total) : .noMatch
    }

    private func matches(_ ruleToken: TokenIdentifier, _ observedToken: TokenIdentifier) -> Bool {
        switch (ruleToken, observedToken) {
        case (.eth, .eth), (.usdc, .usdc):
            return true
        case let (.erc20(ruleAddress, ruleChainId), .erc20(observedAddress, observedChainId)):
            return ruleChainId == observedChainId &&
                normalizedAddress(ruleAddress) == normalizedAddress(observedAddress)
        default:
            return false
        }
    }

    private func normalizedAddress(_ address: String) -> String {
        address.lowercased()
    }

    private func shortAddress(_ address: String) -> String {
        let normalized = normalizedAddress(address)
        guard normalized.count > 12 else { return normalized }
        return "\(normalized.prefix(10))..."
    }
}

import Foundation

final class RuleEngine {
    static let shared = RuleEngine()

    private let keychain: KeychainBackend
    private let authManager = AuthManager.shared
    private let auditLog = AuditLog.shared

    private nonisolated static let configAccount = "config"

    private(set) var config: BastionConfig = .default
    private(set) var configLoaded = false

    private init() {
        self.keychain = SystemKeychainBackend()
    }

    // For testing
    init(keychain: KeychainBackend) {
        self.keychain = keychain
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

    /// Updates config after biometric authentication.
    /// Biometric auth is required since Keychain alone doesn't gate writes with userPresence.
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

    nonisolated func validate(_ request: SignRequest, config: BastionConfig) -> ValidationResult {
        guard config.rules.enabled else {
            return .allowed
        }

        var reasons: [String] = []

        // Check allowed hours
        if let hours = config.rules.allowedHours {
            let calendar = Calendar.current
            let hour = calendar.component(.hour, from: request.timestamp)
            let inRange: Bool
            if hours.start <= hours.end {
                inRange = hour >= hours.start && hour < hours.end
            } else {
                // Wraps midnight (e.g., 22 to 6)
                inRange = hour >= hours.start || hour < hours.end
            }
            if !inRange {
                reasons.append("Outside allowed hours (\(hours.start):00 - \(hours.end):00)")
            }
        }

        // Check max transactions per hour
        if let maxPerHour = config.rules.maxTxPerHour {
            let countThisHour = AuditLog.shared.totalCountToday(type: .signSuccess)
            if countThisHour >= maxPerHour {
                reasons.append("Hourly transaction limit reached (\(maxPerHour))")
            }
        }

        if reasons.isEmpty {
            return .allowed
        }
        return .denied(reasons: reasons)
    }
}

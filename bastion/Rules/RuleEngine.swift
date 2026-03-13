import Foundation

final class RuleEngine {
    static let shared = RuleEngine()

    private let configURL: URL
    private let seManager = SecureEnclaveManager.shared
    private let auditLog = AuditLog.shared

    private(set) var config: BastionConfig = .default
    private(set) var configLoaded = false

    private init() {
        let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let bastionDir = appSupport.appendingPathComponent("Bastion")
        if !FileManager.default.fileExists(atPath: bastionDir.path) {
            try? FileManager.default.createDirectory(at: bastionDir, withIntermediateDirectories: true)
        }
        self.configURL = bastionDir.appendingPathComponent("config.enc")
    }

    // MARK: - Config Management

    nonisolated func loadConfig() throws -> BastionConfig {
        guard FileManager.default.fileExists(atPath: configURL.path) else {
            return .default
        }

        let encrypted = try Data(contentsOf: configURL)
        let plaintext = try seManager.decryptConfig(encrypted)
        let decoder = JSONDecoder()
        return try decoder.decode(BastionConfig.self, from: plaintext)
    }

    nonisolated func saveConfig(_ newConfig: BastionConfig) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let jsonData = try encoder.encode(newConfig)
        let encrypted = try seManager.encryptConfig(jsonData)
        try encrypted.write(to: configURL, options: .atomic)
    }

    func loadConfigOnStartup() {
        do {
            config = try loadConfig()
            configLoaded = true
        } catch {
            // If config can't be loaded (first run or auth declined), use defaults
            config = .default
            configLoaded = false
        }
    }

    func updateConfig(_ newConfig: BastionConfig) throws {
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

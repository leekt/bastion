import Foundation
import LocalAuthentication

// MARK: - Errors

nonisolated enum BastionError: Int, Error, CustomStringConvertible, Sendable {
    case keyCreationFailed = 1
    case keyNotFound = 2
    case signingFailed = 3
    case authFailed = 4
    case userDenied = 5
    case ruleViolation = 6
    case timeout = 9
    case appNotRunning = 10
    case invalidInput = 11

    var description: String {
        switch self {
        case .keyCreationFailed: return "Failed to create Secure Enclave key"
        case .keyNotFound: return "Key not found in Secure Enclave"
        case .signingFailed: return "Signing operation failed"
        case .authFailed: return "Authentication failed"
        case .userDenied: return "User denied the signing request"
        case .ruleViolation: return "Rule violation"
        case .timeout: return "Request timed out"
        case .appNotRunning: return "Bastion app is not running"
        case .invalidInput: return "Invalid input data"
        }
    }

    var nsError: NSError {
        NSError(domain: "com.bastion.error", code: rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

// MARK: - Response Types

nonisolated struct SignResponse: Codable, Sendable {
    let pubkeyX: String
    let pubkeyY: String
    let r: String
    let s: String
}

nonisolated struct PublicKeyResponse: Codable, Sendable {
    let x: String
    let y: String
}

nonisolated struct RulesResponse: Codable, Sendable {
    let authPolicy: String
    let rules: RuleConfig
}

nonisolated struct StateResponse: Codable, Sendable {
    let rateLimits: [RateLimitStatus]
    let spendingLimits: [SpendingLimitStatus]
}

nonisolated struct RateLimitStatus: Codable, Sendable {
    let maxRequests: Int
    let windowSeconds: Int
    let currentCount: Int
    let remaining: Int
    let windowResetsAt: String?
}

nonisolated struct SpendingLimitStatus: Codable, Sendable {
    let token: String
    let allowance: String
    let spent: String
    let remaining: String
    let windowSeconds: Int?
    let windowResetsAt: String?
}

// MARK: - Rule Config

nonisolated struct RuleConfig: Codable, Sendable {
    var enabled: Bool
    var requireExplicitApproval: Bool
    var allowedHours: AllowedHours?
    var allowedChains: [Int]?
    var allowedTargets: [String: [String]]?   // chainId string -> [address]
    var allowedClients: [AllowedClient]?
    var rateLimits: [RateLimitRule]
    var spendingLimits: [SpendingLimitRule]

    static let `default` = RuleConfig(
        enabled: true,
        requireExplicitApproval: false,
        allowedHours: nil,
        allowedChains: nil,
        allowedTargets: nil,
        allowedClients: nil,
        rateLimits: [],
        spendingLimits: []
    )
}

/// Identifies an XPC client allowed to connect.
/// Clients are matched by bundle identifier extracted from their code signature.
nonisolated struct AllowedClient: Codable, Sendable, Identifiable, Hashable {
    let id: String          // unique rule ID
    let bundleId: String    // e.g. "com.bastion.cli", "com.myagent.app"
    let label: String?      // human-readable name for UI display

    var displayDescription: String {
        label ?? bundleId
    }
}

nonisolated struct AllowedHours: Codable, Sendable {
    let start: Int
    let end: Int
}

// MARK: - Rate Limit Rule

/// Time-windowed request counter.
/// Example: maxRequests=10, windowSeconds=3600 → max 10 requests per hour.
nonisolated struct RateLimitRule: Codable, Sendable, Identifiable {
    let id: String
    let maxRequests: Int
    let windowSeconds: Int

    var displayDescription: String {
        let window = Self.formatWindow(windowSeconds)
        return "\(maxRequests) requests per \(window)"
    }

    static func formatWindow(_ seconds: Int) -> String {
        switch seconds {
        case 60: return "minute"
        case 3600: return "hour"
        case 86400: return "day"
        case 604800: return "week"
        default:
            if seconds < 3600 { return "\(seconds / 60) minutes" }
            if seconds < 86400 { return "\(seconds / 3600) hours" }
            return "\(seconds / 86400) days"
        }
    }
}

// MARK: - Spending Limit Rule

/// Per-token spending allowance with optional time window reset.
/// Example: token=.eth, allowance="1000000000000000000" (1 ETH), windowSeconds=86400 → 1 ETH per day.
/// If windowSeconds is nil, the allowance is lifetime (never resets without master key).
nonisolated struct SpendingLimitRule: Codable, Sendable, Identifiable {
    let id: String
    let token: TokenIdentifier
    let allowance: String       // smallest unit (wei for ETH, 6 decimals for USDC)
    let windowSeconds: Int?     // nil = lifetime, 86400 = daily reset

    var displayDescription: String {
        let amount = formatAmount()
        let window = windowSeconds.map { RateLimitRule.formatWindow($0) } ?? "lifetime"
        return "\(amount) \(token.displayName) per \(window)"
    }

    private func formatAmount() -> String {
        guard let raw = UInt128(allowance) else { return allowance }
        let decimals = token.decimals
        let divisor = pow(10.0, Double(decimals))
        let display = Double(raw) / divisor
        if display == display.rounded() {
            return String(format: "%.0f", display)
        }
        return String(format: "%.4f", display)
    }
}

// MARK: - Auth Policy

nonisolated enum AuthPolicy: String, Codable, CaseIterable, Sendable {
    case open
    case passcode
    case biometric
    case biometricOrPasscode

    var displayName: String {
        switch self {
        case .open: return "Open (No Auth)"
        case .passcode: return "Passcode Only"
        case .biometric: return "Biometric Only"
        case .biometricOrPasscode: return "Biometric or Passcode"
        }
    }

    var laPolicy: LAPolicy? {
        switch self {
        case .open: return nil
        case .passcode: return .deviceOwnerAuthentication
        case .biometric: return .deviceOwnerAuthenticationWithBiometrics
        case .biometricOrPasscode: return .deviceOwnerAuthentication
        }
    }

    var accessControlFlags: SecAccessControlCreateFlags {
        switch self {
        case .open: return .privateKeyUsage
        case .passcode: return [.privateKeyUsage, .devicePasscode]
        case .biometric: return [.privateKeyUsage, .biometryCurrentSet]
        case .biometricOrPasscode: return [.privateKeyUsage, .userPresence]
        }
    }
}

nonisolated struct BastionConfig: Codable, Sendable {
    var version: Int = 2
    var authPolicy: AuthPolicy
    var rules: RuleConfig

    static let `default` = BastionConfig(
        authPolicy: .open,
        rules: .default
    )
}

// MARK: - Sign Request (internal)

nonisolated struct SignRequest: Sendable {
    let operation: SigningOperation
    let requestID: String
    let timestamp: Date
    let clientBundleId: String?  // bundle ID of the XPC client, nil if unknown

    /// The 32-byte hash to be signed by the Secure Enclave.
    /// Each operation type produces its own Ethereum-standard hash.
    var data: Data {
        switch operation {
        case .message(let text):
            if text.hasPrefix("0x"), let rawData = Data(hexString: text) {
                return EthHashing.personalMessageHash(data: rawData)
            }
            return EthHashing.personalMessageHash(text)
        case .typedData(let typed):
            return EthHashing.typedDataHash(typed)
        case .userOperation(let op):
            return EthHashing.userOperationHash(op)
        }
    }
}

nonisolated extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        var hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        if hex.count.isMultiple(of: 2) == false {
            hex = "0" + hex
        }
        let len = hex.count / 2
        var data = Data(capacity: len)
        var index = hex.startIndex
        for _ in 0..<len {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}

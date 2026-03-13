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

// MARK: - Rule Config

nonisolated struct RuleConfig: Codable, Sendable {
    var enabled: Bool
    var requireExplicitApproval: Bool
    var maxAmountPerTx: String?
    var dailyLimit: String?
    var whitelistOnly: Bool
    var whitelist: [String]
    var allowedHours: AllowedHours?
    var maxTxPerHour: Int?
    var maxTxPerDayWithoutAuth: Int?

    static let `default` = RuleConfig(
        enabled: true,
        requireExplicitApproval: false,
        maxAmountPerTx: nil,
        dailyLimit: nil,
        whitelistOnly: false,
        whitelist: [],
        allowedHours: nil,
        maxTxPerHour: nil,
        maxTxPerDayWithoutAuth: nil
    )
}

nonisolated struct AllowedHours: Codable, Sendable {
    let start: Int
    let end: Int
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
    var version: Int = 1
    var authPolicy: AuthPolicy
    var rules: RuleConfig

    static let `default` = BastionConfig(
        authPolicy: .open,
        rules: .default
    )
    // NOTE: Default is .open auth with no rate limit.
    // Configure via Rules Settings to set maxTxPerDayWithoutAuth and other rules.
}

nonisolated struct SignRequest: Sendable {
    let data: Data
    let requestID: String
    let timestamp: Date
}

nonisolated extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}

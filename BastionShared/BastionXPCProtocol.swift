import Foundation

@objc protocol BastionXPCProtocol {
    func sign(
        data: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getPublicKey(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func ping(
        withReply reply: @escaping (Bool) -> Void
    )

    func getRules(
        withReply reply: @escaping (Data?, Error?) -> Void
    )
}

let xpcServiceName = "com.bastion.xpc"

enum BastionError: Int, Error, CustomStringConvertible {
    case keyCreationFailed = 1
    case keyNotFound = 2
    case signingFailed = 3
    case authFailed = 4
    case userDenied = 5
    case ruleViolation = 6
    case configCorrupted = 7
    case configEncryptionFailed = 8
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
        case .configCorrupted: return "Configuration file is corrupted or tampered"
        case .configEncryptionFailed: return "Configuration encryption/decryption failed"
        case .timeout: return "Request timed out"
        case .appNotRunning: return "Bastion app is not running"
        case .invalidInput: return "Invalid input data"
        }
    }

    var nsError: NSError {
        NSError(domain: "com.bastion.error", code: rawValue, userInfo: [NSLocalizedDescriptionKey: description])
    }
}

struct SignResponse: Codable {
    let pubkeyX: String
    let pubkeyY: String
    let r: String
    let s: String
}

struct PublicKeyResponse: Codable {
    let x: String
    let y: String
}

struct RulesResponse: Codable {
    let authPolicy: String
    let rules: RuleConfig
}

struct RuleConfig: Codable {
    var enabled: Bool
    var requireExplicitApproval: Bool
    var maxAmountPerTx: String?
    var dailyLimit: String?
    var whitelistOnly: Bool
    var whitelist: [String]
    var allowedHours: AllowedHours?
    var maxTxPerHour: Int?

    static let `default` = RuleConfig(
        enabled: true,
        requireExplicitApproval: true,
        maxAmountPerTx: nil,
        dailyLimit: nil,
        whitelistOnly: false,
        whitelist: [],
        allowedHours: nil,
        maxTxPerHour: nil
    )
}

struct AllowedHours: Codable {
    let start: Int
    let end: Int
}

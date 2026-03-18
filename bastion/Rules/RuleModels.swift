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
    let accountAddress: String?
    let clientBundleId: String?
    let submission: UserOperationSubmissionResponse?
}

nonisolated enum UserOperationSubmissionStatus: String, Codable, Sendable {
    case submitted = "submitted"
    case sendFailed = "send_failed"
}

nonisolated struct UserOperationSubmissionResponse: Codable, Sendable {
    let provider: String
    let status: UserOperationSubmissionStatus
    let userOpHash: String?
    let transactionHash: String?
    let error: String?
}

nonisolated struct PublicKeyResponse: Codable, Sendable {
    let x: String
    let y: String
    let accountAddress: String?
}

nonisolated struct ServiceInfoResponse: Codable, Sendable {
    let version: String
    let serviceRegistrationStatus: String
    let configCorrupted: Bool
}

nonisolated struct RulesResponse: Codable, Sendable {
    let authPolicy: String
    let globalAuthPolicy: String?
    let rules: RuleConfig
    let globalRules: RuleConfig
    let clientProfile: ClientProfileInfo?
    let accountAddress: String?
}

nonisolated struct StateResponse: Codable, Sendable {
    let rateLimits: [RateLimitStatus]
    let spendingLimits: [SpendingLimitStatus]
    let clientProfile: ClientProfileInfo?
    let accountAddress: String?
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
    var allowedSelectors: [String: [String]]? // address -> [4-byte hex selectors]
    var denySelectors: [String]?              // globally blocked selectors
    var allowedClients: [AllowedClient]?
    var rateLimits: [RateLimitRule]
    var spendingLimits: [SpendingLimitRule]
    var rawMessagePolicy: RawMessagePolicy
    var typedDataPolicy: TypedDataPolicy

    static let `default` = RuleConfig(
        enabled: true,
        requireExplicitApproval: false,
        allowedHours: nil,
        allowedChains: nil,
        allowedTargets: nil,
        allowedSelectors: nil,
        denySelectors: nil,
        allowedClients: nil,
        rateLimits: [],
        spendingLimits: [],
        rawMessagePolicy: .default,
        typedDataPolicy: .default
    )

    private enum CodingKeys: String, CodingKey {
        case enabled
        case requireExplicitApproval
        case allowedHours
        case allowedChains
        case allowedTargets
        case allowedSelectors
        case denySelectors
        case allowedClients
        case rateLimits
        case spendingLimits
        case rawMessagePolicy
        case typedDataPolicy
    }

    init(
        enabled: Bool,
        requireExplicitApproval: Bool,
        allowedHours: AllowedHours?,
        allowedChains: [Int]?,
        allowedTargets: [String: [String]]?,
        allowedSelectors: [String: [String]]? = nil,
        denySelectors: [String]? = nil,
        allowedClients: [AllowedClient]?,
        rateLimits: [RateLimitRule],
        spendingLimits: [SpendingLimitRule],
        rawMessagePolicy: RawMessagePolicy = .default,
        typedDataPolicy: TypedDataPolicy = .default
    ) {
        self.enabled = enabled
        self.requireExplicitApproval = requireExplicitApproval
        self.allowedHours = allowedHours
        self.allowedChains = allowedChains
        self.allowedTargets = allowedTargets
        self.allowedSelectors = allowedSelectors
        self.denySelectors = denySelectors
        self.allowedClients = allowedClients
        self.rateLimits = rateLimits
        self.spendingLimits = spendingLimits
        self.rawMessagePolicy = rawMessagePolicy
        self.typedDataPolicy = typedDataPolicy
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        requireExplicitApproval = try container.decodeIfPresent(Bool.self, forKey: .requireExplicitApproval) ?? false
        allowedHours = try container.decodeIfPresent(AllowedHours.self, forKey: .allowedHours)
        allowedChains = try container.decodeIfPresent([Int].self, forKey: .allowedChains)
        allowedTargets = try container.decodeIfPresent([String: [String]].self, forKey: .allowedTargets)
        allowedSelectors = try container.decodeIfPresent([String: [String]].self, forKey: .allowedSelectors)
        denySelectors = try container.decodeIfPresent([String].self, forKey: .denySelectors)
        allowedClients = try container.decodeIfPresent([AllowedClient].self, forKey: .allowedClients)
        rateLimits = try container.decodeIfPresent([RateLimitRule].self, forKey: .rateLimits) ?? []
        spendingLimits = try container.decodeIfPresent([SpendingLimitRule].self, forKey: .spendingLimits) ?? []
        rawMessagePolicy = try container.decodeIfPresent(RawMessagePolicy.self, forKey: .rawMessagePolicy) ?? .default
        typedDataPolicy = try container.decodeIfPresent(TypedDataPolicy.self, forKey: .typedDataPolicy) ?? .default
    }
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

nonisolated struct ClientProfile: Codable, Sendable, Identifiable {
    var id: String
    var bundleId: String
    var label: String?
    var authPolicy: AuthPolicy?
    var keyTag: String
    var rules: RuleConfig

    init(
        id: String = UUID().uuidString,
        bundleId: String,
        label: String? = nil,
        authPolicy: AuthPolicy? = nil,
        keyTag: String = ClientProfile.makeKeyTag(),
        rules: RuleConfig
    ) {
        self.id = id
        self.bundleId = bundleId
        self.label = label
        self.authPolicy = authPolicy
        self.keyTag = keyTag
        self.rules = rules
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case bundleId
        case label
        case authPolicy
        case keyTag
        case rules
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        bundleId = try container.decode(String.self, forKey: .bundleId)
        label = try container.decodeIfPresent(String.self, forKey: .label)
        authPolicy = try container.decodeIfPresent(AuthPolicy.self, forKey: .authPolicy)
        keyTag = try container.decodeIfPresent(String.self, forKey: .keyTag) ?? Self.makeKeyTag()
        rules = try container.decodeIfPresent(RuleConfig.self, forKey: .rules) ?? .default
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(bundleId, forKey: .bundleId)
        try container.encodeIfPresent(label, forKey: .label)
        try container.encodeIfPresent(authPolicy, forKey: .authPolicy)
        try container.encode(keyTag, forKey: .keyTag)
        try container.encode(rules, forKey: .rules)
    }

    static func makeKeyTag() -> String {
        "com.bastion.signingkey.client.\(UUID().uuidString.lowercased())"
    }

    var displayDescription: String {
        label ?? bundleId
    }
}

nonisolated struct ClientProfileInfo: Codable, Sendable, Identifiable {
    let id: String
    let bundleId: String
    let label: String?
    let authPolicy: String
    let keyTag: String
    let accountAddress: String?

    var displayDescription: String {
        label ?? bundleId
    }
}

nonisolated struct AllowedHours: Codable, Sendable {
    let start: Int
    let end: Int
}

nonisolated struct RawMessagePolicy: Codable, Sendable {
    /// Master toggle — when false, all message/rawBytes requests require explicit approval.
    var enabled: Bool
    /// Sub-rule — when false (and enabled=true), only EIP-191 personal messages are allowed;
    /// raw 32-byte signing requests are denied outright.
    var allowRawSigning: Bool

    static let `default` = RawMessagePolicy(enabled: true, allowRawSigning: false)

    init(enabled: Bool, allowRawSigning: Bool = false) {
        self.enabled = enabled
        self.allowRawSigning = allowRawSigning
    }

    private enum CodingKeys: CodingKey {
        case enabled, allowRawSigning
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try container.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        allowRawSigning = try container.decodeIfPresent(Bool.self, forKey: .allowRawSigning) ?? false
    }
}

nonisolated struct TypedDataPolicy: Codable, Sendable {
    var enabled: Bool
    var requireExplicitApproval: Bool
    var domainRules: [TypedDataDomainRule]
    var structRules: [TypedDataStructRule]

    static let `default` = TypedDataPolicy(
        enabled: true,
        requireExplicitApproval: false,
        domainRules: [],
        structRules: []
    )
}

nonisolated struct TypedDataDomainRule: Codable, Sendable, Identifiable {
    let id: String
    var label: String?
    var primaryType: String?
    var name: String?
    var version: String?
    var chainId: Int?
    var verifyingContract: String?

    var displayDescription: String {
        label ?? primaryType ?? name ?? "Domain Rule"
    }
}

nonisolated struct TypedDataStructRule: Codable, Sendable, Identifiable {
    let id: String
    var label: String?
    var primaryType: String
    var matcherJSON: String

    var displayDescription: String {
        label ?? primaryType
    }
}

nonisolated struct BundlerPreferences: Codable, Sendable {
    var zeroDevProjectId: String?
    var chainRPCs: [ChainRPCPreference]

    static let `default` = BundlerPreferences(
        zeroDevProjectId: nil,
        chainRPCs: []
    )
}

nonisolated struct ChainRPCPreference: Codable, Sendable, Identifiable {
    var chainId: Int
    var rpcURL: String

    var id: String {
        String(chainId)
    }
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
    var version: Int = 6
    var authPolicy: AuthPolicy
    var rules: RuleConfig
    var bundlerPreferences: BundlerPreferences
    var clientProfiles: [ClientProfile]

    // M-04: Default to biometricOrPasscode for production safety.
    // Prevents new installs from running with no auth.
    static let `default` = BastionConfig(
        authPolicy: .biometricOrPasscode,
        rules: .default,
        bundlerPreferences: .default,
        clientProfiles: []
    )

    init(
        version: Int = 6,
        authPolicy: AuthPolicy,
        rules: RuleConfig,
        bundlerPreferences: BundlerPreferences = .default,
        clientProfiles: [ClientProfile] = []
    ) {
        self.version = version
        self.authPolicy = authPolicy
        self.rules = rules
        self.bundlerPreferences = bundlerPreferences
        self.clientProfiles = clientProfiles
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case authPolicy
        case rules
        case bundlerPreferences
        case clientProfiles
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 4
        authPolicy = try container.decodeIfPresent(AuthPolicy.self, forKey: .authPolicy) ?? .open
        rules = try container.decodeIfPresent(RuleConfig.self, forKey: .rules) ?? .default
        bundlerPreferences = try container.decodeIfPresent(BundlerPreferences.self, forKey: .bundlerPreferences) ?? .default
        clientProfiles = try container.decodeIfPresent([ClientProfile].self, forKey: .clientProfiles) ?? []
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(authPolicy, forKey: .authPolicy)
        try container.encode(rules, forKey: .rules)
        try container.encode(bundlerPreferences, forKey: .bundlerPreferences)
        try container.encode(clientProfiles, forKey: .clientProfiles)
    }
}

// MARK: - Sign Request (internal)

nonisolated struct SignRequest: Sendable {
    let operation: SigningOperation
    let requestID: String
    let timestamp: Date
    let clientBundleId: String?  // bundle ID of the XPC client, nil if unknown
    let userOperationSubmission: UserOperationSubmissionRequest?

    init(
        operation: SigningOperation,
        requestID: String,
        timestamp: Date,
        clientBundleId: String?,
        userOperationSubmission: UserOperationSubmissionRequest? = nil
    ) {
        self.operation = operation
        self.requestID = requestID
        self.timestamp = timestamp
        self.clientBundleId = clientBundleId
        self.userOperationSubmission = userOperationSubmission
    }

    /// The 32-byte hash to be signed by the Secure Enclave.
    /// Each operation type produces its own Ethereum-standard hash.
    var data: Data {
        switch operation {
        case .message(let text):
            if text.hasPrefix("0x"), let rawData = Data(hexString: text) {
                return EthHashing.personalMessageHash(data: rawData)
            }
            return EthHashing.personalMessageHash(text)
        case .rawBytes(let bytes):
            // Signed directly — no Ethereum prefix applied.
            return bytes
        case .typedData(let typed):
            return EthHashing.typedDataHash(typed)
        case .userOperation(let op):
            return EthHashing.userOperationHash(op)
        }
    }

    var requiresUserOperationSubmission: Bool {
        userOperationSubmission != nil
    }
}

nonisolated enum ApprovalMode: Sendable {
    case policyReview
    case ruleOverride([String])
}

nonisolated struct ApprovalRequest: Sendable {
    let request: SignRequest
    let mode: ApprovalMode
    let clientContext: ClientSigningContext
}

nonisolated struct ClientSigningContext: Sendable {
    let bundleId: String?
    let profileId: String?
    let profileLabel: String?
    let authPolicy: AuthPolicy
    let keyTag: String
    let accountAddress: String?
    let rules: RuleConfig

    var displayName: String {
        profileLabel ?? bundleId ?? "Unknown client"
    }

    var shortBundleName: String {
        guard let bundleId, !bundleId.isEmpty else {
            return "Unknown"
        }
        return bundleId.split(separator: ".").last.map(String.init) ?? bundleId
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

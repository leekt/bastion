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

nonisolated struct ResetSigningKeysResponse: Codable, Sendable {
    let deletedKeyTags: [String]
    let requestedKeyTags: [String]
}

nonisolated struct RulesResponse: Codable, Sendable {
    let authPolicy: String
    let globalAuthPolicy: String?
    let rules: RuleConfig
    let globalRules: RuleConfig?
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
    /// When set, this client is a member of a wallet group and signs for the
    /// shared smart account via `membershipId`'s scoped validator key.
    /// When nil, the client uses its own `keyTag` (private wallet — default).
    var walletGroupId: String?
    /// Points to `AgentMembership.id` inside the referenced wallet group.
    /// Required whenever `walletGroupId` is set.
    var membershipId: String?

    init(
        id: String = UUID().uuidString,
        bundleId: String,
        label: String? = nil,
        authPolicy: AuthPolicy? = nil,
        keyTag: String = ClientProfile.makeKeyTag(),
        rules: RuleConfig,
        walletGroupId: String? = nil,
        membershipId: String? = nil
    ) {
        self.id = id
        self.bundleId = bundleId
        self.label = label
        self.authPolicy = authPolicy
        self.keyTag = keyTag
        self.rules = rules
        self.walletGroupId = walletGroupId
        self.membershipId = membershipId
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case bundleId
        case label
        case authPolicy
        case keyTag
        case rules
        case walletGroupId
        case membershipId
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        bundleId = try container.decode(String.self, forKey: .bundleId)
        label = try container.decodeIfPresent(String.self, forKey: .label)
        authPolicy = try container.decodeIfPresent(AuthPolicy.self, forKey: .authPolicy)
        keyTag = try container.decodeIfPresent(String.self, forKey: .keyTag) ?? Self.makeKeyTag()
        rules = try container.decodeIfPresent(RuleConfig.self, forKey: .rules) ?? .default
        walletGroupId = try container.decodeIfPresent(String.self, forKey: .walletGroupId)
        membershipId = try container.decodeIfPresent(String.self, forKey: .membershipId)
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(id, forKey: .id)
        try container.encode(bundleId, forKey: .bundleId)
        try container.encodeIfPresent(label, forKey: .label)
        try container.encodeIfPresent(authPolicy, forKey: .authPolicy)
        try container.encode(keyTag, forKey: .keyTag)
        try container.encode(rules, forKey: .rules)
        try container.encodeIfPresent(walletGroupId, forKey: .walletGroupId)
        try container.encodeIfPresent(membershipId, forKey: .membershipId)
    }

    static func makeKeyTag() -> String {
        "com.bastion.signingkey.client.\(UUID().uuidString.lowercased())"
    }

    var displayDescription: String {
        label ?? bundleId
    }

    /// True when this profile is a member of a wallet group.
    var isGroupMember: Bool {
        walletGroupId != nil && membershipId != nil
    }
}

// MARK: - Wallet Group

/// A shared smart account. The owner holds a sudo Secure Enclave key that
/// can install and revoke per-agent scoped validators. Every agent member
/// gets its OWN SE key — cryptographic isolation is preserved. The shared
/// quantity is the on-chain smart account address, not the signing key.
nonisolated struct WalletGroup: Codable, Sendable, Identifiable {
    let id: String
    var label: String
    /// Tag of the owner's SE key. Format:
    /// `com.bastion.walletgroup.<groupId>.owner`
    var ownerKeyTag: String
    /// Shared on-chain smart account address (derived from the owner
    /// validator's public key). Computed once at group creation.
    var accountAddress: String?
    /// Chains where this wallet is deployed / has installed validators.
    var chainIds: [Int]
    /// Rules that apply to every agent member in addition to their own
    /// scoped rules. Intersection semantics: both the group's rules and
    /// the agent's rules must pass. Spending limits defined here share a
    /// counter across all members because the rule ID is the same.
    var sharedRules: RuleConfig
    var members: [AgentMembership]
    var createdAt: Date

    init(
        id: String = UUID().uuidString,
        label: String,
        ownerKeyTag: String? = nil,
        accountAddress: String? = nil,
        chainIds: [Int] = [],
        sharedRules: RuleConfig = .default,
        members: [AgentMembership] = [],
        createdAt: Date = Date()
    ) {
        self.id = id
        self.label = label
        self.ownerKeyTag = ownerKeyTag ?? Self.makeOwnerKeyTag(groupId: id)
        self.accountAddress = accountAddress
        self.chainIds = chainIds
        self.sharedRules = sharedRules
        self.members = members
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case label
        case ownerKeyTag
        case accountAddress
        case chainIds
        case sharedRules
        case members
        case createdAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let decodedId = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        id = decodedId
        label = try container.decode(String.self, forKey: .label)
        ownerKeyTag = try container.decodeIfPresent(String.self, forKey: .ownerKeyTag)
            ?? Self.makeOwnerKeyTag(groupId: decodedId)
        accountAddress = try container.decodeIfPresent(String.self, forKey: .accountAddress)
        chainIds = try container.decodeIfPresent([Int].self, forKey: .chainIds) ?? []
        sharedRules = try container.decodeIfPresent(RuleConfig.self, forKey: .sharedRules) ?? .default
        members = try container.decodeIfPresent([AgentMembership].self, forKey: .members) ?? []
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
    }

    static func makeOwnerKeyTag(groupId: String) -> String {
        "com.bastion.walletgroup.\(groupId.lowercased()).owner"
    }

    static func makeAgentKeyTag(groupId: String, memberId: String) -> String {
        "com.bastion.walletgroup.\(groupId.lowercased()).agent.\(memberId.lowercased())"
    }

    func member(id memberId: String) -> AgentMembership? {
        members.first(where: { $0.id == memberId })
    }

    /// Members that are currently allowed to sign (not revoked).
    var activeMembers: [AgentMembership] {
        members.filter { !$0.installStatus.isRevoked }
    }
}

/// A single agent's scoped access to a wallet group. Each membership has
/// its own Secure Enclave key; the owner installs this key on-chain as a
/// permissioned validator module.
nonisolated struct AgentMembership: Codable, Sendable, Identifiable {
    let id: String
    var clientProfileId: String?
    var label: String?
    var keyTag: String
    /// Rules scoped to this single agent. Combined with the group's
    /// `sharedRules` via intersection — both must pass.
    var scopedRules: RuleConfig
    /// Address of the on-chain validator module bound to this membership,
    /// once installed. Nil while status is `.pending`.
    var validatorAddress: String?
    var installStatus: ValidatorInstallStatus
    var installedAt: Date?
    var revokedAt: Date?
    var createdAt: Date

    init(
        id: String = UUID().uuidString,
        clientProfileId: String? = nil,
        label: String? = nil,
        keyTag: String,
        scopedRules: RuleConfig = .default,
        validatorAddress: String? = nil,
        installStatus: ValidatorInstallStatus = .pending,
        installedAt: Date? = nil,
        revokedAt: Date? = nil,
        createdAt: Date = Date()
    ) {
        self.id = id
        self.clientProfileId = clientProfileId
        self.label = label
        self.keyTag = keyTag
        self.scopedRules = scopedRules
        self.validatorAddress = validatorAddress
        self.installStatus = installStatus
        self.installedAt = installedAt
        self.revokedAt = revokedAt
        self.createdAt = createdAt
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case clientProfileId
        case label
        case keyTag
        case scopedRules
        case validatorAddress
        case installStatus
        case installedAt
        case revokedAt
        case createdAt
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? UUID().uuidString
        clientProfileId = try container.decodeIfPresent(String.self, forKey: .clientProfileId)
        label = try container.decodeIfPresent(String.self, forKey: .label)
        keyTag = try container.decode(String.self, forKey: .keyTag)
        scopedRules = try container.decodeIfPresent(RuleConfig.self, forKey: .scopedRules) ?? .default
        validatorAddress = try container.decodeIfPresent(String.self, forKey: .validatorAddress)
        installStatus = try container.decodeIfPresent(ValidatorInstallStatus.self, forKey: .installStatus) ?? .pending
        installedAt = try container.decodeIfPresent(Date.self, forKey: .installedAt)
        revokedAt = try container.decodeIfPresent(Date.self, forKey: .revokedAt)
        createdAt = try container.decodeIfPresent(Date.self, forKey: .createdAt) ?? Date()
    }

    var displayDescription: String {
        label ?? keyTag
    }
}

/// Lifecycle of an agent's validator module relative to the on-chain
/// smart account. Bastion refuses to sign for agents in `.revoked` status
/// and signs for `.pending` only when the group is explicitly marked
/// off-chain-only (Phase 1 manual-install mode).
nonisolated enum ValidatorInstallStatus: Codable, Sendable, Equatable {
    case pending
    case installed(txHash: String)
    case revoked(txHash: String)

    var isRevoked: Bool {
        if case .revoked = self { return true }
        return false
    }

    var isInstalled: Bool {
        if case .installed = self { return true }
        return false
    }

    private enum CodingKeys: String, CodingKey {
        case state
        case txHash
    }

    private enum State: String, Codable {
        case pending
        case installed
        case revoked
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let state = try container.decode(State.self, forKey: .state)
        switch state {
        case .pending:
            self = .pending
        case .installed:
            let hash = try container.decode(String.self, forKey: .txHash)
            self = .installed(txHash: hash)
        case .revoked:
            let hash = try container.decode(String.self, forKey: .txHash)
            self = .revoked(txHash: hash)
        }
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        switch self {
        case .pending:
            try container.encode(State.pending, forKey: .state)
        case .installed(let hash):
            try container.encode(State.installed, forKey: .state)
            try container.encode(hash, forKey: .txHash)
        case .revoked(let hash):
            try container.encode(State.revoked, forKey: .state)
            try container.encode(hash, forKey: .txHash)
        }
    }
}

nonisolated struct ClientProfileInfo: Codable, Sendable, Identifiable {
    let id: String
    let bundleId: String
    let label: String?
    let authPolicy: String
    let keyTag: String
    let accountAddress: String?
    let walletGroupId: String?
    let membershipId: String?

    init(
        id: String,
        bundleId: String,
        label: String?,
        authPolicy: String,
        keyTag: String,
        accountAddress: String?,
        walletGroupId: String? = nil,
        membershipId: String? = nil
    ) {
        self.id = id
        self.bundleId = bundleId
        self.label = label
        self.authPolicy = authPolicy
        self.keyTag = keyTag
        self.accountAddress = accountAddress
        self.walletGroupId = walletGroupId
        self.membershipId = membershipId
    }

    private enum CodingKeys: String, CodingKey {
        case id, bundleId, label, authPolicy, keyTag, accountAddress, walletGroupId, membershipId
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        bundleId = try c.decode(String.self, forKey: .bundleId)
        label = try c.decodeIfPresent(String.self, forKey: .label)
        authPolicy = try c.decode(String.self, forKey: .authPolicy)
        keyTag = try c.decode(String.self, forKey: .keyTag)
        accountAddress = try c.decodeIfPresent(String.self, forKey: .accountAddress)
        walletGroupId = try c.decodeIfPresent(String.self, forKey: .walletGroupId)
        membershipId = try c.decodeIfPresent(String.self, forKey: .membershipId)
    }

    var displayDescription: String {
        label ?? bundleId
    }

    var isGroupMember: Bool {
        walletGroupId != nil && membershipId != nil
    }
}

// MARK: - Wallet Group XPC Requests/Responses

nonisolated struct CreateWalletGroupRequest: Codable, Sendable {
    let label: String
    let chainIds: [Int]
    let sharedRules: RuleConfig?
}

nonisolated struct AddAgentRequest: Codable, Sendable {
    let groupId: String
    let label: String?
    /// Optional pre-existing ClientProfile to bind this membership to.
    /// If nil, the caller is expected to call register afterwards.
    let clientProfileId: String?
    let scopedRules: RuleConfig?
}

nonisolated struct UpdateAgentScopeRequest: Codable, Sendable {
    let groupId: String
    let memberId: String
    let scopedRules: RuleConfig
}

nonisolated struct MarkInstalledRequest: Codable, Sendable {
    let groupId: String
    let memberId: String
    let txHash: String
    let validatorAddress: String?
}

nonisolated struct WalletGroupInfo: Codable, Sendable, Identifiable {
    let id: String
    let label: String
    let ownerKeyTag: String
    let accountAddress: String?
    let chainIds: [Int]
    let sharedRules: RuleConfig
    let members: [AgentMembershipInfo]
    let createdAt: String
    let memberCount: Int
    let activeMemberCount: Int
}

nonisolated struct AgentMembershipInfo: Codable, Sendable, Identifiable {
    let id: String
    let label: String?
    let keyTag: String
    let clientProfileId: String?
    let scopedRules: RuleConfig
    let validatorAddress: String?
    let installStatus: ValidatorInstallStatus
    let installedAt: String?
    let revokedAt: String?
}

nonisolated struct WalletGroupListResponse: Codable, Sendable {
    let groups: [WalletGroupInfo]
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

// MARK: - Audit Redaction

/// Controls how sensitive fields are redacted in the on-disk audit log.
nonisolated enum AuditRedactionLevel: String, Codable, CaseIterable, Sendable {
    /// No redaction — full fidelity (default).
    case none
    /// Payloads (raw message text, typed-data JSON, UserOp JSON) are removed.
    /// Detail strings containing addresses or amounts are replaced with "[REDACTED]".
    case redactPayloads
    /// Payloads, all detail strings, and the digest hex are replaced with "[REDACTED]".
    case redactAll
}

nonisolated struct BastionConfig: Codable, Sendable {
    var version: Int = 8
    var authPolicy: AuthPolicy
    var rules: RuleConfig
    var bundlerPreferences: BundlerPreferences
    var clientProfiles: [ClientProfile]
    var walletGroups: [WalletGroup]
    var auditRedactionLevel: AuditRedactionLevel

    // M-04: Default to biometricOrPasscode for production safety.
    // Prevents new installs from running with no auth.
    static let `default` = BastionConfig(
        authPolicy: .biometricOrPasscode,
        rules: .default,
        bundlerPreferences: .default,
        clientProfiles: [],
        walletGroups: [],
        auditRedactionLevel: .none
    )

    init(
        version: Int = 8,
        authPolicy: AuthPolicy,
        rules: RuleConfig,
        bundlerPreferences: BundlerPreferences = .default,
        clientProfiles: [ClientProfile] = [],
        walletGroups: [WalletGroup] = [],
        auditRedactionLevel: AuditRedactionLevel = .none
    ) {
        self.version = version
        self.authPolicy = authPolicy
        self.rules = rules
        self.bundlerPreferences = bundlerPreferences
        self.clientProfiles = clientProfiles
        self.walletGroups = walletGroups
        self.auditRedactionLevel = auditRedactionLevel
    }

    private enum CodingKeys: String, CodingKey {
        case version
        case authPolicy
        case rules
        case bundlerPreferences
        case clientProfiles
        case walletGroups
        case auditRedactionLevel
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        version = try container.decodeIfPresent(Int.self, forKey: .version) ?? 4
        // H-01: Default to biometricOrPasscode when the key is missing from stored JSON.
        // The previous default of .open silently downgraded security for configs saved
        // before authPolicy was introduced.
        authPolicy = try container.decodeIfPresent(AuthPolicy.self, forKey: .authPolicy) ?? .biometricOrPasscode
        rules = try container.decodeIfPresent(RuleConfig.self, forKey: .rules) ?? .default
        bundlerPreferences = try container.decodeIfPresent(BundlerPreferences.self, forKey: .bundlerPreferences) ?? .default
        clientProfiles = try container.decodeIfPresent([ClientProfile].self, forKey: .clientProfiles) ?? []
        // v7 → v8 migration: older configs simply have no walletGroups.
        walletGroups = try container.decodeIfPresent([WalletGroup].self, forKey: .walletGroups) ?? []
        auditRedactionLevel = try container.decodeIfPresent(AuditRedactionLevel.self, forKey: .auditRedactionLevel) ?? .none
    }

    func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(authPolicy, forKey: .authPolicy)
        try container.encode(rules, forKey: .rules)
        try container.encode(bundlerPreferences, forKey: .bundlerPreferences)
        try container.encode(clientProfiles, forKey: .clientProfiles)
        try container.encode(walletGroups, forKey: .walletGroups)
        try container.encode(auditRedactionLevel, forKey: .auditRedactionLevel)
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
    let preflightResult: PreflightResult?

    init(
        request: SignRequest,
        mode: ApprovalMode,
        clientContext: ClientSigningContext,
        preflightResult: PreflightResult? = nil
    ) {
        self.request = request
        self.mode = mode
        self.clientContext = clientContext
        self.preflightResult = preflightResult
    }
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

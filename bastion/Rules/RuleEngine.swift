import Foundation

final class RuleEngine {
    static let shared = RuleEngine()

    private let keychain: KeychainBackend
    let stateStore: StateStore
    private let authManager = AuthManager.shared
    private let auditLog = AuditLog.shared

    private nonisolated static let configAccount = "config"
    private nonisolated static let configBackupAccount = "config.premigration"

    private(set) var config: BastionConfig = .default
    private(set) var configLoaded = false
    /// True when keychain data existed but failed to decode — rules were reset to
    /// defaults. Surface this in the UI so the user knows why their rules disappeared.
    private(set) var configCorrupted = false

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

    private nonisolated func loadConfigRaw() -> (config: BastionConfig, corrupted: Bool) {
        guard let data = keychain.read(account: Self.configAccount) else {
            return (.default, false) // new install — no config yet
        }
        guard let decoded = try? JSONDecoder().decode(BastionConfig.self, from: data) else {
            return (.default, true) // data exists but unreadable — corruption
        }
        if decoded.version < 7, keychain.read(account: Self.configBackupAccount) == nil {
            keychain.write(account: Self.configBackupAccount, data: data)
        }
        return (normalizedConfig(migrateConfig(decoded)), false)
    }

    nonisolated func loadConfig() -> BastionConfig {
        loadConfigRaw().config
    }

    /// Returns true if a pre-migration config backup exists in the keychain.
    nonisolated func hasConfigBackup() -> Bool {
        keychain.read(account: Self.configBackupAccount) != nil
    }

    /// Reads and decodes the pre-migration config backup without applying migration.
    /// Returns nil if no backup exists or the backup data cannot be decoded.
    nonisolated func restoreConfigBackup() -> BastionConfig? {
        guard let data = keychain.read(account: Self.configBackupAccount) else {
            return nil
        }
        return try? JSONDecoder().decode(BastionConfig.self, from: data)
    }

    // P0.2 / P0.3: Upgrade configs saved before schema version 7.
    // - v6: inherited the old insecure default of authPolicy: .open
    // - v7: repair legacy per-client placeholder rules that were stored as
    //       disabled/empty instead of cloning the global template
    private nonisolated func migrateConfig(_ config: BastionConfig) -> BastionConfig {
        guard config.version < 7 else { return config }
        var migrated = config

        if migrated.version < 6, migrated.authPolicy == .open {
            migrated.authPolicy = .biometricOrPasscode
        }

        migrated.clientProfiles = migrated.clientProfiles.map { originalProfile in
            var profile = originalProfile

            if migrated.version < 6, profile.authPolicy == .open {
                profile.authPolicy = .biometricOrPasscode
            }

            if migrated.version < 7,
               looksLikeLegacyDisabledProfileRules(profile.rules),
               migrated.rules.enabled {
                profile.rules = clonedRulesForClient(from: migrated.rules)
            }

            return profile
        }
        return migrated
    }

    private nonisolated func looksLikeLegacyDisabledProfileRules(_ rules: RuleConfig) -> Bool {
        guard rules.enabled == false,
              rules.requireExplicitApproval == false,
              rules.allowedHours == nil,
              (rules.allowedChains?.isEmpty ?? true),
              (rules.allowedTargets?.isEmpty ?? true),
              (rules.allowedSelectors?.isEmpty ?? true),
              (rules.denySelectors?.isEmpty ?? true),
              (rules.allowedClients?.isEmpty ?? true),
              rules.rateLimits.isEmpty,
              rules.spendingLimits.isEmpty,
              rules.rawMessagePolicy.enabled == false,
              rules.rawMessagePolicy.allowRawSigning == false,
              rules.typedDataPolicy.enabled == false,
              rules.typedDataPolicy.requireExplicitApproval == false,
              rules.typedDataPolicy.domainRules.isEmpty,
              rules.typedDataPolicy.structRules.isEmpty else {
            return false
        }

        return true
    }

    nonisolated func saveConfig(_ newConfig: BastionConfig) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(normalizedConfig(newConfig))
        keychain.write(account: Self.configAccount, data: data)
    }

    // L-01: Load synchronously to prevent race with ensureConfigLoadedIfNeeded.
    func loadConfigOnStartup() {
        let result = loadConfigRaw()
        config = result.config
        configCorrupted = result.corrupted
        configLoaded = true
    }

    private func ensureConfigLoadedIfNeeded() {
        guard !configLoaded else { return }
        let result = loadConfigRaw()
        config = result.config
        configCorrupted = result.corrupted
        configLoaded = true
    }

    func updateConfig(_ newConfig: BastionConfig) async throws {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to update Bastion rules"
        )
        let normalized = normalizedConfig(newConfig)
        try saveConfig(normalized)
        config = normalized
        configLoaded = true
        configCorrupted = false
    }

    func ensureClientProfile(bundleId: String?) -> ClientProfile? {
        ensureConfigLoadedIfNeeded()

        guard let bundleId = normalizedBundleId(bundleId) else {
            return nil
        }

        if let existing = clientProfile(bundleId: bundleId) {
            return existing
        }

        let profile = ClientProfile(
            bundleId: bundleId,
            label: nil,
            authPolicy: config.authPolicy,
            keyTag: ClientProfile.makeKeyTag(),
            rules: clonedRulesForClient(from: config.rules)
        )

        config.clientProfiles.append(profile)
        config = normalizedConfig(config)
        // M-02: Don't silently swallow save errors. If we can't persist the
        // profile, remove it from the in-memory config to prevent orphaned
        // SE keys and fresh counter exploits on restart.
        do {
            try saveConfig(config)
        } catch {
            config.clientProfiles.removeAll { $0.id == profile.id }
            return nil
        }
        auditLog.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: "profile",
            reason: "Auto-created client profile for \(bundleId)"
        ))
        return clientProfile(bundleId: bundleId)
    }

    func effectiveRules(for bundleId: String?) -> RuleConfig {
        ensureConfigLoadedIfNeeded()
        return ensureClientProfile(bundleId: bundleId)?.rules ?? config.rules
    }

    func clientProfile(bundleId: String?) -> ClientProfile? {
        ensureConfigLoadedIfNeeded()
        guard let bundleId = normalizedBundleId(bundleId) else {
            return nil
        }
        return config.clientProfiles.first {
            $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame
        }
    }

    func clientProfile(id: String?) -> ClientProfile? {
        ensureConfigLoadedIfNeeded()
        guard let id else { return nil }
        return config.clientProfiles.first { $0.id == id }
    }

    func clientProfileInfo(bundleId: String?) -> ClientProfileInfo? {
        ensureConfigLoadedIfNeeded()
        guard let profile = ensureClientProfile(bundleId: bundleId) else {
            return nil
        }

        return ClientProfileInfo(
            id: profile.id,
            bundleId: profile.bundleId,
            label: profile.label,
            authPolicy: profile.authPolicy?.rawValue ?? config.authPolicy.rawValue,
            keyTag: profile.keyTag,
            accountAddress: accountAddress(for: profile)
        )
    }

    func signingContext(for bundleId: String?) -> ClientSigningContext {
        ensureConfigLoadedIfNeeded()
        if let profile = ensureClientProfile(bundleId: bundleId) {
            return ClientSigningContext(
                bundleId: profile.bundleId,
                profileId: profile.id,
                profileLabel: profile.label,
                authPolicy: profile.authPolicy ?? config.authPolicy,
                keyTag: profile.keyTag,
                accountAddress: accountAddress(for: profile),
                rules: profile.rules
            )
        }

        return ClientSigningContext(
            bundleId: bundleId,
            profileId: nil,
            profileLabel: nil,
            authPolicy: config.authPolicy,
            keyTag: SecureEnclaveManager.defaultSigningKeyIdentifier,
            accountAddress: accountAddress(forKeyTag: SecureEnclaveManager.defaultSigningKeyIdentifier),
            rules: config.rules
        )
    }

    func accountAddress(for profile: ClientProfile) -> String? {
        accountAddress(forKeyTag: profile.keyTag)
    }

    // MARK: - Validation

    enum ValidationResult {
        case allowed
        case denied(reasons: [String])
    }

    private enum OperationInspection {
        case notApplicable
        case known(targets: [String], selectors: [SelectorObservation], spending: [SpendObservation], hasUnrecognizedCalldata: Bool)
        case opaque(String)
    }

    private struct SelectorObservation {
        let target: String
        let selector: Data? // 4 bytes, nil for plain ETH transfers
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

        var commonReasons: [String] = []
        validateAllowedClients(request, rules: config.rules, reasons: &commonReasons)

        switch request.operation {
        case .message, .rawBytes:
            return mergeValidation(commonReasons, validateRawMessage(request, rules: config.rules))
        case .typedData(let typedData):
            return mergeValidation(commonReasons, validateTypedData(typedData, config: config.rules))
        case .userOperation:
            return mergeValidation(commonReasons, validateUserOperation(request, config: config))
        }
    }

    nonisolated func requiresExplicitApproval(for request: SignRequest, config: BastionConfig) -> Bool {
        switch request.operation {
        case .message, .rawBytes:
            // Require explicit approval when rule-based signing is disabled for messages.
            return !config.rules.rawMessagePolicy.enabled
        case .typedData:
            // Require explicit approval when rule-based signing is disabled for EIP-712.
            if !config.rules.typedDataPolicy.enabled { return true }
            return config.rules.typedDataPolicy.requireExplicitApproval
        case .userOperation:
            return config.rules.requireExplicitApproval
        }
    }

    /// Records state after a successful sign (increment counters, track spending).
    nonisolated func recordSuccess(request: SignRequest, config: BastionConfig) {
        guard case .userOperation = request.operation else {
            return
        }

        recordUserOperationSuccess(request: request, config: config)
    }

    private nonisolated func validateRawMessage(_ request: SignRequest, rules: RuleConfig) -> ValidationResult {
        let policy = rules.rawMessagePolicy
        // When rule-based signing is disabled, message requests are still allowed
        // but require explicit authentication (handled by requiresExplicitApproval).
        guard policy.enabled else {
            return .allowed
        }

        // Sub-rule: when allowRawSigning is false, only EIP-191 personal messages are
        // permitted. Raw 32-byte signing requests are denied outright.
        if case .rawBytes = request.operation, !policy.allowRawSigning {
            return .denied(reasons: ["Raw bytes signing is not permitted; only EIP-191 personal message signing is allowed"])
        }

        return .allowed
    }

    private nonisolated func validateTypedData(_ typedData: EIP712TypedData, config: RuleConfig) -> ValidationResult {
        let policy = config.typedDataPolicy
        // When rule-based signing is disabled, EIP-712 requests are still allowed
        // but will require explicit authentication (handled by requiresExplicitApproval).
        guard policy.enabled else {
            return .allowed
        }

        var reasons: [String] = []

        if !policy.domainRules.isEmpty {
            let allowed = policy.domainRules.contains { matchesTypedDataDomainRule($0, typedData: typedData) }
            if !allowed {
                reasons.append("Typed-data domain not in allowlist")
            }
        }

        if !policy.structRules.isEmpty {
            let allowed = policy.structRules.contains { matchesTypedDataStructRule($0, typedData: typedData) }
            if !allowed {
                reasons.append("Typed-data struct payload not in allowlist")
            }
        }

        return reasons.isEmpty ? .allowed : .denied(reasons: reasons)
    }

    private nonisolated func validateUserOperation(_ request: SignRequest, config: BastionConfig) -> ValidationResult {
        var reasons: [String] = []
        let inspection = inspect(request.operation)

        // C-01: Opaque calldata (delegatecall, unknown call types) is ALWAYS denied
        // regardless of which rules are configured. This prevents bypass when only
        // rate limits or hours are set.
        if case .opaque(let reason) = inspection {
            reasons.append("UserOperation calldata cannot be verified: \(reason)")
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

        // 3a. Allowed selectors (per-target function whitelist)
        if let allowedSelectors = config.rules.allowedSelectors, !allowedSelectors.isEmpty {
            validateAllowedSelectors(inspection: inspection, allowedSelectors: allowedSelectors, reasons: &reasons)
        }

        // 3b. Deny selectors (global blocklist)
        if let denySelectors = config.rules.denySelectors, !denySelectors.isEmpty {
            validateDenySelectors(inspection: inspection, denySelectors: denySelectors, reasons: &reasons)
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

    private nonisolated func recordUserOperationSuccess(request: SignRequest, config: BastionConfig) {
        // Record rate limit entries
        for rule in config.rules.rateLimits {
            stateStore.recordRequest(ruleId: rule.id, windowSeconds: rule.windowSeconds)
        }

        guard case .known(_, _, let observations, _) = inspect(request.operation) else {
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

    private nonisolated func matchesTypedDataDomainRule(
        _ rule: TypedDataDomainRule,
        typedData: EIP712TypedData
    ) -> Bool {
        // L-02: Require at least one non-nil constraint. An empty rule should
        // NOT match everything — that's a misconfiguration.
        guard normalizedOptional(rule.primaryType) != nil ||
              normalizedOptional(rule.name) != nil ||
              normalizedOptional(rule.version) != nil ||
              rule.chainId != nil ||
              normalizedAddressOptional(rule.verifyingContract) != nil else {
            return false
        }

        if let primaryType = normalizedOptional(rule.primaryType),
           primaryType.caseInsensitiveCompare(typedData.primaryType) != .orderedSame {
            return false
        }
        if let name = normalizedOptional(rule.name),
           name != typedData.domain.name {
            return false
        }
        if let version = normalizedOptional(rule.version),
           version != typedData.domain.version {
            return false
        }
        if let chainId = rule.chainId,
           chainId != typedData.domain.chainId {
            return false
        }
        if let verifyingContract = normalizedAddressOptional(rule.verifyingContract),
           verifyingContract != normalizedAddressOptional(typedData.domain.verifyingContract) {
            return false
        }
        return true
    }

    private nonisolated func matchesTypedDataStructRule(
        _ rule: TypedDataStructRule,
        typedData: EIP712TypedData
    ) -> Bool {
        guard rule.primaryType.caseInsensitiveCompare(typedData.primaryType) == .orderedSame else {
            return false
        }

        let matcherJSON = rule.matcherJSON.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !matcherJSON.isEmpty else {
            return true
        }

        guard let matcherObject = jsonObject(from: matcherJSON),
              let matcherMap = matcherObject as? [String: Any] else {
            return false
        }

        let messageObject = typedData.message.mapValues(\.value)
        return jsonSubsetMatches(expected: matcherMap, actual: messageObject)
    }

    private nonisolated func validateAllowedClients(
        _ request: SignRequest,
        rules: RuleConfig,
        reasons: inout [String]
    ) {
        guard let allowedClients = rules.allowedClients, !allowedClients.isEmpty else {
            return
        }

        if let clientId = request.clientBundleId {
            let allowed = allowedClients.contains { $0.bundleId == clientId }
            if !allowed {
                reasons.append("Client \(clientId) not in allowlist")
            }
        } else {
            reasons.append("Unknown client — allowlist is configured but client identity unavailable")
        }
    }

    private nonisolated func mergeValidation(
        _ commonReasons: [String],
        _ operationValidation: ValidationResult
    ) -> ValidationResult {
        switch operationValidation {
        case .allowed:
            return commonReasons.isEmpty ? .allowed : .denied(reasons: commonReasons)
        case .denied(let reasons):
            return .denied(reasons: commonReasons + reasons)
        }
    }

    private nonisolated func inspect(_ operation: SigningOperation) -> OperationInspection {
        switch operation {
        case .message, .rawBytes:
            return .notApplicable
        case .typedData(let data):
            if let verifyingContract = data.domain.verifyingContract {
                return .known(targets: [verifyingContract], selectors: [], spending: [], hasUnrecognizedCalldata: false)
            }
            return .known(targets: [], selectors: [], spending: [], hasUnrecognizedCalldata: false)
        case .userOperation(let op):
            switch CalldataDecoder.inspect(op) {
            case .decoded(let executions):
                let hasUnrecognized = executions.contains(where: \.hasUnrecognizedCalldata)
                return .known(
                    targets: executions.map(\.to),
                    selectors: executions.map { SelectorObservation(target: $0.to, selector: $0.selector) },
                    spending: spendObservations(from: executions, chainId: op.chainId),
                    hasUnrecognizedCalldata: hasUnrecognized
                )
            case .opaque(let reason):
                return .opaque(reason)
            }
        }
    }

    private nonisolated func spendObservations(
        from executions: [CalldataDecoder.DecodedExecution],
        chainId: Int
    ) -> [SpendObservation] {
        var observations: [SpendObservation] = []

        for execution in executions {
            if execution.value != "0" {
                observations.append(SpendObservation(token: .eth, amount: execution.value))
            }

            // M-06: Only count transfers and transferFroms as spending.
            // Approvals don't move funds immediately and should be handled
            // by a separate policy (visible in UI but don't count toward limits).
            if let tokenOperation = execution.tokenOperation,
               tokenOperation.kind != .approve {
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

    private nonisolated func validateTargets(
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
        case .known(let targets, _, _, _):
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

    private nonisolated func validateAllowedSelectors(
        inspection: OperationInspection,
        allowedSelectors: [String: [String]],
        reasons: inout [String]
    ) {
        switch inspection {
        case .opaque(let reason):
            reasons.append("Unable to inspect call selectors: \(reason)")
        case .notApplicable:
            return
        case .known(_, let selectorObs, _, _):
            for obs in selectorObs {
                let normalizedTarget = normalizedAddress(obs.target)
                guard let allowedForTarget = allowedSelectors.first(where: {
                    normalizedAddress($0.key) == normalizedTarget
                })?.value else {
                    continue // no allowlist configured for this target → pass
                }
                let normalizedAllowed = Set(allowedForTarget.map {
                    $0.lowercased().hasPrefix("0x") ? String($0.dropFirst(2)) : $0.lowercased()
                })
                guard let sel = obs.selector else {
                    continue // plain ETH transfers have no selector → pass
                }
                let hexSel = sel.map { String(format: "%02x", $0) }.joined()
                if !normalizedAllowed.contains(hexSel) {
                    reasons.append("Function 0x\(hexSel) not in allowlist for \(shortAddress(obs.target))")
                }
            }
        }
    }

    private nonisolated func validateDenySelectors(
        inspection: OperationInspection,
        denySelectors: [String],
        reasons: inout [String]
    ) {
        let denied = Set(denySelectors.map {
            $0.lowercased().hasPrefix("0x") ? String($0.dropFirst(2)) : $0.lowercased()
        })
        switch inspection {
        case .opaque(let reason):
            reasons.append("Unable to inspect call selectors: \(reason)")
        case .notApplicable:
            return
        case .known(_, let selectorObs, _, _):
            for obs in selectorObs {
                guard let sel = obs.selector else { continue }
                let hexSel = sel.map { String(format: "%02x", $0) }.joined()
                if denied.contains(hexSel) {
                    reasons.append("Function 0x\(hexSel) is globally blocked on \(shortAddress(obs.target))")
                }
            }
        }
    }

    private nonisolated func validateSpendingLimits(
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
        case .known(_, _, let observations, let hasUnrecognizedCalldata):
            // H-03: Unrecognized function selectors mean spending cannot be verified.
            if hasUnrecognizedCalldata {
                reasons.append("UserOperation contains unrecognized function calls — spending cannot be fully verified")
            }
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

    private nonisolated func matchedSpendAmount(
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

    private nonisolated func matches(_ ruleToken: TokenIdentifier, _ observedToken: TokenIdentifier) -> Bool {
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

    private nonisolated func normalizedAddress(_ address: String) -> String {
        address.lowercased()
    }

    private nonisolated func shortAddress(_ address: String) -> String {
        let normalized = normalizedAddress(address)
        guard normalized.count > 12 else { return normalized }
        return "\(normalized.prefix(10))..."
    }

    private nonisolated func normalizedOptional(_ text: String?) -> String? {
        guard let text else { return nil }
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    private nonisolated func normalizedAddressOptional(_ address: String?) -> String? {
        guard let normalized = normalizedOptional(address) else {
            return nil
        }
        return normalizedAddress(normalized)
    }

    private nonisolated func jsonObject(from json: String) -> Any? {
        guard let data = json.data(using: .utf8) else {
            return nil
        }
        return try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
    }

    private nonisolated func jsonSubsetMatches(expected: Any, actual: Any?) -> Bool {
        guard let actual else {
            return false
        }

        switch expected {
        case let expectedDict as [String: Any]:
            guard let actualDict = actual as? [String: Any] else {
                return false
            }
            for (key, value) in expectedDict {
                guard jsonSubsetMatches(expected: value, actual: actualDict[key]) else {
                    return false
                }
            }
            return true
        case let expectedArray as [Any]:
            guard let actualArray = actual as? [Any], expectedArray.count == actualArray.count else {
                return false
            }
            for (expectedValue, actualValue) in zip(expectedArray, actualArray) {
                guard jsonSubsetMatches(expected: expectedValue, actual: actualValue) else {
                    return false
                }
            }
            return true
        case let expectedString as String:
            return String(describing: actual) == expectedString
        case let expectedNumber as NSNumber:
            guard let actualNumber = actual as? NSNumber else {
                return false
            }
            return expectedNumber == actualNumber
        case _ as NSNull:
            return actual is NSNull
        default:
            return String(describing: actual) == String(describing: expected)
        }
    }

    private func normalizedConfig(_ config: BastionConfig) -> BastionConfig {
        var normalized = config
        normalized.version = 7
        if let projectId = normalized.bundlerPreferences.zeroDevProjectId?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !projectId.isEmpty {
            normalized.bundlerPreferences.zeroDevProjectId = projectId
        } else {
            normalized.bundlerPreferences.zeroDevProjectId = nil
        }
        normalized.bundlerPreferences.chainRPCs = normalized.bundlerPreferences.chainRPCs
            .map { endpoint in
                ChainRPCPreference(
                    chainId: endpoint.chainId,
                    rpcURL: endpoint.rpcURL.trimmingCharacters(in: .whitespacesAndNewlines)
                )
            }
            .filter { !$0.rpcURL.isEmpty }
            .sorted { lhs, rhs in
                lhs.chainId < rhs.chainId
            }
        normalized.clientProfiles = normalized.clientProfiles.map { profile in
            var profile = profile
            if profile.authPolicy == nil {
                profile.authPolicy = normalized.authPolicy
            }
            return profile
        }
        normalized.clientProfiles.sort {
            if $0.bundleId.caseInsensitiveCompare($1.bundleId) == .orderedSame {
                return $0.displayDescription.localizedCaseInsensitiveCompare($1.displayDescription) == .orderedAscending
            }
            return $0.bundleId.localizedCaseInsensitiveCompare($1.bundleId) == .orderedAscending
        }
        return normalized
    }

    private func clonedRulesForClient(from template: RuleConfig) -> RuleConfig {
        var cloned = template
        cloned.allowedClients = nil
        cloned.rateLimits = template.rateLimits.map {
            RateLimitRule(id: UUID().uuidString, maxRequests: $0.maxRequests, windowSeconds: $0.windowSeconds)
        }
        cloned.spendingLimits = template.spendingLimits.map {
            SpendingLimitRule(id: UUID().uuidString, token: $0.token, allowance: $0.allowance, windowSeconds: $0.windowSeconds)
        }
        return cloned
    }

    private func normalizedBundleId(_ bundleId: String?) -> String? {
        guard let bundleId else {
            return nil
        }
        let trimmed = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            return nil
        }
        return trimmed
    }

    private func accountAddress(forKeyTag keyTag: String) -> String? {
        (try? SecureEnclaveManager.shared.getPublicKey(keyTag: keyTag))?.accountAddress
    }
}

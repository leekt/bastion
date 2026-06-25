import Foundation

final class RuleEngine {
    static let shared = RuleEngine()

    private let keychain: KeychainBackend
    #if DEBUG
    private let runtimeQAConfigOverride: RuntimeQAConfigOverrideProvider
    #endif
    let stateStore: StateStore
    // Internal (default) so extensions in other files within the module
    // — e.g. WalletGroupOnChain — can authenticate and audit.
    let authManager = AuthManager.shared
    let auditLog = AuditLog.shared

    private nonisolated static let configAccount = "config"
    private nonisolated static let configBackupAccount = "config.premigration"
    private nonisolated static let configRecoveryAccount = "config.recovery"
    private nonisolated static let pauseFallbackAccount = "pause-state-fallback"

    private(set) var config: BastionConfig = .default
    private(set) var configLoaded = false
    /// True when keychain data existed but failed to decode — rules were reset to
    /// defaults. Surface this in the UI so the user knows why their rules disappeared.
    private(set) var configCorrupted = false

    private init() {
        self.keychain = SystemKeychainBackend()
        #if DEBUG
        self.runtimeQAConfigOverride = .live
        #endif
        self.stateStore = .shared
    }

    #if DEBUG
    init(
        keychain: KeychainBackend,
        runtimeQAConfigOverride: RuntimeQAConfigOverrideProvider = .disabled
    ) {
        self.keychain = keychain
        self.runtimeQAConfigOverride = runtimeQAConfigOverride
        self.stateStore = StateStore(keychain: keychain)
    }
    #else
    // For testing
    init(keychain: KeychainBackend) {
        self.keychain = keychain
        self.stateStore = StateStore(keychain: keychain)
    }
    #endif

    // MARK: - Config Management

    nonisolated struct ConfigRecoverySnapshot: Codable, Sendable {
        let capturedAt: Date
        let reason: String
        let rawConfig: Data

        var byteCount: Int { rawConfig.count }
    }

    private nonisolated static func corruptedConfigFallback() -> BastionConfig {
        var fallback = BastionConfig.default
        fallback.pauseState = PauseState(
            paused: true,
            lockedDown: false,
            pausedAt: Date(),
            reason: "Bastion config is corrupt; signing is paused until rules are recovered"
        )
        return fallback
    }

    #if DEBUG
    private nonisolated func loadRuntimeQAConfigOverrideRaw() -> (config: BastionConfig, corrupted: Bool)? {
        guard let data = runtimeQAConfigOverride.readDataIfEnabled() else {
            return nil
        }
        guard let decoded = try? JSONDecoder().decode(BastionConfig.self, from: data) else {
            return (applyingPauseFallback(to: Self.corruptedConfigFallback()), true)
        }
        let normalized = normalizedConfig(migrateConfig(decoded))
        do {
            try validateBastionConfig(normalized)
        } catch {
            return (applyingPauseFallback(to: Self.corruptedConfigFallback()), true)
        }
        return (applyingPauseFallback(to: normalized), false)
    }
    #endif

    private nonisolated func loadConfigRaw() -> (config: BastionConfig, corrupted: Bool) {
        #if DEBUG
        if let override = loadRuntimeQAConfigOverrideRaw() {
            return override
        }
        #endif

        let data: Data
        switch keychain.readResult(account: Self.configAccount) {
        case .missing:
            return (applyingPauseFallback(to: .default), false) // new install — no config yet
        case .failure:
            return (applyingPauseFallback(to: Self.corruptedConfigFallback()), true)
        case .found(let found):
            data = found
        }
        guard let decoded = try? JSONDecoder().decode(BastionConfig.self, from: data) else {
            persistConfigRecoverySnapshot(rawConfig: data, reason: "Stored config could not be decoded")
            return (applyingPauseFallback(to: Self.corruptedConfigFallback()), true) // data exists but unreadable — corruption
        }
        if decoded.version < 7,
           case .missing = keychain.readResult(account: Self.configBackupAccount) {
            keychain.write(account: Self.configBackupAccount, data: data)
        }
        let normalized = normalizedConfig(migrateConfig(decoded))
        do {
            try validateBastionConfig(normalized)
        } catch {
            persistConfigRecoverySnapshot(rawConfig: data, reason: "Stored config failed schema validation: \(error.localizedDescription)")
            return (applyingPauseFallback(to: Self.corruptedConfigFallback()), true)
        }
        clearConfigRecoverySnapshot()
        return (applyingPauseFallback(to: normalized), false)
    }

    nonisolated func loadConfig() -> BastionConfig {
        loadConfigRaw().config
    }

    /// Returns true if a pre-migration config backup exists in the keychain.
    nonisolated func hasConfigBackup() -> Bool {
        if case .found = keychain.readResult(account: Self.configBackupAccount) {
            return true
        }
        return false
    }

    /// Reads and decodes the pre-migration config backup without applying migration.
    /// Returns nil if no backup exists or the backup data cannot be decoded.
    nonisolated func restoreConfigBackup() -> BastionConfig? {
        guard case .found(let data) = keychain.readResult(account: Self.configBackupAccount) else {
            return nil
        }
        return try? JSONDecoder().decode(BastionConfig.self, from: data)
    }

    nonisolated func configRecoverySnapshot() -> ConfigRecoverySnapshot? {
        guard case .found(let data) = keychain.readResult(account: Self.configRecoveryAccount) else {
            return nil
        }
        return try? JSONDecoder().decode(ConfigRecoverySnapshot.self, from: data)
    }

    private nonisolated func persistConfigRecoverySnapshot(rawConfig: Data, reason: String) {
        let snapshot = ConfigRecoverySnapshot(
            capturedAt: Date(),
            reason: reason,
            rawConfig: rawConfig
        )
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        _ = keychain.write(account: Self.configRecoveryAccount, data: data)
    }

    private nonisolated func clearConfigRecoverySnapshot() {
        _ = keychain.delete(account: Self.configRecoveryAccount)
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
        let normalized = normalizedConfig(newConfig)
        try validateBastionConfig(normalized)
        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(normalized)
        #if DEBUG
        if runtimeQAConfigOverride.isEnabled() {
            guard runtimeQAConfigOverride.writeData(data) else {
                throw BastionError.storageFailed
            }
            return
        }
        #endif
        guard keychain.write(account: Self.configAccount, data: data) else {
            throw BastionError.storageFailed
        }
        clearConfigRecoverySnapshot()
        removePauseFallback()
    }

    // L-01: Load synchronously to prevent race with ensureConfigLoadedIfNeeded.
    func loadConfigOnStartup() {
        let result = loadConfigRaw()
        config = result.config
        configCorrupted = result.corrupted
        configLoaded = true
        auditLog.redactionLevel = config.auditRedactionLevel
    }

    func ensureConfigLoadedIfNeeded() {
        guard !configLoaded else { return }
        let result = loadConfigRaw()
        config = result.config
        configCorrupted = result.corrupted
        configLoaded = true
        auditLog.redactionLevel = config.auditRedactionLevel
    }

    func updateConfig(_ newConfig: BastionConfig) async throws {
        try validateBastionConfig(normalizedConfig(newConfig))
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to update Bastion rules"
        )
        let normalized = normalizedConfig(newConfig)
        try saveConfig(normalized)
        // v9: snapshot for the policy-version log (best-effort).
        ConfigVersionStore.shared.recordVersion(normalized)
        config = normalized
        configLoaded = true
        configCorrupted = false
        auditLog.redactionLevel = normalized.auditRedactionLevel

        // PR4: After persisting the new policy, reconcile any in-flight
        // session grants and live XPC connections so they can't keep
        // operating with broader scope than the new rules allow. Without
        // this, an attacker who got a 30-minute session before the
        // owner tightened the allowlist could keep using the old scope
        // until the session expires.
        await applyPolicyReconciliation(normalized)
    }

    /// PR4: shared reconciliation hook. Internal so emergency lockdown
    /// (LockdownManager) can trigger it after force-pause as well as the
    /// regular updateConfig path.
    @MainActor
    func applyPolicyReconciliation(_ normalized: BastionConfig) async {
        SessionStore.shared.reconcile { [weak self] bundleId in
            self?.effectiveRules(for: bundleId, createProfile: false) ?? normalized.rules
        }
        XPCServer.shared.reconcileConnections(against: normalized.rules)
    }

    /// v9: Pause / lockdown writes that intentionally skip biometric. Pause
    /// must be instant — every paused-state mutation goes through the
    /// LockdownManager which calls this method.
    @discardableResult
    func unsafelyApplyPauseState(_ newState: PauseState) -> Bool {
        ensureConfigLoadedIfNeeded()
        let previous = config
        var updated = config
        updated.pauseState = newState
        let normalized = normalizedConfig(updated)
        do {
            try saveConfig(normalized)
            config = normalized
            configLoaded = true
            configCorrupted = false
            auditLog.redactionLevel = normalized.auditRedactionLevel
            return true
        } catch {
            // Engaging pause/lockdown is fail-closed: keep the in-memory safety
            // stop and try to persist a sidecar fallback if Keychain is down.
            // Clearing pause/lockdown is fail-closed in the other direction:
            // never unpause memory, and never remove the fallback, unless the
            // durable config write succeeded above.
            guard newState.paused || newState.lockedDown else {
                config = previous
                configLoaded = true
                configCorrupted = true
                auditLog.redactionLevel = previous.auditRedactionLevel
                return false
            }
            config = normalized
            configLoaded = true
            auditLog.redactionLevel = normalized.auditRedactionLevel
            let fallbackSaved = persistPauseFallback(newState)
            if !fallbackSaved {
                configCorrupted = true
            }
            return fallbackSaved
        }
    }

    nonisolated func globalClientAllowlistDenial(bundleId: String?) -> String? {
        ensureConfigLoadedIfNeeded()
        return Self.clientAllowlistDenial(bundleId: bundleId, rules: config.rules)
    }

    nonisolated static func clientAllowlistDenial(bundleId: String?, rules: RuleConfig) -> String? {
        guard let allowedClients = rules.allowedClients else {
            return nil
        }
        guard !allowedClients.isEmpty else {
            return "Client allowlist is empty — no clients permitted"
        }
        guard let bundleId else {
            return "Unknown client — allowlist is configured but client identity unavailable"
        }
        let allowed = allowedClients.contains {
            $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame
        }
        return allowed ? nil : "Client \(bundleId) not in allowlist"
    }

    private nonisolated func applyingPauseFallback(to config: BastionConfig) -> BastionConfig {
        guard let fallback = loadPauseFallback(), fallback.paused || fallback.lockedDown else {
            return config
        }
        var updated = config
        updated.pauseState = fallback
        return updated
    }

    private nonisolated func loadPauseFallback() -> PauseState? {
        let data: Data
        switch keychain.readResult(account: Self.pauseFallbackAccount) {
        case .missing:
            return nil
        case .failure:
            return PauseState(
                paused: true,
                lockedDown: true,
                pausedAt: Date(),
                reason: "Bastion pause fallback is unavailable; signing is locked down until recovery"
            )
        case .found(let found):
            data = found
        }
        return try? JSONDecoder().decode(PauseState.self, from: data)
    }

    private nonisolated func persistPauseFallback(_ state: PauseState) -> Bool {
        guard state.paused || state.lockedDown else {
            removePauseFallback()
            return true
        }
        guard let data = try? JSONEncoder().encode(state) else {
            return false
        }
        return keychain.write(account: Self.pauseFallbackAccount, data: data)
    }

    private nonisolated func removePauseFallback() {
        _ = keychain.delete(account: Self.pauseFallbackAccount)
    }

    // L-05: Maximum number of client profiles to prevent unbounded growth.
    private nonisolated static let maxClientProfiles = 20

    func ensureClientProfile(bundleId: String?) -> ClientProfile? {
        ensureConfigLoadedIfNeeded()

        guard let bundleId = normalizedBundleId(bundleId) else {
            return nil
        }
        guard !configCorrupted else {
            return nil
        }

        if let existing = clientProfile(bundleId: bundleId) {
            return existing
        }

        // L-05: Cap the number of client profiles.
        guard config.clientProfiles.count < Self.maxClientProfiles else {
            NSLog("[RuleEngine] Client profile cap reached (%d). Refusing to create profile for %@", Self.maxClientProfiles, bundleId)
            return nil
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
        // Profile auto-creation is a side-effect of a signing attempt —
        // the actual sign event recorded by SigningManager will carry the
        // full request + client context, so the operator already sees the
        // first appearance of a new bundle on its own audit row. We
        // previously recorded a `.signSuccess` event with no request and
        // no client context here, which surfaced as "Unknown client |
        // sign_success" rows in the audit history. Suppressed.
        return clientProfile(bundleId: bundleId)
    }

    func effectiveRules(for bundleId: String?, createProfile: Bool = true) -> RuleConfig {
        ensureConfigLoadedIfNeeded()
        let profile = createProfile ? ensureClientProfile(bundleId: bundleId) : clientProfile(bundleId: bundleId)
        guard let profile else {
            return config.rules
        }
        if let (group, member) = activeGroupMembership(for: profile) {
            return mergeGroupRules(group: group.sharedRules, member: member.scopedRules)
        }
        return profile.rules
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

    func clientProfileInfo(bundleId: String?, createProfile: Bool = true) -> ClientProfileInfo? {
        ensureConfigLoadedIfNeeded()
        let profile = createProfile ? ensureClientProfile(bundleId: bundleId) : clientProfile(bundleId: bundleId)
        guard let profile else {
            return nil
        }

        if let (group, member) = activeGroupMembership(for: profile) {
            return ClientProfileInfo(
                id: profile.id,
                bundleId: profile.bundleId,
                label: profile.label ?? member.label,
                authPolicy: profile.authPolicy?.rawValue ?? config.authPolicy.rawValue,
                keyTag: nil,
                accountAddress: group.accountAddress,
                walletGroupId: group.id,
                membershipId: member.id
            )
        }

        return ClientProfileInfo(
            id: profile.id,
            bundleId: profile.bundleId,
            label: profile.label,
            authPolicy: profile.authPolicy?.rawValue ?? config.authPolicy.rawValue,
            keyTag: nil,
            accountAddress: accountAddress(for: profile),
            walletGroupId: nil,
            membershipId: nil
        )
    }

    /// Direct profile-info lookup by id. Used by the XPC pollPairing handler
    /// after a fresh pairing accept, where the bundleId path would
    /// auto-create a duplicate profile.
    func clientProfileInfo(forId id: String) -> ClientProfileInfo? {
        ensureConfigLoadedIfNeeded()
        guard let profile = config.clientProfiles.first(where: { $0.id == id }) else {
            return nil
        }
        if let (group, member) = activeGroupMembership(for: profile) {
            return ClientProfileInfo(
                id: profile.id,
                bundleId: profile.bundleId,
                label: profile.label ?? member.label,
                authPolicy: profile.authPolicy?.rawValue ?? config.authPolicy.rawValue,
                keyTag: nil,
                accountAddress: group.accountAddress,
                walletGroupId: group.id,
                membershipId: member.id
            )
        }
        return ClientProfileInfo(
            id: profile.id,
            bundleId: profile.bundleId,
            label: profile.label,
            authPolicy: profile.authPolicy?.rawValue ?? config.authPolicy.rawValue,
            keyTag: nil,
            accountAddress: accountAddress(for: profile),
            walletGroupId: nil,
            membershipId: nil
        )
    }

    func keyLifecyclePlan(forProfileId id: String) -> KeyLifecyclePlan? {
        ensureConfigLoadedIfNeeded()
        guard let profile = config.clientProfiles.first(where: { $0.id == id }) else {
            return nil
        }
        return KeyLifecyclePlanner.privateClientRotationPlan(profile: profile)
    }

    func rotatePrivateClientKey(
        profileId: String,
        replacementKeyTag: String,
        replacementAccountAddress: String? = nil,
        deleteOldKeyAfterSave: Bool = true
    ) throws -> ClientKeyRotationResult {
        ensureConfigLoadedIfNeeded()

        guard let profileIndex = config.clientProfiles.firstIndex(where: { $0.id == profileId }) else {
            throw BastionError.invalidInput
        }

        let profile = config.clientProfiles[profileIndex]
        guard !profile.isGroupMember else {
            throw BastionError.ruleViolation
        }

        let trimmedTag = replacementKeyTag.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmedTag.hasPrefix("com.bastion.signingkey.client."),
              trimmedTag != profile.keyTag else {
            throw BastionError.invalidInput
        }

        let oldKeyTag = profile.keyTag
        let oldAccountAddress = accountAddress(forKeyTag: oldKeyTag)
        config.clientProfiles[profileIndex].keyTag = trimmedTag

        do {
            try saveConfig(config)
        } catch {
            config.clientProfiles[profileIndex].keyTag = oldKeyTag
            throw error
        }

        if deleteOldKeyAfterSave {
            _ = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: [oldKeyTag])
        }

        return ClientKeyRotationResult(
            profileId: profile.id,
            bundleId: profile.bundleId,
            oldKeyTag: oldKeyTag,
            newKeyTag: trimmedTag,
            oldAccountAddress: oldAccountAddress,
            newAccountAddress: replacementAccountAddress
        )
    }

    func signingContext(for bundleId: String?, createProfile: Bool = true) -> ClientSigningContext {
        ensureConfigLoadedIfNeeded()
        let profile = createProfile ? ensureClientProfile(bundleId: bundleId) : clientProfile(bundleId: bundleId)
        if let profile {
            if let (group, member) = activeGroupMembership(for: profile) {
                // Shared smart account address, agent's OWN SE key, MERGED rules
                // (intersection of group.sharedRules and member.scopedRules).
                return ClientSigningContext(
                    bundleId: profile.bundleId,
                    profileId: profile.id,
                    profileLabel: profile.label ?? member.label,
                    authPolicy: profile.authPolicy ?? config.authPolicy,
                    keyTag: member.keyTag,
                    accountAddress: group.accountAddress,
                    rules: mergeGroupRules(group: group.sharedRules, member: member.scopedRules)
                )
            }
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

    /// Resolves the active installed group membership for a profile, or nil
    /// if the profile is unlinked or its membership cannot sign yet.
    private func activeGroupMembership(for profile: ClientProfile) -> (WalletGroup, AgentMembership)? {
        guard let groupId = profile.walletGroupId,
              let memberId = profile.membershipId,
              let group = config.walletGroups.first(where: { $0.id == groupId }),
              let member = group.member(id: memberId),
              member.installStatus.isInstalled else {
            return nil
        }
        return (group, member)
    }

    func signingBlockedReason(for bundleId: String?) -> String? {
        ensureConfigLoadedIfNeeded()
        guard let profile = clientProfile(bundleId: bundleId) else {
            return "Client is not paired with Bastion"
        }
        return linkedGroupMembershipBlockReason(for: profile)
    }

    private func linkedGroupMembershipBlockReason(for profile: ClientProfile) -> String? {
        guard profile.walletGroupId != nil || profile.membershipId != nil else {
            return nil
        }
        guard let groupId = profile.walletGroupId,
              let memberId = profile.membershipId,
              let group = config.walletGroups.first(where: { $0.id == groupId }),
              let member = group.member(id: memberId) else {
            return "Client wallet-group membership is missing; signing is blocked"
        }
        switch member.installStatus {
        case .installed:
            return nil
        case .pending:
            return "Agent validator is pending on-chain installation"
        case .revoked:
            return "Agent validator has been revoked"
        }
    }

    // MARK: - Validation

    enum ValidationResult {
        case allowed
        /// Non-overrideable safety stop. SigningManager must reject these
        /// without opening the owner-override approval path.
        case blocked(reasons: [String])
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
        /// Optional counterparty / decoded recipient. Used for per-target
        /// scoping of spending limit rules. Nil when the observation came
        /// from a path that doesn't expose a target (e.g. trace-derived
        /// totals before counterparty enrichment).
        let target: String?

        nonisolated init(token: TokenIdentifier, amount: String, target: String? = nil) {
            self.token = token
            self.amount = amount
            self.target = target?.lowercased()
        }
    }

    private enum SessionSpendToken: String {
        case eth
        case usdc
    }

    private struct SessionSpendTotals {
        var nativeWei: UInt128 = 0
        var usdcBaseUnits: UInt128 = 0
    }

    private enum SpendEvaluation {
        case noMatch
        case amount(UInt128)
        case unsupportedAmount
    }

    /// Validates a signing operation against all configured rules.
    ///
    /// When `traceAnalysis` and `simulatedSpendObservations` are provided (from preflight
    /// simulation), they are used to enhance spending limit and target validation with
    /// actual on-chain execution data rather than static calldata decoding alone.
    nonisolated func validate(
        _ request: SignRequest,
        config: BastionConfig,
        traceAnalysis: TraceAnalysis? = nil,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> ValidationResult {
        // v9: pause / emergency lockdown rejects everything before we look at
        // per-operation rules. Lockdown produces a more pointed reason.
        if config.pauseState.lockedDown {
            let reason = config.pauseState.reason ?? "Bastion is locked down — owner suspended all signing"
            return .blocked(reasons: [reason])
        }
        if config.pauseState.paused {
            let reason = config.pauseState.reason ?? "Bastion is paused — resume from the menu bar to sign"
            return .blocked(reasons: [reason])
        }

        // v9: temporary scoped agent sessions tighten the rule check. A session
        // can only narrow what the profile already allows — never widen it.
        if let denial = validateActiveSessions(
            request,
            traceAnalysis: traceAnalysis,
            simulatedSpendObservations: simulatedSpendObservations
        ) {
            return denial
        }

        // PR2: skip rule evaluation when this operation's posture says so.
        // Per-operation rather than the old single `enabled` flag, so a
        // user can keep userOp rule evaluation while turning off raw-msg
        // rules independently. requiresExplicitApproval will still force
        // the approval popup for `.requireApprovalWithoutRuleEvaluation`,
        // so "skip rules" never means "auto-sign without owner check".
        guard posture(for: request, config: config).evaluatesRules else {
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
            return mergeValidation(commonReasons, validateUserOperation(
                request,
                config: config,
                traceAnalysis: traceAnalysis,
                simulatedSpendObservations: simulatedSpendObservations
            ))
        }
    }

    /// v9 session-scope check. Looks up active sessions for the request's
    /// client and tightens the check: chain must be in session.chains, target
    /// must be in session.allowedTargets if non-empty, and the request must
    /// arrive before session.expiresAt. Returns a denial if any constraint
    /// fails; nil means sessions don't apply or all session constraints pass.
    private nonisolated func validateActiveSessions(
        _ request: SignRequest,
        traceAnalysis: TraceAnalysis? = nil,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> ValidationResult? {
        if let reason = SessionSnapshotStore.shared.storageHealthFailure() {
            return .blocked(reasons: [reason])
        }
        guard SessionSnapshotStore.shared.anyActive() else { return nil }

        // Match by bundleId — the only identity the rule engine has at this
        // point. SessionStore stores the bundleId at grant-time so we don't
        // need to dip into MainActor-isolated config here.
        let sessions = SessionSnapshotStore.shared.activeSessions(
            forBundleId: request.clientBundleId
        )
        guard !sessions.isEmpty else { return nil }

        // Each active session imposes its own scope; the tightest applies.
        // If any active grant for this client forbids the operation, deny.
        var deniedReasons: [String] = []

        for session in sessions {
            if let chainId = request.operation.chainId,
               !session.chains.isEmpty,
               !session.chains.contains(chainId) {
                deniedReasons.append("Session for \(session.clientLabel) does not allow chain \(chainId)")
                continue
            }
            // Target + spending checks for userOps only — message and
            // typedData operations don't decode into per-target spends.
            if case .userOperation(let op) = request.operation {
                let decoded = CalldataDecoder.decode(op)
                let leaves = decoded.executions.flatMap(\.allLeafExecutions)

                if !session.allowedTargets.isEmpty {
                    let targets = sessionTargetAddresses(
                        leaves: leaves,
                        traceAnalysis: traceAnalysis,
                        senderAddress: op.sender
                    )
                    let allow = Set(session.allowedTargets.map { $0.lowercased() })
                    if let outOfScope = targets.first(where: { !allow.contains($0) }) {
                        deniedReasons.append("Session does not allow target \(outOfScope.prefix(10))…")
                        continue
                    }
                }

                if let spendDenial = exceedsSessionSpend(
                    session: session,
                    leaves: leaves,
                    simulatedSpendObservations: simulatedSpendObservations
                ) {
                    deniedReasons.append(spendDenial)
                }
            }
        }

        if !deniedReasons.isEmpty { return .denied(reasons: deniedReasons) }
        return nil
    }

    private nonisolated func sessionTargetAddresses(
        leaves: [CalldataDecoder.DecodedExecution],
        traceAnalysis: TraceAnalysis?,
        senderAddress: String?
    ) -> [String] {
        var targets = Set(leaves.map { normalizedAddress($0.to) })
        guard let traceAnalysis else {
            return Array(targets)
        }
        var infra = Set<String>()
        if let senderAddress {
            infra.insert(normalizedAddress(senderAddress))
        }
        infra.insert(normalizedAddress(EntryPointAddress.v0_7))
        infra.insert(normalizedAddress(EntryPointAddress.v0_8))
        infra.insert(normalizedAddress(EntryPointAddress.v0_9))
        infra.insert(normalizedAddress("0x0000000000000000000000000000000000000000"))
        for address in traceAnalysis.touchedAddresses.map(normalizedAddress) {
            guard !infra.contains(address), !isPrecompileAddress(address) else { continue }
            targets.insert(address)
        }
        return Array(targets)
    }

    /// Sums USDC + ETH spends across `leaves` and compares projected
    /// cumulative spend against the session's caps.
    private nonisolated func exceedsSessionSpend(
        session: AgentSession,
        leaves: [CalldataDecoder.DecodedExecution],
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> String? {
        let totals: SessionSpendTotals
        do {
            totals = try sessionSpendTotals(
                staticTotals: sessionSpendTotals(leaves: leaves),
                simulatedSpendObservations: simulatedSpendObservations
            )
        } catch {
            return "Session spend evaluation failed — denying"
        }

        if let cap = session.ethLimit {
            guard cap.isFinite, cap >= 0 else {
                return "Invalid session ETH cap — denying"
            }
            let capWei = UInt128(cap * 1e18)
            let spent = stateStore.spentAmount(
                ruleId: Self.sessionSpendRuleId(sessionId: session.id, token: .eth),
                windowSeconds: sessionWindowSeconds(session)
            )
            let (projected, overflow) = spent.addingReportingOverflow(totals.nativeWei)
            if overflow || projected > capWei {
                return "Session ETH cap exceeded (\(cap) ETH max)"
            }
        }
        if let cap = session.usdcLimit {
            guard cap.isFinite, cap >= 0 else {
                return "Invalid session USDC cap — denying"
            }
            let capBase = UInt128(cap * 1e6)
            let spent = stateStore.spentAmount(
                ruleId: Self.sessionSpendRuleId(sessionId: session.id, token: .usdc),
                windowSeconds: sessionWindowSeconds(session)
            )
            let (projected, overflow) = spent.addingReportingOverflow(totals.usdcBaseUnits)
            if overflow || projected > capBase {
                return "Session USDC cap exceeded (\(Int(cap)) USDC max)"
            }
        }
        return nil
    }

    private nonisolated func recordActiveSessionSpendIfNeeded(
        request: SignRequest,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) throws {
        guard case .userOperation(let op) = request.operation else { return }
        let sessions = SessionSnapshotStore.shared.activeSessions(forBundleId: request.clientBundleId)
        guard !sessions.isEmpty else { return }

        let decoded = CalldataDecoder.decode(op)
        let totals = try sessionSpendTotals(
            staticTotals: sessionSpendTotals(leaves: decoded.executions.flatMap(\.allLeafExecutions)),
            simulatedSpendObservations: simulatedSpendObservations
        )
        guard totals.nativeWei > 0 || totals.usdcBaseUnits > 0 else { return }

        for session in sessions {
            let windowSeconds = sessionWindowSeconds(session)
            if session.ethLimit != nil && totals.nativeWei > 0 {
                guard stateStore.recordSpend(
                    ruleId: Self.sessionSpendRuleId(sessionId: session.id, token: .eth),
                    amount: String(totals.nativeWei),
                    windowSeconds: windowSeconds
                ) else {
                    throw BastionError.storageFailed
                }
            }
            if session.usdcLimit != nil && totals.usdcBaseUnits > 0 {
                guard stateStore.recordSpend(
                    ruleId: Self.sessionSpendRuleId(sessionId: session.id, token: .usdc),
                    amount: String(totals.usdcBaseUnits),
                    windowSeconds: windowSeconds
                ) else {
                    throw BastionError.storageFailed
                }
            }
        }
    }

    private nonisolated func sessionSpendTotals(
        leaves: [CalldataDecoder.DecodedExecution]
    ) throws -> SessionSpendTotals {
        var totals = SessionSpendTotals()
        let knownUsdcAddresses = Set(USDCAddresses.addresses.values.map { $0.lowercased() })

        for leaf in leaves {
            if leaf.value != "0" {
                guard let v = UInt128(leaf.value) else { throw BastionError.ruleViolation }
                let (sum, overflow) = totals.nativeWei.addingReportingOverflow(v)
                if overflow { throw BastionError.ruleViolation }
                totals.nativeWei = sum
            }
            if let tokenOp = leaf.tokenOperation,
               knownUsdcAddresses.contains(leaf.to.lowercased()) {
                guard let amt = UInt128(tokenOp.amount) else { throw BastionError.ruleViolation }
                let (sum, overflow) = totals.usdcBaseUnits.addingReportingOverflow(amt)
                if overflow { throw BastionError.ruleViolation }
                totals.usdcBaseUnits = sum
            }
        }

        return totals
    }

    private nonisolated func sessionSpendTotals(
        staticTotals: SessionSpendTotals,
        simulatedSpendObservations: [SimulatedSpendObservation]?
    ) throws -> SessionSpendTotals {
        guard let simulatedSpendObservations, !simulatedSpendObservations.isEmpty else {
            return staticTotals
        }
        var simulated = SessionSpendTotals()
        for observation in simulatedSpendObservations {
            guard let amount = UInt128(observation.amount) else { throw BastionError.ruleViolation }
            switch observation.token {
            case .eth:
                let (sum, overflow) = simulated.nativeWei.addingReportingOverflow(amount)
                if overflow { throw BastionError.ruleViolation }
                simulated.nativeWei = sum
            case .usdc:
                let (sum, overflow) = simulated.usdcBaseUnits.addingReportingOverflow(amount)
                if overflow { throw BastionError.ruleViolation }
                simulated.usdcBaseUnits = sum
            case .erc20:
                continue
            }
        }
        return SessionSpendTotals(
            nativeWei: max(staticTotals.nativeWei, simulated.nativeWei),
            usdcBaseUnits: max(staticTotals.usdcBaseUnits, simulated.usdcBaseUnits)
        )
    }

    private nonisolated func sessionWindowSeconds(_ session: AgentSession) -> Int {
        max(1, Int(ceil(session.expiresAt.timeIntervalSince(session.startedAt))))
    }

    private nonisolated static func sessionSpendRuleId(sessionId: UUID, token: SessionSpendToken) -> String {
        "session.\(sessionId.uuidString).\(token.rawValue)"
    }

    nonisolated func requiresExplicitApproval(
        for request: SignRequest,
        config: BastionConfig,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> Bool {
        // PR2: posture is the single source of truth. Each operation type
        // carries its own posture; the legacy enabled / requireExplicit
        // booleans are derived for wire compatibility but ignored here.
        // SigningPosture.requiresApprovalPopup encodes the post-PR23
        // semantic that "skip rules" means "always approve" — the
        // disabled-UserOp auto-sign bug is now structurally impossible.
        if highValueConfirmationPhrase(
            for: request,
            config: config,
            simulatedSpendObservations: simulatedSpendObservations
        ) != nil {
            return true
        }
        if case .typedData(let typedData) = request.operation,
           PermitClassifier.classify(typedData) != nil {
            return true
        }
        return posture(for: request, config: config).requiresApprovalPopup
    }

    nonisolated func highValueConfirmationPhrase(
        for request: SignRequest,
        config: BastionConfig,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> String? {
        guard config.highValue.enabled,
              case .userOperation(let op) = request.operation else {
            return nil
        }
        guard let phrase = normalizedHighValuePhrase(config.highValue) else {
            return nil
        }
        let threshold = config.highValue.thresholdUsd
        guard threshold.isFinite, threshold > 0 else {
            return phrase
        }
        let simulatedSpendMatches = simulatedSpendObservations.map {
            highValueSpendMatches(observations: $0, thresholdUsd: threshold)
        } ?? false
        if simulatedSpendMatches {
            return phrase
        }

        let decoded = CalldataDecoder.decode(op)
        let staticSpendMatches = highValueSpendMatches(
            observations: spendObservations(from: decoded.executions, chainId: op.chainId),
            thresholdUsd: threshold
        )
        return staticSpendMatches ? phrase : nil
    }

    private nonisolated func normalizedHighValuePhrase(_ rule: HighValueRule) -> String? {
        guard rule.enabled else { return nil }
        let trimmed = rule.confirmationPhrase.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? HighValueRule.default.confirmationPhrase : trimmed
    }

    private nonisolated func highValueSpendMatches(
        observations: [SpendObservation],
        thresholdUsd: Double
    ) -> Bool {
        highValueSpendMatches(
            observations: observations.map { ($0.token, $0.amount) },
            thresholdUsd: thresholdUsd
        )
    }

    private nonisolated func highValueSpendMatches(
        observations: [SimulatedSpendObservation],
        thresholdUsd: Double
    ) -> Bool {
        highValueSpendMatches(
            observations: observations.map { ($0.token, $0.amount) },
            thresholdUsd: thresholdUsd
        )
    }

    private nonisolated func highValueSpendMatches(
        observations: [(TokenIdentifier, String)],
        thresholdUsd: Double
    ) -> Bool {
        var usdcTotal: UInt128 = 0
        for (token, amount) in observations {
            guard let parsed = UInt128(amount) else {
                return true
            }
            guard parsed > 0 else { continue }
            switch token {
            case .usdc:
                let (sum, overflow) = usdcTotal.addingReportingOverflow(parsed)
                if overflow { return true }
                usdcTotal = sum
            case .eth, .erc20:
                // Without a trusted price oracle, non-USDC spend cannot be proven
                // below a USD threshold. Require the extra typed confirmation.
                return true
            }
        }
        return (Double(String(usdcTotal)) ?? Double.greatestFiniteMagnitude) / 1_000_000 >= thresholdUsd
    }

    /// Resolves the posture for a given request. Public so SigningManager
    /// and tests can ask the same question the validator asks.
    nonisolated func posture(for request: SignRequest, config: BastionConfig) -> SigningPosture {
        switch request.operation {
        case .message, .rawBytes: return config.rules.rawMessagePolicy.posture
        case .typedData:          return config.rules.typedDataPolicy.posture
        case .userOperation:      return config.rules.userOpPosture
        }
    }

    /// Records state after a successful sign (increment counters, track spending).
    ///
    /// M-06: When `simulatedSpendObservations` is provided, trace-based observations are
    /// used for recording spending (same data that validation used). When nil, falls back
    /// to static calldata inspection (original behavior).
    nonisolated func recordSuccess(
        request: SignRequest,
        config: BastionConfig,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) throws {
        guard case .userOperation = request.operation else {
            return
        }

        try recordUserOperationSuccess(
            request: request,
            config: config,
            simulatedSpendObservations: simulatedSpendObservations
        )
        try recordActiveSessionSpendIfNeeded(
            request: request,
            simulatedSpendObservations: simulatedSpendObservations
        )
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

    private nonisolated func validateUserOperation(
        _ request: SignRequest,
        config: BastionConfig,
        traceAnalysis: TraceAnalysis? = nil,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) -> ValidationResult {
        var reasons: [String] = []
        let inspection = inspect(request.operation)

        // C-01: Opaque calldata (delegatecall, unknown call types) is ALWAYS denied
        // regardless of which rules are configured. This prevents bypass when only
        // rate limits or hours are set.
        if case .opaque(let reason) = inspection {
            reasons.append("UserOperation calldata cannot be verified: \(reason)")
        }
        if case .known(_, _, _, let hasUnrecognizedCalldata) = inspection,
           hasUnrecognizedCalldata {
            reasons.append("UserOperation contains unrecognized function calls — calldata cannot be fully verified")
        }

        // 1. Allowed hours
        if let hours = config.rules.allowedHours {
            // P1: an empty window (start == end) is the merge sentinel for
            // "group ∩ member windows are disjoint" — every hour is denied
            // and we surface a clearer reason than the standard "outside
            // hours X:00 - X:00".
            if hours.start == hours.end {
                reasons.append("Wallet group and agent allowed-hours have no overlap — no hours permitted")
            } else {
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
        }

        // 2. Chain ID check
        if let allowedChains = config.rules.allowedChains,
           let chainId = request.operation.chainId {
            if !allowedChains.contains(chainId) {
                reasons.append("Chain \(ChainConfig.name(for: chainId)) (\(chainId)) not allowed")
            }
        }

        // 3. Target check (verifying contract or decoded inner call targets)
        // When trace analysis is available, also check traced addresses against the allowlist.
        if let allowedTargets = config.rules.allowedTargets,
           let chainId = request.operation.chainId {
            let senderAddr: String? = {
                if case .userOperation(let op) = request.operation { return op.sender }
                return nil
            }()
            validateTargets(
                inspection: inspection,
                allowedTargets: allowedTargets,
                chainId: chainId,
                traceAnalysis: traceAnalysis,
                senderAddress: senderAddr,
                reasons: &reasons
            )
        }

        // 3a. Allowed selectors (per-target function whitelist)
        if let allowedSelectors = config.rules.allowedSelectors {
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

        // 5. Spending limit checks (native ETH + direct ERC-20 transfers/approvals).
        // When trace-based simulated spend observations are available, they override
        // static calldata-derived observations because they capture transfers at any
        // call depth, including DeFi protocol side effects (e.g., swap outputs).
        validateSpendingLimits(
            inspection: inspection,
            rules: config.rules.spendingLimits,
            simulatedObservations: simulatedSpendObservations,
            reasons: &reasons
        )

        if reasons.isEmpty {
            return .allowed
        }
        return .denied(reasons: reasons)
    }

    private nonisolated func recordUserOperationSuccess(
        request: SignRequest,
        config: BastionConfig,
        simulatedSpendObservations: [SimulatedSpendObservation]? = nil
    ) throws {
        // Record rate limit entries
        for rule in config.rules.rateLimits {
            guard stateStore.recordRequest(ruleId: rule.id, windowSeconds: rule.windowSeconds) else {
                throw BastionError.storageFailed
            }
        }

        guard case .known(_, _, let staticObservations, _) = inspect(request.operation) else {
            return
        }

        // M-06: Use the same max-of-both principle as validation. When trace-based
        // observations are available, record the higher of static vs trace spend
        // so counters stay consistent with what validation checked.
        let traceObservations: [SpendObservation]? = {
            guard let simulated = simulatedSpendObservations, !simulated.isEmpty else { return nil }
            return simulated.map { SpendObservation(token: $0.token, amount: $0.amount) }
        }()

        for rule in config.rules.spendingLimits {
            let staticEval = matchedSpendAmount(for: rule, observations: staticObservations)
            let traceEval = traceObservations.map { matchedSpendAmount(for: rule, observations: $0) }

            let staticAmount: UInt128
            switch staticEval {
            case .amount(let a): staticAmount = a
            case .noMatch: staticAmount = 0
            case .unsupportedAmount: continue
            }

            let traceAmount: UInt128
            if let te = traceEval {
                switch te {
                case .amount(let a): traceAmount = a
                case .noMatch: traceAmount = 0
                case .unsupportedAmount: continue
                }
            } else {
                traceAmount = 0
            }

            let effectiveAmount = max(staticAmount, traceAmount)
            guard effectiveAmount > 0 else { continue }
            guard stateStore.recordSpend(
                ruleId: rule.id,
                amount: String(effectiveAmount),
                windowSeconds: rule.windowSeconds
            ) else {
                throw BastionError.storageFailed
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
        if let denial = Self.clientAllowlistDenial(bundleId: request.clientBundleId, rules: rules) {
            reasons.append(denial)
        }
    }

    private nonisolated func mergeValidation(
        _ commonReasons: [String],
        _ operationValidation: ValidationResult
    ) -> ValidationResult {
        switch operationValidation {
        case .allowed:
            return commonReasons.isEmpty ? .allowed : .denied(reasons: commonReasons)
        case .blocked(let reasons):
            return .blocked(reasons: commonReasons + reasons)
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
                // R3-04: Use leaf executions for selector extraction so that denied
                // selectors cannot be bypassed by wrapping calls in a multicall.
                // Targets and hasUnrecognizedCalldata are computed from top-level
                // executions (the decoder already flattens inner targets there),
                // but SelectorObservations must reflect the actual functions called.
                let leafExecutions = executions.flatMap(\.allLeafExecutions)
                let hasUnrecognized = executions.contains(where: \.hasUnrecognizedCalldata)
                return .known(
                    targets: executions.map(\.to),
                    selectors: leafExecutions.map { SelectorObservation(target: $0.to, selector: $0.selector) },
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

        // Use allLeafExecutions so that multicall wrappers are transparently unwrapped:
        // a multicall with two ERC-20 transfers produces two leaf executions, each
        // contributing its own SpendObservation. Without this, only the multicall node
        // itself would be inspected and its tokenOperation is nil by design.
        for execution in executions.flatMap(\.allLeafExecutions) {
            if execution.value != "0" {
                // Native ETH transfer — target is the call's `to`.
                observations.append(SpendObservation(
                    token: .eth,
                    amount: execution.value,
                    target: execution.to
                ))
            }

            // R3-01: Approvals count toward spending limits. Unlimited approvals
            // (amount == type(uint256).max) produce nil from UInt128 parsing and
            // fall through to .unsupportedAmount → denial, forcing biometric override.
            if let tokenOperation = execution.tokenOperation {
                let token: TokenIdentifier
                if let usdcAddress = USDCAddresses.address(for: chainId),
                   usdcAddress.caseInsensitiveCompare(execution.to) == .orderedSame {
                    token = .usdc
                } else {
                    token = .erc20(address: execution.to, chainId: chainId)
                }
                // For ERC-20 transfer/approve, the per-target scope refers to
                // the counterparty (token recipient or spender), not the token
                // contract. Falls back to the contract address when unknown.
                let target = tokenOperation.counterparty ?? execution.to
                observations.append(SpendObservation(token: token, amount: tokenOperation.amount, target: target))
            }
        }

        return observations
    }

    private nonisolated func validateTargets(
        inspection: OperationInspection,
        allowedTargets: [String: [String]],
        chainId: Int,
        traceAnalysis: TraceAnalysis? = nil,
        senderAddress: String? = nil,
        reasons: inout [String]
    ) {
        guard !allowedTargets.isEmpty else {
            reasons.append("No targets allowed for any chain")
            return
        }
        let chainKey = String(chainId)
        // Distinguish "key absent" (no restriction for this chain) from "key
        // present but empty" (deny-all). The merge logic emits an empty
        // sentinel array for impossible intersections — treating that as
        // "no restriction" was the prior bug.
        guard let chainTargets = allowedTargets[chainKey] else {
            return
        }
        guard !chainTargets.isEmpty else {
            reasons.append("No targets allowed for chain \(chainId)")
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

            // When trace analysis is available, also check all addresses touched during
            // simulated execution. This catches targets reached via internal calls (e.g.,
            // a router calling into a pool contract) that static calldata decoding misses.
            if let trace = traceAnalysis {
                // R2-H-01: Filter infrastructure addresses from trace to avoid false denials.
                // EntryPoints, the account itself, precompiles, and the zero address are not
                // meaningful targets — they appear in every UserOp execution trace.
                let infraAddresses: Set<String> = {
                    var infra = Set<String>()
                    if let sender = senderAddress {
                        infra.insert(normalizedAddress(sender))
                    }
                    infra.insert(normalizedAddress(EntryPointAddress.v0_7))
                    infra.insert(normalizedAddress(EntryPointAddress.v0_8))
                    infra.insert(normalizedAddress(EntryPointAddress.v0_9))
                    infra.insert(normalizedAddress("0x0000000000000000000000000000000000000000"))
                    return infra
                }()

                let tracedTargets = trace.touchedAddresses
                    .map(normalizedAddress)
                    .filter { addr in
                        !infraAddresses.contains(addr) && !isPrecompileAddress(addr)
                    }

                for normalized in tracedTargets {
                    // Skip addresses already checked via static inspection to avoid
                    // duplicate violation messages.
                    guard !normalizedTargets.contains(normalized) else { continue }
                    if !normalizedAllowed.contains(normalized) {
                        reasons.append("Traced target \(shortAddress(normalized)) not in allowlist for chain \(chainId)")
                    }
                }
            }
        }
    }

    private nonisolated func validateAllowedSelectors(
        inspection: OperationInspection,
        allowedSelectors: [String: [String]],
        reasons: inout [String]
    ) {
        guard !allowedSelectors.isEmpty else {
            reasons.append("No function selectors allowed")
            return
        }
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
        simulatedObservations: [SimulatedSpendObservation]? = nil,
        reasons: inout [String]
    ) {
        guard !rules.isEmpty else { return }

        switch inspection {
        case .opaque(let reason):
            reasons.append("Unable to inspect UserOperation spending: \(reason)")
        case .notApplicable:
            return
        case .known(_, _, let staticObservations, let hasUnrecognizedCalldata):
            // H-02: Unrecognized function selectors mean spending cannot be verified.
            // This is a hard block regardless of whether trace data is available.
            // Trace data can supplement but never excuse opaque calldata.
            if hasUnrecognizedCalldata {
                reasons.append("UserOperation contains unrecognized function calls — spending cannot be fully verified")
            }

            // H-02: Max-of-both principle. Always compute static spend. If trace-based
            // observations are available, also compute trace spend. For each rule, use
            // the HIGHER of the two amounts. This ensures trace data can only ADD
            // spending (e.g., catching DeFi side-effects), never reduce it.
            let traceObservations: [SpendObservation]? = {
                guard let simulated = simulatedObservations, !simulated.isEmpty else { return nil }
                return simulated.map { SpendObservation(token: $0.token, amount: $0.amount) }
            }()

            for rule in rules {
                let staticEval = matchedSpendAmount(for: rule, observations: staticObservations)
                let traceEval = traceObservations.map { matchedSpendAmount(for: rule, observations: $0) }

                // If either source reports unsupported, treat as unsupported.
                if case .unsupportedAmount = staticEval {
                    reasons.append("Unable to safely evaluate \(rule.token.displayName) amount for spending limit")
                    continue
                }
                if case .unsupportedAmount = traceEval {
                    reasons.append("Unable to safely evaluate \(rule.token.displayName) amount for spending limit (trace)")
                    continue
                }

                let staticAmount: UInt128
                switch staticEval {
                case .amount(let a): staticAmount = a
                case .noMatch: staticAmount = 0
                case .unsupportedAmount: continue // already handled above
                }

                let traceAmount: UInt128
                if let te = traceEval {
                    switch te {
                    case .amount(let a): traceAmount = a
                    case .noMatch: traceAmount = 0
                    case .unsupportedAmount: continue // already handled above
                    }
                } else {
                    traceAmount = 0
                }

                let pendingSpend = max(staticAmount, traceAmount)
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

    private nonisolated func matchedSpendAmount(
        for rule: SpendingLimitRule,
        observations: [SpendObservation]
    ) -> SpendEvaluation {
        var total: UInt128 = 0
        var sawMatch = false

        for observation in observations where matches(rule.token, observation.token) {
            // v9: per-target scoping. When the rule is target-scoped, only
            // observations whose decoded target matches contribute. Trace-only
            // observations (target == nil) are conservatively counted toward
            // every per-target rule that *could* apply, rather than silently
            // skipped, so we never under-count spending.
            if let ruleTarget = rule.targetAddress {
                if let observedTarget = observation.target, observedTarget != ruleTarget {
                    continue
                }
            }
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

    /// R2-H-01: Returns true if the address is a precompile (numeric value < 0x200 / 512).
    private nonisolated func isPrecompileAddress(_ address: String) -> Bool {
        let hex = address.hasPrefix("0x") ? String(address.dropFirst(2)) : address
        guard let data = Data(hexString: hex), data.count <= 20 else { return false }
        // Pad to 20 bytes and check if the value is < 0x200.
        // Addresses < 0x200 have all leading bytes zero except possibly the last two,
        // and the last two bytes form a value < 512.
        let bytes = [UInt8](data)
        let padCount = max(0, 20 - bytes.count)
        // Check all bytes except the last two are zero.
        for i in 0..<(padCount + bytes.count - 2) {
            let byteValue: UInt8
            if i < padCount {
                byteValue = 0
            } else {
                byteValue = bytes[i - padCount]
            }
            if byteValue != 0 { return false }
        }
        // Last two bytes form a uint16 value.
        let highByte: UInt8 = bytes.count >= 2 ? bytes[bytes.count - 2] : 0
        let lowByte: UInt8 = bytes[bytes.count - 1]
        let value = UInt16(highByte) << 8 | UInt16(lowByte)
        return value < 0x200
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

    private func validateBastionConfig(_ config: BastionConfig) throws {
        try validateRuleConfig(config.rules)
        for profile in config.clientProfiles {
            try validateRuleConfig(profile.rules)
        }
        for group in config.walletGroups {
            try validateRuleConfig(group.sharedRules)
            for member in group.members {
                try validateRuleConfig(member.scopedRules)
            }
        }
        if config.highValue.enabled,
           (!config.highValue.thresholdUsd.isFinite || config.highValue.thresholdUsd <= 0) {
            throw BastionError.invalidInput
        }
    }

    func validateRuleConfig(_ rules: RuleConfig) throws {
        for rule in rules.rateLimits {
            guard rule.maxRequests > 0, rule.windowSeconds > 0 else {
                throw BastionError.invalidInput
            }
        }
        for rule in rules.spendingLimits {
            guard UInt128(rule.allowance) != nil else {
                throw BastionError.invalidInput
            }
            if let windowSeconds = rule.windowSeconds, windowSeconds <= 0 {
                throw BastionError.invalidInput
            }
        }
    }

    private func normalizedConfig(_ config: BastionConfig) -> BastionConfig {
        var normalized = config
        normalized.version = 9
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
        if normalized.highValue.enabled {
            normalized.highValue.confirmationPhrase =
                normalizedHighValuePhrase(normalized.highValue) ?? HighValueRule.default.confirmationPhrase
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

    /// Forces fresh UUIDs for any rate-limit or spending-limit rule. Used when
    /// accepting a `RuleConfig` from an external caller (e.g. CLI / MCP) to
    /// guarantee that two agents in the same wallet group cannot share a
    /// counter key in `StateStore`. State counters are keyed by rule.id, so
    /// duplicate IDs would let one agent's spend exhaust another's budget.
    nonisolated func regeneratedScopedRuleIDs(_ rules: RuleConfig) -> RuleConfig {
        var out = rules
        out.rateLimits = rules.rateLimits.map {
            RateLimitRule(id: UUID().uuidString, maxRequests: $0.maxRequests, windowSeconds: $0.windowSeconds)
        }
        out.spendingLimits = rules.spendingLimits.map {
            SpendingLimitRule(id: UUID().uuidString, token: $0.token, allowance: $0.allowance, windowSeconds: $0.windowSeconds)
        }
        return out
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
        // Non-creating lookup. The previous getPublicKey path lazily
        // materialised an SE key when none existed — fine on the signing
        // hot path, but render-path callers (settings header, menu bar
        // snapshot, ClientProfileInfo bridging) would prompt biometric on
        // every redraw. Returning nil for "no key yet" lets the UI hide
        // the address until the first real sign creates the key.
        #if DEBUG
        if let runtimeQAPublicKey = try? RuntimeQASigningProvider.shared.publicKeyIfEnabled(keyTag: keyTag) {
            return runtimeQAPublicKey.accountAddress
        }
        #endif
        return SecureEnclaveManager.shared.getPublicKeyIfExists(keyTag: keyTag)?.accountAddress
    }

    // MARK: - Wallet Group Management

    /// Maximum wallet groups per install — cap prevents unbounded SE key growth.
    private nonisolated static let maxWalletGroups = 10
    /// Maximum agents per group — paired with maxClientProfiles (20) so an owner
    /// can't exceed practical SE slot budget.
    private nonisolated static let maxAgentsPerGroup = 20

    nonisolated static func normalizedWalletGroupLabel(_ label: String) throws -> String {
        let normalized = label.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !normalized.isEmpty else {
            throw BastionError.invalidInput
        }
        return normalized
    }

    nonisolated static func normalizedWalletGroupMemberLabel(_ label: String?) -> String? {
        let trimmed = label?.trimmingCharacters(in: .whitespacesAndNewlines)
        return (trimmed?.isEmpty == true) ? nil : trimmed
    }

    #if DEBUG
    private nonisolated static func runtimeQAWalletGroupOwnerKeyTag(groupId: String) -> String {
        "\(RuntimeQASigningProvider.keyTagPrefix)walletgroup.\(groupId.lowercased()).owner"
    }

    private nonisolated static func runtimeQAWalletGroupAgentKeyTag(groupId: String, memberId: String) -> String {
        "\(RuntimeQASigningProvider.keyTagPrefix)walletgroup.\(groupId.lowercased()).agent.\(memberId.lowercased())"
    }

    private func runtimeQAGroupPublicKeyIfEnabled(keyTag: String) throws -> PublicKeyResponse? {
        guard runtimeQAConfigOverride.isEnabled() else {
            return nil
        }
        return try RuntimeQASigningProvider.shared.publicKeyIfEnabled(keyTag: keyTag)
    }
    #endif

    func listWalletGroups() -> [WalletGroup] {
        ensureConfigLoadedIfNeeded()
        return config.walletGroups
    }

    func walletGroup(id: String) -> WalletGroup? {
        ensureConfigLoadedIfNeeded()
        return config.walletGroups.first(where: { $0.id == id })
    }

    /// Creates a wallet group and provisions the owner's sudo SE key.
    /// Requires biometric/passcode auth — owner operations are always gated.
    func createWalletGroup(
        label: String,
        chainIds: [Int] = [],
        sharedRules: RuleConfig = .default
    ) async throws -> WalletGroup {
        let normalizedLabel = try Self.normalizedWalletGroupLabel(label)

        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to create wallet group \"\(normalizedLabel)\""
        )

        ensureConfigLoadedIfNeeded()

        guard config.walletGroups.count < Self.maxWalletGroups else {
            throw BastionError.ruleViolation
        }
        try validateRuleConfig(sharedRules)

        let groupId = UUID().uuidString
        let ownerKeyTag: String
        let pubkey: PublicKeyResponse
        #if DEBUG
        let runtimeQAOwnerKeyTag = Self.runtimeQAWalletGroupOwnerKeyTag(groupId: groupId)
        if let runtimeQAPubkey = try runtimeQAGroupPublicKeyIfEnabled(keyTag: runtimeQAOwnerKeyTag) {
            ownerKeyTag = runtimeQAOwnerKeyTag
            pubkey = runtimeQAPubkey
        } else {
            ownerKeyTag = WalletGroup.makeOwnerKeyTag(groupId: groupId)
            _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: ownerKeyTag)
            pubkey = try SecureEnclaveManager.shared.getPublicKey(keyTag: ownerKeyTag)
        }
        #else
        ownerKeyTag = WalletGroup.makeOwnerKeyTag(groupId: groupId)
        _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: ownerKeyTag)
        pubkey = try SecureEnclaveManager.shared.getPublicKey(keyTag: ownerKeyTag)
        #endif

        let group = WalletGroup(
            id: groupId,
            label: normalizedLabel,
            ownerKeyTag: ownerKeyTag,
            accountAddress: pubkey.accountAddress,
            chainIds: chainIds,
            sharedRules: sharedRules,
            members: [],
            createdAt: Date()
        )

        config.walletGroups.append(group)
        config = normalizedConfig(config)
        do {
            try saveConfig(config)
        } catch {
            // Rollback in-memory state; SE key is orphaned but harmless (no profile binds to it).
            config.walletGroups.removeAll { $0.id == groupId }
            throw error
        }

        auditLog.record(AuditEvent(
            type: .walletGroupCreated,
            dataPrefix: "walletgroup.\(groupId.prefix(8))",
            reason: "Created wallet group \"\(normalizedLabel)\" (\(pubkey.accountAddress ?? "unknown"))"
        ))

        return group
    }

    /// Adds a new agent to a wallet group with a freshly provisioned SE key.
    /// The optional `clientProfileId` binds an existing profile to this
    /// membership; if omitted, the caller can later register a profile and
    /// link it via `linkClientProfile`.
    func addAgentToGroup(
        groupId: String,
        label: String?,
        clientProfileId: String?,
        scopedRules: RuleConfig = .default
    ) async throws -> AgentMembership {
        let normalizedLabel = Self.normalizedWalletGroupMemberLabel(label)

        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to add an agent to the wallet group"
        )

        ensureConfigLoadedIfNeeded()

        guard let groupIdx = config.walletGroups.firstIndex(where: { $0.id == groupId }) else {
            throw BastionError.invalidInput
        }

        guard config.walletGroups[groupIdx].members.count < Self.maxAgentsPerGroup else {
            throw BastionError.ruleViolation
        }
        try validateRuleConfig(scopedRules)

        // Validate that clientProfileId, if provided, actually exists and is
        // not already a member of another group.
        if let profileId = clientProfileId {
            guard let idx = config.clientProfiles.firstIndex(where: { $0.id == profileId }) else {
                throw BastionError.invalidInput
            }
            if config.clientProfiles[idx].walletGroupId != nil {
                throw BastionError.ruleViolation
            }
        }

        let memberId = UUID().uuidString
        let keyTag: String
        #if DEBUG
        let runtimeQAAgentKeyTag = Self.runtimeQAWalletGroupAgentKeyTag(groupId: groupId, memberId: memberId)
        if let _ = try runtimeQAGroupPublicKeyIfEnabled(keyTag: runtimeQAAgentKeyTag) {
            keyTag = runtimeQAAgentKeyTag
        } else {
            keyTag = WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: memberId)
            _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: keyTag)
        }
        #else
        keyTag = WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: memberId)
        _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: keyTag)
        #endif

        // Regenerate counter IDs so this membership's spending and rate-limit
        // rules cannot collide with another member's counters in StateStore.
        let isolatedScope = regeneratedScopedRuleIDs(scopedRules)

        let membership = AgentMembership(
            id: memberId,
            clientProfileId: clientProfileId,
            label: normalizedLabel,
            keyTag: keyTag,
            scopedRules: isolatedScope,
            installStatus: .pending
        )

        config.walletGroups[groupIdx].members.append(membership)

        // Bind the client profile to this membership so signingContext resolves
        // to the group's shared account address.
        if let profileId = clientProfileId,
           let profileIdx = config.clientProfiles.firstIndex(where: { $0.id == profileId }) {
            config.clientProfiles[profileIdx].walletGroupId = groupId
            config.clientProfiles[profileIdx].membershipId = memberId
        }

        config = normalizedConfig(config)
        do {
            try saveConfig(config)
        } catch {
            config.walletGroups[groupIdx].members.removeAll { $0.id == memberId }
            if let profileId = clientProfileId,
               let profileIdx = config.clientProfiles.firstIndex(where: { $0.id == profileId }) {
                config.clientProfiles[profileIdx].walletGroupId = nil
                config.clientProfiles[profileIdx].membershipId = nil
            }
            _ = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: [keyTag])
            throw error
        }

        auditLog.record(AuditEvent(
            type: .walletGroupAgentAdded,
            dataPrefix: "walletgroup.\(groupId.prefix(8)).agent.\(memberId.prefix(8))",
            reason: "Added agent \(label ?? memberId) to group \(config.walletGroups[groupIdx].label)"
        ))

        return membership
    }

    /// Marks an agent's on-chain validator as installed and records the tx
    /// hash. Phase 1: owner calls this after manually submitting the install
    /// UserOp. Phase 2: Bastion will submit the UserOp and call this itself.
    func markAgentInstalled(
        groupId: String,
        memberId: String,
        txHash: String,
        validatorAddress: String?
    ) async throws -> AgentMembership {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to record an agent validator install"
        )

        ensureConfigLoadedIfNeeded()

        guard let groupIdx = config.walletGroups.firstIndex(where: { $0.id == groupId }),
              let memberIdx = config.walletGroups[groupIdx].members.firstIndex(where: { $0.id == memberId }) else {
            throw BastionError.invalidInput
        }

        config.walletGroups[groupIdx].members[memberIdx].installStatus = .installed(txHash: txHash)
        config.walletGroups[groupIdx].members[memberIdx].installedAt = Date()
        if let validatorAddress {
            config.walletGroups[groupIdx].members[memberIdx].validatorAddress = validatorAddress
        }

        let updated = config.walletGroups[groupIdx].members[memberIdx]
        try saveConfig(config)

        auditLog.record(AuditEvent(
            type: .walletGroupAgentInstalled,
            dataPrefix: "walletgroup.\(groupId.prefix(8)).agent.\(memberId.prefix(8))",
            reason: "Agent validator installed: tx=\(txHash.prefix(14))..."
        ))

        return updated
    }

    /// Updates an agent's scoped rules. Group sharedRules are unchanged.
    func updateAgentScope(
        groupId: String,
        memberId: String,
        scopedRules: RuleConfig
    ) async throws {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to update an agent's scope"
        )

        ensureConfigLoadedIfNeeded()

        guard let groupIdx = config.walletGroups.firstIndex(where: { $0.id == groupId }),
              let memberIdx = config.walletGroups[groupIdx].members.firstIndex(where: { $0.id == memberId }) else {
            throw BastionError.invalidInput
        }
        try validateRuleConfig(scopedRules)

        // Reissue counter IDs on every scope update so a caller cannot
        // (intentionally or accidentally) reuse another member's rule.id and
        // share a StateStore counter with them.
        config.walletGroups[groupIdx].members[memberIdx].scopedRules =
            regeneratedScopedRuleIDs(scopedRules)
        try saveConfig(config)

        auditLog.record(AuditEvent(
            type: .walletGroupAgentScopeUpdated,
            dataPrefix: "walletgroup.\(groupId.prefix(8)).agent.\(memberId.prefix(8))",
            reason: "Updated scope for agent \(memberId.prefix(8))"
        ))
    }

    /// Revokes an agent: marks the membership revoked, unbinds any linked
    /// ClientProfile, and deletes the agent's SE key so it can never sign
    /// again. The on-chain validator uninstall (when implemented in Phase 2)
    /// will land in markAgentUninstalled; for now the caller passes a
    /// placeholder/optional tx hash.
    func removeAgentFromGroup(
        groupId: String,
        memberId: String,
        txHash: String?
    ) async throws {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to revoke an agent from the wallet group"
        )

        ensureConfigLoadedIfNeeded()

        guard let groupIdx = config.walletGroups.firstIndex(where: { $0.id == groupId }),
              let memberIdx = config.walletGroups[groupIdx].members.firstIndex(where: { $0.id == memberId }) else {
            throw BastionError.invalidInput
        }

        let member = config.walletGroups[groupIdx].members[memberIdx]
        let revocationTx = txHash ?? "local-only"
        config.walletGroups[groupIdx].members[memberIdx].installStatus = .revoked(txHash: revocationTx)
        config.walletGroups[groupIdx].members[memberIdx].revokedAt = Date()

        // Unbind any ClientProfile pointing at this membership so future
        // signing requests fall back to a private wallet (or are blocked if
        // there is no private key for this profile).
        for profileIdx in config.clientProfiles.indices {
            if config.clientProfiles[profileIdx].walletGroupId == groupId
                && config.clientProfiles[profileIdx].membershipId == memberId {
                config.clientProfiles[profileIdx].walletGroupId = nil
                config.clientProfiles[profileIdx].membershipId = nil
            }
        }

        try saveConfig(config)

        // Delete the agent's SE key. Even if an on-chain uninstall hasn't
        // landed yet, Bastion cannot sign for this agent anymore.
        _ = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: [member.keyTag])

        auditLog.record(AuditEvent(
            type: .walletGroupAgentRemoved,
            dataPrefix: "walletgroup.\(groupId.prefix(8)).agent.\(memberId.prefix(8))",
            reason: "Revoked agent \(member.label ?? memberId.prefix(8).description); key deleted"
        ))
    }

    /// Returns the list of SE key tags associated with a group (owner + all
    /// non-revoked members). Used by resetSigningKeys to wipe group keys too.
    nonisolated func walletGroupKeyTags() -> [String] {
        let groups = loadConfig().walletGroups
        var tags: [String] = []
        for group in groups {
            tags.append(group.ownerKeyTag)
            for member in group.members where !member.installStatus.isRevoked {
                tags.append(member.keyTag)
            }
        }
        return tags
    }

    // MARK: - Rule Merging (Group ∩ Agent)

    /// Intersection semantics: a request must satisfy BOTH the group's
    /// sharedRules and the agent's scopedRules. For allowlist-style fields,
    /// the result is the intersection of both sets. For cap-style fields
    /// (rate limits, spending limits), the tighter cap wins — and we keep
    /// BOTH rules with their original IDs so the group counter (shared
    /// across all members) and the agent counter (per-member) both
    /// increment.
    /// PR3: thin shim over `MergedPolicyComposer`. Existing callers (rule
    /// engine validators, signing context resolution) still consume a
    /// `RuleConfig`, so we flatten back through `MergedPolicy.toRuleConfig()`.
    /// New callers (UI surfacing the effective merged policy, audit log)
    /// should call `mergedPolicy(group:member:)` directly to keep the
    /// typed unsatisfiable cases visible.
    nonisolated func mergeGroupRules(group: RuleConfig, member: RuleConfig) -> RuleConfig {
        MergedPolicyComposer.compose(group: group, member: member).toRuleConfig()
    }

    /// Typed merge result. Use this when the caller needs to know
    /// *whether* an unsatisfiable constraint exists (for UI / audit /
    /// short-circuit denial) rather than only the flattened RuleConfig.
    nonisolated func mergedPolicy(group: RuleConfig, member: RuleConfig) -> MergedPolicy {
        MergedPolicyComposer.compose(group: group, member: member)
    }

    /// Posture merge: kept as a thin alias around `MergedPolicyComposer`'s
    /// strict-OR so test fixtures and other callers don't need to know
    /// about the composer type. The follow-up task (#53) replaces this
    /// with a typed merge result.
    nonisolated static func stricterPosture(_ a: SigningPosture, _ b: SigningPosture) -> SigningPosture {
        MergedPolicyComposer.stricterPosture(a, b)
    }

    /// Intersects two AllowedClient lists by bundleId. Nil means "no
    /// restriction" so nil ∩ X = X. When both sides restrict, only bundles
    /// present in BOTH survive. An empty result means "intersection is empty"
    /// and is preserved (not collapsed to nil) so the rule engine denies.
    nonisolated func intersectAllowedClients(_ a: [AllowedClient]?, _ b: [AllowedClient]?) -> [AllowedClient]? {
        switch (a, b) {
        case (nil, nil): return nil
        case (nil, let x?): return x
        case (let x?, nil): return x
        case (let x?, let y?):
            let ySet = Set(y.map { $0.bundleId.lowercased() })
            return x.filter { ySet.contains($0.bundleId.lowercased()) }
        }
    }

    private nonisolated func unionArrays(_ a: [String]?, _ b: [String]?) -> [String]? {
        switch (a, b) {
        case (nil, nil): return nil
        case (nil, let x?): return x
        case (let x?, nil): return x
        case (let x?, let y?):
            return Array(Set(x).union(y))
        }
    }

    /// For allowedHours: returns the narrower window. Both nil → nil. One nil
    /// → the other. Both set → the intersection (or the tighter range).
    ///
    /// P1 fix: when same-day windows don't overlap (e.g. group 09:00–12:00 vs
    /// member 14:00–18:00), the previous behaviour returned the member's
    /// range, which silently bypassed the group constraint. We now collapse
    /// to an "always-deny" sentinel (start == end == 0) so validation rejects
    /// every hour. Cross-midnight ranges still fall back to member because
    /// reasoning about wrapping intersections is messy and the audit trail
    /// will surface the eventual denial in the rare case of a real conflict.
    private nonisolated func tighterHours(_ a: AllowedHours?, _ b: AllowedHours?) -> AllowedHours? {
        switch (a, b) {
        case (nil, nil): return nil
        case (nil, let x?): return x
        case (let x?, nil): return x
        case (let x?, let y?):
            if x.start <= x.end && y.start <= y.end {
                let newStart = max(x.start, y.start)
                let newEnd = min(x.end, y.end)
                if newStart < newEnd {
                    return AllowedHours(start: newStart, end: newEnd)
                }
                // No overlap — return an empty window (start == end). The
                // validator's `hour >= start && hour < end` check is then
                // always false → every hour is denied.
                return AllowedHours(start: 0, end: 0)
            }
            // Cross-midnight case — keep member as canonical. Documented
            // limitation; safer than silently widening either side.
            return y
        }
    }
}

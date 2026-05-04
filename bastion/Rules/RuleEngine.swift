import Foundation

final class RuleEngine {
    static let shared = RuleEngine()

    private let keychain: KeychainBackend
    let stateStore: StateStore
    // Internal (default) so extensions in other files within the module
    // — e.g. WalletGroupOnChain — can authenticate and audit.
    let authManager = AuthManager.shared
    let auditLog = AuditLog.shared

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

    func ensureConfigLoadedIfNeeded() {
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
        // v9: snapshot for the policy-version log (best-effort).
        ConfigVersionStore.shared.recordVersion(normalized)
        config = normalized
        configLoaded = true
        configCorrupted = false

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
            self?.effectiveRules(for: bundleId) ?? normalized.rules
        }
        XPCServer.shared.reconcileConnections(against: normalized.rules)
    }

    /// v9: Pause / lockdown writes that intentionally skip biometric. Pause
    /// must be instant — every paused-state mutation goes through the
    /// LockdownManager which calls this method. Persisted best-effort.
    func unsafelyApplyPauseState(_ newState: PauseState) {
        var updated = config
        updated.pauseState = newState
        let normalized = normalizedConfig(updated)
        try? saveConfig(normalized)
        config = normalized
    }

    // L-05: Maximum number of client profiles to prevent unbounded growth.
    private nonisolated static let maxClientProfiles = 20

    func ensureClientProfile(bundleId: String?) -> ClientProfile? {
        ensureConfigLoadedIfNeeded()

        guard let bundleId = normalizedBundleId(bundleId) else {
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

    func effectiveRules(for bundleId: String?) -> RuleConfig {
        ensureConfigLoadedIfNeeded()
        guard let profile = ensureClientProfile(bundleId: bundleId) else {
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

    func clientProfileInfo(bundleId: String?) -> ClientProfileInfo? {
        ensureConfigLoadedIfNeeded()
        guard let profile = ensureClientProfile(bundleId: bundleId) else {
            return nil
        }

        if let (group, member) = activeGroupMembership(for: profile) {
            return ClientProfileInfo(
                id: profile.id,
                bundleId: profile.bundleId,
                label: profile.label ?? member.label,
                authPolicy: profile.authPolicy?.rawValue ?? config.authPolicy.rawValue,
                keyTag: member.keyTag,
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
            keyTag: profile.keyTag,
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
                keyTag: member.keyTag,
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
            keyTag: profile.keyTag,
            accountAddress: accountAddress(for: profile),
            walletGroupId: nil,
            membershipId: nil
        )
    }

    func signingContext(for bundleId: String?) -> ClientSigningContext {
        ensureConfigLoadedIfNeeded()
        if let profile = ensureClientProfile(bundleId: bundleId) {
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

    /// Resolves the active (non-revoked) group membership for a profile, or nil
    /// if the profile is unlinked or its membership has been revoked.
    private func activeGroupMembership(for profile: ClientProfile) -> (WalletGroup, AgentMembership)? {
        guard let groupId = profile.walletGroupId,
              let memberId = profile.membershipId,
              let group = config.walletGroups.first(where: { $0.id == groupId }),
              let member = group.member(id: memberId),
              !member.installStatus.isRevoked else {
            return nil
        }
        return (group, member)
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
            return .denied(reasons: [reason])
        }
        if config.pauseState.paused {
            let reason = config.pauseState.reason ?? "Bastion is paused — resume from the menu bar to sign"
            return .denied(reasons: [reason])
        }

        // v9: temporary scoped agent sessions tighten the rule check. A session
        // can only narrow what the profile already allows — never widen it.
        if let denial = validateActiveSessions(request) {
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
    private nonisolated func validateActiveSessions(_ request: SignRequest) -> ValidationResult? {
        guard SessionSnapshotStore.shared.anyActive() else { return nil }

        // Match by bundleId — the only identity the rule engine has at this
        // point. SessionStore stores the bundleId at grant-time so we don't
        // need to dip into MainActor-isolated config here.
        let sessions = SessionSnapshotStore.shared.activeSessions(
            forBundleId: request.clientBundleId
        )
        guard !sessions.isEmpty else { return nil }

        // Each active session imposes its own scope; the *tightest* applies.
        // We only deny when *every* session forbids the operation.
        var anyAllow = false
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
                    let targets = leaves.map { $0.to.lowercased() }
                    let allow = Set(session.allowedTargets.map { $0.lowercased() })
                    if let outOfScope = targets.first(where: { !allow.contains($0) }) {
                        deniedReasons.append("Session does not allow target \(outOfScope.prefix(10))…")
                        continue
                    }
                }

                // Per-request spend ceiling. Sessions don't track cumulative
                // spend across requests yet (would need a separate counter
                // store keyed by session id) — the cap is enforced as a
                // single-request maximum, which is conservative: any single
                // sign that would exceed the session's cap is denied.
                if let spendDenial = exceedsSessionSpend(session: session, leaves: leaves) {
                    deniedReasons.append(spendDenial)
                    continue
                }
            }
            anyAllow = true
            break
        }

        if anyAllow { return nil }
        if !deniedReasons.isEmpty { return .denied(reasons: deniedReasons) }
        return nil
    }

    /// Sums USDC + ETH spends across `leaves` and compares against the
    /// session's caps. Returns a denial reason if any cap is exceeded; nil
    /// when the request fits. Treats nil/zero caps as "no cap from this
    /// session" — distinct from "0 cap" (deny all spends).
    ///
    /// Known limitation: this is a per-request ceiling, not a cumulative
    /// counter across the session window. A session that grants 50 USDC
    /// today admits unlimited 50-USDC requests until the window closes.
    /// Cumulative tracking would require a session-spend store keyed by
    /// session id; tracked separately.
    private nonisolated func exceedsSessionSpend(
        session: AgentSession,
        leaves: [CalldataDecoder.DecodedExecution]
    ) -> String? {
        // Native ETH from execution.value (wei). Only summed when an ETH cap
        // is configured — saves an O(n) walk on every sign.
        var nativeWei: UInt128 = 0
        var usdcAmount: UInt128 = 0
        let knownUsdcAddresses = Set(USDCAddresses.addresses.values.map { $0.lowercased() })

        for leaf in leaves {
            if leaf.value != "0", let v = UInt128(leaf.value) {
                let (sum, overflow) = nativeWei.addingReportingOverflow(v)
                if overflow { return "Session ETH cap evaluation overflowed — denying" }
                nativeWei = sum
            }
            if let tokenOp = leaf.tokenOperation,
               knownUsdcAddresses.contains(leaf.to.lowercased()),
               let amt = UInt128(tokenOp.amount) {
                let (sum, overflow) = usdcAmount.addingReportingOverflow(amt)
                if overflow { return "Session USDC cap evaluation overflowed — denying" }
                usdcAmount = sum
            }
        }

        if let cap = session.ethLimit, cap > 0 {
            let capWei = UInt128(cap * 1e18)
            if nativeWei > capWei {
                return "Session ETH cap exceeded (\(cap) ETH max)"
            }
        }
        if let cap = session.usdcLimit, cap > 0 {
            let capBase = UInt128(cap * 1e6)
            if usdcAmount > capBase {
                return "Session USDC cap exceeded (\(Int(cap)) USDC max)"
            }
        }
        return nil
    }

    nonisolated func requiresExplicitApproval(for request: SignRequest, config: BastionConfig) -> Bool {
        // PR2: posture is the single source of truth. Each operation type
        // carries its own posture; the legacy enabled / requireExplicit
        // booleans are derived for wire compatibility but ignored here.
        // SigningPosture.requiresApprovalPopup encodes the post-PR23
        // semantic that "skip rules" means "always approve" — the
        // disabled-UserOp auto-sign bug is now structurally impossible.
        return posture(for: request, config: config).requiresApprovalPopup
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
    ) {
        guard case .userOperation = request.operation else {
            return
        }

        recordUserOperationSuccess(
            request: request,
            config: config,
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
    ) {
        // Record rate limit entries
        for rule in config.rules.rateLimits {
            stateStore.recordRequest(ruleId: rule.id, windowSeconds: rule.windowSeconds)
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
            stateStore.recordSpend(
                ruleId: rule.id,
                amount: String(effectiveAmount),
                windowSeconds: rule.windowSeconds
            )
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
        // nil = no allowlist configured (allow). Present-but-empty = explicit
        // deny-all. Previously we collapsed both into "no restriction" which
        // let an empty allowlist (e.g. emitted by future merge logic) silently
        // permit every caller.
        guard let allowedClients = rules.allowedClients else {
            return
        }
        guard !allowedClients.isEmpty else {
            reasons.append("Client allowlist is empty — no clients permitted")
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

    private func normalizedConfig(_ config: BastionConfig) -> BastionConfig {
        var normalized = config
        normalized.version = 8
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
        SecureEnclaveManager.shared.getPublicKeyIfExists(keyTag: keyTag)?.accountAddress
    }

    // MARK: - Wallet Group Management

    /// Maximum wallet groups per install — cap prevents unbounded SE key growth.
    private nonisolated static let maxWalletGroups = 10
    /// Maximum agents per group — paired with maxClientProfiles (20) so an owner
    /// can't exceed practical SE slot budget.
    private nonisolated static let maxAgentsPerGroup = 20

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
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to create wallet group \"\(label)\""
        )

        ensureConfigLoadedIfNeeded()

        guard config.walletGroups.count < Self.maxWalletGroups else {
            throw BastionError.ruleViolation
        }

        let groupId = UUID().uuidString
        let ownerKeyTag = WalletGroup.makeOwnerKeyTag(groupId: groupId)

        // Provision owner SE key (silent — authPolicy is enforced by the
        // app-level biometric gate above, not by the SE key's access control).
        _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: ownerKeyTag)
        let pubkey = try SecureEnclaveManager.shared.getPublicKey(keyTag: ownerKeyTag)

        let group = WalletGroup(
            id: groupId,
            label: label,
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
            reason: "Created wallet group \"\(label)\" (\(pubkey.accountAddress ?? "unknown"))"
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
        let keyTag = WalletGroup.makeAgentKeyTag(groupId: groupId, memberId: memberId)
        _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: keyTag)

        // Regenerate counter IDs so this membership's spending and rate-limit
        // rules cannot collide with another member's counters in StateStore.
        let isolatedScope = regeneratedScopedRuleIDs(scopedRules)

        let membership = AgentMembership(
            id: memberId,
            clientProfileId: clientProfileId,
            label: label,
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

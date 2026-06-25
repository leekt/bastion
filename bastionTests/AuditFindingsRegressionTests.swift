import Testing
@testable import bastion
import Foundation

// Regression tests for the five P1/P2/P3 findings from the v2 redesign
// audit. Each test pins one fix so accidental reverts surface as a red
// CI run instead of a security regression.
//
// Originals:
//   P1 disabled UserOp can auto-sign         → RuleEngine.swift:576
//   P1 wallet-group allowedClients merge     → RuleEngine.swift:1780
//   P1 wallet-group hours non-overlap        → RuleEngine.swift:668
//   P2 ZeroDev project precedence            → WalletGroupOnChain.swift:355
//   P3 REST token logged to stderr           → mcp/src/rest-server.ts:340

// MockKeychainBackend already lives in StateStoreTests.swift at file scope —
// reused here to avoid redeclaration.

private func makeUserOpRequest(chainId: Int = 1, clientBundleId: String? = "com.bastion.cli") -> SignRequest {
    SignRequest(
        operation: .userOperation(UserOperation(
            sender: "0x1234567890abcdef1234567890abcdef12345678",
            nonce: "0x0",
            callData: KernelEncoding.executeCalldata(
                single: .init(to: "0x0000000000000000000000000000000000000001", value: 0, data: Data())
            ),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0f4240",
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x0f4240",
            maxPriorityFeePerGas: "0x59682f00",
            maxFeePerGas: "0x06fc23ac00",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: chainId,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )),
        requestID: UUID().uuidString,
        timestamp: Date(),
        clientBundleId: clientBundleId
    )
}

@Suite("Audit findings — RuleEngine regressions")
struct AuditFindingsRegressionTests {

    private func engine() -> RuleEngine {
        RuleEngine(keychain: MockKeychainBackend())
    }

    // MARK: - P1: Disabled UserOp must require approval

    @Test("Disabled rule engine forces explicit approval for userOps")
    func disabledUserOpForcesApproval() {
        // Build a config where rule-based signing is OFF — the previous bug
        // was that validate() short-circuited to .allowed and
        // requiresExplicitApproval() returned config.rules.requireExplicitApproval
        // (false), letting Silent auth sign without any review.
        let disabledRules = RuleConfig(
            enabled: false,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let config = BastionConfig(authPolicy: .open, rules: disabledRules)
        let request = makeUserOpRequest()

        #expect(engine().requiresExplicitApproval(for: request, config: config) == true)
    }

    @Test("Enabled rules + explicit approval flag is also honoured")
    func enabledRulesRespectsExplicitApprovalFlag() {
        // Sanity: when the engine is enabled, the explicit flag still drives.
        let rules = RuleConfig(
            enabled: true,
            requireExplicitApproval: true,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let config = BastionConfig(authPolicy: .biometric, rules: rules)
        let request = makeUserOpRequest()

        #expect(engine().requiresExplicitApproval(for: request, config: config) == true)

        // PR2: requireExplicitApproval is now a derived property on
        // RuleConfig — set the underlying posture instead.
        var auto = rules
        auto.userOpPosture = .enforceRulesAndAutoSign
        let autoConfig = BastionConfig(authPolicy: .biometric, rules: auto)
        #expect(engine().requiresExplicitApproval(for: request, config: autoConfig) == false)
    }

    @Test("Trace-only high-value spend forces explicit approval")
    func traceOnlyHighValueSpendForcesApproval() {
        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndAutoSign
        let config = BastionConfig(
            authPolicy: .open,
            rules: rules,
            highValue: HighValueRule(enabled: true, thresholdUsd: 100, confirmationPhrase: "TRANSFER")
        )
        let request = makeUserOpRequest()
        let observations = [
            SimulatedSpendObservation(token: .eth, amount: "101"),
        ]

        #expect(engine().requiresExplicitApproval(
            for: request,
            config: config,
            simulatedSpendObservations: observations
        ) == true)
        #expect(engine().highValueConfirmationPhrase(
            for: request,
            config: config,
            simulatedSpendObservations: observations
        ) == "TRANSFER")
    }

    @Test("High-value confirmation normalizes USDC base units and empty phrase")
    func highValueUsesUsdEquivalentUnitsAndSafePhrase() {
        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndAutoSign
        let config = BastionConfig(
            authPolicy: .open,
            rules: rules,
            highValue: HighValueRule(enabled: true, thresholdUsd: 100, confirmationPhrase: "")
        )
        let request = makeUserOpRequest()
        let below = [SimulatedSpendObservation(token: .usdc, amount: "99999999")]
        let atThreshold = [SimulatedSpendObservation(token: .usdc, amount: "100000000")]

        #expect(engine().highValueConfirmationPhrase(
            for: request,
            config: config,
            simulatedSpendObservations: below
        ) == nil)
        #expect(engine().highValueConfirmationPhrase(
            for: request,
            config: config,
            simulatedSpendObservations: atThreshold
        ) == HighValueRule.default.confirmationPhrase)
    }

    @Test("Pause and lockdown are non-overrideable hard blocks")
    func pauseAndLockdownHardBlockValidation() {
        var paused = BastionConfig.default
        paused.pauseState = PauseState(paused: true, lockedDown: false, pausedAt: Date(), reason: "paused")
        let pausedResult = engine().validate(makeUserOpRequest(), config: paused)
        if case .blocked(let reasons) = pausedResult {
            #expect(reasons == ["paused"])
        } else {
            Issue.record("Expected paused config to hard-block")
        }

        var locked = BastionConfig.default
        locked.pauseState = PauseState(paused: true, lockedDown: true, pausedAt: Date(), reason: "locked")
        let lockedResult = engine().validate(makeUserOpRequest(), config: locked)
        if case .blocked(let reasons) = lockedResult {
            #expect(reasons == ["locked"])
        } else {
            Issue.record("Expected lockdown config to hard-block")
        }
    }

    @Test("Multiple active sessions apply tightest scope")
    func multipleSessionsApplyTightestScope() {
        let bundleId = "com.example.agent"
        let broad = AgentSession(
            clientLabel: "Agent",
            clientId: nil,
            clientBundleId: bundleId,
            chains: [1],
            usdcLimit: nil,
            ethLimit: nil,
            allowedTargets: [],
            expiresAt: Date().addingTimeInterval(3600),
            intent: nil
        )
        let narrow = AgentSession(
            clientLabel: "Agent",
            clientId: nil,
            clientBundleId: bundleId,
            chains: [8453],
            usdcLimit: nil,
            ethLimit: nil,
            allowedTargets: [],
            expiresAt: Date().addingTimeInterval(3600),
            intent: nil
        )
        SessionSnapshotStore.shared.update([broad, narrow])
        defer { SessionSnapshotStore.shared.update([]) }

        let result = engine().validate(makeUserOpRequest(chainId: 1, clientBundleId: bundleId), config: .default)
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("does not allow chain 1") })
        } else {
            Issue.record("Expected narrower active session to deny")
        }
    }

    @Test("Global client allowlist helper fails closed for empty, unknown, and mismatched clients")
    func globalClientAllowlistDenial() {
        var rules = RuleConfig.default
        rules.allowedClients = []
        #expect(RuleEngine.clientAllowlistDenial(bundleId: "com.example.agent", rules: rules) != nil)

        rules.allowedClients = [
            AllowedClient(id: UUID().uuidString, bundleId: "com.example.agent", label: nil),
        ]
        #expect(RuleEngine.clientAllowlistDenial(bundleId: nil, rules: rules) != nil)
        #expect(RuleEngine.clientAllowlistDenial(bundleId: "com.other.agent", rules: rules) != nil)
        #expect(RuleEngine.clientAllowlistDenial(bundleId: "COM.EXAMPLE.AGENT", rules: rules) == nil)
    }

    // MARK: - P1: allowedClients must intersect, not "group ?? member"

    @Test("Wallet-group allowedClients intersects with member allowlist")
    func intersectAllowedClients() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: [
                AllowedClient(id: UUID().uuidString, bundleId: "com.cursor.app", label: nil),
                AllowedClient(id: UUID().uuidString, bundleId: "com.anthropic.claude-code", label: nil),
                AllowedClient(id: UUID().uuidString, bundleId: "com.example.tradebot", label: nil),
            ],
            rateLimits: [],
            spendingLimits: []
        )
        // Member intentionally narrows the group — only Claude Code may use
        // this membership. Pre-fix, the broad group list silently won.
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: [
                AllowedClient(id: UUID().uuidString, bundleId: "com.anthropic.claude-code", label: nil),
            ],
            rateLimits: [],
            spendingLimits: []
        )

        let merged = engine().mergeGroupRules(group: group, member: member)
        let bundles = (merged.allowedClients ?? []).map { $0.bundleId.lowercased() }
        #expect(bundles == ["com.anthropic.claude-code"])
    }

    @Test("allowedClients nil on one side falls through to the other")
    func allowedClientsNilFallthrough() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: [
                AllowedClient(id: UUID().uuidString, bundleId: "com.anthropic.claude-code", label: nil),
            ],
            rateLimits: [],
            spendingLimits: []
        )
        let merged = engine().mergeGroupRules(group: group, member: member)
        #expect(merged.allowedClients?.count == 1)
        #expect(merged.allowedClients?.first?.bundleId == "com.anthropic.claude-code")
    }

    @Test("Empty intersection of allowedClients denies everything (sentinel preserved)")
    func allowedClientsEmptyIntersectionDenies() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: [
                AllowedClient(id: UUID().uuidString, bundleId: "com.cursor.app", label: nil),
            ],
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: nil,
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: [
                AllowedClient(id: UUID().uuidString, bundleId: "com.anthropic.claude-code", label: nil),
            ],
            rateLimits: [],
            spendingLimits: []
        )
        let merged = engine().mergeGroupRules(group: group, member: member)
        // Empty (not nil) — validateAllowedClients treats empty as deny-all.
        #expect(merged.allowedClients?.isEmpty == true)
    }

    @Test("Empty allowedTargets sentinel denies instead of widening to unrestricted")
    func emptyAllowedTargetsSentinelDenies() {
        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndAutoSign
        rules.allowedTargets = [:]
        let config = BastionConfig(authPolicy: .biometric, rules: rules)
        let result = engine().validate(makeUserOpRequest(chainId: 8453), config: config)
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("No targets allowed") })
        } else {
            Issue.record("Expected empty allowedTargets sentinel to deny")
        }
    }

    @Test("Empty allowedSelectors sentinel denies instead of skipping selector validation")
    func emptyAllowedSelectorsSentinelDenies() {
        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndAutoSign
        rules.allowedSelectors = [:]
        let config = BastionConfig(authPolicy: .biometric, rules: rules)
        let result = engine().validate(makeUserOpRequest(), config: config)
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("No function selectors allowed") })
        } else {
            Issue.record("Expected empty allowedSelectors sentinel to deny")
        }
    }

    @Test("Unknown calldata hard-blocks even without spending limits")
    func unknownCalldataHardBlocksWithoutSpendingRules() {
        let request = SignRequest(
            operation: .userOperation(UserOperation(
                sender: "0x1234567890abcdef1234567890abcdef12345678",
                nonce: "0x0",
                callData: KernelEncoding.executeCalldata(
                    single: .init(
                        to: "0x0000000000000000000000000000000000000001",
                        value: 0,
                        data: Data([0xde, 0xad, 0xbe, 0xef])
                    )
                ),
                factory: nil,
                factoryData: nil,
                verificationGasLimit: "0x0f4240",
                callGasLimit: "0x0f4240",
                preVerificationGas: "0x0f4240",
                maxPriorityFeePerGas: "0x59682f00",
                maxFeePerGas: "0x06fc23ac00",
                paymaster: nil,
                paymasterVerificationGasLimit: nil,
                paymasterPostOpGasLimit: nil,
                paymasterData: nil,
                chainId: 1,
                entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
                entryPointVersion: .v0_7
            )),
            requestID: UUID().uuidString,
            timestamp: Date(),
            clientBundleId: "com.bastion.cli"
        )
        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndAutoSign
        rules.spendingLimits = []
        let result = engine().validate(request, config: BastionConfig(authPolicy: .biometric, rules: rules))
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("unrecognized function calls") })
        } else {
            Issue.record("Expected unknown calldata to deny without spending rules")
        }
    }

    // MARK: - P1: tighterHours must collapse non-overlap to deny

    @Test("Same-day non-overlapping hour windows produce always-deny sentinel")
    func tighterHoursNoOverlap() {
        // Group: 09:00–12:00, Member: 14:00–18:00. Pre-fix this returned the
        // member range, silently allowing 14:00–18:00. The fix collapses to
        // start == end == 0 so validation rejects every hour.
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: AllowedHours(start: 9, end: 12),
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: AllowedHours(start: 14, end: 18),
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let merged = engine().mergeGroupRules(group: group, member: member)
        #expect(merged.allowedHours?.start == merged.allowedHours?.end)

        // Drive the validator with a request landing inside the member range.
        // It must still be denied because the merged window is empty.
        let bastion = BastionConfig(authPolicy: .biometric, rules: merged)
        let request = SignRequest(
            operation: .userOperation(UserOperation(
                sender: "0x1234567890abcdef1234567890abcdef12345678",
                nonce: "0x0",
                callData: KernelEncoding.executeCalldata(
                    single: .init(to: "0x0000000000000000000000000000000000000001", value: 0, data: Data())
                ),
                factory: nil,
                factoryData: nil,
                verificationGasLimit: "0x0f4240",
                callGasLimit: "0x0f4240",
                preVerificationGas: "0x0f4240",
                maxPriorityFeePerGas: "0x59682f00",
                maxFeePerGas: "0x06fc23ac00",
                paymaster: nil,
                paymasterVerificationGasLimit: nil,
                paymasterPostOpGasLimit: nil,
                paymasterData: nil,
                chainId: 1,
                entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
                entryPointVersion: .v0_7
            )),
            requestID: UUID().uuidString,
            // Pin timestamp to 15:00 — inside the member window pre-fix.
            timestamp: Calendar.current.date(bySettingHour: 15, minute: 0, second: 0, of: Date()) ?? Date(),
            clientBundleId: nil
        )
        let result = engine().validate(request, config: bastion)
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("no overlap") || $0.contains("Outside allowed hours") })
        } else {
            Issue.record("Expected denial for non-overlapping wallet group hours")
        }
    }

    @Test("Overlapping hour windows produce the intersection")
    func tighterHoursOverlap() {
        let group = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: AllowedHours(start: 9, end: 18),
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let member = RuleConfig(
            enabled: true,
            requireExplicitApproval: false,
            allowedHours: AllowedHours(start: 12, end: 14),
            allowedChains: nil,
            allowedTargets: nil,
            allowedClients: nil,
            rateLimits: [],
            spendingLimits: []
        )
        let merged = engine().mergeGroupRules(group: group, member: member)
        #expect(merged.allowedHours?.start == 12)
        #expect(merged.allowedHours?.end == 14)
    }
}

import Testing
@testable import bastion
import Foundation

// PR2 tests: SigningPosture replaces the legacy enabled × requireExplicitApproval
// boolean pair across all three operation types. Each test fixes one
// posture × operation combination so an accidental revert to the old flag
// matrix is a red CI run, not a silent change of behaviour.

@Suite("Signing posture — semantics + migration")
struct SigningPostureTests {

    // MARK: - Boolean → posture mapping

    @Test("from(enabled:true, requireApproval:false) → enforceRulesAndAutoSign")
    func mapAutoSign() {
        #expect(SigningPosture.from(enabled: true, requireExplicitApproval: false) == .enforceRulesAndAutoSign)
    }

    @Test("from(enabled:true, requireApproval:true) → enforceRulesAndRequireApproval")
    func mapAlwaysApprove() {
        #expect(SigningPosture.from(enabled: true, requireExplicitApproval: true) == .enforceRulesAndRequireApproval)
    }

    @Test("from(enabled:false, requireApproval:_) → requireApprovalWithoutRuleEvaluation")
    func mapDisabled() {
        #expect(SigningPosture.from(enabled: false, requireExplicitApproval: false) == .requireApprovalWithoutRuleEvaluation)
        #expect(SigningPosture.from(enabled: false, requireExplicitApproval: true) == .requireApprovalWithoutRuleEvaluation)
    }

    // MARK: - Behaviour bits

    @Test("evaluatesRules / requiresApprovalPopup pairs are coherent")
    func behaviourBits() {
        #expect(SigningPosture.enforceRulesAndAutoSign.evaluatesRules == true)
        #expect(SigningPosture.enforceRulesAndAutoSign.requiresApprovalPopup == false)

        #expect(SigningPosture.enforceRulesAndRequireApproval.evaluatesRules == true)
        #expect(SigningPosture.enforceRulesAndRequireApproval.requiresApprovalPopup == true)

        #expect(SigningPosture.requireApprovalWithoutRuleEvaluation.evaluatesRules == false)
        #expect(SigningPosture.requireApprovalWithoutRuleEvaluation.requiresApprovalPopup == true)
    }

    @Test("Settings posture picker presentation keeps order, labels, and selected state")
    func settingsPosturePickerPresentation() {
        let segments = PosturePickerPresentation.segments(selected: .enforceRulesAndRequireApproval)

        #expect(segments.map(\.posture) == [
            .enforceRulesAndAutoSign,
            .enforceRulesAndRequireApproval,
            .requireApprovalWithoutRuleEvaluation,
        ])
        #expect(segments.map(\.shortLabel) == ["Auto-sign", "Always confirm", "Skip rules"])
        #expect(segments.map(\.accessibilityLabel) == [
            SigningPosture.enforceRulesAndAutoSign.displayName,
            SigningPosture.enforceRulesAndRequireApproval.displayName,
            SigningPosture.requireApprovalWithoutRuleEvaluation.displayName,
        ])
        #expect(segments.map(\.accessibilityHint) == [
            SigningPosture.enforceRulesAndAutoSign.hint,
            SigningPosture.enforceRulesAndRequireApproval.hint,
            SigningPosture.requireApprovalWithoutRuleEvaluation.hint,
        ])
        #expect(segments.map(\.isSelected) == [false, true, false])
    }

    @Test("Shared Bastion atoms expose stable labels, status semantics, and design scale")
    func sharedBastionAtomsPresentationContract() {
        #expect(BastionFormat.shortHex("") == "")
        #expect(BastionFormat.shortHex("0x1234") == "0x1234")
        #expect(BastionFormat.shortHex("0x1234567890abcdef", head: 6, tail: 4) == "0x123456…cdef")
        #expect(BastionFormat.shortHex("1234567890abcdef", head: 6, tail: 4) == "123456…cdef")
        #expect(AddressCopyFeedback.resetDelay == 0.9)
        #expect(AddressCopyFeedback.shouldReset(scheduledGeneration: 1, currentGeneration: 1) == true)
        #expect(AddressCopyFeedback.shouldReset(scheduledGeneration: 1, currentGeneration: 2) == false)

        #expect(ChainBadgePresentation.make(chainId: 1) == ChainBadgePresentation(chainId: 1, name: "Ethereum", glyph: "◆"))
        #expect(ChainBadgePresentation.make(chainId: 11_155_111).name == "Sepolia")
        #expect(ChainBadgePresentation.make(chainId: 8453).name == "Base")
        #expect(ChainBadgePresentation.make(chainId: 84_532).name == "Base Sepolia")
        #expect(ChainBadgePresentation.make(chainId: 42_161).name == "Arbitrum")
        #expect(ChainBadgePresentation.make(chainId: 999_999) == ChainBadgePresentation(chainId: 999_999, name: "Chain 999999", glyph: "◇"))

        #expect(StatusDot.State.ok.symbolName == "checkmark")
        #expect(StatusDot.State.warn.symbolName == "exclamationmark")
        #expect(StatusDot.State.bad.symbolName == "xmark")
        #expect(StatusDot.State.idle.symbolName == nil)
        #expect(StatusDot.State.ok.accessibilityLabel == "Status: ok")
        #expect(StatusDot.State.warn.accessibilityLabel == "Status: warning")
        #expect(StatusDot.State.bad.accessibilityLabel == "Status: error")
        #expect(StatusDot.State.idle.accessibilityLabel == "Status: idle")

        let signOnly = RequestModeChipPresentation.make(mode: .signOnly)
        #expect(signOnly.label == "Sign only")
        #expect(signOnly.style == .outline)
        #expect(signOnly.statusDot == .idle)
        #expect(signOnly.help == "Bastion returns a signature to the requesting client.")

        let approveAndSend = RequestModeChipPresentation.make(mode: .approveAndSend)
        #expect(approveAndSend.label == "Approve + send")
        #expect(approveAndSend.style == .accent)
        #expect(approveAndSend.statusDot == .warn)
        #expect(approveAndSend.help == "Bastion signs and submits the UserOperation after approval.")

        #expect(BastionFont.caption.size == 11)
        #expect(BastionFont.label.size == 12)
        #expect(BastionFont.body.size == 13)
        #expect(BastionFont.title.size == 17)
        #expect(BastionFont.large.size == 24)
        #expect(BastionSpacing.xs.value == 4)
        #expect(BastionSpacing.s.value == 8)
        #expect(BastionSpacing.m.value == 12)
        #expect(BastionSpacing.l.value == 16)
        #expect(BastionSpacing.xl.value == 24)
        #expect(BastionTokens.radiusSmall == 6)
        #expect(BastionTokens.radiusMedium == 8)
        #expect(BastionTokens.radiusLarge == 12)
        #expect(BastionTokens.radiusXL == 16)
        #expect(BastionTokens.windowRadius == 14)
    }

    // MARK: - RuleEngine.requiresExplicitApproval consults posture

    private func engine() -> RuleEngine { RuleEngine(keychain: MockKeychainBackend()) }

    private func userOpRequest() -> SignRequest {
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
                chainId: 1,
                entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
                entryPointVersion: .v0_7
            )),
            requestID: UUID().uuidString,
            timestamp: Date(),
            clientBundleId: nil
        )
    }

    private func messageRequest() -> SignRequest {
        SignRequest(
            operation: .message("hello"),
            requestID: UUID().uuidString,
            timestamp: Date(),
            clientBundleId: nil
        )
    }

    private func makeConfig(
        userOpPosture: SigningPosture = .enforceRulesAndAutoSign,
        rawMessagePosture: SigningPosture = .enforceRulesAndAutoSign,
        typedDataPosture: SigningPosture = .enforceRulesAndAutoSign
    ) -> BastionConfig {
        var rules = RuleConfig.default
        rules.userOpPosture = userOpPosture
        rules.rawMessagePolicy = RawMessagePolicy(posture: rawMessagePosture)
        rules.typedDataPolicy = TypedDataPolicy(posture: typedDataPosture)
        return BastionConfig(authPolicy: .biometric, rules: rules)
    }

    @Test("Auto-sign userOp does not require explicit approval")
    func autoSignUserOp() {
        let config = makeConfig(userOpPosture: .enforceRulesAndAutoSign)
        #expect(engine().requiresExplicitApproval(for: userOpRequest(), config: config) == false)
    }

    @Test("Always-confirm userOp requires approval")
    func alwaysConfirmUserOp() {
        let config = makeConfig(userOpPosture: .enforceRulesAndRequireApproval)
        #expect(engine().requiresExplicitApproval(for: userOpRequest(), config: config) == true)
    }

    @Test("Skip-rules userOp requires approval (the post-PR23 fix, now structural)")
    func skipRulesUserOpRequiresApproval() {
        let config = makeConfig(userOpPosture: .requireApprovalWithoutRuleEvaluation)
        #expect(engine().requiresExplicitApproval(for: userOpRequest(), config: config) == true)
    }

    @Test("Posture is independent across operation types")
    func independentPerOperation() {
        // Skip rules for messages, auto-sign userOps. Each operation
        // type's posture must apply independently.
        let config = makeConfig(
            userOpPosture: .enforceRulesAndAutoSign,
            rawMessagePosture: .requireApprovalWithoutRuleEvaluation
        )
        #expect(engine().requiresExplicitApproval(for: userOpRequest(), config: config) == false)
        #expect(engine().requiresExplicitApproval(for: messageRequest(), config: config) == true)
    }

    // MARK: - Codable migration

    @Test("Decoding a legacy config with enabled=false and no posture key yields requireApprovalWithoutRuleEvaluation")
    func legacyDisabledMigratesToApprovalOnly() throws {
        let json = """
        {
          "enabled": false,
          "requireExplicitApproval": false,
          "rateLimits": [],
          "spendingLimits": []
        }
        """.data(using: .utf8)!
        let rules = try JSONDecoder().decode(RuleConfig.self, from: json)
        #expect(rules.userOpPosture == .requireApprovalWithoutRuleEvaluation)
        #expect(rules.requireExplicitApproval == true)
    }

    @Test("Decoding legacy enabled=true requireApproval=true → enforceRulesAndRequireApproval")
    func legacyEnabledRequireMigrates() throws {
        let json = """
        {
          "enabled": true,
          "requireExplicitApproval": true,
          "rateLimits": [],
          "spendingLimits": []
        }
        """.data(using: .utf8)!
        let rules = try JSONDecoder().decode(RuleConfig.self, from: json)
        #expect(rules.userOpPosture == .enforceRulesAndRequireApproval)
    }

    @Test("Round-trip encodes posture + legacy mirrors")
    func roundTripIncludesLegacyMirrors() throws {
        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndRequireApproval
        let data = try JSONEncoder().encode(rules)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any]
        #expect(json?["userOpPosture"] as? String == SigningPosture.enforceRulesAndRequireApproval.rawValue)
        // Legacy mirrors written so older readers stay coherent.
        #expect(json?["enabled"] as? Bool == true)
        #expect(json?["requireExplicitApproval"] as? Bool == true)
    }

    @Test("Posture field wins over legacy mirrors when both are present")
    func postureWinsOverLegacyMirrors() throws {
        // Adversarial input: posture says auto-sign, legacy mirrors say
        // approval-only. Since posture is the source of truth, decode
        // must honour it.
        let json = """
        {
          "userOpPosture": "enforce_and_auto",
          "enabled": false,
          "requireExplicitApproval": true,
          "rateLimits": [],
          "spendingLimits": []
        }
        """.data(using: .utf8)!
        let rules = try JSONDecoder().decode(RuleConfig.self, from: json)
        #expect(rules.userOpPosture == .enforceRulesAndAutoSign)
        #expect(rules.enabled == true)
    }
}

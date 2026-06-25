import Foundation
import Testing
@testable import bastion

@Suite("RiskScorer")
struct RiskScorerTests {
    @Test("Allowed-hours signals use the supplied clock including wrapped windows")
    func allowedHoursUsesInjectedClock() {
        var daytimeRules = RuleConfig.default
        daytimeRules.allowedHours = AllowedHours(start: 9, end: 17)

        let outside = RiskScorer.signals(
            for: messageRequest(),
            config: .default,
            clientContext: clientContext(rules: daytimeRules),
            now: fixedDate(hour: 20),
            calendar: utcCalendar()
        )
        #expect(outside.map(\.id) == ["outside-hours"])
        #expect(outside.first?.tone == .warn)

        var overnightRules = RuleConfig.default
        overnightRules.allowedHours = AllowedHours(start: 22, end: 6)

        let insideWrapped = RiskScorer.signals(
            for: messageRequest(),
            config: .default,
            clientContext: clientContext(rules: overnightRules),
            now: fixedDate(hour: 23),
            calendar: utcCalendar()
        )
        #expect(insideWrapped.isEmpty)

        let outsideWrapped = RiskScorer.signals(
            for: messageRequest(),
            config: .default,
            clientContext: clientContext(rules: overnightRules),
            now: fixedDate(hour: 12),
            calendar: utcCalendar()
        )
        #expect(outsideWrapped.map(\.id) == ["outside-hours"])
    }

    @Test("ERC-20 approvals surface high-value allowance, labelled first interaction, and allowlist signals")
    func approvalSignalsAreConcreteAndLabelled() {
        let token = "0x1111111111111111111111111111111111111111"
        let spender = "0x2222222222222222222222222222222222222222"
        let request = userOperationRequest(
            callData: KernelEncoding.executeCalldata(
                single: .init(
                    to: token,
                    value: 0,
                    data: approveCalldata(spender: spender, amount: 150)
                )
            )
        )

        var rules = RuleConfig.default
        rules.allowedTargets = ["1": ["0x3333333333333333333333333333333333333333"]]
        let config = BastionConfig(
            authPolicy: .biometricOrPasscode,
            rules: .default,
            addressBook: [
                AddressBookEntry(address: token, label: "Treasury Token", chainId: 1)
            ],
            highValue: HighValueRule(enabled: true, thresholdUsd: 100, confirmationPhrase: "TRANSFER")
        )

        let signals = RiskScorer.signals(
            for: request,
            config: config,
            clientContext: clientContext(rules: rules),
            recentAuditDetails: []
        )
        let ids = signals.map(\.id)

        #expect(ids.contains("high-value"))
        #expect(ids.contains("allowance-increase"))
        #expect(ids.contains { $0.hasPrefix("first-interaction-") })
        #expect(ids.contains("outside-allowlist"))
        #expect(signals.first(where: { $0.id == "high-value" })?.tone == .danger)
        #expect(signals.first(where: { $0.id == "allowance-increase" })?.tone == .warn)
        #expect(signals.first(where: { $0.id.hasPrefix("first-interaction-") })?.label == "New target — labelled Treasury Token")
        #expect(signals.first(where: { $0.id == "outside-allowlist" })?.detail?.contains(token.prefix(10)) == true)
    }

    @Test("Recent audit details suppress first-interaction signal for known targets")
    func recentAuditDetailsSuppressFirstInteraction() {
        let knownTarget = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let request = userOperationRequest(
            callData: KernelEncoding.executeCalldata(
                single: .init(to: knownTarget, value: 0, data: Data())
            )
        )

        let newTargetSignals = RiskScorer.signals(
            for: request,
            config: .default,
            clientContext: clientContext(),
            recentAuditDetails: []
        )
        #expect(newTargetSignals.contains { $0.id.hasPrefix("first-interaction-") })

        let knownTargetSignals = RiskScorer.signals(
            for: request,
            config: .default,
            clientContext: clientContext(),
            recentAuditDetails: ["Previously approved target \(knownTarget)"]
        )
        #expect(!knownTargetSignals.contains { $0.id.hasPrefix("first-interaction-") })
    }

    @Test("Unknown calldata produces a warning signal")
    func unknownCalldataProducesWarningSignal() {
        let request = userOperationRequest(
            callData: KernelEncoding.executeCalldata(
                single: .init(
                    to: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    value: 0,
                    data: Data(hexString: "0x12345678")!
                )
            )
        )

        let signals = RiskScorer.signals(
            for: request,
            config: .default,
            clientContext: clientContext(),
            recentAuditDetails: []
        )
        let unknown = signals.first { $0.id == "unknown-selector" }

        #expect(unknown?.tone == .warn)
        #expect(unknown?.label == "Unknown selector")
    }

    private func messageRequest() -> SignRequest {
        SignRequest(
            operation: .message("hello"),
            requestID: "risk-message",
            timestamp: fixedDate(hour: 10),
            clientBundleId: "com.example.agent"
        )
    }

    private func userOperationRequest(callData: Data) -> SignRequest {
        SignRequest(
            operation: .userOperation(UserOperation(
                sender: "0x1234567890abcdef1234567890abcdef12345678",
                nonce: "0x0",
                callData: callData,
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
            requestID: "risk-userop",
            timestamp: fixedDate(hour: 10),
            clientBundleId: "com.example.agent"
        )
    }

    private func clientContext(rules: RuleConfig = .default) -> ClientSigningContext {
        ClientSigningContext(
            bundleId: "com.example.agent",
            profileId: "profile-example",
            profileLabel: "Example Agent",
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.client.example",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: rules
        )
    }

    private func approveCalldata(spender: String, amount: UInt64) -> Data {
        let spenderWord = String(repeating: "0", count: 24) + spender.drop0x
        let amountWord = String(amount, radix: 16).leftPadded(to: 64)
        return Data(hexString: "0x095ea7b3\(spenderWord)\(amountWord)")!
    }

    private func fixedDate(hour: Int) -> Date {
        DateComponents(
            calendar: utcCalendar(),
            timeZone: TimeZone(secondsFromGMT: 0),
            year: 2026,
            month: 1,
            day: 1,
            hour: hour
        ).date!
    }

    private func utcCalendar() -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(secondsFromGMT: 0)!
        return calendar
    }
}

private extension String {
    var drop0x: String {
        hasPrefix("0x") ? String(dropFirst(2)) : self
    }

    func leftPadded(to length: Int) -> String {
        if count >= length { return self }
        return String(repeating: "0", count: length - count) + self
    }
}

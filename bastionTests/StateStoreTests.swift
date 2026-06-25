import AppKit
import Foundation
import Testing
@testable import bastion

// MARK: - Mock Keychain Backend

/// In-memory keychain backend for testing without real Keychain.
nonisolated final class MockKeychainBackend: KeychainBackend, @unchecked Sendable {
    private var storage: [String: Data] = [:]
    private let lock = NSLock()

    nonisolated func read(account: String) -> Data? {
        lock.lock()
        defer { lock.unlock() }
        return storage[account]
    }

    @discardableResult
    nonisolated func write(account: String, data: Data) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        storage[account] = data
        return true
    }

    @discardableResult
    nonisolated func delete(account: String) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: account)
        return true
    }
}

nonisolated final class FailingWriteKeychainBackend: KeychainBackend, @unchecked Sendable {
    nonisolated func read(account: String) -> Data? { nil }
    @discardableResult nonisolated func write(account: String, data: Data) -> Bool { false }
    @discardableResult nonisolated func delete(account: String) -> Bool { false }
}

nonisolated final class FailingReadKeychainBackend: KeychainBackend, @unchecked Sendable {
    nonisolated func read(account: String) -> Data? { nil }
    nonisolated func readResult(account: String) -> KeychainReadResult { .failure }
    @discardableResult nonisolated func write(account: String, data: Data) -> Bool { true }
    @discardableResult nonisolated func delete(account: String) -> Bool { true }
}

@MainActor
private final class MockPairingConfigUpdater: PairingConfigUpdating {
    var pairingConfig: BastionConfig
    var appliedConfigs: [BastionConfig] = []
    var error: Error?

    init(config: BastionConfig = .default, error: Error? = nil) {
        self.pairingConfig = config
        self.error = error
    }

    func applyPairingConfig(_ config: BastionConfig) async throws {
        if let error { throw error }
        pairingConfig = config
        appliedConfigs.append(config)
    }
}

@MainActor
private final class SuspendingPairingConfigUpdater: PairingConfigUpdating {
    var pairingConfig: BastionConfig
    var appliedConfigs: [BastionConfig] = []

    private var applyStartedContinuation: CheckedContinuation<Void, Never>?
    private var releaseContinuation: CheckedContinuation<Void, Never>?

    init(config: BastionConfig = .default) {
        self.pairingConfig = config
    }

    func applyPairingConfig(_ config: BastionConfig) async throws {
        appliedConfigs.append(config)
        applyStartedContinuation?.resume()
        applyStartedContinuation = nil
        await withCheckedContinuation { continuation in
            releaseContinuation = continuation
        }
        pairingConfig = config
    }

    func waitForApplyStarted() async {
        if !appliedConfigs.isEmpty {
            return
        }
        await withCheckedContinuation { continuation in
            applyStartedContinuation = continuation
        }
    }

    func releaseApply() {
        releaseContinuation?.resume()
        releaseContinuation = nil
    }
}

@MainActor
private final class MockMenuBarLockdownManager: MenuBarLockdownManaging {
    var setPausedCalls: [(paused: Bool, reason: String?)] = []
    var enterLockdownReasons: [String] = []
    var leaveLockdownCalls = 0
    var setPausedResults: [Bool]
    var enterLockdownResults: [Bool]
    var leaveLockdownResults: [Bool]
    var residualSurfaceValue: LockdownManager.ResidualSurface

    init(
        setPausedResults: [Bool] = [true],
        enterLockdownResults: [Bool] = [true],
        leaveLockdownResults: [Bool] = [true],
        residualSurface: LockdownManager.ResidualSurface = .init(installedValidators: 0, activeSessions: 0)
    ) {
        self.setPausedResults = setPausedResults
        self.enterLockdownResults = enterLockdownResults
        self.leaveLockdownResults = leaveLockdownResults
        self.residualSurfaceValue = residualSurface
    }

    func setPaused(_ paused: Bool, reason: String?) async -> Bool {
        setPausedCalls.append((paused, reason))
        return setPausedResults.isEmpty ? true : setPausedResults.removeFirst()
    }

    func enterLockdown(reason: String) async -> Bool {
        enterLockdownReasons.append(reason)
        return enterLockdownResults.isEmpty ? true : enterLockdownResults.removeFirst()
    }

    func leaveLockdown() async -> Bool {
        leaveLockdownCalls += 1
        return leaveLockdownResults.isEmpty ? true : leaveLockdownResults.removeFirst()
    }

    func residualSurface() -> LockdownManager.ResidualSurface {
        residualSurfaceValue
    }
}

// MARK: - Test Helpers

private func makeMessageRequest(
    requestID: String = UUID().uuidString,
    clientBundleId: String? = nil
) -> SignRequest {
    SignRequest(
        operation: .message("hello world"),
        requestID: requestID,
        timestamp: Date(),
        clientBundleId: clientBundleId
    )
}

private func makeTypedDataRequest(
    requestID: String = UUID().uuidString,
    chainId: Int,
    clientBundleId: String? = "com.example.agent"
) -> SignRequest {
    let typedData = EIP712TypedData(
        types: [
            "EIP712Domain": [
                EIP712Field(name: "name", type: "string"),
                EIP712Field(name: "version", type: "string"),
                EIP712Field(name: "chainId", type: "uint256"),
            ],
            "Mail": [
                EIP712Field(name: "from", type: "string"),
                EIP712Field(name: "to", type: "string"),
                EIP712Field(name: "contents", type: "string"),
            ],
        ],
        primaryType: "Mail",
        domain: EIP712Domain(
            name: "Test",
            version: "1",
            chainId: chainId,
            verifyingContract: nil,
            salt: nil
        ),
        message: [
            "from": AnyCodable("alice"),
            "to": AnyCodable("bob"),
            "contents": AnyCodable("Hello, Bob!"),
        ]
    )
    return SignRequest(
        operation: .typedData(typedData),
        requestID: requestID,
        timestamp: Date(),
        clientBundleId: clientBundleId
    )
}

private func makeClientContext(
    bundleId: String? = "com.example.agent",
    profileLabel: String? = "Example Agent"
) -> ClientSigningContext {
    ClientSigningContext(
        bundleId: bundleId,
        profileId: bundleId,
        profileLabel: profileLabel,
        authPolicy: .biometricOrPasscode,
        keyTag: "com.bastion.signingkey.test",
        accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
        rules: .default
    )
}

private let defaultValidCallData: Data = KernelEncoding.executeCalldata(
    single: .init(to: "0x0000000000000000000000000000000000000001", value: 0, data: Data())
)

private func makeUserOpRequest(
    sender: String = "0x1234567890abcdef1234567890abcdef12345678",
    chainId: Int = 1,
    callData: Data? = nil,
    requestID: String = UUID().uuidString,
    clientBundleId: String? = nil,
    submission: UserOperationSubmissionRequest? = nil
) -> SignRequest {
    SignRequest(
        operation: .userOperation(UserOperation(
            sender: sender,
            nonce: "0x0",
            callData: callData ?? defaultValidCallData,
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
        requestID: requestID,
        timestamp: Date(),
        clientBundleId: clientBundleId,
        userOperationSubmission: submission
    )
}

private func makeTypedDataRequest(
    domainName: String = "Permit2",
    version: String = "1",
    chainId: Int = 11155111,
    verifyingContract: String = "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    primaryType: String = "Permit",
    message: [String: AnyCodable] = [
        "owner": AnyCodable("0x1234567890abcdef1234567890abcdef12345678"),
        "spender": AnyCodable("0x7777777777777777777777777777777777777777"),
        "value": AnyCodable("50000000"),
    ],
    clientBundleId: String? = nil
) -> SignRequest {
    let typedData = EIP712TypedData(
        types: [
            "EIP712Domain": [
                EIP712Field(name: "name", type: "string"),
                EIP712Field(name: "version", type: "string"),
                EIP712Field(name: "chainId", type: "uint256"),
                EIP712Field(name: "verifyingContract", type: "address"),
            ],
            primaryType: [
                EIP712Field(name: "owner", type: "address"),
                EIP712Field(name: "spender", type: "address"),
                EIP712Field(name: "value", type: "uint256"),
            ],
        ],
        primaryType: primaryType,
        domain: EIP712Domain(
            name: domainName,
            version: version,
            chainId: chainId,
            verifyingContract: verifyingContract,
            salt: nil
        ),
        message: message
    )

    return SignRequest(
        operation: .typedData(typedData),
        requestID: UUID().uuidString,
        timestamp: Date(),
        clientBundleId: clientBundleId
    )
}

private func makeRawBytesRequest(
    bytes: Data = Data(repeating: 0xab, count: 32),
    requestID: String = UUID().uuidString,
    clientBundleId: String? = nil
) -> SignRequest {
    SignRequest(
        operation: .rawBytes(bytes),
        requestID: requestID,
        timestamp: Date(),
        clientBundleId: clientBundleId
    )
}

private func makeKernelSingleCallData(target: String, value: UInt64 = 0, calldata: Data = Data()) -> Data {
    KernelEncoding.executeCalldata(single: .init(to: target, value: value, data: calldata))
}

private func makeERC20TransferCalldata(to recipient: String, amount: UInt64) -> Data {
    Data([0xa9, 0x05, 0x9c, 0xbb]) + paddedAddress(recipient) + uint256(amount)
}

private func makeERC20ApproveCalldata(spender: String, amount: UInt64) -> Data {
    Data([0x09, 0x5e, 0xa7, 0xb3]) + paddedAddress(spender) + uint256(amount)
}

private func paddedAddress(_ address: String) -> Data {
    Data(repeating: 0, count: 12) + (Data(hexString: address) ?? Data())
}

private func uint256(_ value: UInt64) -> Data {
    var data = Data(repeating: 0, count: 32)
    var remaining = value
    for index in stride(from: 31, through: 24, by: -1) {
        data[index] = UInt8(remaining & 0xff)
        remaining >>= 8
    }
    return data
}

// MARK: - StateStore Rate Limit Tests

@Suite("StateStore Rate Limits")
struct StateStoreRateLimitTests {

    @Test("Fresh store returns count 0")
    func freshStoreStartsAtZero() {
        let store = StateStore(keychain: MockKeychainBackend())
        #expect(store.rateLimitCount(ruleId: "test", windowSeconds: 3600) == 0)
    }

    @Test("Recording requests increases count")
    func recordIncrementsCount() {
        let store = StateStore(keychain: MockKeychainBackend())
        store.recordRequest(ruleId: "r1", windowSeconds: 3600)
        #expect(store.rateLimitCount(ruleId: "r1", windowSeconds: 3600) == 1)
        store.recordRequest(ruleId: "r1", windowSeconds: 3600)
        #expect(store.rateLimitCount(ruleId: "r1", windowSeconds: 3600) == 2)
    }

    @Test("Different rule IDs are independent")
    func independentRuleIds() {
        let store = StateStore(keychain: MockKeychainBackend())
        store.recordRequest(ruleId: "a", windowSeconds: 3600)
        store.recordRequest(ruleId: "a", windowSeconds: 3600)
        store.recordRequest(ruleId: "b", windowSeconds: 3600)
        #expect(store.rateLimitCount(ruleId: "a", windowSeconds: 3600) == 2)
        #expect(store.rateLimitCount(ruleId: "b", windowSeconds: 3600) == 1)
        #expect(store.rateLimitCount(ruleId: "c", windowSeconds: 3600) == 0)
    }

    @Test("Persists across instances via shared keychain")
    func persistsAcrossInstances() {
        let keychain = MockKeychainBackend()
        let store1 = StateStore(keychain: keychain)
        store1.recordRequest(ruleId: "r1", windowSeconds: 3600)
        store1.recordRequest(ruleId: "r1", windowSeconds: 3600)

        let store2 = StateStore(keychain: keychain)
        #expect(store2.rateLimitCount(ruleId: "r1", windowSeconds: 3600) == 2)
    }

    @Test("Corrupted keychain data fails closed")
    func corruptedDataFailsClosed() {
        let keychain = MockKeychainBackend()
        keychain.write(account: "state.ratelimit.test", data: Data("garbage".utf8))
        let store = StateStore(keychain: keychain)
        #expect(store.rateLimitCount(ruleId: "test", windowSeconds: 3600) == Int.max)
    }

    @Test("Malformed spend entries fail closed")
    func malformedSpendEntryFailsClosed() {
        let keychain = MockKeychainBackend()
        let timestamp = Date().timeIntervalSince1970
        let raw = #"{"entries":[{"timestamp":\#(timestamp),"amount":"not-a-number"}]}"#
        keychain.write(account: "state.spending.bad", data: Data(raw.utf8))
        let store = StateStore(keychain: keychain)

        #expect(store.spentAmount(ruleId: "bad", windowSeconds: 3600) == UInt128.max)
    }

    @Test("Rate limit status reports correctly")
    func rateLimitStatus() {
        let store = StateStore(keychain: MockKeychainBackend())
        let rule = RateLimitRule(id: "r1", maxRequests: 5, windowSeconds: 3600)

        store.recordRequest(ruleId: "r1", windowSeconds: 3600)
        store.recordRequest(ruleId: "r1", windowSeconds: 3600)

        let status = store.rateLimitStatus(rule: rule)
        #expect(status.maxRequests == 5)
        #expect(status.windowSeconds == 3600)
        #expect(status.currentCount == 2)
        #expect(status.remaining == 3)
    }
}

// MARK: - StateStore Spending Limit Tests

@Suite("StateStore Spending Limits")
struct StateStoreSpendingLimitTests {

    @Test("Fresh store returns 0 spent")
    func freshStoreZeroSpent() {
        let store = StateStore(keychain: MockKeychainBackend())
        #expect(store.spentAmount(ruleId: "s1", windowSeconds: 3600) == 0)
    }

    @Test("Recording spend accumulates")
    func recordSpendAccumulates() {
        let store = StateStore(keychain: MockKeychainBackend())
        store.recordSpend(ruleId: "s1", amount: "1000", windowSeconds: 3600)
        #expect(store.spentAmount(ruleId: "s1", windowSeconds: 3600) == 1000)
        store.recordSpend(ruleId: "s1", amount: "500", windowSeconds: 3600)
        #expect(store.spentAmount(ruleId: "s1", windowSeconds: 3600) == 1500)
    }

    @Test("Lifetime spending sums everything")
    func lifetimeSpending() {
        let store = StateStore(keychain: MockKeychainBackend())
        store.recordSpend(ruleId: "s1", amount: "100", windowSeconds: nil)
        store.recordSpend(ruleId: "s1", amount: "200", windowSeconds: nil)
        #expect(store.spentAmount(ruleId: "s1", windowSeconds: nil) == 300)
    }

    @Test("Different rule IDs are independent")
    func independentSpendingRuleIds() {
        let store = StateStore(keychain: MockKeychainBackend())
        store.recordSpend(ruleId: "eth", amount: "1000", windowSeconds: 3600)
        store.recordSpend(ruleId: "usdc", amount: "500", windowSeconds: 3600)
        #expect(store.spentAmount(ruleId: "eth", windowSeconds: 3600) == 1000)
        #expect(store.spentAmount(ruleId: "usdc", windowSeconds: 3600) == 500)
    }

    @Test("Spending limit status reports correctly")
    func spendingLimitStatus() {
        let store = StateStore(keychain: MockKeychainBackend())
        let rule = SpendingLimitRule(
            id: "s1",
            token: .eth,
            allowance: "1000000000000000000",
            windowSeconds: 86400
        )
        store.recordSpend(ruleId: "s1", amount: "400000000000000000", windowSeconds: 86400)
        let status = store.spendingLimitStatus(rule: rule)
        #expect(status.token == "ETH")
        #expect(status.allowance == "1000000000000000000")
        #expect(status.spent == "400000000000000000")
        #expect(status.remaining == "600000000000000000")
        #expect(status.windowResetsAt != nil)
        #expect(status.windowResetsAt.flatMap { ISO8601DateFormatter().date(from: $0) } != nil)
    }

    @Test("Lifetime spending limit status has no reset timestamp")
    func lifetimeSpendingLimitStatusHasNoReset() {
        let store = StateStore(keychain: MockKeychainBackend())
        let rule = SpendingLimitRule(
            id: "s1",
            token: .eth,
            allowance: "1000000000000000000",
            windowSeconds: nil
        )
        store.recordSpend(ruleId: "s1", amount: "400000000000000000", windowSeconds: nil)

        let status = store.spendingLimitStatus(rule: rule)
        #expect(status.spent == "400000000000000000")
        #expect(status.remaining == "600000000000000000")
        #expect(status.windowResetsAt == nil)
    }

    @Test("Global cap tile presentation formats values and warnings")
    func globalCapTilePresentation() {
        let usdcRule = SpendingLimitRule(
            id: "usdc",
            token: .usdc,
            allowance: "250000000",
            windowSeconds: 86_400
        )
        let usdcStatus = SpendingLimitStatus(
            token: "USDC",
            allowance: "250000000",
            spent: "150250000",
            remaining: "99750000",
            windowSeconds: 86_400,
            windowResetsAt: nil
        )
        let usdcTile = GlobalCapTilePresentation.spendingLimit(
            prefix: "Total USDC",
            rule: usdcRule,
            status: usdcStatus
        )

        #expect(usdcTile.label == "Total USDC/day")
        #expect(usdcTile.value == "250")
        #expect(usdcTile.used == 150.25)
        #expect(usdcTile.total == 250.0)
        #expect(usdcTile.unit == " USDC")
        #expect(usdcTile.warn == false)
        #expect(usdcTile.showsUsage == true)

        let exhaustedTile = GlobalCapTilePresentation.spendingLimit(
            prefix: "Total USDC",
            rule: usdcRule,
            status: SpendingLimitStatus(
                token: "USDC",
                allowance: "250000000",
                spent: "250000000",
                remaining: "0",
                windowSeconds: 86_400,
                windowResetsAt: nil
            )
        )
        #expect(exhaustedTile.warn == true)

        let rateRule = RateLimitRule(id: "rate", maxRequests: 3, windowSeconds: 3600)
        let rateTile = GlobalCapTilePresentation.rateLimit(
            rule: rateRule,
            status: RateLimitStatus(
                maxRequests: 3,
                windowSeconds: 3600,
                currentCount: 3,
                remaining: 0,
                windowResetsAt: nil
            )
        )
        #expect(rateTile.label == "Signatures/hour")
        #expect(rateTile.value == "3")
        #expect(rateTile.used == 3.0)
        #expect(rateTile.total == 3.0)
        #expect(rateTile.warn == true)
        #expect(rateTile.showsUsage == true)

        let hoursTile = GlobalCapTilePresentation.allowedHours(AllowedHours(start: 9, end: 17))
        #expect(hoursTile.label == "Allowed hours")
        #expect(hoursTile.value == "09:00 – 17:00")
        #expect(hoursTile.showsUsage == false)
        #expect(hoursTile.warn == false)

        let unrestrictedHoursTile = GlobalCapTilePresentation.allowedHours(nil)
        #expect(unrestrictedHoursTile.value == "any time")
        #expect(unrestrictedHoursTile.showsUsage == false)
    }
}

// MARK: - Token Config Tests

@Suite("Token Config")
struct TokenConfigTests {

    @Test("USDC addresses exist for major chains")
    func usdcAddresses() {
        #expect(USDCAddresses.address(for: 1) != nil)
        #expect(USDCAddresses.address(for: 8453) != nil)
        #expect(USDCAddresses.address(for: 42161) != nil)
        #expect(USDCAddresses.address(for: 10) != nil)
        #expect(USDCAddresses.address(for: 137) != nil)
        #expect(USDCAddresses.address(for: 999999) == nil)
    }

    @Test("Token display names")
    func tokenDisplayNames() {
        #expect(TokenIdentifier.eth.displayName == "ETH")
        #expect(TokenIdentifier.usdc.displayName == "USDC")
        let erc20 = TokenIdentifier.erc20(address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", chainId: 1)
        #expect(erc20.displayName.contains("ERC20"))
    }

    @Test("ETH contract address is nil")
    func ethContractAddress() {
        #expect(TokenIdentifier.eth.contractAddress(chainId: 1) == nil)
    }

    @Test("USDC contract address returns correct address")
    func usdcContractAddress() {
        let addr = TokenIdentifier.usdc.contractAddress(chainId: 1)
        #expect(addr == "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    }

    @Test("Token decimals")
    func tokenDecimals() {
        #expect(TokenIdentifier.eth.decimals == 18)
        #expect(TokenIdentifier.usdc.decimals == 6)
    }

    @Test("Chain config names")
    func chainConfigNames() {
        #expect(ChainConfig.name(for: 1) == "Ethereum")
        #expect(ChainConfig.name(for: 8453) == "Base")
        #expect(ChainConfig.name(for: 999) == "Chain 999")
    }
}

// MARK: - RuleEngine Config Tests

@Suite("RuleEngine Config")
struct RuleEngineConfigTests {

    @Test("Load default config when keychain empty")
    func loadDefaultConfig() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let config = engine.loadConfig()
        #expect(config.authPolicy == .biometricOrPasscode)
        #expect(config.rules.enabled == true)
        #expect(config.rules.requireExplicitApproval == true)
        #expect(config.rules.rateLimits.isEmpty)
        #expect(config.rules.spendingLimits.isEmpty)
        #expect(SettingsApprovalPreviewTiming.presentationDelay == 0.15)
    }

    @Test("Corrupt keychain data falls back to defaults and sets configCorrupted")
    func corruptConfigSetsFlag() {
        let keychain = MockKeychainBackend()
        keychain.write(account: "config", data: Data("not valid json".utf8))
        let engine = RuleEngine(keychain: keychain)
        engine.loadConfigOnStartup()
        #expect(engine.configCorrupted == true)
        #expect(engine.config.pauseState.paused == true)
        #expect(engine.config.authPolicy == .biometricOrPasscode)
        #expect(engine.config.rules.enabled == true)
    }

    @Test("Corrupt keychain data records recovery snapshot")
    func corruptConfigRecordsRecoverySnapshot() throws {
        let keychain = MockKeychainBackend()
        let raw = Data("{\"version\":".utf8)
        keychain.write(account: "config", data: raw)
        let engine = RuleEngine(keychain: keychain)

        engine.loadConfigOnStartup()

        let snapshot = try #require(engine.configRecoverySnapshot())
        #expect(snapshot.rawConfig == raw)
        #expect(snapshot.byteCount == raw.count)
        #expect(snapshot.reason.contains("could not be decoded"))
    }

    @Test("Schema-invalid decoded config records recovery snapshot")
    func schemaInvalidConfigRecordsRecoverySnapshot() throws {
        let keychain = MockKeychainBackend()
        var config = BastionConfig.default
        config.highValue = HighValueRule(enabled: true, thresholdUsd: 0, confirmationPhrase: "CONFIRM")
        let raw = try JSONEncoder().encode(config)
        keychain.write(account: "config", data: raw)
        let engine = RuleEngine(keychain: keychain)

        engine.loadConfigOnStartup()

        #expect(engine.configCorrupted == true)
        let snapshot = try #require(engine.configRecoverySnapshot())
        #expect(snapshot.rawConfig == raw)
        #expect(snapshot.reason.contains("schema validation"))
    }

    @Test("Empty keychain does not set configCorrupted")
    func emptyKeychainNoCorruptFlag() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        engine.loadConfigOnStartup()
        #expect(engine.configCorrupted == false)
    }

    @Test("Saving new config then reloading clears configCorrupted")
    func saveConfigClearsCorruptFlag() throws {
        let keychain = MockKeychainBackend()
        keychain.write(account: "config", data: Data("not valid json".utf8))
        let engine = RuleEngine(keychain: keychain)
        engine.loadConfigOnStartup()
        #expect(engine.configCorrupted == true)
        // Recover by writing a valid config
        try engine.saveConfig(.default)
        engine.loadConfigOnStartup()
        #expect(engine.configCorrupted == false)
        #expect(engine.configRecoverySnapshot() == nil)
    }

    @Test("Config save fails closed when Keychain write fails")
    func saveConfigFailsWhenKeychainWriteFails() {
        let engine = RuleEngine(keychain: FailingWriteKeychainBackend())
        #expect(throws: BastionError.self) {
            try engine.saveConfig(.default)
        }
    }

    @Test("Save and load config with rate limits")
    func saveAndLoadRateLimits() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var newConfig = BastionConfig.default
        newConfig.authPolicy = .biometric
        newConfig.rules.rateLimits = [
            RateLimitRule(id: "r1", maxRequests: 10, windowSeconds: 3600),
            RateLimitRule(id: "r2", maxRequests: 50, windowSeconds: 86400),
        ]

        try engine.saveConfig(newConfig)
        let loaded = engine.loadConfig()
        #expect(loaded.authPolicy == .biometric)
        #expect(loaded.rules.rateLimits.count == 2)
        #expect(loaded.rules.rateLimits[0].maxRequests == 10)
        #expect(loaded.rules.rateLimits[1].windowSeconds == 86400)
    }

    @Test("Save and load config with spending limits")
    func saveAndLoadSpendingLimits() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var newConfig = BastionConfig.default
        newConfig.rules.spendingLimits = [
            SpendingLimitRule(id: "s1", token: .eth, allowance: "1000000000000000000", windowSeconds: 86400),
            SpendingLimitRule(id: "s2", token: .usdc, allowance: "1000000", windowSeconds: nil),
        ]

        try engine.saveConfig(newConfig)
        let loaded = engine.loadConfig()
        #expect(loaded.rules.spendingLimits.count == 2)
        #expect(loaded.rules.spendingLimits[0].token == .eth)
        #expect(loaded.rules.spendingLimits[1].token == .usdc)
        #expect(loaded.rules.spendingLimits[1].windowSeconds == nil)
    }

    @Test("Save and load config with allowed targets")
    func saveAndLoadAllowedTargets() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var newConfig = BastionConfig.default
        newConfig.rules.allowedTargets = [
            "1": ["0xdead", "0xbeef"],
            "8453": ["0xcafe"],
        ]

        try engine.saveConfig(newConfig)
        let loaded = engine.loadConfig()
        #expect(loaded.rules.allowedTargets?["1"]?.count == 2)
        #expect(loaded.rules.allowedTargets?["8453"]?.first == "0xcafe")
    }

    @Test("Settings diff presentation reports semantic save bar state")
    func settingsDiffPresentation() {
        let saved = BastionConfig.default
        var draft = saved

        #expect(SettingsDiffPresentation.hasUnsavedChanges(saved: saved, draft: draft) == false)
        #expect(SettingsDiffPresentation.diffLines(saved: saved, draft: draft).isEmpty)

        draft.authPolicy = .biometric
        draft.rules.allowedHours = AllowedHours(start: 9, end: 17)
        draft.rules.spendingLimits.append(SpendingLimitRule(
            id: "usdc-daily",
            token: .usdc,
            allowance: "1000000",
            windowSeconds: 86_400
        ))
        draft.rules.rateLimits.append(RateLimitRule(id: "requests", maxRequests: 5, windowSeconds: 3_600))
        draft.rules.rawMessagePolicy.enabled = false
        draft.rules.typedDataPolicy.enabled = false

        let lines = SettingsDiffPresentation.diffLines(saved: saved, draft: draft)
        #expect(lines.map(\.removed) == [
            "Auth policy: Biometric or Passcode",
            "Allowed hours: any time",
            "Spending limits: 0 rules",
            "Rate limits: 0 rules",
            "Raw message signing: on",
            "EIP-712 typed data: on",
        ])
        #expect(lines.map(\.added) == [
            "Auth policy: Biometric Only",
            "Allowed hours: 09:00–17:00",
            "Spending limits: 1 rules",
            "Rate limits: 1 rules",
            "Raw message signing: off",
            "EIP-712 typed data: off",
        ])

        let idle = SettingsDiffPresentation.saveBar(saved: saved, draft: draft, isSaving: false)
        #expect(idle == SaveBarPresentation(
            changeCount: 6,
            subtitle: "6 changes will affect running agents on next request",
            saveButtonTitle: "Save",
            actionsDisabled: false
        ))
        #expect(SettingsDiffPresentation.hasUnsavedChanges(saved: saved, draft: draft) == true)

        let saving = SettingsDiffPresentation.saveBar(saved: saved, draft: draft, isSaving: true)
        #expect(saving.saveButtonTitle == "Saving…")
        #expect(saving.actionsDisabled == true)
    }

    @Test("Settings navigation presentation covers sidebar inventory and panel routing")
    func settingsNavigationPresentation() {
        var config = BastionConfig.default
        config.clientProfiles = [
            ClientProfile(
                id: "client-a",
                bundleId: "com.example.agent",
                label: "Example Agent",
                rules: .default
            ),
            ClientProfile(
                id: "client-b",
                bundleId: "com.example.unlabeled",
                label: nil,
                rules: .default
            ),
        ]
        config.walletGroups = [
            WalletGroup(id: "group-a", label: "Treasury Group", chainIds: [8453]),
            WalletGroup(id: "group-b", label: "", chainIds: [1]),
        ]

        let navigation = SettingsNavigationPresentation.make(config: config, selection: .policyHistory)
        #expect(navigation.showsFakeTitleBar == false)
        #expect(navigation.defaultItems.map(\.label) == [
            "Default profile",
            "App preferences",
            "Rule templates",
            "High-value rule",
            "Address book",
            "Policy simulator",
            "Policy history",
        ])
        #expect(navigation.defaultItems.map(\.selection) == [
            .defaultProfile,
            .appPreferences,
            .ruleTemplates,
            .highValueRule,
            .addressBook,
            .policySimulator,
            .policyHistory,
        ])
        #expect(navigation.defaultItems.first(where: { $0.selection == .policyHistory })?.selected == true)
        #expect(navigation.defaultItems.filter(\.selected).map(\.selection) == [.policyHistory])

        #expect(navigation.clientItems.map(\.label) == ["Example Agent", "com.example.unlabeled"])
        #expect(navigation.clientItems.map(\.sublabel) == ["com.example.agent", "com.example.unlabeled"])
        #expect(navigation.clientItems.map(\.selection) == [.client(id: "client-a"), .client(id: "client-b")])
        #expect(navigation.clientsEmptyMessage == nil)

        #expect(navigation.walletGroupItems.map(\.label) == ["Treasury Group", "Wallet Group"])
        #expect(navigation.walletGroupItems.map(\.selection) == [.walletGroup(id: "group-a"), .walletGroup(id: "group-b")])
        #expect(navigation.walletGroupsEmptyMessage == nil)
        #expect(navigation.mainPanelRoute == .policyHistory)

        let expectedRoutes: [(SettingsSelection, SettingsMainPanelRoute)] = [
            (.defaultProfile, .defaultProfile),
            (.appPreferences, .appPreferences),
            (.ruleTemplates, .ruleTemplates),
            (.highValueRule, .highValueRule),
            (.addressBook, .addressBook),
            (.policySimulator, .policySimulator),
            (.policyHistory, .policyHistory),
            (.client(id: "client-a"), .client(id: "client-a")),
            (.walletGroup(id: "group-a"), .walletGroup(id: "group-a")),
        ]
        for (selection, route) in expectedRoutes {
            #expect(SettingsNavigationPresentation.mainPanelRoute(config: config, selection: selection) == route)
        }
        #expect(SettingsNavigationPresentation.mainPanelRoute(config: config, selection: .client(id: "missing")) == .emptySelection)
        #expect(SettingsNavigationPresentation.mainPanelRoute(config: config, selection: .walletGroup(id: "missing")) == .emptySelection)

        let emptyNavigation = SettingsNavigationPresentation.make(config: .default, selection: .defaultProfile)
        #expect(emptyNavigation.clientsEmptyMessage == "No agents paired yet")
        #expect(emptyNavigation.walletGroupsEmptyMessage == "No groups")
        #expect(emptyNavigation.clientItems.isEmpty)
        #expect(emptyNavigation.walletGroupItems.isEmpty)
    }

    @Test("Rule templates present reusable cards and apply defaults deterministically")
    func ruleTemplatesPresentationAndDefaultApply() throws {
        let presentation = RuleTemplatesPanelPresentation.make()
        #expect(presentation.title == "Rule templates")
        #expect(presentation.subtitle == "Reusable starting points for new agents. Apply one to defaults or pair an agent from it.")
        #expect(presentation.subtitle.contains("edit") == false)
        #expect(presentation.subtitle.contains("clone") == false)
        #expect(presentation.newAgentButtonTitle == "+ New agent")
        #expect(presentation.cards.map(\.template) == [.conservative, .readOnly, .treasury])
        #expect(presentation.cards.map(\.id) == ["conservative", "readOnly", "treasury"])
        #expect(presentation.cards.contains { $0.template == .custom } == false)

        let conservative = try #require(presentation.cards.first { $0.template == .conservative })
        #expect(conservative.title == "Conservative DeFi")
        #expect(conservative.hint == PairingPolicyTemplate.conservative.hint)
        #expect(conservative.metrics == [
            RuleTemplateMetricPresentation(key: "USDC/DAY", value: "50/day"),
            RuleTemplateMetricPresentation(key: "ETH/DAY", value: "0.02/day"),
            RuleTemplateMetricPresentation(key: "RATE", value: "60/hour"),
            RuleTemplateMetricPresentation(key: "AUTH", value: "Biometric Only"),
        ])
        #expect(conservative.applyButtonTitle == "Apply to default")
        #expect(conservative.pairButtonTitle == "Pair agent")

        let readOnly = try #require(presentation.cards.first { $0.template == .readOnly })
        #expect(readOnly.metrics == [
            RuleTemplateMetricPresentation(key: "USDC/DAY", value: "0/day"),
            RuleTemplateMetricPresentation(key: "ETH/DAY", value: "0/day"),
            RuleTemplateMetricPresentation(key: "RATE", value: "200/hour"),
            RuleTemplateMetricPresentation(key: "AUTH", value: "Biometric Only"),
        ])

        let treasury = try #require(presentation.cards.first { $0.template == .treasury })
        #expect(treasury.metrics == [
            RuleTemplateMetricPresentation(key: "USDC/DAY", value: "10000/day"),
            RuleTemplateMetricPresentation(key: "ETH/DAY", value: "5/day"),
            RuleTemplateMetricPresentation(key: "RATE", value: "10/hour"),
            RuleTemplateMetricPresentation(key: "AUTH", value: "Biometric or Passcode"),
        ])

        var config = BastionConfig.default
        config.authPolicy = .open
        config.rules = .default
        config.clientProfiles = [
            ClientProfile(
                id: "client-a",
                bundleId: "com.example.agent",
                label: "Example Agent",
                rules: .default
            )
        ]

        let result = RuleTemplateApplication.applyToDefault(.treasury, config: config)
        #expect(result.config.authPolicy == .biometricOrPasscode)
        #expect(result.config.rules.userOpPosture == .enforceRulesAndRequireApproval)
        #expect(result.config.rules.allowedHours?.start == 9)
        #expect(result.config.rules.allowedHours?.end == 18)
        #expect(result.config.rules.allowedChains == [1, 8453])
        #expect(result.config.rules.rateLimits.map(\.maxRequests) == [10])
        #expect(result.config.rules.rateLimits.map(\.windowSeconds) == [3_600])
        #expect(result.config.rules.rawMessagePolicy.enabled == false)
        #expect(result.config.rules.typedDataPolicy.requireExplicitApproval == true)
        #expect(result.config.rules.spendingLimits.contains { $0.token == .usdc && $0.allowance == "10000000000" && $0.windowSeconds == 86_400 })
        #expect(result.config.rules.spendingLimits.contains { $0.token == .eth && $0.allowance == "5000000000000000000" && $0.windowSeconds == 86_400 })
        #expect(result.config.clientProfiles.map(\.id) == ["client-a"])
        #expect(result.statusMessage == "Applied Treasury custodian to the default profile")
        #expect(result.statusIsError == false)
        #expect(result.selection == .defaultProfile)
    }

    @Test("Policy history restore lists recovery sources and loads draft without saving")
    func policyHistoryRestorePresentationAndLoadDraft() throws {
        var historical = BastionConfig.default
        historical.version = 7
        historical.authPolicy = .biometric
        historical.clientProfiles = [
            ClientProfile(
                id: "restored-client",
                bundleId: "com.example.restored",
                label: "Restored Agent",
                rules: .default
            )
        ]
        historical.walletGroups = [
            WalletGroup(id: "restored-group", label: "Restored Group", chainIds: [8453])
        ]
        historical.rules.allowedHours = AllowedHours(start: 10, end: 16)

        var premigration = BastionConfig.default
        premigration.version = 5
        premigration.authPolicy = .open
        premigration.clientProfiles = [
            ClientProfile(
                id: "legacy-client",
                bundleId: "com.example.legacy",
                label: "Legacy Agent",
                rules: .default
            )
        ]
        let recoveryDate = Date(timeIntervalSince1970: 0)
        let recoverySnapshot = RuleEngine.ConfigRecoverySnapshot(
            capturedAt: recoveryDate,
            reason: "Stored config could not be decoded",
            rawConfig: Data("{bad".utf8)
        )
        let versionTimestamp = Date(timeIntervalSince1970: 3_600)
        let version = PolicyVersion(
            id: "policy-version-1",
            timestamp: versionTimestamp,
            summary: "auth=biometric · clients=1 · groups=1 · templates=0",
            config: historical
        )
        let utc = try #require(TimeZone(secondsFromGMT: 0))
        let presentation = PolicyHistoryPanelPresentation.make(
            versions: [version],
            premigrationBackup: premigration,
            recoverySnapshot: recoverySnapshot,
            recoveryExportStatus: "Exported recovery.json",
            recoveryExportError: nil,
            timeZone: utc
        )
        #expect(presentation.title == "Policy history")
        #expect(presentation.subtitle == "Every saved policy change is snapshotted. Restore an older version with biometric auth.")
        #expect(presentation.recovery == PolicyHistoryRecoveryCardPresentation(
            title: "Corrupt config recovery",
            metadata: "Stored config could not be decoded · 4 bytes · \(PolicyHistoryPanelPresentation.displayTimestamp(recoveryDate, timeZone: utc))",
            exportButtonTitle: "Export raw",
            exportButtonDisabled: false,
            loadBackupButtonTitle: "Load backup",
            exportStatus: "Exported recovery.json",
            exportError: nil
        ))
        let exportingPresentation = PolicyHistoryPanelPresentation.make(
            versions: [],
            premigrationBackup: nil,
            recoverySnapshot: recoverySnapshot,
            recoveryExportStatus: nil,
            recoveryExportError: nil,
            recoveryExportIsExporting: true,
            timeZone: utc
        )
        #expect(exportingPresentation.recovery?.exportButtonTitle == "Exporting…")
        #expect(exportingPresentation.recovery?.exportButtonDisabled == true)
        #expect(presentation.backup == PolicyHistoryBackupCardPresentation(
            title: "Pre-migration backup",
            metadata: "Schema v5 · auth=open · clients=1",
            loadButtonTitle: "Load backup"
        ))
        #expect(presentation.savedVersionsTitle == "Saved versions")
        #expect(presentation.emptyVersionsMessage == nil)
        #expect(presentation.versions == [
            PolicyHistoryVersionRowPresentation(
                id: "policy-version-1",
                timestamp: PolicyHistoryPanelPresentation.displayTimestamp(versionTimestamp, timeZone: utc),
                summary: "auth=biometric · clients=1 · groups=1 · templates=0",
                restoreButtonTitle: "Restore"
            )
        ])

        let emptyPresentation = PolicyHistoryPanelPresentation.make(
            versions: [],
            premigrationBackup: nil,
            recoverySnapshot: nil,
            recoveryExportStatus: nil,
            recoveryExportError: nil,
            timeZone: utc
        )
        #expect(emptyPresentation.recovery == nil)
        #expect(emptyPresentation.backup == nil)
        #expect(emptyPresentation.emptyVersionsMessage == "No prior versions recorded yet.")
        #expect(emptyPresentation.versions.isEmpty)

        #expect(PolicyRecoverySnapshotExportPresentation.defaultFileName(for: recoveryDate, timeZone: utc) == "bastion-corrupt-config-19700101-000000.json")
        #expect(PolicyRecoverySnapshotExportPresentation.successMessage(for: URL(fileURLWithPath: "/tmp/recovery.json")) == "Exported recovery.json")
        let exportError = NSError(domain: NSCocoaErrorDomain, code: NSFileNoSuchFileError, userInfo: [NSLocalizedDescriptionKey: "missing destination"])
        #expect(PolicyRecoverySnapshotExportPresentation.failureMessage(for: exportError) == "Export failed: missing destination")

        var exportState = PolicyRecoverySnapshotExportState(status: "old.json", error: "Export failed: stale", isExporting: false)
        #expect(exportState.beginExport() == true)
        #expect(exportState.status == nil)
        #expect(exportState.error == nil)
        #expect(exportState.isExporting == true)
        #expect(exportState.beginExport() == false)

        exportState.cancelExport()
        #expect(exportState.isExporting == false)

        #expect(exportState.beginExport() == true)
        exportState.succeed(url: URL(fileURLWithPath: "/tmp/recovery.json"))
        #expect(exportState.status == "Exported recovery.json")
        #expect(exportState.error == nil)
        #expect(exportState.isExporting == false)

        #expect(exportState.beginExport() == true)
        exportState.fail(exportError)
        #expect(exportState.status == nil)
        #expect(exportState.error == "Export failed: missing destination")
        #expect(exportState.isExporting == false)

        let result = PolicyHistoryRestore.loadDraft(historical, savedConfig: .default)

        #expect(result.draftConfig.version == 7)
        #expect(result.draftConfig.authPolicy == .biometric)
        #expect(result.draftConfig.clientProfiles.map(\.id) == ["restored-client"])
        #expect(result.draftConfig.walletGroups.map(\.id) == ["restored-group"])
        #expect(result.draftConfig.rules.allowedHours?.start == 10)
        #expect(result.draftConfig.rules.allowedHours?.end == 16)
        #expect(result.selection == .defaultProfile)
        #expect(result.statusMessage == "Loaded version into draft. Review and Save to apply.")
        #expect(result.statusIsError == false)
        #expect(result.requiresSave == true)

        let noOpResult = PolicyHistoryRestore.loadDraft(.default, savedConfig: .default)
        #expect(noOpResult.requiresSave == false)
    }

    @Test("Menu bar status presentation reports availability states")
    func menuBarStatusPresentation() {
        let active = MenuBarStatusPresentation.make(
            armed: true,
            activeClients: 2,
            pauseState: .default
        )
        #expect(active == MenuBarStatusPresentation(
            mode: .active,
            headerTitle: "Bastion",
            subtitle: "Armed · 2 agents configured",
            showsStats: true,
            showsPolicyStatusWarning: false,
            pauseButtonTitle: "Pause"
        ))

        let corrupt = MenuBarStatusPresentation.make(
            armed: false,
            activeClients: 1,
            pauseState: .default
        )
        #expect(corrupt.mode == .configCorrupt)
        #expect(corrupt.subtitle == "Rules config corrupt")
        #expect(corrupt.showsStats == true)
        #expect(corrupt.showsPolicyStatusWarning == true)

        let empty = MenuBarStatusPresentation.make(
            armed: false,
            activeClients: 0,
            pauseState: .default
        )
        #expect(empty.mode == .empty)
        #expect(empty.subtitle == "Idle · no agents paired")
        #expect(empty.showsStats == false)
        #expect(empty.showsPolicyStatusWarning == false)
        #expect(empty.pauseButtonTitle == nil)

        let paused = MenuBarStatusPresentation.make(
            armed: true,
            activeClients: 3,
            pauseState: PauseState(paused: true, lockedDown: false, pausedAt: nil, reason: nil)
        )
        #expect(paused.mode == .paused)
        #expect(paused.headerTitle == "Bastion paused")
        #expect(paused.subtitle == "Approval UI is in review-only mode")
        #expect(paused.showsStats == true)
        #expect(paused.pauseButtonTitle == "Resume")

        let lockedDown = MenuBarStatusPresentation.make(
            armed: true,
            activeClients: 3,
            pauseState: PauseState(paused: true, lockedDown: true, pausedAt: nil, reason: "incident response")
        )
        #expect(lockedDown.mode == .lockedDown)
        #expect(lockedDown.headerTitle == "Lockdown active")
        #expect(lockedDown.subtitle == "incident response")
        #expect(lockedDown.showsStats == false)
        #expect(lockedDown.pauseButtonTitle == nil)

        #expect(MenuBarStatusPresentation.armedSubtitle(armed: true, activeClients: 0) == "Armed · default rules")
        #expect(MenuBarStatusPresentation.armedSubtitle(armed: true, activeClients: 1) == "Armed · 1 agent configured")
        #expect(MenuBarApprovalPreviewTiming.presentationDelay == 0.15)
    }

    @Test("Pause and resume menu actions route through lockdown manager")
    @MainActor
    func pauseResumeMenuActions() async {
        let pauseManager = MockMenuBarLockdownManager(setPausedResults: [true])
        let pauseActions = MenuBarStatusActionController(lockdownManager: pauseManager)
        let pauseOutcome = await pauseActions.togglePause(current: .default)
        #expect(pauseManager.setPausedCalls.count == 1)
        #expect(pauseManager.setPausedCalls[0].paused == true)
        #expect(pauseManager.setPausedCalls[0].reason == nil)
        #expect(pauseOutcome.errorMessage == nil)

        let toggleResumeManager = MockMenuBarLockdownManager(setPausedResults: [true])
        let toggleResumeActions = MenuBarStatusActionController(lockdownManager: toggleResumeManager)
        let toggleResumeOutcome = await toggleResumeActions.togglePause(
            current: PauseState(paused: true, lockedDown: false, pausedAt: nil, reason: "Owner paused signing")
        )
        #expect(toggleResumeManager.setPausedCalls.count == 1)
        #expect(toggleResumeManager.setPausedCalls[0].paused == false)
        #expect(toggleResumeManager.setPausedCalls[0].reason == nil)
        #expect(toggleResumeOutcome.errorMessage == nil)

        let pauseFailureManager = MockMenuBarLockdownManager(setPausedResults: [false])
        let pauseFailureOutcome = await MenuBarStatusActionController(lockdownManager: pauseFailureManager)
            .togglePause(current: .default)
        #expect(pauseFailureManager.setPausedCalls[0].paused == true)
        #expect(pauseFailureOutcome.errorMessage == "Pause is active in memory, but the paused state could not be saved.")

        let resumeFailureManager = MockMenuBarLockdownManager(setPausedResults: [false])
        let resumeFailureOutcome = await MenuBarStatusActionController(lockdownManager: resumeFailureManager)
            .resumeSigning()
        #expect(resumeFailureManager.setPausedCalls.count == 1)
        #expect(resumeFailureManager.setPausedCalls[0].paused == false)
        #expect(resumeFailureOutcome.errorMessage == "Could not fully resume signing. Authentication may have been cancelled or the updated state could not be saved.")
    }

    @Test("Emergency lockdown menu presents residual surface and outcomes")
    @MainActor
    func emergencyLockdownMenuActions() async {
        let presentation = MenuBarLockdownPresentation.make(
            reason: "incident response",
            installedValidators: 2,
            activeSessions: 1
        )
        #expect(presentation.title == "Lockdown active")
        #expect(presentation.subtitle == "incident response")
        #expect(presentation.detail == "New requests are denied. Validators left installed on-chain remain part of the attack surface — uninstall to fully revoke.")
        #expect(presentation.installedValidators == 2)
        #expect(presentation.installedValidatorsLabel == "validators on-chain")
        #expect(presentation.installedValidatorsWarn == true)
        #expect(presentation.activeSessions == 1)
        #expect(presentation.activeSessionsLabel == "active sessions")
        #expect(presentation.activeSessionsWarn == true)
        #expect(presentation.leaveButtonTitle == "Leave lockdown")

        let clearPresentation = MenuBarLockdownPresentation.make(
            reason: nil,
            installedValidators: 0,
            activeSessions: 0
        )
        #expect(clearPresentation.subtitle == "All signing rejected")
        #expect(clearPresentation.installedValidatorsWarn == false)
        #expect(clearPresentation.activeSessionsWarn == false)

        let enterLockdownManager = MockMenuBarLockdownManager(enterLockdownResults: [true])
        let enterLockdownOutcome = await MenuBarStatusActionController(lockdownManager: enterLockdownManager)
            .enterLockdown(reason: "Owner emergency lockdown")
        #expect(enterLockdownManager.enterLockdownReasons == ["Owner emergency lockdown"])
        #expect(enterLockdownOutcome.errorMessage == nil)

        let enterLockdownFailureManager = MockMenuBarLockdownManager(enterLockdownResults: [false])
        let enterLockdownFailureOutcome = await MenuBarStatusActionController(lockdownManager: enterLockdownFailureManager)
            .enterLockdown(reason: "Owner emergency lockdown")
        #expect(enterLockdownFailureManager.enterLockdownReasons == ["Owner emergency lockdown"])
        #expect(enterLockdownFailureOutcome.errorMessage == "Lockdown is active in memory, but some lockdown state or session revocation could not be saved.")

        let leaveLockdownManager = MockMenuBarLockdownManager(leaveLockdownResults: [true])
        let leaveLockdownOutcome = await MenuBarStatusActionController(lockdownManager: leaveLockdownManager)
            .leaveLockdown()
        #expect(leaveLockdownManager.leaveLockdownCalls == 1)
        #expect(leaveLockdownOutcome.errorMessage == nil)

        let leaveLockdownFailureManager = MockMenuBarLockdownManager(leaveLockdownResults: [false])
        let leaveLockdownFailureOutcome = await MenuBarStatusActionController(lockdownManager: leaveLockdownFailureManager)
            .leaveLockdown()
        #expect(leaveLockdownFailureManager.leaveLockdownCalls == 1)
        #expect(leaveLockdownFailureOutcome.errorMessage == "Could not fully leave lockdown. Authentication may have been cancelled or the updated state could not be saved.")
    }

    @Test("Menu bar activity presentation reports stats, pending confirmations, and recent rows")
    func menuBarActivityPresentation() {
        let stats = MenuBarStatsPresentation.make(totalToday: 61, silentToday: 60, overridesToday: 1)
        #expect(stats.tiles == [
            MenuBarStatTilePresentation(value: 61, label: "signed today", warn: false),
            MenuBarStatTilePresentation(value: 60, label: "silent", warn: false),
            MenuBarStatTilePresentation(value: 1, label: "overrides", warn: true),
        ])
        #expect(MenuBarStatsPresentation.make(totalToday: 1, silentToday: 0, overridesToday: 0).tiles[2].warn == false)

        let submittedAt = Date(timeIntervalSince1970: 1_710_000_000)
        let pendingStatus = PendingUserOperationStatus(
            requestID: "userop-1",
            clientDisplayName: "Bundler Agent",
            provider: "ZeroDev",
            chainId: 8453,
            userOpHash: "0x1234567890abcdef1234567890abcdef12",
            submittedAt: submittedAt
        )
        let pending = MenuBarPendingSubmissionsPresentation.make([pendingStatus])
        #expect(pending.sectionTitle == "Pending confirmations")
        #expect(pending.auditButtonTitle == "Audit")
        #expect(pending.rows.count == 1)
        #expect(pending.rows[0].id == "userop-1")
        #expect(pending.rows[0].clientDisplayName == "Bundler Agent")
        #expect(pending.rows[0].provider == "ZeroDev")
        #expect(pending.rows[0].chainId == 8453)
        #expect(pending.rows[0].statusLabel == "Awaiting receipt")
        #expect(pending.rows[0].submittedAt == submittedAt)
        #expect(pending.rows[0].userOpHash == "0x1234567890abcdef1234567890abcdef12")
        #expect(pending.rows[0].userOpHashShort == "0x12345678…cdef12")
        #expect(pending.rows[0].rowHelp == "Client: Bundler Agent\nProvider: ZeroDev\nChain: 8453\nUserOperation: 0x1234567890abcdef1234567890abcdef12")

        let client = makeClientContext(profileLabel: "Example Agent")
        let autoRecord = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "auto-1",
                approvalMode: .auto,
                request: makeMessageRequest(requestID: "auto-1", clientBundleId: "com.example.agent"),
                clientContext: client
            )
        ])
        let overrideRecord = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "override-1",
                approvalMode: .ruleOverride,
                request: makeMessageRequest(requestID: "override-1", clientBundleId: "com.example.agent"),
                clientContext: client
            )
        ])
        let pendingRecord = AuditRequestRecord(events: [
            AuditEvent(
                type: .signPending,
                dataPrefix: "pending-1",
                request: makeMessageRequest(requestID: "pending-1", clientBundleId: "com.example.agent"),
                clientContext: client
            )
        ])
        let deniedRecord = AuditRequestRecord(events: [
            AuditEvent(
                type: .signDenied,
                dataPrefix: "denied-1",
                request: makeMessageRequest(requestID: "denied-1", clientBundleId: "com.example.agent"),
                clientContext: client
            )
        ])

        let recent = MenuBarRecentActivityPresentation.make(
            records: [autoRecord, overrideRecord, pendingRecord, deniedRecord],
            limit: 3
        )
        #expect(recent.sectionTitle == "Recent activity")
        #expect(recent.viewAllButtonTitle == "View all")
        #expect(recent.emptyMessage == "No recent activity")
        #expect(recent.rows.map(\.id) == ["auto-1", "override-1", "pending-1"])
        #expect(recent.rows[0].title == "Raw / Message Signing · Personal-sign UTF-8 message")
        #expect(recent.rows[0].client == "Example Agent")
        #expect(recent.rows[0].mode == .signOnly)
        #expect(recent.rows[0].dot == .ok)
        #expect(recent.rows[0].trailingTag == "silent")
        #expect(recent.rows[0].trailingTagDot == .idle)
        #expect(recent.rows[0].rowHelp == "Activity: Raw / Message Signing · Personal-sign UTF-8 message\nClient: Example Agent\nMode: Sign only\nTag: silent")
        #expect(recent.rows[1].dot == .ok)
        #expect(recent.rows[1].trailingTag == "override")
        #expect(recent.rows[1].trailingTagDot == .warn)
        #expect(recent.rows[1].rowHelp == "Activity: Raw / Message Signing · Personal-sign UTF-8 message\nClient: Example Agent\nMode: Sign only\nTag: override")
        #expect(recent.rows[2].dot == .warn)
        #expect(recent.rows[2].trailingTag == nil)
        #expect(recent.rows[2].rowHelp == "Activity: Raw / Message Signing · Personal-sign UTF-8 message\nClient: Example Agent\nMode: Sign only")
        #expect(MenuBarRecentActivityPresentation.make(records: []).rows.isEmpty)
    }

    @Test("Audit history filters and saved views keep chips, search, and rows in sync")
    func auditHistoryFiltersAndSavedViews() {
        let treasury = makeClientContext(bundleId: "com.example.treasury", profileLabel: "Treasury Bot")
        let agent = makeClientContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
        let silent = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "silent-1",
                approvalMode: .auto,
                request: makeMessageRequest(requestID: "silent-1", clientBundleId: "com.example.treasury"),
                clientContext: treasury
            )
        ])
        let override = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "override-1",
                approvalMode: .ruleOverride,
                request: makeMessageRequest(requestID: "override-1", clientBundleId: "com.example.treasury"),
                clientContext: treasury
            )
        ])
        let failed = AuditRequestRecord(events: [
            AuditEvent(
                type: .signDenied,
                dataPrefix: "failed-1",
                reason: "Rule denied",
                request: makeMessageRequest(requestID: "failed-1", clientBundleId: "com.example.agent"),
                clientContext: agent
            )
        ])
        let chainRecord = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "typed-chain",
                approvalMode: .policyReview,
                request: makeTypedDataRequest(requestID: "typed-chain", chainId: 8453),
                clientContext: agent
            )
        ])

        let state = AuditHistoryFilterState(
            records: [silent, override, failed, chainRecord],
            search: "",
            filters: .default,
            savedView: nil
        )
        #expect(state.hasActiveFilters == false)
        #expect(state.filteredRecords.map(\.id) == ["silent-1", "override-1", "failed-1", "typed-chain"])

        let overrides = state.applyingSavedView(.overrides)
        #expect(overrides.savedView == .overrides)
        #expect(overrides.search == "")
        #expect(overrides.filters == AuditFilters(outcome: .overrides, client: nil, chainId: nil, range: .last24h))
        #expect(overrides.filteredRecords.map(\.id) == ["override-1"])

        let silentView = state.applyingSavedView(.silent)
        #expect(silentView.filteredRecords.map(\.id) == ["silent-1"])
        let failedView = state.applyingSavedView(.failed)
        #expect(failedView.filteredRecords.map(\.id) == ["failed-1"])

        let searched = overrides.settingSearch(" treasury ")
        #expect(searched.savedView == nil)
        #expect(searched.search == " treasury ")
        #expect(searched.filteredRecords.map(\.id) == ["override-1"])

        let clientFiltered = overrides.settingFilter(\.client, to: Optional("Treasury Bot"))
        #expect(clientFiltered.savedView == nil)
        #expect(clientFiltered.filters.client == "Treasury Bot")
        #expect(clientFiltered.filteredRecords.map(\.id) == ["override-1"])

        let chainFiltered = state.settingFilter(\.chainId, to: Optional(8453))
        #expect(chainFiltered.filteredRecords.map(\.id) == ["typed-chain"])

        let cleared = searched.clearingFilters()
        #expect(cleared.search == "")
        #expect(cleared.filters == .default)
        #expect(cleared.savedView == nil)
        #expect(cleared.hasActiveFilters == false)

        let lowerIdentity = state.settingSearch(" treasury ").rowsContentIdentity
        let upperIdentity = state.settingSearch("TREASURY").rowsContentIdentity
        #expect(lowerIdentity == upperIdentity)
    }

    @Test("Audit tamper recovery banner presents broken, in-flight, error, and recovered states")
    func auditTamperRecoveryBannerPresentation() {
        let broken = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: false,
            recoveryMessage: nil,
            recoveryError: nil
        )
        #expect(broken.tone == .bad)
        #expect(broken.title == "Audit log integrity check failed")
        #expect(broken.message == "Export the visible records if needed, then archive and reset the broken log to resume audit writes.")
        #expect(broken.showsRecoveryActions == true)
        #expect(broken.exportButtonTitle == "Export…")
        #expect(broken.recoverButtonTitle == "Archive and reset")
        #expect(broken.dismissButtonTitle == nil)
        #expect(broken.disablesActions == false)
        #expect(broken.recoveryError == nil)
        #expect(broken.recoveryDetail == nil)

        let recovering = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: true,
            recoveryMessage: "stale success",
            recoveryError: nil
        )
        #expect(recovering.recoverButtonTitle == "Resetting…")
        #expect(recovering.disablesActions == true)
        #expect(recovering.recoveryDetail == nil)

        let failed = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: false,
            recoveryMessage: nil,
            recoveryError: "Recovery failed: owner authentication canceled"
        )
        #expect(failed.recoveryError == "Recovery failed: owner authentication canceled")
        #expect(failed.disablesActions == false)
        #expect(failed.showsRecoveryActions == true)

        let recovered = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: false,
            isRecovering: false,
            recoveryMessage: "Archived broken audit log to /tmp/audit-tampered.log",
            recoveryError: nil
        )
        #expect(recovered.tone == .ok)
        #expect(recovered.title == "Audit log recovery complete")
        #expect(recovered.message == "Archived broken audit log to /tmp/audit-tampered.log")
        #expect(recovered.recoveryDetail == "Archived broken audit log to /tmp/audit-tampered.log")
        #expect(recovered.showsRecoveryActions == false)
        #expect(recovered.exportButtonTitle == nil)
        #expect(recovered.recoverButtonTitle == nil)
        #expect(recovered.dismissButtonTitle == "Dismiss")
        #expect(recovered.disablesActions == false)
    }

    @Test("Expandable audit row presentation exposes metadata, timeline, and transaction actions")
    func expandableAuditRowPresentation() {
        let client = makeClientContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
        let request = makeTypedDataRequest(requestID: "typed-chain", chainId: 8453)
        let txHash = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .signSuccess,
                dataPrefix: "typed-chain",
                approvalMode: .ruleOverride,
                request: request,
                clientContext: client
            ),
            AuditEvent(
                type: .userOpSubmitted,
                dataPrefix: "typed-chain",
                request: request,
                clientContext: client,
                submission: AuditSubmissionSnapshot(
                    provider: "ZeroDev",
                    status: "submitted",
                    userOpHash: "0x1234",
                    transactionHash: nil,
                    detail: "Submitted"
                )
            ),
            AuditEvent(
                type: .userOpReceiptSuccess,
                dataPrefix: "typed-chain",
                request: request,
                clientContext: client,
                submission: AuditSubmissionSnapshot(
                    provider: "ZeroDev",
                    status: "receipt_success",
                    userOpHash: "0x1234",
                    transactionHash: txHash,
                    detail: "Confirmed"
                )
            )
        ])

        let collapsed = AuditRowPresentation.make(record, expanded: false)
        #expect(collapsed.id == "typed-chain")
        #expect(collapsed.clientDisplayName == "Example Agent")
        #expect(collapsed.operationTitle == "EIP-712 Typed Data")
        #expect(collapsed.executionMode == .approveAndSend)
        #expect(collapsed.outcome == AuditChipPresentation(label: "Confirmed", tone: .ok))
        #expect(collapsed.chainId == 8453)
        #expect(collapsed.disclosureSymbol == "›")
        #expect(collapsed.accessibilityLabelResult == "Confirmed")
        #expect(collapsed.accessibilityHint == "Expand details")
        #expect(collapsed.rowHelp == "Client: Example Agent\nOperation: EIP-712 Typed Data\nOutcome: Confirmed")

        let expandedRow = AuditRowPresentation.make(record, expanded: true)
        #expect(expandedRow.disclosureSymbol == "▾")
        #expect(expandedRow.accessibilityHint == "Collapse details")
        #expect(expandedRow.rowHelp == collapsed.rowHelp)

        let detail = AuditExpandedDetailPresentation.make(record, auditIntegrityBroken: false)
        #expect(detail.requestID == "typed-chain")
        #expect(detail.operationKindLabel == "Typed data")
        #expect(detail.executionMode == .approveAndSend)
        #expect(detail.rulePath == AuditChipPresentation(label: "—", tone: .neutral))
        #expect(detail.transactionHash == txHash)
        #expect(detail.transactionChainId == 8453)
        #expect(detail.auditSignature == AuditChipPresentation(label: "Tamper-evident · verified", tone: .ok))
        #expect(AuditExpandedDetailPresentation.make(record, auditIntegrityBroken: true).auditSignature == AuditChipPresentation(label: "Tampered — verify install", tone: .bad))

        #expect(detail.timelineRows.count == 3)
        #expect(detail.timelineRows[0].resultLabel == "Signed (Override)")
        #expect(detail.timelineRows[0].dotTone == .warn)
        #expect(detail.timelineRows[0].isLast == false)
        #expect(detail.timelineRows[1].resultLabel == "Submitted")
        #expect(detail.timelineRows[1].dotTone == .neutral)
        #expect(detail.timelineRows[2].resultLabel == "Confirmed")
        #expect(detail.timelineRows[2].dotTone == .ok)
        #expect(detail.timelineRows[2].transactionAction == .openExplorer)
        #expect(detail.timelineRows[2].transactionActionLabel == "View tx ↗")
        #expect(detail.timelineRows[2].transactionChainId == 8453)
        #expect(detail.timelineRows[2].isLast == true)

        let noExplorer = AuditTimelineEntryPresentation.make(record.events[2], isLast: true, chainId: nil)
        #expect(noExplorer.transactionAction == .copyHash)
        #expect(noExplorer.transactionActionLabel == "Copy tx")
        #expect(noExplorer.transactionAction?.label(copied: true) == "Copied")
    }

    @Test("Pairing wizard presentation covers manual and incoming validation")
    func pairingWizardPresentationCoversValidationAndSuccessCopy() {
        let missingName = PairingFlowPresentation.make(
            step: 0,
            hasPendingRequest: false,
            displayName: " ",
            bundleId: "com.example.agent",
            selectedChains: [8453]
        )
        #expect(missingName.headerTitle == "Pair new agent")
        #expect(missingName.stepLabel == "Step 1 of 5")
        #expect(missingName.handshakeTitle == "New agent")
        #expect(missingName.isBundleEditable == true)
        #expect(missingName.primaryButtonLabel == "Continue")
        #expect(missingName.canContinue == false)
        #expect(missingName.validationMessage == "Enter a display name before continuing.")

        let missingBundle = PairingFlowPresentation.make(
            step: 0,
            hasPendingRequest: false,
            displayName: "Example Agent",
            bundleId: " ",
            selectedChains: [8453]
        )
        #expect(missingBundle.validationMessage == "Enter the agent bundle ID before continuing.")

        let missingChains = PairingFlowPresentation.make(
            step: 2,
            hasPendingRequest: false,
            displayName: "Example Agent",
            bundleId: "com.example.agent",
            selectedChains: []
        )
        #expect(missingChains.canContinue == false)
        #expect(missingChains.validationMessage == "Select at least one allowed chain.")

        let incomingInstall = PairingFlowPresentation.make(
            step: 3,
            hasPendingRequest: true,
            displayName: " Incoming Agent ",
            bundleId: " com.example.incoming ",
            selectedChains: [1, 8453]
        )
        #expect(incomingInstall.handshakeTitle == "Incoming pair request")
        #expect(incomingInstall.handshakeSubtitle == "Confirm that these details match the agent terminal before creating a signing profile.")
        #expect(incomingInstall.isBundleEditable == false)
        #expect(incomingInstall.primaryButtonLabel == "Pair")
        #expect(incomingInstall.canContinue == true)
        #expect(incomingInstall.validationMessage == nil)
        #expect(incomingInstall.chainsLabel == "Ethereum, Base")
        #expect(incomingInstall.installRows == [
            "Generate Secure Enclave key",
            "Owner authorizes validator install",
            "Submit install UserOp via ZeroDev bundler",
            "Confirmation appears in Audit History",
        ])

        let success = PairingFlowPresentation.make(
            step: 4,
            hasPendingRequest: true,
            displayName: " Incoming Agent ",
            bundleId: " com.example.incoming ",
            selectedChains: [8453]
        )
        #expect(success.headerTitle == "Pairing complete")
        #expect(success.primaryButtonLabel == "Done")
        #expect(success.canContinue == true)
        #expect(success.validationMessage == nil)
        #expect(success.successTitle == "Profile created")
        #expect(success.successSubtitle == "Incoming Agent is paired locally.")
        #expect(success.successNotice == "Validator is not yet installed on-chain. Install it with the wallet-group CLI when you're ready, then refresh Settings to see the on-chain status.")
    }

    @Test("Signing approval presentation covers popup actions and idle guard")
    func signingApprovalPresentationCoversPopupActionsAndIdleGuard() {
        let client = makeClientContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
        let request = makeMessageRequest(requestID: "approval-message", clientBundleId: "com.example.agent")
        let approval = ApprovalRequest(
            request: request,
            mode: .policyReview,
            clientContext: client
        )
        let panelChrome = SigningRequestPanelChrome.current
        #expect(panelChrome.cardWidth == 420)
        #expect(panelChrome.detailScrollMaxHeight == 392)
        #expect(panelChrome.contentRect(fitting: NSSize(width: 999, height: 512.2)) == NSRect(x: 0, y: 0, width: 420, height: 513))
        #expect(panelChrome.styleMask.contains(.titled) == false)
        #expect(panelChrome.styleMask.contains(.closable) == false)
        #expect(panelChrome.styleMask.contains(.fullSizeContentView) == false)
        #expect(panelChrome.styleMask.contains(.nonactivatingPanel) == true)
        #expect(panelChrome.hasNativeShadow == false)
        #expect(panelChrome.hasClearBackground == true)
        #expect(panelChrome.usesTransparentHostView == true)
        #expect(panelChrome.usesNativeTitlebar == false)
        #expect(panelChrome.usesNativeCloseButton == false)
        #expect(ApprovalPreviewWindowHidingPlan.windowIDsToHide(
            primary: ApprovalPreviewWindowCandidate(id: 1, isApprovalPanel: false),
            allWindows: [
                ApprovalPreviewWindowCandidate(id: 2, isApprovalPanel: false),
                ApprovalPreviewWindowCandidate(id: 1, isApprovalPanel: false),
                ApprovalPreviewWindowCandidate(id: 3, isApprovalPanel: true),
                ApprovalPreviewWindowCandidate(id: 4, isApprovalPanel: false),
            ]
        ) == [1, 2, 4])
        #expect(SigningRequestActionTiming.approveCallbackDelay == 0.05)
        #expect(SigningRequestActionTiming.doneFlashDelay == 0.9)
        #expect(SigningRequestActionTiming.denyCallbackDelay == 0.45)
        #expect(SigningRequestActionTiming.shouldApply(scheduledGeneration: 3, currentGeneration: 3) == true)
        #expect(SigningRequestActionTiming.shouldApply(scheduledGeneration: 3, currentGeneration: 4) == false)

        let collapsed = SigningRequestPresentation.make(
            approval: approval,
            remainingSeconds: 9,
            showRaw: false,
            authStage: .idle,
            confirmationText: ""
        )
        #expect(collapsed.accessibilityLabel == "Signing request approval")
        #expect(collapsed.headerTitle == "Approve request")
        #expect(collapsed.operationKindLabel == "Message")
        #expect(collapsed.modeLabel == "Sign only")
        #expect(collapsed.clientDisplayName == "Example Agent")
        #expect(collapsed.countdownLabel == "00:09")
        #expect(collapsed.countdownAccessibilityLabel == "Auto-deny in 9 seconds")
        #expect(collapsed.rawDigestButtonTitle == "Show raw digest")
        #expect(collapsed.rawDigestHex == "0x\(request.data.hex)")
        #expect(collapsed.idleAssurance == "Signature stays in Secure Enclave")
        #expect(collapsed.denyButtonTitle == "Deny")
        #expect(collapsed.denyAccessibilityLabel == "Deny signing request")
        #expect(collapsed.denyAccessibilityHint == "Reject this request from Example Agent without signing.")
        #expect(collapsed.primaryButtonTitle == "Sign")
        #expect(collapsed.primaryAccessibilityLabel == "Approve signing request")
        #expect(collapsed.primaryAccessibilityHint == "Sign this request from Example Agent.")
        #expect(collapsed.canSubmitApproval == true)
        #expect(collapsed.canTriggerPrimary == true)

        let messageDecoded = SigningRequestDecodedPresentation.make(approval: approval, config: .default)
        #expect(messageDecoded.headline == "Sign message: \"hello world\"")
        #expect(messageDecoded.rows == [
            SigningRequestDecodedPresentation.Row(
                key: "From",
                value: .address(value: "0x1234567890abcdef1234567890abcdef12345678", muted: true, label: nil)
            ),
            SigningRequestDecodedPresentation.Row(
                key: "Type",
                value: .text(value: "EIP-191 personal-sign", monospace: false)
            ),
            SigningRequestDecodedPresentation.Row(key: "Flow", value: .flow(.signOnly)),
        ])

        let expanded = SigningRequestPresentation.make(
            approval: approval,
            remainingSeconds: 60,
            showRaw: true,
            authStage: .authing,
            confirmationText: ""
        )
        #expect(expanded.rawDigestButtonTitle == "Hide raw digest")
        #expect(expanded.authingText == "Touch ID to authorize…")
        #expect(expanded.doneText == "Signed · returning signature to Example Agent")
        #expect(expanded.deniedText == "Denied · Example Agent will see a rejection")
        #expect(expanded.canTriggerPrimary == false)

        let overrideApproval = ApprovalRequest(
            request: makeUserOpRequest(requestID: "approval-override", clientBundleId: "com.example.agent"),
            mode: .ruleOverride(["USDC spending limit exceeded: 50 USDC per day"]),
            clientContext: client,
            typedConfirmationPhrase: " SIGN "
        )
        let blockedOverride = SigningRequestPresentation.make(
            approval: overrideApproval,
            remainingSeconds: 42,
            showRaw: false,
            authStage: .idle,
            confirmationText: " wrong "
        )
        #expect(blockedOverride.accessibilityLabel == "Rule violation, owner authentication required")
        #expect(blockedOverride.headerTitle == "Rule violation")
        #expect(blockedOverride.primaryButtonTitle == "Override & Sign")
        #expect(blockedOverride.primaryAccessibilityLabel == "Override rules and sign")
        #expect(blockedOverride.primaryAccessibilityHint == "Authorize this request even though it violates configured rules. Owner authentication required.")
        #expect(blockedOverride.idleAssurance == "Owner authentication required")
        #expect(blockedOverride.canSubmitApproval == false)
        #expect(blockedOverride.canTriggerPrimary == false)
        #expect(SigningRequestPresentation.requiredConfirmationPhrase(for: overrideApproval) == "SIGN")
        #expect(SigningViolationPresentation.make(approval: overrideApproval) == SigningViolationPresentation(
            title: "Rules broken",
            reasons: ["USDC spending limit exceeded: 50 USDC per day"]
        ))
        #expect(SigningTypedConfirmationPresentation.make(
            approval: overrideApproval,
            confirmationText: " wrong "
        ) == SigningTypedConfirmationPresentation(
            title: "Extra confirmation required",
            message: "This request changes a spend or limit boundary. Type SIGN to continue.",
            placeholder: "Type SIGN",
            requiredPhrase: "SIGN",
            isSatisfied: false
        ))

        let allowedOverride = SigningRequestPresentation.make(
            approval: overrideApproval,
            remainingSeconds: 42,
            showRaw: false,
            authStage: .idle,
            confirmationText: " SIGN "
        )
        #expect(allowedOverride.canSubmitApproval == true)
        #expect(allowedOverride.canTriggerPrimary == true)
        #expect(SigningTypedConfirmationPresentation.make(
            approval: overrideApproval,
            confirmationText: " SIGN "
        )?.isSatisfied == true)
        #expect(SigningRequestPresentation.canTriggerPrimary(authStage: .done, canSubmitApproval: true) == false)
        #expect(SigningRequestPresentation.canTriggerPrimary(authStage: .idle, canSubmitApproval: false) == false)
        let nonRiskyOverride = ApprovalRequest(
            request: request,
            mode: .ruleOverride(["Outside allowed hours (09:00 - 18:00)"]),
            clientContext: client
        )
        #expect(SigningRequestPresentation.requiredConfirmationPhrase(for: nonRiskyOverride) == nil)
        #expect(SigningTypedConfirmationPresentation.make(
            approval: nonRiskyOverride,
            confirmationText: ""
        ) == nil)

        let recipient = "0x2222222222222222222222222222222222222222"
        let token = USDCAddresses.address(for: 8453)!
        let userOpRequest = makeUserOpRequest(
            chainId: 8453,
            callData: makeKernelSingleCallData(
                target: token,
                calldata: makeERC20TransferCalldata(to: recipient, amount: 12_345_678)
            ),
            requestID: "approval-send-userop",
            clientBundleId: "com.example.agent",
            submission: UserOperationSubmissionRequest(projectId: "project-123")
        )
        let preflight = PreflightResult(
            passed: true,
            gasEstimate: GasEstimate(
                callGasLimit: "0x5208",
                verificationGasLimit: "0x0",
                preVerificationGas: "0x0",
                paymasterVerificationGasLimit: nil,
                paymasterPostOpGasLimit: nil
            ),
            aaError: nil,
            failureReason: nil,
            staticWarnings: [],
            diagnosis: "Bundler accepted simulation",
            recommendations: [],
            severity: .success
        )
        let userOpApproval = ApprovalRequest(
            request: userOpRequest,
            mode: .policyReview,
            clientContext: client,
            preflightResult: preflight
        )
        var labelledConfig = BastionConfig.default
        labelledConfig.addressBook = [
            AddressBookEntry(address: recipient, label: "Treasury vault", chainId: 8453),
        ]
        let userOpDecoded = SigningRequestDecodedPresentation.make(
            approval: userOpApproval,
            config: labelledConfig
        )
        #expect(userOpDecoded.headline == "Send 12345678")
        #expect(userOpDecoded.rows == [
            SigningRequestDecodedPresentation.Row(
                key: "To",
                value: .address(value: recipient, muted: true, label: "Treasury vault")
            ),
            SigningRequestDecodedPresentation.Row(
                key: "From",
                value: .address(value: "0x1234567890abcdef1234567890abcdef12345678", muted: true, label: nil)
            ),
            SigningRequestDecodedPresentation.Row(key: "On", value: .chain(8453)),
            SigningRequestDecodedPresentation.Row(
                key: "Submit",
                value: .text(value: "ZeroDev", monospace: false)
            ),
            SigningRequestDecodedPresentation.Row(
                key: "Max fee",
                value: .text(value: "21,000 gas · bundler accepted", monospace: false)
            ),
            SigningRequestDecodedPresentation.Row(key: "Flow", value: .flow(.approveAndSend)),
        ])

        #expect(SigningPreflightPresentation.make(
            preflight: preflight,
            isExporting: false,
            exportError: nil
        ) == SigningPreflightPresentation(
            title: "Preflight passed",
            diagnosis: "Bundler accepted simulation",
            traceWarning: nil,
            recommendationRows: [],
            exportButtonTitle: "Export debug",
            isExporting: false,
            exportStatus: nil,
            exportError: nil,
            severity: .success
        ))

        let warningPreflight = PreflightResult(
            passed: true,
            gasEstimate: nil,
            aaError: nil,
            failureReason: nil,
            staticWarnings: ["paymaster estimate changed"],
            diagnosis: "Simulation completed with warnings",
            recommendations: ["Review the changed estimate"],
            severity: .warning
        )
        #expect(SigningPreflightPresentation.make(
            preflight: warningPreflight,
            isExporting: true,
            exportError: "Export failed: permission denied"
        ) == SigningPreflightPresentation(
            title: "Preflight passed with warnings",
            diagnosis: "Simulation completed with warnings",
            traceWarning: nil,
            recommendationRows: [
                SigningPreflightRecommendationPresentation(id: 0, text: "Review the changed estimate"),
            ],
            exportButtonTitle: "Exporting…",
            isExporting: true,
            exportStatus: nil,
            exportError: "Export failed: permission denied",
            severity: .warning
        ))

        let failedPreflight = PreflightResult(
            passed: false,
            gasEstimate: nil,
            aaError: "AA24",
            failureReason: "signature validation failed",
            staticWarnings: [],
            diagnosis: "Account validation failed",
            recommendations: ["Export this bundle for support"],
            severity: .error
        )
        #expect(SigningPreflightPresentation.make(
            preflight: failedPreflight,
            isExporting: false,
            exportError: nil
        ).title == "Preflight failed · AA24")

        let unknownTarget = "0x3333333333333333333333333333333333333333"
        let unknownCalldata = Data([0x12, 0x34, 0x56, 0x78]) + Data(repeating: 0xab, count: 40)
        let unknownRequest = makeUserOpRequest(
            chainId: 8453,
            callData: makeKernelSingleCallData(target: unknownTarget, calldata: unknownCalldata),
            requestID: "approval-unknown-calldata",
            clientBundleId: "com.example.agent"
        )
        let unknownApproval = ApprovalRequest(
            request: unknownRequest,
            mode: .policyReview,
            clientContext: client
        )
        #expect(SigningUnknownCalldataPresentation.make(approval: unknownApproval) == SigningUnknownCalldataPresentation(
            title: "Unrecognized contract call",
            message: "Bastion could not decode this calldata. Approve only if you recognize the target and selector.",
            target: unknownTarget,
            selectorHex: "0x12345678",
            chainId: 8453,
            calldataHex: "0x\(BastionFormat.shortHex(unknownCalldata.hex, head: 14, tail: 10))"
        ))
        #expect(SigningUnknownCalldataPresentation.make(approval: approval) == nil)
    }

    @Test("Signing approval warning presentation covers preflight and unknown calldata")
    func signingApprovalWarningPresentationCoversPreflightAndUnknownCalldata() {
        let warningPreflight = PreflightResult(
            passed: true,
            gasEstimate: nil,
            aaError: nil,
            failureReason: nil,
            staticWarnings: ["Dummy signature was used"],
            diagnosis: "Bundler accepted the simulation with warnings",
            recommendations: [
                "Review gas and paymaster fields before approving",
                PreflightTraceDiagnostics.unsupportedRecommendation,
            ],
            severity: .warning,
            traceWarning: PreflightTraceDiagnostics.unsupportedWarning
        )
        #expect(SigningPreflightPresentation.make(
            preflight: warningPreflight,
            isExporting: false,
            exportError: nil
        ) == SigningPreflightPresentation(
            title: "Preflight passed with warnings",
            diagnosis: "Bundler accepted the simulation with warnings",
            traceWarning: PreflightTraceDiagnostics.unsupportedWarning,
            recommendationRows: [
                SigningPreflightRecommendationPresentation(id: 0, text: "Review gas and paymaster fields before approving"),
                SigningPreflightRecommendationPresentation(id: 1, text: PreflightTraceDiagnostics.unsupportedRecommendation),
            ],
            exportButtonTitle: "Export debug",
            isExporting: false,
            exportStatus: nil,
            exportError: nil,
            severity: .warning
        ))

        let duplicateRecommendations = PreflightResult(
            passed: true,
            gasEstimate: nil,
            aaError: nil,
            failureReason: nil,
            staticWarnings: ["Duplicated warning"],
            diagnosis: "Simulation completed with duplicate remediation",
            recommendations: ["Retry with a fresh nonce", "Retry with a fresh nonce"],
            severity: .warning
        )
        #expect(SigningPreflightPresentation.make(
            preflight: duplicateRecommendations,
            isExporting: false,
            exportError: nil
        ).recommendationRows == [
            SigningPreflightRecommendationPresentation(id: 0, text: "Retry with a fresh nonce"),
            SigningPreflightRecommendationPresentation(id: 1, text: "Retry with a fresh nonce"),
        ])

        let failedPreflight = PreflightResult(
            passed: false,
            gasEstimate: nil,
            aaError: "AA24",
            failureReason: "signature validation failed",
            staticWarnings: [],
            diagnosis: "Preflight simulation failed with AA24",
            recommendations: [],
            severity: .error
        )
        #expect(SigningPreflightPresentation.make(
            preflight: failedPreflight,
            isExporting: false,
            exportStatus: "Exported bastion-preflight.json",
            exportError: nil
        ) == SigningPreflightPresentation(
            title: "Preflight failed · AA24",
            diagnosis: "Preflight simulation failed with AA24",
            traceWarning: nil,
            recommendationRows: [],
            exportButtonTitle: "Export debug",
            isExporting: false,
            exportStatus: "Exported bastion-preflight.json",
            exportError: nil,
            severity: .error
        ))

        var exportState = SigningPreflightExportState(status: "old.json", error: "Export failed: stale", isExporting: false)
        #expect(exportState.beginExport() == true)
        #expect(exportState.status == nil)
        #expect(exportState.error == nil)
        #expect(exportState.isExporting == true)
        #expect(exportState.beginExport() == false)

        exportState.cancelExport()
        #expect(exportState.isExporting == false)

        #expect(exportState.beginExport() == true)
        exportState.succeed(url: URL(fileURLWithPath: "/tmp/bastion-preflight.json"))
        #expect(exportState.status == "Exported bastion-preflight.json")
        #expect(exportState.error == nil)
        #expect(exportState.isExporting == false)

        #expect(exportState.beginExport() == true)
        exportState.fail(NSError(domain: NSCocoaErrorDomain, code: NSFileWriteNoPermissionError, userInfo: [NSLocalizedDescriptionKey: "permission denied"]))
        #expect(exportState.status == nil)
        #expect(exportState.error == "Export failed: permission denied")
        #expect(exportState.isExporting == false)

        #expect(exportState.beginExport() == true)
        exportState.unavailable()
        #expect(exportState.status == nil)
        #expect(exportState.error == "Debug export unavailable for this request")
        #expect(exportState.isExporting == false)

        let target = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        let calldata = Data(hexString: "0x1234567890abcdef1234567890abcdef")!
        let request = makeUserOpRequest(
            chainId: 8453,
            callData: KernelEncoding.executeCalldata(
                single: .init(to: target, value: 0, data: calldata)
            ),
            requestID: "approval-unknown-calldata",
            clientBundleId: "com.example.agent"
        )
        let approval = ApprovalRequest(
            request: request,
            mode: .policyReview,
            clientContext: makeClientContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
        )
        #expect(SigningUnknownCalldataPresentation.make(approval: approval) == SigningUnknownCalldataPresentation(
            title: "Unrecognized contract call",
            message: "Bastion could not decode this calldata. Approve only if you recognize the target and selector.",
            target: target,
            selectorHex: "0x12345678",
            chainId: 8453,
            calldataHex: "0x\(BastionFormat.shortHex(calldata.hex, head: 14, tail: 10))"
        ))

        let messageApproval = ApprovalRequest(
            request: makeMessageRequest(requestID: "approval-message-no-calldata"),
            mode: .policyReview,
            clientContext: makeClientContext()
        )
        #expect(SigningUnknownCalldataPresentation.make(approval: messageApproval) == nil)
    }

    @Test("Incoming pairing prompt presents requester and broker outcomes")
    @MainActor
    func incomingPairingPromptPresentationAndBrokerOutcomes() async throws {
        let now = Date(timeIntervalSince1970: 1_000)
        let visible = PendingPairingRequest(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000101")!,
            bundleId: "com.example.agent",
            processName: "Example Agent",
            pairingCode: "AB · CD · EF",
            createdAt: now,
            expiresAt: now.addingTimeInterval(60)
        )
        let expired = PendingPairingRequest(
            id: UUID(uuidString: "00000000-0000-0000-0000-000000000102")!,
            bundleId: "com.example.expired",
            processName: "Expired Agent",
            pairingCode: "GH · JK · MN",
            createdAt: now.addingTimeInterval(-120),
            expiresAt: now.addingTimeInterval(-1)
        )

        let prompt = PendingPairingPromptPresentation.make(errorMessage: "Pairing failed: storage")
        #expect(prompt.title == "Incoming pair request")
        #expect(prompt.errorMessage == "Pairing failed: storage")
        #expect(PendingPairingPromptPresentation.visibleRequests([expired, visible], now: now) == [visible])

        let row = PendingPairingRequestPresentation.make(visible)
        #expect(row.processName == "Example Agent")
        #expect(row.bundleId == "com.example.agent")
        #expect(row.pairingCode == "AB · CD · EF")
        #expect(row.rejectButtonTitle == "Reject")
        #expect(row.acceptButtonTitle == "Accept")
        #expect(row.rowHelp == "Process: Example Agent\nBundle ID: com.example.agent\nPairing code: AB · CD · EF")

        let updater = MockPairingConfigUpdater()
        let broker = PairingBroker(configUpdater: updater)
        let request = broker.registerIncoming(bundleId: "com.example.agent", processName: "Example Agent")

        let defaultProfileLabel = try #require(request.defaultProfileLabel)
        #expect(defaultProfileLabel == "Example Agent")
        try await broker.accept(request, label: "  \(defaultProfileLabel)  ", template: nil)

        #expect(broker.pending.isEmpty)
        #expect(updater.appliedConfigs.count == 1)
        let profile = try #require(updater.pairingConfig.clientProfiles.first)
        #expect(profile.bundleId == "com.example.agent")
        #expect(profile.label == "Example Agent")
        #expect(profile.authPolicy == BastionConfig.default.authPolicy)
        if case .accepted(let profileId) = broker.poll(requestId: request.id).state {
            #expect(profileId == profile.id)
        } else {
            Issue.record("Expected accepted pairing outcome")
        }
        #expect(broker.reject(request, reason: "late reject") == false)
        if case .accepted(let profileId) = broker.poll(requestId: request.id).state {
            #expect(profileId == profile.id)
        } else {
            Issue.record("Expected stale reject to preserve accepted pairing outcome")
        }
        do {
            try await broker.accept(request, label: nil, template: nil)
            Issue.record("Expected stale pairing accept to throw")
        } catch let error as PairingBrokerError {
            #expect(error == .requestNoLongerPending)
        } catch {
            Issue.record("Expected PairingBrokerError.requestNoLongerPending, got \(error)")
        }
        #expect(updater.appliedConfigs.count == 1)
        #expect(updater.pairingConfig.clientProfiles.count == 1)

        let expiredUpdater = MockPairingConfigUpdater()
        let expiredBroker = PairingBroker(configUpdater: expiredUpdater, expiry: -1)
        let expiredRequest = expiredBroker.registerIncoming(bundleId: "com.example.expired", processName: "Expired Agent")
        do {
            try await expiredBroker.accept(expiredRequest, label: nil, template: nil)
            Issue.record("Expected expired pairing accept to throw")
        } catch let error as PairingBrokerError {
            #expect(error == .requestNoLongerPending)
        } catch {
            Issue.record("Expected PairingBrokerError.requestNoLongerPending, got \(error)")
        }
        #expect(expiredUpdater.appliedConfigs.isEmpty)
        #expect(expiredBroker.pending.isEmpty)
        #expect(expiredBroker.poll(requestId: expiredRequest.id).state == .expired)

        let rejectedRequest = broker.registerIncoming(bundleId: "com.example.reject", processName: "Reject Agent")
        #expect(broker.reject(rejectedRequest, reason: "owner rejected") == true)
        let rejected = broker.poll(requestId: rejectedRequest.id)
        #expect(rejected.state == .rejected)
        #expect(rejected.reason == "owner rejected")
        #expect(broker.pending.contains(rejectedRequest) == false)
        #expect(broker.reject(rejectedRequest, reason: "late reject") == false)
        let stillRejected = broker.poll(requestId: rejectedRequest.id)
        #expect(stillRejected.state == .rejected)
        #expect(stillRejected.reason == "owner rejected")
        do {
            try await broker.accept(rejectedRequest, label: nil, template: nil)
            Issue.record("Expected rejected pairing accept to throw")
        } catch let error as PairingBrokerError {
            #expect(error == .requestNoLongerPending)
        } catch {
            Issue.record("Expected PairingBrokerError.requestNoLongerPending, got \(error)")
        }
        #expect(updater.appliedConfigs.count == 1)

        let suspendedUpdater = SuspendingPairingConfigUpdater()
        let suspendedBroker = PairingBroker(configUpdater: suspendedUpdater)
        let suspendedRequest = suspendedBroker.registerIncoming(bundleId: "com.example.double", processName: "Double Agent")
        let firstAccept = Task { @MainActor in
            try await suspendedBroker.accept(suspendedRequest, label: nil, template: nil)
        }
        await suspendedUpdater.waitForApplyStarted()
        do {
            try await suspendedBroker.accept(suspendedRequest, label: nil, template: nil)
            Issue.record("Expected duplicate in-flight pairing accept to throw")
        } catch let error as PairingBrokerError {
            #expect(error == .requestAlreadyResolving)
        } catch {
            Issue.record("Expected PairingBrokerError.requestAlreadyResolving, got \(error)")
        }
        #expect(suspendedUpdater.appliedConfigs.count == 1)
        #expect(suspendedBroker.reject(suspendedRequest, reason: "reject during accept") == false)
        #expect(suspendedBroker.poll(requestId: suspendedRequest.id).state == .pending)
        suspendedUpdater.releaseApply()
        try await firstAccept.value
        #expect(suspendedUpdater.appliedConfigs.count == 1)
        #expect(suspendedBroker.pending.isEmpty)
        if case .accepted = suspendedBroker.poll(requestId: suspendedRequest.id).state {
            // Expected terminal outcome.
        } else {
            Issue.record("Expected in-flight reject to preserve accepted pairing outcome")
        }
    }

    @Test("Menu bar refresh loop stops when panel task is cancelled")
    @MainActor
    func menuBarRefreshLoopStopsWhenSleepIsCancelled() async {
        var refreshCount = 0
        var requestedIntervals: [Duration] = []

        await MenuBarPanelRefreshScheduler.run(
            sleep: { interval in
                requestedIntervals.append(interval)
                throw CancellationError()
            },
            refresh: {
                refreshCount += 1
            }
        )

        #expect(refreshCount == 1)
        #expect(requestedIntervals == [.seconds(1)])
    }

    @Test("Address book draft validates and canonicalizes entries")
    func addressBookDraftValidationAndCanonicalization() throws {
        let mixedAddress = "0XABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"
        let longLabel = String(repeating: "L", count: 70)
        let draft = AddressBookEntryDraft(
            address: " \(mixedAddress) ",
            label: " \(longLabel) ",
            chainId: " 8453 "
        )

        #expect(draft.validationMessage == nil)
        let entry = try #require(draft.makeEntry())
        #expect(entry.address == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
        #expect(entry.label == String(repeating: "L", count: 64))
        #expect(entry.chainId == 8453)
        #expect(AddressBookRowPresentation.make(entry) == AddressBookRowPresentation(
            removeAccessibilityLabel: "Remove address label \(String(repeating: "L", count: 64))",
            removeHelp: "Remove \(String(repeating: "L", count: 64)) for 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd on chain 8453"
        ))

        let bareAddress = "1111111111111111111111111111111111111111"
        let anyChainEntry = try #require(AddressBookEntryDraft(
            address: bareAddress,
            label: " Treasury ",
            chainId: " "
        ).makeEntry())
        #expect(anyChainEntry.address == "0x1111111111111111111111111111111111111111")
        #expect(anyChainEntry.label == "Treasury")
        #expect(anyChainEntry.chainId == nil)
        #expect(AddressBookRowPresentation.make(anyChainEntry).removeHelp == "Remove Treasury for 0x1111111111111111111111111111111111111111 on any chain")

        let invalidAddress = AddressBookEntryDraft(address: "0x123", label: "Treasury", chainId: "1")
        #expect(invalidAddress.validationMessage == AddressBookEntryDraft.addressError)
        #expect(invalidAddress.makeEntry() == nil)

        let blankLabel = AddressBookEntryDraft(address: bareAddress, label: "   ", chainId: "")
        #expect(blankLabel.validationMessage == AddressBookEntryDraft.labelError)
        #expect(blankLabel.makeEntry() == nil)

        let invalidChain = AddressBookEntryDraft(address: bareAddress, label: "Treasury", chainId: "0")
        #expect(invalidChain.validationMessage == AddressBookEntryDraft.chainIdError)
        #expect(invalidChain.makeEntry() == nil)
    }

    @Test("High-value rule draft validates threshold and normalizes phrase")
    func highValueRuleDraftValidationAndPhraseNormalization() {
        let valid = HighValueRuleDraft(
            enabled: true,
            thresholdText: " 250.5 ",
            confirmationPhrase: " CONFIRM "
        )

        #expect(valid.validationMessage == nil)
        #expect(valid.thresholdUsd == 250.5)
        #expect(valid.normalizedConfirmationPhrase == "CONFIRM")

        let blankPhrase = HighValueRuleDraft(
            enabled: true,
            thresholdText: "100",
            confirmationPhrase: "   "
        )
        #expect(blankPhrase.normalizedConfirmationPhrase == HighValueRule.default.confirmationPhrase)

        let missingThreshold = HighValueRuleDraft(
            enabled: true,
            thresholdText: "   ",
            confirmationPhrase: "CONFIRM"
        )
        #expect(missingThreshold.validationMessage == HighValueRuleDraft.requiredThresholdError)
        #expect(missingThreshold.thresholdUsd == nil)

        let invalidThreshold = HighValueRuleDraft(
            enabled: true,
            thresholdText: "0",
            confirmationPhrase: "CONFIRM"
        )
        #expect(invalidThreshold.validationMessage == HighValueRuleDraft.positiveThresholdError)
        #expect(invalidThreshold.thresholdUsd == nil)

        let disabledBlankThreshold = HighValueRuleDraft(
            enabled: false,
            thresholdText: "",
            confirmationPhrase: "CONFIRM"
        )
        #expect(disabledBlankThreshold.validationMessage == nil)
        #expect(HighValueRuleDraft.thresholdText(for: 10_000) == "10000")
        #expect(HighValueRuleDraft.thresholdText(for: 250.5) == "250.5")
    }

    @Test("Target allowlist draft validates and canonicalizes entries")
    func targetAllowlistDraftValidationAndCanonicalization() throws {
        let mixedAddress = "0XABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"
        let draft = TargetAllowlistEntryDraft(
            chainId: " 8453 ",
            address: " \(mixedAddress) ",
            usdcDailyCap: " 12.5 "
        )

        #expect(draft.validationMessage == nil)
        let entry = try #require(draft.makeEntry())
        #expect(entry.chainId == 8453)
        #expect(entry.address == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
        #expect(entry.usdcDailyCap == 12.5)
        #expect(entry.usdcAllowanceRaw == "12500000")
        let addedRules = TargetAllowlistMutation.add(entry, to: .default)
        #expect(addedRules.allowedTargets == ["8453": ["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"]])
        #expect(addedRules.spendingLimits.count == 1)
        #expect(addedRules.spendingLimits.first?.token == .usdc)
        #expect(addedRules.spendingLimits.first?.allowance == "12500000")
        #expect(addedRules.spendingLimits.first?.windowSeconds == 86_400)
        #expect(addedRules.spendingLimits.first?.targetAddress == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd")
        #expect(TargetAllowlistPresentation.capLabel(for: entry.address, in: addedRules) == "12.50 USDC")
        let targetStore = StateStore(keychain: MockKeychainBackend())
        if let targetLimit = addedRules.spendingLimits.first {
            targetStore.recordSpend(ruleId: targetLimit.id, amount: "2500000", windowSeconds: targetLimit.windowSeconds)
        }
        #expect(TargetAllowlistPresentation.usedLabel(for: entry.address, in: addedRules, stateStore: targetStore) == "2.50 USDC")

        let duplicateRules = TargetAllowlistMutation.add(entry, to: addedRules)
        #expect(duplicateRules.allowedTargets?["8453"]?.count == 1)
        #expect(duplicateRules.spendingLimits.filter { $0.targetAddress == entry.address && $0.token == .usdc }.count == 1)

        let bareAddress = "1111111111111111111111111111111111111111"
        let uncappedEntry = try #require(TargetAllowlistEntryDraft(
            chainId: "1",
            address: bareAddress,
            usdcDailyCap: " "
        ).makeEntry())
        #expect(uncappedEntry.address == "0x1111111111111111111111111111111111111111")
        #expect(uncappedEntry.usdcDailyCap == nil)
        #expect(uncappedEntry.usdcAllowanceRaw == nil)
        let uncappedRules = TargetAllowlistMutation.add(uncappedEntry, to: .default)
        #expect(uncappedRules.allowedTargets == ["1": ["0x1111111111111111111111111111111111111111"]])
        #expect(uncappedRules.spendingLimits.isEmpty)

        let invalidChain = TargetAllowlistEntryDraft(chainId: "0", address: bareAddress, usdcDailyCap: "")
        #expect(invalidChain.validationMessage == TargetAllowlistEntryDraft.chainIdError)
        #expect(invalidChain.makeEntry() == nil)

        let invalidAddress = TargetAllowlistEntryDraft(chainId: "1", address: "0x123", usdcDailyCap: "")
        #expect(invalidAddress.validationMessage == TargetAllowlistEntryDraft.addressError)
        #expect(invalidAddress.makeEntry() == nil)

        let zeroCap = TargetAllowlistEntryDraft(chainId: "1", address: bareAddress, usdcDailyCap: "0")
        #expect(zeroCap.validationMessage == TargetAllowlistEntryDraft.usdcCapError)
        #expect(zeroCap.makeEntry() == nil)

        let hugeCap = TargetAllowlistEntryDraft(chainId: "1", address: bareAddress, usdcDailyCap: "1e20")
        #expect(hugeCap.validationMessage == TargetAllowlistEntryDraft.usdcCapTooLargeError)
        #expect(hugeCap.makeEntry() == nil)
    }

    @Test("Target allowlist removal prunes entries and target caps")
    func targetAllowlistRemovalPrunesEntriesAndTargetCaps() throws {
        let removed = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let remaining = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        let otherChain = "0xcccccccccccccccccccccccccccccccccccccccc"

        var rules = RuleConfig.default
        rules.allowedTargets = [
            "8453": [removed, remaining],
            "1": [otherChain],
        ]
        rules.spendingLimits = [
            SpendingLimitRule(token: .usdc, allowance: "12500000", windowSeconds: 86_400, targetAddress: removed),
            SpendingLimitRule(token: .eth, allowance: "1000000000000000000", windowSeconds: nil, targetAddress: remaining),
            SpendingLimitRule(token: .usdc, allowance: "50000000", windowSeconds: 86_400),
        ]

        #expect(TargetAllowlistMutation.targetLimit(for: "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", in: rules)?.allowance == "12500000")
        #expect(TargetAllowlistRowPresentation.make(chainId: 8453, address: " 0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ") == TargetAllowlistRowPresentation(
            removeAccessibilityLabel: "Remove target 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa on chain 8453",
            removeHelp: "Remove 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa from the chain 8453 target allowlist and clear its per-target cap."
        ))

        let updated = TargetAllowlistMutation.remove(
            chainId: 8453,
            address: " 0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
            from: rules
        )

        #expect(updated.allowedTargets?["8453"] == [remaining])
        #expect(updated.allowedTargets?["1"] == [otherChain])
        #expect(updated.spendingLimits.map(\.allowance) == ["1000000000000000000", "50000000"])
        #expect(TargetAllowlistMutation.targetLimit(for: removed, in: updated) == nil)
        #expect(TargetAllowlistMutation.targetLimit(for: remaining.uppercased(), in: updated)?.token == .eth)

        var single = RuleConfig.default
        single.allowedTargets = ["10": [removed]]
        single.spendingLimits = [
            SpendingLimitRule(token: .usdc, allowance: "1000000", windowSeconds: 86_400, targetAddress: removed),
        ]

        let emptied = TargetAllowlistMutation.remove(chainId: 10, address: removed, from: single)
        #expect(emptied.allowedTargets == nil)
        #expect(emptied.spendingLimits.isEmpty)
    }

    @Test("Policy simulator evaluates UserOperation JSON and decode errors")
    func policySimulatorEvaluatorDecodesUserOperationJSONAndErrors() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let timestamp = Date(timeIntervalSince1970: 0)
        let sample = PolicySimulatorEvaluator.sampleUserOperationJSON

        #expect(PolicySimulatorEvaluator.canEvaluate(" \n\t ") == false)
        #expect(PolicySimulatorEvaluator.canEvaluate(sample) == true)

        let allowed = PolicySimulatorEvaluator.evaluate(
            sample,
            config: .default,
            engine: engine,
            requestID: "simulator-test",
            timestamp: timestamp
        )
        if case .result(let result) = allowed {
            #expect(result.allowed == true)
            #expect(result.summary == "Rule engine would sign this silently or after configured auth.")
            #expect(result.reasons.isEmpty)
        } else {
            Issue.record("Expected sample UserOperation to evaluate successfully")
        }

        var chainLocked = BastionConfig.default
        chainLocked.rules.allowedChains = [1]
        let denied = PolicySimulatorEvaluator.evaluate(
            sample,
            config: chainLocked,
            engine: engine,
            requestID: "simulator-test",
            timestamp: timestamp
        )
        if case .result(let result) = denied {
            #expect(result.allowed == false)
            #expect(result.summary == "Rule engine would block this and require owner override.")
            #expect(result.reasons == ["Chain Base (8453) not allowed"])
        } else {
            Issue.record("Expected chain policy denial")
        }

        #expect(PolicySimulatorEvaluator.evaluate(" \n ", config: .default, engine: engine) == .error(PolicySimulatorEvaluator.emptyInputError))

        let invalidCallData = #"""
        {
          "sender": "0x4c7a3df6c0e2db14ab39a8f4c98e1d5a3e89b21d",
          "nonce": "0x1",
          "callData": "0xzz",
          "chainId": 8453,
          "entryPointVersion": "v0.7"
        }
        """#
        #expect(
            PolicySimulatorEvaluator.evaluate(invalidCallData, config: .default, engine: engine)
                == .error("\(PolicySimulatorEvaluator.decodeErrorPrefix)\(PolicySimulatorEvaluator.invalidCallDataError)")
        )

        let invalidVersion = sample.replacingOccurrences(
            of: "\"entryPointVersion\": \"v0.7\"",
            with: "\"entryPointVersion\": \"v1\""
        )
        #expect(
            PolicySimulatorEvaluator.evaluate(invalidVersion, config: .default, engine: engine)
                == .error("\(PolicySimulatorEvaluator.decodeErrorPrefix)\(PolicySimulatorEvaluator.invalidEntryPointVersionError)")
        )

        let malformedJSON = "{"
        if case .error(let message) = PolicySimulatorEvaluator.evaluate(malformedJSON, config: .default, engine: engine) {
            #expect(message.hasPrefix(PolicySimulatorEvaluator.decodeErrorPrefix))
        } else {
            Issue.record("Expected malformed JSON to produce a simulator error")
        }
    }

    @Test("Save and load operation-specific policies")
    func saveAndLoadOperationSpecificPolicies() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var newConfig = BastionConfig.default
        newConfig.rules.rawMessagePolicy.enabled = false
        newConfig.rules.typedDataPolicy.enabled = true
        newConfig.rules.typedDataPolicy.requireExplicitApproval = true
        newConfig.rules.typedDataPolicy.domainRules = [
            TypedDataDomainRule(
                id: "domain-1",
                label: "Permit2",
                primaryType: "Permit",
                name: "Permit2",
                version: "1",
                chainId: 11155111,
                verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            )
        ]
        newConfig.rules.typedDataPolicy.structRules = [
            TypedDataStructRule(
                id: "struct-1",
                label: "Fixed spender",
                primaryType: "Permit",
                matcherJSON: "{\"spender\":\"0x7777777777777777777777777777777777777777\"}"
            )
        ]

        try engine.saveConfig(newConfig)
        let loaded = engine.loadConfig()
        #expect(loaded.rules.rawMessagePolicy.enabled == false)
        #expect(loaded.rules.typedDataPolicy.requireExplicitApproval == true)
        #expect(loaded.rules.typedDataPolicy.domainRules.first?.name == "Permit2")
        #expect(loaded.rules.typedDataPolicy.structRules.first?.primaryType == "Permit")
    }

    @Test("Materializing client profile copies global defaults")
    func materializeClientProfileCopiesGlobalDefaults() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var config = BastionConfig.default
        config.authPolicy = .biometric
        config.rules.allowedChains = [1]
        config.rules.allowedTargets = ["1": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]
        config.rules.allowedClients = [
            AllowedClient(id: "legacy", bundleId: "com.legacy.agent", label: "Legacy")
        ]
        config.rules.rateLimits = [
            RateLimitRule(id: "r1", maxRequests: 5, windowSeconds: 3600)
        ]
        config.rules.spendingLimits = [
            SpendingLimitRule(id: "s1", token: .eth, allowance: "100", windowSeconds: nil)
        ]

        try engine.saveConfig(config)
        engine.loadConfigOnStartup()

        let profile = engine.ensureClientProfile(bundleId: "com.example.agent")

        #expect(profile?.bundleId == "com.example.agent")
        #expect(profile?.authPolicy == .biometric)
        #expect(profile?.rules.allowedChains == [1])
        #expect(profile?.rules.allowedTargets?["1"]?.first == "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        #expect(profile?.rules.allowedClients == nil)
        #expect(profile?.rules.rateLimits.first?.id != "r1")
        #expect(profile?.rules.spendingLimits.first?.id != "s1")
        #expect(engine.config.clientProfiles.count == 1)
    }

    @Test("P0.2: Pre-v6 config with open auth policy is migrated to biometricOrPasscode")
    func migratesLegacyOpenAuthPolicy() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        // Directly write a raw version-5 JSON config to bypass normalizedConfig.
        // This simulates a config saved by an old app version that defaulted to .open.
        let json = """
        {
            "version": 5,
            "authPolicy": "open",
            "rules": {
                "enabled": true, "requireExplicitApproval": false,
                "rateLimits": [], "spendingLimits": [],
                "rawMessagePolicy": {"enabled": true},
                "typedDataPolicy": {"enabled": true, "requireExplicitApproval": false, "domainRules": [], "structRules": []}
            },
            "bundlerPreferences": {"chainRPCs": []},
            "clientProfiles": [
                {
                    "id": "profile-1",
                    "bundleId": "com.example.agent",
                    "authPolicy": "open",
                    "keyTag": "com.bastion.signingkey.client.test",
                    "rules": {
                        "enabled": true, "requireExplicitApproval": false,
                        "rateLimits": [], "spendingLimits": [],
                        "rawMessagePolicy": {"enabled": true},
                        "typedDataPolicy": {"enabled": true, "requireExplicitApproval": false, "domainRules": [], "structRules": []}
                    }
                }
            ]
        }
        """
        keychain.write(account: "config", data: json.data(using: .utf8)!)

        let loaded = engine.loadConfig()
        #expect(loaded.authPolicy == .biometricOrPasscode)
        #expect(loaded.clientProfiles.first?.authPolicy == .biometricOrPasscode)
        // The migration is the assertion-of-interest here; the version
        // floor is whatever normalizedConfig pins to. Use >= so this
        // assertion stays correct across future schema bumps.
        #expect(loaded.version >= 7)
    }

    @Test("P0.2: Version 6+ config with explicit open policy is not migrated")
    func doesNotMigrateExplicitOpenPolicy() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var config = BastionConfig.default
        config.authPolicy = .open
        try engine.saveConfig(config)

        let loaded = engine.loadConfig()
        #expect(loaded.authPolicy == .open)
        // Test cares that authPolicy is preserved; the version is set
        // by the normalizer, not the migration. Floor at 7 so this stays
        // robust across future schema bumps.
        #expect(loaded.version >= 7)
    }

    @Test("Existing client profile overrides global defaults")
    func existingClientProfileOverridesGlobalDefaults() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        var profileRules = RuleConfig.default
        profileRules.allowedChains = [8453]

        var config = BastionConfig.default
        config.rules.allowedChains = [1]
        config.clientProfiles = [
            ClientProfile(
                id: "client-1",
                bundleId: "com.example.agent",
                label: "Example Agent",
                authPolicy: .passcode,
                keyTag: "com.bastion.signingkey.client.test-agent",
                rules: profileRules
            )
        ]

        try engine.saveConfig(config)
        engine.loadConfigOnStartup()

        let effective = engine.effectiveRules(for: "com.example.agent")
        #expect(effective.allowedChains == [8453])
        #expect(engine.clientProfile(bundleId: "com.example.agent")?.authPolicy == .passcode)
    }
}

// MARK: - Preflight Debug Export Tests

@Suite("Preflight debug export")
struct PreflightDebugExportTests {

    @Test("debug bundle includes request, preflight result, and decoded calldata")
    func debugBundleIncludesRequestAndPreflightResult() throws {
        let request = makeUserOpRequest(requestID: "req-preflight-debug")
        guard case .userOperation(let op) = request.operation else {
            Issue.record("Expected UserOperation request")
            return
        }
        let result = PreflightResult(
            passed: false,
            gasEstimate: nil,
            aaError: "AA24",
            failureReason: "signature validation failed",
            staticWarnings: ["maxFeePerGas is low"],
            diagnosis: "Preflight simulation failed with AA24",
            recommendations: ["Export this bundle for support"],
            severity: .error,
            traceWarning: PreflightTraceDiagnostics.unsupportedWarning
        )

        let data = try #require(PreflightSimulator.shared.debugBundle(op: op, signature: nil, result: result))
        let bundle = try JSONDecoder().decode(PreflightDebugBundle.self, from: data)

        #expect(bundle.userOperation.sender == op.sender)
        #expect(bundle.preflightResult.aaError == "AA24")
        #expect(bundle.preflightResult.recommendations == ["Export this bundle for support"])
        #expect(bundle.preflightResult.traceWarning == PreflightTraceDiagnostics.unsupportedWarning)
        #expect(bundle.decodedCalldata != nil)
        #expect(bundle.exportedAt.isEmpty == false)
    }
}

// MARK: - RuleEngine Validation Tests

@Suite("RuleEngine Validation")
struct RuleEngineValidationTests {

    @Test("Disabled rules allow everything")
    func disabledRulesAllowAll() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.enabled = false
        let result = engine.validate(makeMessageRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed")
        }
    }

    @Test("Allowed chains: matching chain passes")
    func allowedChainsPass() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedChains = [1, 8453]
        let result = engine.validate(makeUserOpRequest(chainId: 1), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed for chain 1")
        }
    }

    @Test("Allowed chains: non-matching chain denies")
    func allowedChainsDeny() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedChains = [1, 8453]
        let result = engine.validate(makeUserOpRequest(chainId: 137), config: config)
        if case .denied(let reasons) = result {
            #expect(reasons.first?.contains("not allowed") == true)
        } else {
            Issue.record("Expected .denied for chain 137")
        }
    }

    @Test("Allowed targets: matching target passes")
    func allowedTargetsPass() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        let target = "0x9999999999999999999999999999999999999999"
        config.rules.allowedTargets = ["1": [target]]
        let result = engine.validate(
            makeUserOpRequest(
                sender: "0x1234567890abcdef1234567890abcdef12345678",
                chainId: 1,
                callData: makeKernelSingleCallData(target: target)
            ),
            config: config
        )
        if case .allowed = result { } else {
            Issue.record("Expected .allowed for matching target")
        }
    }

    @Test("Allowed targets: non-matching target denies")
    func allowedTargetsDeny() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedTargets = ["1": ["0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]]
        let result = engine.validate(
            makeUserOpRequest(
                sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                chainId: 1,
                callData: makeKernelSingleCallData(target: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            ),
            config: config
        )
        if case .denied = result { } else {
            Issue.record("Expected .denied for non-matching target")
        }
    }

    @Test("Raw message signing disabled means require-approval, not denied")
    func rawMessageDisabled() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy.enabled = false
        let request = makeMessageRequest()
        // Validation should pass (not denied) — signing is still allowed but requires explicit approval
        let result = engine.validate(request, config: config)
        if case .denied = result {
            Issue.record("Expected .allowed when raw signing is disabled — should require approval, not block")
        }
        // requiresExplicitApproval must be true when rule-based signing is disabled
        #expect(engine.requiresExplicitApproval(for: request, config: config) == true)
    }

    @Test("Typed-data domain rule allows matching payload")
    func typedDataDomainRulePasses() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.typedDataPolicy.domainRules = [
            TypedDataDomainRule(
                id: "d1",
                label: nil,
                primaryType: "Permit",
                name: "Permit2",
                version: "1",
                chainId: 11155111,
                verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            )
        ]
        let result = engine.validate(makeTypedDataRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected matching typed-data domain to pass")
        }
    }

    @Test("Typed-data domain rule denies non-matching payload")
    func typedDataDomainRuleDenies() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.typedDataPolicy.domainRules = [
            TypedDataDomainRule(
                id: "d1",
                label: nil,
                primaryType: "Permit",
                name: "Permit2",
                version: "1",
                chainId: 1,
                verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3"
            )
        ]
        let result = engine.validate(makeTypedDataRequest(chainId: 11155111), config: config)
        if case .denied(let reasons) = result {
            #expect(reasons.first?.contains("domain") == true)
        } else {
            Issue.record("Expected mismatched typed-data domain to deny")
        }
    }

    @Test("Typed-data struct matcher hardens selected values")
    func typedDataStructMatcher() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.typedDataPolicy.structRules = [
            TypedDataStructRule(
                id: "s1",
                label: nil,
                primaryType: "Permit",
                matcherJSON: "{\"spender\":\"0x7777777777777777777777777777777777777777\",\"value\":\"50000000\"}"
            )
        ]

        let matching = engine.validate(makeTypedDataRequest(), config: config)
        if case .allowed = matching { } else {
            Issue.record("Expected matching struct subset to pass")
        }

        let mismatched = engine.validate(
            makeTypedDataRequest(message: [
                "owner": AnyCodable("0x1234567890abcdef1234567890abcdef12345678"),
                "spender": AnyCodable("0x9999999999999999999999999999999999999999"),
                "value": AnyCodable("50000000"),
            ]),
            config: config
        )
        if case .denied(let reasons) = mismatched {
            #expect(reasons.first?.contains("struct") == true)
        } else {
            Issue.record("Expected mismatched struct subset to deny")
        }
    }

    @Test("Permit-style typed data forces explicit approval even under auto-sign posture")
    func permitTypedDataForcesApproval() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.typedDataPolicy.posture = .enforceRulesAndAutoSign
        let typedData = EIP712TypedData(
            types: [
                "EIP712Domain": [
                    EIP712Field(name: "name", type: "string"),
                    EIP712Field(name: "version", type: "string"),
                    EIP712Field(name: "chainId", type: "uint256"),
                    EIP712Field(name: "verifyingContract", type: "address"),
                ],
                "Permit": [
                    EIP712Field(name: "owner", type: "address"),
                    EIP712Field(name: "spender", type: "address"),
                    EIP712Field(name: "value", type: "uint256"),
                    EIP712Field(name: "nonce", type: "uint256"),
                    EIP712Field(name: "deadline", type: "uint256"),
                ],
            ],
            primaryType: "Permit",
            domain: EIP712Domain(
                name: "Token",
                version: "1",
                chainId: 1,
                verifyingContract: "0x1111111111111111111111111111111111111111",
                salt: nil
            ),
            message: [
                "owner": AnyCodable("0x1234567890abcdef1234567890abcdef12345678"),
                "spender": AnyCodable("0x7777777777777777777777777777777777777777"),
                "value": AnyCodable("50000000"),
                "nonce": AnyCodable("1"),
                "deadline": AnyCodable("9999999999"),
            ]
        )
        let request = SignRequest(
            operation: .typedData(typedData),
            requestID: UUID().uuidString,
            timestamp: Date(),
            clientBundleId: nil
        )
        #expect(engine.requiresExplicitApproval(for: request, config: config) == true)
    }

    @Test("Allowed hours within range passes")
    func allowedHoursWithinRange() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let hour = Calendar.current.component(.hour, from: Date())
        var config = BastionConfig.default
        config.rules.allowedHours = AllowedHours(start: hour, end: (hour + 1) % 24)
        let result = engine.validate(makeUserOpRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed within allowed hours")
        }
    }

    @Test("Allowed hours outside range denies")
    func allowedHoursOutsideRange() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let hour = Calendar.current.component(.hour, from: Date())
        let start = (hour + 2) % 24
        let end = (hour + 3) % 24
        var config = BastionConfig.default
        config.rules.allowedHours = AllowedHours(start: start, end: end)
        let result = engine.validate(makeUserOpRequest(), config: config)
        if case .denied = result { } else {
            Issue.record("Expected .denied outside allowed hours")
        }
    }

    @Test("Message requests bypass chain/target rules")
    func messageBypassesChainRules() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedChains = [1]
        config.rules.allowedTargets = ["1": ["0xaaaa"]]
        // Messages have no chainId or target — should pass
        let result = engine.validate(makeMessageRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed for message with chain/target rules")
        }
    }

    @Test("ETH spending limit: UserOp native transfer denies")
    func spendingLimitUserOpEthDeny() {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        var config = BastionConfig.default
        config.rules.spendingLimits = [
            SpendingLimitRule(id: "s1", token: .eth, allowance: "1000000000000000000", windowSeconds: 3600)
        ]
        let result = engine.validate(
            makeUserOpRequest(
                callData: makeKernelSingleCallData(
                    target: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    value: 2_000_000_000_000_000_000
                )
            ),
            config: config
        )
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("ETH spending limit exceeded") })
        } else {
            Issue.record("Expected .denied for ETH spending limit overflow")
        }
    }

    @Test("ERC-20 spending limit: UserOp transfer denies")
    func spendingLimitUserOpERC20Deny() {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        var config = BastionConfig.default
        let usdc = USDCAddresses.address(for: 1)!
        config.rules.spendingLimits = [
            SpendingLimitRule(id: "usdc", token: .usdc, allowance: "1000000", windowSeconds: 3600)
        ]
        let result = engine.validate(
            makeUserOpRequest(
                callData: makeKernelSingleCallData(
                    target: usdc,
                    calldata: makeERC20TransferCalldata(
                        to: "0xcccccccccccccccccccccccccccccccccccccccc",
                        amount: 2_000_000
                    )
                )
            ),
            config: config
        )
        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("USDC spending limit exceeded") })
        } else {
            Issue.record("Expected .denied for USDC spending limit overflow")
        }
    }

    @Test("Simulated spend observations enforce spending limits")
    func simulatedSpendObservationsEnforceSpendingLimits() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.spendingLimits = [
            SpendingLimitRule(id: "trace-eth", token: .eth, allowance: "1000000000000000000", windowSeconds: 3600)
        ]
        let request = makeUserOpRequest(
            callData: makeKernelSingleCallData(
                target: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                value: 0
            )
        )

        let result = engine.validate(
            request,
            config: config,
            simulatedSpendObservations: [
                SimulatedSpendObservation(token: .eth, amount: "2000000000000000000")
            ]
        )

        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("ETH spending limit exceeded") })
        } else {
            Issue.record("Expected simulated ETH spend to deny")
        }
    }

    @Test("Record success tracks decoded UserOp spending")
    func recordSuccessTracksDecodedUserOpSpending() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        var config = BastionConfig.default
        let usdc = USDCAddresses.address(for: 1)!
        let ethRuleId = UUID().uuidString
        let usdcRuleId = UUID().uuidString
        config.rules.spendingLimits = [
            SpendingLimitRule(id: ethRuleId, token: .eth, allowance: "5000000000000000000", windowSeconds: 3600),
            SpendingLimitRule(id: usdcRuleId, token: .usdc, allowance: "5000000", windowSeconds: 3600),
        ]

        let request = makeUserOpRequest(
            callData: makeKernelSingleCallData(
                target: usdc,
                value: 1_000_000_000_000_000_000,
                calldata: makeERC20TransferCalldata(
                    to: "0xdddddddddddddddddddddddddddddddddddddddd",
                    amount: 2_000_000
                )
            )
        )

        try engine.recordSuccess(request: request, config: config)

        #expect(engine.stateStore.spentAmount(ruleId: ethRuleId, windowSeconds: 3600) == UInt128("1000000000000000000"))
        #expect(engine.stateStore.spentAmount(ruleId: usdcRuleId, windowSeconds: 3600) == UInt128("2000000"))
    }

    @Test("Record success uses higher simulated spend for counters")
    func recordSuccessUsesHigherSimulatedSpend() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        var config = BastionConfig.default
        let ethRuleId = UUID().uuidString
        config.rules.spendingLimits = [
            SpendingLimitRule(id: ethRuleId, token: .eth, allowance: "5000000000000000000", windowSeconds: 3600)
        ]
        let request = makeUserOpRequest(
            callData: makeKernelSingleCallData(
                target: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                value: 1_000_000_000_000_000_000
            )
        )

        try engine.recordSuccess(
            request: request,
            config: config,
            simulatedSpendObservations: [
                SimulatedSpendObservation(token: .eth, amount: "3000000000000000000")
            ]
        )

        #expect(engine.stateStore.spentAmount(ruleId: ethRuleId, windowSeconds: 3600) == UInt128("3000000000000000000"))
    }

    @Test("Session USDC spend cap is cumulative")
    func sessionUSDCSpendCapIsCumulative() throws {
        let bundleId = "com.example.agent"
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        let session = AgentSession(
            clientLabel: "Agent",
            clientId: nil,
            clientBundleId: bundleId,
            chains: [1],
            usdcLimit: 1.5,
            ethLimit: nil,
            allowedTargets: [],
            expiresAt: Date().addingTimeInterval(3600),
            intent: nil
        )
        SessionSnapshotStore.shared.update([session])
        defer { SessionSnapshotStore.shared.update([]) }

        let usdc = USDCAddresses.address(for: 1)!
        let request = makeUserOpRequest(
            callData: makeKernelSingleCallData(
                target: usdc,
                calldata: makeERC20TransferCalldata(
                    to: "0xdddddddddddddddddddddddddddddddddddddddd",
                    amount: 1_000_000
                )
            ),
            clientBundleId: bundleId
        )

        if case .allowed = engine.validate(request, config: .default) { } else {
            Issue.record("Expected first 1 USDC session spend to pass")
        }
        try engine.recordSuccess(request: request, config: .default)

        let second = engine.validate(request, config: .default)
        if case .denied(let reasons) = second {
            #expect(reasons.contains { $0.contains("Session USDC cap exceeded") })
        } else {
            Issue.record("Expected cumulative session spend to deny second request")
        }
    }

    @Test("Opaque UserOp denies when spending rules are configured")
    func opaqueUserOpDeniedForSpendingRules() {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        var config = BastionConfig.default
        config.rules.spendingLimits = [
            SpendingLimitRule(id: "eth", token: .eth, allowance: "1000000000000000000", windowSeconds: 3600)
        ]

        let result = engine.validate(
            makeUserOpRequest(callData: Data([0xde, 0xad, 0xbe, 0xef])),
            config: config
        )

        if case .denied(let reasons) = result {
            #expect(reasons.contains { $0.contains("Unable to inspect UserOperation spending") })
        } else {
            Issue.record("Expected opaque UserOp to be denied when spending rules are configured")
        }
    }

    @Test("Allowed clients: matching client passes")
    func allowedClientsPass() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedClients = [
            AllowedClient(id: "c1", bundleId: "com.bastion.cli", label: "Bastion CLI")
        ]
        let result = engine.validate(
            makeMessageRequest(clientBundleId: "com.bastion.cli"),
            config: config
        )
        if case .allowed = result { } else {
            Issue.record("Expected .allowed for matching client")
        }
    }

    @Test("Allowed clients: non-matching client denies")
    func allowedClientsDeny() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedClients = [
            AllowedClient(id: "c1", bundleId: "com.bastion.cli", label: "Bastion CLI")
        ]
        let result = engine.validate(
            makeMessageRequest(clientBundleId: "com.malicious.agent"),
            config: config
        )
        if case .denied(let reasons) = result {
            #expect(reasons.first?.contains("not in allowlist") == true)
        } else {
            Issue.record("Expected .denied for non-matching client")
        }
    }

    @Test("Allowed clients: nil bundle ID denies when allowlist configured")
    func allowedClientsNilBundleIdDeny() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedClients = [
            AllowedClient(id: "c1", bundleId: "com.bastion.cli", label: nil)
        ]
        let result = engine.validate(
            makeMessageRequest(clientBundleId: nil),
            config: config
        )
        if case .denied = result { } else {
            Issue.record("Expected .denied for nil client bundle ID")
        }
    }

    @Test("No client allowlist allows all clients")
    func noClientAllowlistAllowsAll() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.allowedClients = nil
        let result = engine.validate(
            makeMessageRequest(clientBundleId: "com.anything.goes"),
            config: config
        )
        if case .allowed = result { } else {
            Issue.record("Expected .allowed when no client allowlist")
        }
    }

    @Test("requiresExplicitApproval reflects per-type rule-based toggle")
    func allOperationsRequireApprovalReview() {
        let engine = RuleEngine(keychain: MockKeychainBackend())

        // When rule-based signing is enabled (default), no explicit approval required
        var enabledConfig = BastionConfig.default
        enabledConfig.rules.rawMessagePolicy.enabled = true
        enabledConfig.rules.typedDataPolicy.enabled = true
        enabledConfig.rules.requireExplicitApproval = false
        enabledConfig.rules.typedDataPolicy.requireExplicitApproval = false
        #expect(engine.requiresExplicitApproval(for: makeMessageRequest(), config: enabledConfig) == false)
        #expect(engine.requiresExplicitApproval(for: makeTypedDataRequest(), config: enabledConfig) == false)
        #expect(engine.requiresExplicitApproval(for: makeUserOpRequest(), config: enabledConfig) == false)

        // When rule-based signing is disabled for each type, explicit approval is required
        var disabledConfig = BastionConfig.default
        disabledConfig.rules.rawMessagePolicy.enabled = false
        disabledConfig.rules.typedDataPolicy.enabled = false
        disabledConfig.rules.requireExplicitApproval = true
        #expect(engine.requiresExplicitApproval(for: makeMessageRequest(), config: disabledConfig) == true)
        #expect(engine.requiresExplicitApproval(for: makeTypedDataRequest(), config: disabledConfig) == true)
        #expect(engine.requiresExplicitApproval(for: makeUserOpRequest(), config: disabledConfig) == true)
    }

    @Test("Spending limit state tracking works")
    func spendingLimitStateTracking() {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        // Record spending directly to verify state store mechanism works
        engine.stateStore.recordSpend(ruleId: "s1", amount: "1500000000000000000", windowSeconds: 3600)
        let spent = engine.stateStore.spentAmount(ruleId: "s1", windowSeconds: 3600)
        #expect(spent == UInt128("1500000000000000000"))

        // Record more spending
        engine.stateStore.recordSpend(ruleId: "s1", amount: "500000000000000000", windowSeconds: 3600)
        let totalSpent = engine.stateStore.spentAmount(ruleId: "s1", windowSeconds: 3600)
        #expect(totalSpent == UInt128("2000000000000000000"))
    }
}

// MARK: - Raw Bytes Signing Policy Tests

@Suite("RawMessagePolicy — raw bytes signing sub-rule")
struct RawMessagePolicyTests {

    @Test("Message signing disabled: both .message and .rawBytes return allowed + requiresApproval=true")
    func messagingDisabledRequiresApproval() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy.enabled = false

        // Both types allowed (not denied) — explicit approval gate handles the rest
        let msgResult = engine.validate(makeMessageRequest(), config: config)
        let rawResult = engine.validate(makeRawBytesRequest(), config: config)
        if case .denied = msgResult { Issue.record(".message should not be denied when toggle is off") }
        if case .denied = rawResult { Issue.record(".rawBytes should not be denied when toggle is off") }

        // requiresExplicitApproval must be true for both
        #expect(engine.requiresExplicitApproval(for: makeMessageRequest(), config: config) == true)
        #expect(engine.requiresExplicitApproval(for: makeRawBytesRequest(), config: config) == true)
    }

    @Test("Message signing enabled, allowRawSigning=false: .rawBytes is denied")
    func rawSigningDisabledDeniesRawBytes() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy.enabled = true
        config.rules.rawMessagePolicy.allowRawSigning = false

        let result = engine.validate(makeRawBytesRequest(), config: config)
        if case .denied(let reasons) = result {
            #expect(reasons.first?.contains("Raw bytes signing is not permitted") == true)
        } else {
            Issue.record("Expected .rawBytes to be denied when allowRawSigning=false")
        }
    }

    @Test("Message signing enabled, allowRawSigning=false: EIP-191 .message is still allowed")
    func rawSigningDisabledPermitsEIP191Message() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy.enabled = true
        config.rules.rawMessagePolicy.allowRawSigning = false

        let result = engine.validate(makeMessageRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected EIP-191 .message to pass when allowRawSigning=false")
        }
        #expect(engine.requiresExplicitApproval(for: makeMessageRequest(), config: config) == false)
    }

    @Test("Message signing enabled, allowRawSigning=true: both types are allowed")
    func rawSigningEnabledAllowsBothTypes() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy.enabled = true
        config.rules.rawMessagePolicy.allowRawSigning = true

        let msgResult = engine.validate(makeMessageRequest(), config: config)
        let rawResult = engine.validate(makeRawBytesRequest(), config: config)
        if case .allowed = msgResult { } else { Issue.record("Expected .message to be allowed") }
        if case .allowed = rawResult { } else { Issue.record("Expected .rawBytes to be allowed") }
        #expect(engine.requiresExplicitApproval(for: makeRawBytesRequest(), config: config) == false)
    }

    @Test("RawMessagePolicy decodes allowRawSigning with backward-compatible default")
    func decodesAllowRawSigningWithDefault() throws {
        // Old saved config without allowRawSigning field should default to false
        let json = """
        {"enabled": true}
        """.data(using: .utf8)!
        let policy = try JSONDecoder().decode(RawMessagePolicy.self, from: json)
        #expect(policy.enabled == true)
        #expect(policy.allowRawSigning == false)
    }

    @Test("rawBytes request carries data directly with no Ethereum prefix")
    func rawBytesDataPassthrough() {
        let payload = Data((0..<32).map { UInt8($0) })
        let request = makeRawBytesRequest(bytes: payload)
        #expect(request.data == payload)
    }
}

// MARK: - Data Hex Extension Tests

@Suite("Data Hex Extension")
struct DataHexTests {

    @Test("Hex string round-trip")
    func hexRoundTrip() {
        let original = Data([0xDE, 0xAD, 0xBE, 0xEF])
        let hex = original.hex
        #expect(hex == "deadbeef")
        let decoded = Data(hexString: hex)
        #expect(decoded == original)
    }

    @Test("Hex string with 0x prefix")
    func hexWith0xPrefix() {
        let data = Data(hexString: "0xdeadbeef")
        #expect(data == Data([0xDE, 0xAD, 0xBE, 0xEF]))
    }

    @Test("Odd-length hex string is left-padded")
    func oddLengthHex() {
        let data = Data(hexString: "0xabc")
        #expect(data == Data([0x0A, 0xBC]))
    }

    @Test("Empty hex string")
    func emptyHex() {
        let data = Data(hexString: "")
        #expect(data == Data())
    }
}

// MARK: - RuleEngine Config Backup Tests

@Suite("RuleEngine Config Backup")
struct RuleEngineConfigBackupTests {

    /// Raw v5 config JSON — simulates a config saved before schema version 7.
    private static let v5ConfigJSON = """
    {
        "version": 5,
        "authPolicy": "open",
        "rules": {
            "enabled": true, "requireExplicitApproval": false,
            "rateLimits": [], "spendingLimits": [],
            "rawMessagePolicy": {"enabled": true},
            "typedDataPolicy": {"enabled": true, "requireExplicitApproval": false, "domainRules": [], "structRules": []}
        },
        "bundlerPreferences": {"chainRPCs": []},
        "clientProfiles": []
    }
    """

    @Test("Migration from v5 creates a backup")
    func migrationCreatesBackup() {
        let keychain = MockKeychainBackend()
        keychain.write(account: "config", data: Self.v5ConfigJSON.data(using: .utf8)!)
        let engine = RuleEngine(keychain: keychain)

        _ = engine.loadConfig()

        #expect(engine.hasConfigBackup() == true)
    }

    @Test("Second load does not overwrite existing backup")
    func secondLoadDoesNotOverwriteBackup() throws {
        let keychain = MockKeychainBackend()
        keychain.write(account: "config", data: Self.v5ConfigJSON.data(using: .utf8)!)
        let engine = RuleEngine(keychain: keychain)

        // First load — creates the backup
        _ = engine.loadConfig()
        let backupAfterFirst = keychain.read(account: "config.premigration")

        // Overwrite the main config slot with a different v5 payload
        let v5AltJSON = """
        {
            "version": 5,
            "authPolicy": "passcode",
            "rules": {
                "enabled": false, "requireExplicitApproval": false,
                "rateLimits": [], "spendingLimits": [],
                "rawMessagePolicy": {"enabled": true},
                "typedDataPolicy": {"enabled": true, "requireExplicitApproval": false, "domainRules": [], "structRules": []}
            },
            "bundlerPreferences": {"chainRPCs": []},
            "clientProfiles": []
        }
        """
        keychain.write(account: "config", data: v5AltJSON.data(using: .utf8)!)

        // Second load — backup must NOT be overwritten
        _ = engine.loadConfig()
        let backupAfterSecond = keychain.read(account: "config.premigration")

        #expect(backupAfterFirst == backupAfterSecond)
    }

    @Test("restoreConfigBackup returns the pre-migration config")
    func restoreConfigBackupReturnsPremigrationConfig() {
        let keychain = MockKeychainBackend()
        keychain.write(account: "config", data: Self.v5ConfigJSON.data(using: .utf8)!)
        let engine = RuleEngine(keychain: keychain)

        _ = engine.loadConfig()

        let backup = engine.restoreConfigBackup()
        #expect(backup != nil)
        // Backup holds the original (unmodified) data — version and auth policy are from before migration
        #expect(backup?.version == 5)
        #expect(backup?.authPolicy == .open)
    }

    @Test("No backup is created when config is already at current version")
    func noBackupForCurrentVersionConfig() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)

        // Save a fully-current config (version 7)
        try engine.saveConfig(.default)

        _ = engine.loadConfig()

        #expect(engine.hasConfigBackup() == false)
    }

    @Test("ConfigVersionStore records newest versions and prunes locked-down snapshots")
    func configVersionStoreRecordsAndPrunesSnapshots() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ConfigVersionStore-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let store = ConfigVersionStore(directoryURL: directory, maxVersions: 2)

        var first = BastionConfig.default
        first.authPolicy = .open

        var second = BastionConfig.default
        second.authPolicy = .biometric
        second.clientProfiles = [
            ClientProfile(
                id: "client-a",
                bundleId: "com.example.agent",
                label: "Example Agent",
                rules: .default
            )
        ]

        var third = BastionConfig.default
        third.authPolicy = .biometricOrPasscode
        third.walletGroups = [
            WalletGroup(id: "group-a", label: "Treasury Group", chainIds: [8453])
        ]

        store.recordVersion(first)
        Thread.sleep(forTimeInterval: 0.01)
        store.recordVersion(second)
        Thread.sleep(forTimeInterval: 0.01)
        store.recordVersion(third)

        let versions = store.versions()
        #expect(versions.count == 2)
        let newest = try #require(versions.first)
        let older = try #require(versions.last)
        #expect(newest.config.authPolicy == .biometricOrPasscode)
        #expect(newest.summary.contains("auth=biometricOrPasscode"))
        #expect(newest.summary.contains("groups=1"))
        #expect(older.config.authPolicy == .biometric)
        #expect(older.summary.contains("clients=1"))
        #expect(store.resolve(versionId: newest.id)?.authPolicy == .biometricOrPasscode)
        #expect(store.resolve(versionId: "missing") == nil)

        let snapshotFiles = try FileManager.default.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: nil
        )
        #expect(snapshotFiles.count == 2)
        let directoryMode = (try FileManager.default.attributesOfItem(atPath: directory.path)[.posixPermissions] as? NSNumber)?.intValue
        #expect(directoryMode == 0o700)
        for file in snapshotFiles {
            let fileMode = (try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue
            #expect(fileMode == 0o600)
        }
    }

    @Test("ConfigVersionStore records snapshot failures to diagnostics")
    func configVersionStoreRecordsSnapshotFailuresToDiagnostics() throws {
        let directoryFile = FileManager.default.temporaryDirectory
            .appendingPathComponent("ConfigVersionStore-file-\(UUID().uuidString)")
        try Data("not a directory".utf8).write(to: directoryFile)
        defer { try? FileManager.default.removeItem(at: directoryFile) }

        let recorder = PolicyHistoryDiagnosticRecorder()
        let store = ConfigVersionStore(
            directoryURL: directoryFile,
            maxVersions: 3,
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )

        store.recordVersion(.default)

        let entry = try #require(recorder.entries().first)
        #expect(entry.level == .warning)
        #expect(entry.category == .policy)
        #expect(entry.event == "policy_history_snapshot_failed")
        #expect(entry.message.contains("Policy history snapshot failed:"))
        #expect(entry.context["historyDirectory"] == directoryFile.path)
        #expect(entry.context["maxVersions"] == "3")
        #expect(entry.context["error"]?.isEmpty == false)
    }

    @Test("ConfigVersionStore records corrupt snapshot read failures to diagnostics")
    func configVersionStoreRecordsCorruptSnapshotReadFailuresToDiagnostics() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent("ConfigVersionStore-corrupt-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let recorder = PolicyHistoryDiagnosticRecorder()
        let store = ConfigVersionStore(
            directoryURL: directory,
            maxVersions: 5,
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )
        var valid = BastionConfig.default
        valid.authPolicy = .biometric
        store.recordVersion(valid)
        let corruptFile = directory.appendingPathComponent("corrupt-version.json")
        try Data("{bad".utf8).write(to: corruptFile)

        let versions = store.versions()

        #expect(versions.count == 1)
        #expect(versions.first?.config.authPolicy == .biometric)
        let entry = try #require(recorder.entries().first { $0.event == "policy_history_snapshot_read_failed" })
        #expect(entry.level == .warning)
        #expect(entry.category == .policy)
        #expect(entry.message.contains("Policy history snapshot read failed for corrupt-version.json:"))
        #expect(entry.context["historyDirectory"] == directory.path)
        #expect(entry.context["snapshotFile"] == "corrupt-version.json")
        #expect(entry.context["error"]?.isEmpty == false)
    }
}

private final class PolicyHistoryDiagnosticRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [DiagnosticLogEntry] = []

    func record(
        level: DiagnosticLevel,
        category: DiagnosticCategory,
        event: String,
        message: String,
        context: [String: String]
    ) {
        lock.withLock {
            recorded.append(DiagnosticLogEntry(
                timestamp: "test",
                level: level,
                category: category,
                event: event,
                message: message,
                context: context
            ))
        }
    }

    func entries() -> [DiagnosticLogEntry] {
        lock.withLock { recorded }
    }
}

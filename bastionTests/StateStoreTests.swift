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

    nonisolated func write(account: String, data: Data) {
        lock.lock()
        defer { lock.unlock() }
        storage[account] = data
    }

    nonisolated func delete(account: String) {
        lock.lock()
        defer { lock.unlock() }
        storage.removeValue(forKey: account)
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

private func makeUserOpRequest(
    sender: String = "0x1234567890abcdef1234567890abcdef12345678",
    chainId: Int = 1,
    requestID: String = UUID().uuidString,
    clientBundleId: String? = nil
) -> SignRequest {
    SignRequest(
        operation: .userOperation(UserOperation(
            sender: sender,
            nonce: "0x0",
            callData: Data(),
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
        clientBundleId: clientBundleId
    )
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

    @Test("Corrupted keychain data returns 0")
    func corruptedDataReturnsZero() {
        let keychain = MockKeychainBackend()
        keychain.write(account: "state.ratelimit.test", data: Data("garbage".utf8))
        let store = StateStore(keychain: keychain)
        #expect(store.rateLimitCount(ruleId: "test", windowSeconds: 3600) == 0)
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
        #expect(config.authPolicy == .open)
        #expect(config.rules.enabled == true)
        #expect(config.rules.rateLimits.isEmpty)
        #expect(config.rules.spendingLimits.isEmpty)
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
        config.rules.allowedTargets = ["1": ["0x1234567890abcdef1234567890abcdef12345678"]]
        let result = engine.validate(
            makeUserOpRequest(sender: "0x1234567890abcdef1234567890abcdef12345678", chainId: 1),
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
            makeUserOpRequest(sender: "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", chainId: 1),
            config: config
        )
        if case .denied = result { } else {
            Issue.record("Expected .denied for non-matching target")
        }
    }

    @Test("Allowed hours within range passes")
    func allowedHoursWithinRange() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let hour = Calendar.current.component(.hour, from: Date())
        var config = BastionConfig.default
        config.rules.allowedHours = AllowedHours(start: hour, end: (hour + 1) % 24)
        let result = engine.validate(makeMessageRequest(), config: config)
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
        let result = engine.validate(makeMessageRequest(), config: config)
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

    @Test("ETH spending limit: UserOp passes (no explicit ethValue)")
    func spendingLimitUserOpPasses() {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        var config = BastionConfig.default
        config.rules.spendingLimits = [
            SpendingLimitRule(id: "s1", token: .eth, allowance: "2000000000000000000", windowSeconds: 3600)
        ]
        // UserOps don't carry explicit ethValue; spending limit check requires calldata parsing (TODO)
        let result = engine.validate(makeUserOpRequest(), config: config)
        if case .allowed = result { } else {
            Issue.record("Expected .allowed for UserOp (spending limits require calldata parsing)")
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

    @Test("Empty hex string")
    func emptyHex() {
        let data = Data(hexString: "")
        #expect(data == Data())
    }
}

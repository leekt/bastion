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

private let defaultValidCallData: Data = KernelEncoding.executeCalldata(
    single: .init(to: "0x0000000000000000000000000000000000000001", value: 0, data: Data())
)

private func makeUserOpRequest(
    sender: String = "0x1234567890abcdef1234567890abcdef12345678",
    chainId: Int = 1,
    callData: Data? = nil,
    requestID: String = UUID().uuidString,
    clientBundleId: String? = nil
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
        clientBundleId: clientBundleId
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
        #expect(config.authPolicy == .biometricOrPasscode)
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

    @Test("Raw message signing can be disabled")
    func rawMessageDisabled() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy.enabled = false
        let result = engine.validate(makeMessageRequest(), config: config)
        if case .denied(let reasons) = result {
            #expect(reasons.first?.contains("disabled") == true)
        } else {
            Issue.record("Expected .denied when raw signing is disabled")
        }
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

    @Test("Record success tracks decoded UserOp spending")
    func recordSuccessTracksDecodedUserOpSpending() {
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

        engine.recordSuccess(request: request, config: config)

        #expect(engine.stateStore.spentAmount(ruleId: ethRuleId, windowSeconds: 3600) == UInt128("1000000000000000000"))
        #expect(engine.stateStore.spentAmount(ruleId: usdcRuleId, windowSeconds: 3600) == UInt128("2000000"))
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

    @Test("All signing operation types require approval review")
    func allOperationsRequireApprovalReview() {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let config = BastionConfig.default

        #expect(engine.requiresExplicitApproval(for: makeMessageRequest(), config: config))
        #expect(engine.requiresExplicitApproval(for: makeTypedDataRequest(), config: config))
        #expect(engine.requiresExplicitApproval(for: makeUserOpRequest(), config: config))
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

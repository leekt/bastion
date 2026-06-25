import Foundation
import Testing
@testable import bastion

@Suite("Deterministic request flow coverage")
struct RequestFlowIntegrationTests {

    @Test("Raw bytes sign flow validates, hashes, and audits as sign-only")
    func rawBytesSignOnlyFlow() throws {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.rawMessagePolicy = RawMessagePolicy(
            posture: .enforceRulesAndAutoSign,
            allowRawSigning: true
        )

        let payload = Data((0..<32).map { UInt8($0) })
        let request = rawRequest(bytes: payload, requestID: "flow-raw")

        expectAllowed(engine.validate(request, config: config))
        #expect(engine.requiresExplicitApproval(for: request, config: config) == false)
        #expect(request.executionMode == .signOnly)
        #expect(request.data == payload)

        let audit = try temporaryAuditLog()
        let log = audit.log
        log.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: request.requestID,
            approvalMode: .auto,
            request: request,
            clientContext: clientContext(rules: config.rules)
        ))

        let record = try latestRecord(from: log)
        #expect(record.executionMode == .signOnly)
        #expect(record.latestResultLabel == "Signed (Auto)")
        #expect(record.request?.operationKind == "raw_bytes")
        #expect(record.request?.digestHex == "0x" + payload.hex)
    }

    @Test("Typed-data approval flow validates policy and audits approval")
    func typedDataApprovalFlow() throws {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        let request = typedDataRequest(requestID: "flow-typed")
        var config = BastionConfig.default
        config.rules.typedDataPolicy = TypedDataPolicy(
            posture: .enforceRulesAndRequireApproval,
            domainRules: [
                TypedDataDomainRule(
                    id: "domain-permit2",
                    label: "Permit2",
                    primaryType: "Permit",
                    name: "Permit2",
                    version: "1",
                    chainId: 11155111,
                    verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3"
                )
            ],
            structRules: [
                TypedDataStructRule(
                    id: "permit-spender",
                    label: "Known spender",
                    primaryType: "Permit",
                    matcherJSON: #"{"spender":"0x7777777777777777777777777777777777777777","value":"50000000"}"#
                )
            ]
        )

        expectAllowed(engine.validate(request, config: config))
        #expect(engine.requiresExplicitApproval(for: request, config: config) == true)
        #expect(request.executionMode == .signOnly)

        let audit = try temporaryAuditLog()
        let log = audit.log
        log.record(AuditEvent(
            type: .signPending,
            dataPrefix: request.requestID,
            request: request,
            clientContext: clientContext(rules: config.rules)
        ))
        log.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: request.requestID,
            approvalMode: .policyReview,
            request: request,
            clientContext: clientContext(rules: config.rules)
        ))

        let record = try latestRecord(from: log)
        #expect(record.executionMode == .signOnly)
        #expect(record.latestResultLabel == "Signed (Approved)")
        #expect(record.events.count == 2)
        #expect(record.request?.operationKind == "typed_data")
        #expect(record.request?.summary == "Permit for Permit2")
        #expect(record.request?.details.contains("Primary Type: Permit") == true)
    }

    @Test("UserOperation approve-and-send flow carries provider submission state")
    func userOperationApproveAndSendFlow() throws {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var config = BastionConfig.default
        config.rules.userOpPosture = .enforceRulesAndRequireApproval

        let submission = UserOperationSubmissionRequest(provider: .zeroDev, projectId: "project-1")
        let request = userOperationRequest(
            requestID: "flow-userop",
            submission: submission
        )

        expectAllowed(engine.validate(request, config: config))
        #expect(engine.requiresExplicitApproval(for: request, config: config) == true)
        #expect(request.executionMode == .approveAndSend)

        let audit = try temporaryAuditLog()
        let log = audit.log
        log.record(AuditEvent(
            type: .preflightCompleted,
            dataPrefix: request.requestID,
            request: request,
            clientContext: clientContext(rules: config.rules)
        ))
        log.record(AuditEvent(
            type: .signSuccess,
            dataPrefix: request.requestID,
            approvalMode: .policyReview,
            request: request,
            clientContext: clientContext(rules: config.rules)
        ))
        log.record(AuditEvent(
            type: .userOpSubmitted,
            dataPrefix: request.requestID,
            request: request,
            clientContext: clientContext(rules: config.rules),
            submission: AuditSubmissionSnapshot(
                provider: "ZeroDev",
                status: "submitted",
                userOpHash: "0xabc123",
                transactionHash: nil,
                detail: "Submission accepted"
            )
        ))

        let record = try latestRecord(from: log)
        #expect(record.executionMode == .approveAndSend)
        #expect(record.latestResultLabel == "Submitted")
        #expect(record.latestSubmission?.userOpHash == "0xabc123")
        #expect(record.events.map(\.type).contains(.preflightCompleted))
        #expect(record.request?.details.contains("Post-Approval Action: Submit to ZeroDev") == true)
    }

    @Test("UserOperation preflight failure flow preserves diagnosis before approval")
    func userOperationPreflightFailureFlow() throws {
        let submission = UserOperationSubmissionRequest(provider: .zeroDev, projectId: "project-1")
        let request = userOperationRequest(
            requestID: "flow-preflight-failure",
            submission: submission
        )
        let result = PreflightResult(
            passed: false,
            gasEstimate: nil,
            aaError: "AA24",
            failureReason: "AA24 invalid signature",
            staticWarnings: ["maxFeePerGas is below the bundler slow tier"],
            diagnosis: "Preflight simulation failed with AA24",
            recommendations: ["Rebuild the UserOperation with a fresh signature"],
            severity: .error
        )

        guard case .userOperation(let op) = request.operation else {
            Issue.record("Expected UserOperation request")
            return
        }
        let bundleData = try #require(PreflightSimulator.shared.debugBundle(
            op: op,
            signature: nil,
            result: result
        ))
        let bundle = try JSONDecoder().decode(PreflightDebugBundle.self, from: bundleData)
        #expect(bundle.preflightResult.aaError == "AA24")
        #expect(bundle.preflightResult.severity == .error)

        let audit = try temporaryAuditLog()
        let log = audit.log
        log.record(AuditEvent(
            type: .preflightCompleted,
            dataPrefix: request.requestID,
            reason: result.failureReason,
            request: request,
            clientContext: clientContext()
        ))

        let record = try latestRecord(from: log)
        #expect(record.executionMode == .approveAndSend)
        #expect(record.latestResultLabel == "Preflight")
        #expect(record.latestReason == "AA24 invalid signature")
        #expect(record.request?.details.contains("Post-Approval Action: Submit to ZeroDev") == true)
    }

    @Test("Per-client signing contexts keep profile key tags separated")
    func perClientKeySeparationFlow() throws {
        let engine = RuleEngine(keychain: MockKeychainBackend())
        var alphaRules = RuleConfig.default
        alphaRules.allowedChains = [1]
        var betaRules = RuleConfig.default
        betaRules.allowedChains = [8453]

        let alpha = ClientProfile(
            id: "profile-alpha",
            bundleId: "com.example.alpha",
            label: "Alpha",
            keyTag: "com.bastion.signingkey.client.alpha",
            rules: alphaRules
        )
        let beta = ClientProfile(
            id: "profile-beta",
            bundleId: "com.example.beta",
            label: "Beta",
            keyTag: "com.bastion.signingkey.client.beta",
            rules: betaRules
        )
        let config = BastionConfig(
            authPolicy: .biometricOrPasscode,
            rules: .default,
            clientProfiles: [alpha, beta]
        )

        try engine.saveConfig(config)
        engine.loadConfigOnStartup()

        let alphaContext = engine.signingContext(for: "com.example.alpha", createProfile: false)
        let betaContext = engine.signingContext(for: "com.example.beta", createProfile: false)

        #expect(alphaContext.profileId == "profile-alpha")
        #expect(betaContext.profileId == "profile-beta")
        #expect(alphaContext.keyTag == "com.bastion.signingkey.client.alpha")
        #expect(betaContext.keyTag == "com.bastion.signingkey.client.beta")
        #expect(alphaContext.keyTag != betaContext.keyTag)
        #expect(alphaContext.rules.allowedChains == [1])
        #expect(betaContext.rules.allowedChains == [8453])
    }

    @Test("Legacy config migration hardens auth and preserves profile key tags")
    func configMigrationFlow() throws {
        let keychain = MockKeychainBackend()
        let engine = RuleEngine(keychain: keychain)
        let legacyConfig = """
        {
          "version": 5,
          "authPolicy": "open",
          "rules": {
            "enabled": true,
            "requireExplicitApproval": false,
            "rateLimits": [],
            "spendingLimits": [],
            "rawMessagePolicy": {"enabled": true},
            "typedDataPolicy": {
              "enabled": true,
              "requireExplicitApproval": false,
              "domainRules": [],
              "structRules": []
            }
          },
          "bundlerPreferences": {"chainRPCs": []},
          "clientProfiles": [
            {
              "id": "profile-alpha",
              "bundleId": "com.example.alpha",
              "authPolicy": "open",
              "keyTag": "com.bastion.signingkey.client.alpha",
              "rules": {
                "enabled": true,
                "requireExplicitApproval": false,
                "rateLimits": [],
                "spendingLimits": [],
                "rawMessagePolicy": {"enabled": true},
                "typedDataPolicy": {
                  "enabled": true,
                  "requireExplicitApproval": false,
                  "domainRules": [],
                  "structRules": []
                }
              }
            }
          ]
        }
        """
        keychain.write(account: "config", data: Data(legacyConfig.utf8))

        let loaded = engine.loadConfig()
        let profile = try #require(loaded.clientProfiles.first)

        #expect(loaded.version >= 7)
        #expect(loaded.authPolicy == .biometricOrPasscode)
        #expect(profile.authPolicy == .biometricOrPasscode)
        #expect(profile.keyTag == "com.bastion.signingkey.client.alpha")
        #expect(profile.bundleId == "com.example.alpha")
    }

    private func expectAllowed(_ result: RuleEngine.ValidationResult) {
        if case .allowed = result {
            return
        }
        Issue.record("Expected request to be allowed, got \(result)")
    }

    private final class TemporaryAuditLog {
        let directory: URL
        let log: AuditLog

        init() throws {
            directory = FileManager.default.temporaryDirectory
                .appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            log = AuditLog(logURL: directory.appendingPathComponent("audit.log"), keychain: MockKeychainBackend())
        }

        deinit {
            try? FileManager.default.removeItem(at: directory)
        }
    }

    private func temporaryAuditLog() throws -> TemporaryAuditLog {
        try TemporaryAuditLog()
    }

    private func latestRecord(from log: AuditLog) throws -> AuditRequestRecord {
        try #require(log.recentRequestRecords(limit: 10).first)
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

    private func rawRequest(bytes: Data, requestID: String) -> SignRequest {
        SignRequest(
            operation: .rawBytes(bytes),
            requestID: requestID,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.agent"
        )
    }

    private func typedDataRequest(requestID: String) -> SignRequest {
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
                ],
            ],
            primaryType: "Permit",
            domain: EIP712Domain(
                name: "Permit2",
                version: "1",
                chainId: 11155111,
                verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                salt: nil
            ),
            message: [
                "owner": AnyCodable("0x1234567890abcdef1234567890abcdef12345678"),
                "spender": AnyCodable("0x7777777777777777777777777777777777777777"),
                "value": AnyCodable("50000000"),
            ]
        )

        return SignRequest(
            operation: .typedData(typedData),
            requestID: requestID,
            timestamp: Date(timeIntervalSince1970: 1_710_000_100),
            clientBundleId: "com.example.agent"
        )
    }

    private func userOperationRequest(
        requestID: String,
        submission: UserOperationSubmissionRequest?
    ) -> SignRequest {
        SignRequest(
            operation: .userOperation(UserOperation(
                sender: "0x1234567890abcdef1234567890abcdef12345678",
                nonce: "0x0",
                callData: KernelEncoding.executeCalldata(
                    single: .init(
                        to: "0x0000000000000000000000000000000000000001",
                        value: 0,
                        data: Data()
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
                chainId: 11155111,
                entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
                entryPointVersion: .v0_7
            )),
            requestID: requestID,
            timestamp: Date(timeIntervalSince1970: 1_710_000_200),
            clientBundleId: "com.example.agent",
            userOperationSubmission: submission
        )
    }
}

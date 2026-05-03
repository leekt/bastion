import Foundation
import Darwin

final class XPCServer: NSObject, NSXPCListenerDelegate {
    static let shared = XPCServer()

    private var listener: NSXPCListener?
    private let signingManager = SigningManager.shared
    private let ruleEngine = RuleEngine.shared

    private override init() {
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: xpcServiceName)
        listener?.delegate = self
        listener?.resume()
    }

    func stop() {
        listener?.invalidate()
        listener = nil
    }

    // MARK: - NSXPCListenerDelegate

    nonisolated func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        if !verifyClientCodeSignature(connection: newConnection) {
            return false
        }

        let clientBundleId = bundleIdentifier(for: newConnection.processIdentifier)

        newConnection.exportedInterface = NSXPCInterface(with: BastionXPCProtocol.self)
        newConnection.exportedObject = XPCHandler(
            signingManager: signingManager,
            ruleEngine: ruleEngine,
            clientBundleId: clientBundleId
        )
        newConnection.invalidationHandler = {}
        newConnection.resume()
        return true
    }

    // MARK: - Client Identification

    /// Extracts the bundle identifier from a running process via its code signature.
    private nonisolated func bundleIdentifier(for pid: Int32) -> String? {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return nil
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
              let sCode = staticCode else {
            return nil
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(sCode, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let signingInfo = info as? [String: Any],
              let plist = signingInfo[kSecCodeInfoPList as String] as? [String: Any],
              let bundleId = plist["CFBundleIdentifier"] as? String else {
            // CLI tools may not have a bundle identifier — try the identifier from code signing
            if let info = info as? [String: Any],
               let identifier = info[kSecCodeInfoIdentifier as String] as? String {
                return identifier
            }
            return nil
        }
        return bundleId
    }

    // MARK: - Code Signing Verification

    /// Team ID that signed Bastion.app — only clients signed by the same team are accepted.
    private nonisolated static let requiredTeamID = "926A27BQ7W"
    private nonisolated static let untrustedDevSignatureStatus = OSStatus(CSSMERR_TP_NOT_TRUSTED)

    private nonisolated func verifyClientCodeSignature(connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return false
        }

        // Require valid code signature
        let validityStatus = SecCodeCheckValidity(secCode, [], nil)
#if DEBUG
        let allowUntrustedDevSignature = validityStatus == Self.untrustedDevSignatureStatus
#else
        let allowUntrustedDevSignature = false
#endif
        guard validityStatus == errSecSuccess || allowUntrustedDevSignature else {
            return false
        }

        // Verify the client is signed by the same team
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return false
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            code,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        ) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return false
        }

        if let teamID = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String {
            return teamID == Self.requiredTeamID
        }

#if DEBUG
        return isAllowedDebugSidecar(pid: pid, signingInfo: signingInfo)
#else
        return false
#endif
    }

#if DEBUG
    // L-04: Require both identifier match AND path check. The previous
    // fallback accepted any binary at the CLI path regardless of identity.
    // The code signing identifier for a fat/single-arch CLI tool may be reported
    // with an architecture suffix (e.g. "bastion-cli-arm64") or without one
    // ("bastion-cli"), depending on how the binary was built and signed.
    private nonisolated func isAllowedDebugSidecar(pid: Int32, signingInfo: [String: Any]) -> Bool {
        guard let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String,
              identifier == "bastion-cli" || identifier.hasPrefix("bastion-cli-") else {
            return false
        }
        return executablePath(for: pid)?.hasSuffix("/bastion.app/Contents/MacOS/bastion-cli") == true
    }

    private nonisolated func executablePath(for pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: 4096)
        let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard result > 0 else {
            return nil
        }
        return String(cString: buffer)
    }
#endif
}

// Separate handler class for XPC callbacks (runs on XPC queue, not MainActor)
private nonisolated final class XPCHandler: NSObject, BastionXPCProtocol, @unchecked Sendable {
    private enum ResolvedUserOperationRequest {
        case direct(UserOperation, UserOperationSubmissionRequest?)
        case intent(UserOperationIntentRequestEnvelope)
    }

    // H-04: Rate limit openUI to prevent UI flood attacks.
    private static let openUIRateLimit = 5
    private static let openUIWindowSeconds: TimeInterval = 10.0
    private static let openUILock = NSLock()
    private static var openUITimestamps: [Date] = []

    private let signingManager: SigningManager
    private let ruleEngine: RuleEngine
    private let clientBundleId: String?

    nonisolated init(signingManager: SigningManager, ruleEngine: RuleEngine, clientBundleId: String?) {
        self.signingManager = signingManager
        self.ruleEngine = ruleEngine
        self.clientBundleId = clientBundleId
        super.init()
    }

    private nonisolated static func bridgedError(_ error: Error) -> NSError {
        if let bastionError = error as? BastionError {
            return bastionError.nsError
        }
        return NSError(
            domain: "com.bastion.error",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: String(describing: error)]
        )
    }

    nonisolated func sign(
        data: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard data.count == 32 else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            do {
                // Legacy: treat raw 32-byte input as rawBytes signing (no EIP-191 prefix).
                let request = SignRequest(
                    operation: .rawBytes(data),
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: self.clientBundleId
                )
                let result = try await signingManager.processSignRequest(request)
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            do {
                let context = ruleEngine.signingContext(for: self.clientBundleId)
                let raw = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
                let result = PublicKeyResponse(
                    x: raw.x,
                    y: raw.y,
                    accountAddress: context.accountAddress ?? raw.accountAddress
                )
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func resetSigningKeys(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            // C-01: Require biometric/passcode authentication before deleting signing keys.
            // Key deletion is irreversible and must not be available without owner confirmation.
            do {
                try await AuthManager.shared.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Authorize deletion of all signing keys"
                )
            } catch {
                reply(nil, BastionError.authFailed.nsError)
                return
            }

            let storedConfig = ruleEngine.loadConfig()
            var keyTags: [String] = [
                SecureEnclaveManager.defaultSigningKeyIdentifier,
                SecureEnclaveManager.legacySigningKeyIdentifier
            ]
            keyTags.append(contentsOf: storedConfig.clientProfiles.map(\.keyTag))
            // Wallet group keys — owner sudo keys + all non-revoked agent
            // validators. Revoked agents already had their SE keys deleted
            // during removeAgentFromGroup.
            keyTags.append(contentsOf: ruleEngine.walletGroupKeyTags())

            let deleted = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: keyTags)
            let result = ResetSigningKeysResponse(
                deletedKeyTags: deleted.sorted(),
                requestedKeyTags: Array(Set(keyTags)).sorted()
            )

            AuditLog.shared.record(AuditEvent(
                type: .keyReset,
                dataPrefix: "reset",
                reason: "Deleted \(deleted.count) of \(keyTags.count) requested keys"
            ))

            do {
                let data = try JSONEncoder().encode(result)
                reply(data, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func ping(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    nonisolated func openUI(
        target: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    ) {
        // H-04: Rate limit openUI calls to prevent UI flood attacks.
        let allowed: Bool = Self.openUILock.withLock {
            let now = Date()
            let cutoff = now.addingTimeInterval(-Self.openUIWindowSeconds)
            Self.openUITimestamps.removeAll { $0 < cutoff }
            if Self.openUITimestamps.count >= Self.openUIRateLimit {
                return false
            }
            Self.openUITimestamps.append(now)
            return true
        }

        guard allowed else {
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "openUI rate limit exceeded — max \(Self.openUIRateLimit) calls per \(Int(Self.openUIWindowSeconds)) seconds"]
            ))
            return
        }

        Task { @MainActor in
            guard let uiTarget = ServiceUITarget(rawValue: target) else {
                reply(false, BastionError.invalidInput.nsError)
                return
            }

            ServiceUIBridge.openInCurrentProcess(uiTarget)
            reply(true, nil)
        }
    }

    nonisolated func getRules(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            let context = ruleEngine.signingContext(for: self.clientBundleId)
            // M-02: Return only the client's effective rules, not the global config.
            // Each client already gets its resolved rules via signingContext.
            let response = RulesResponse(
                authPolicy: context.authPolicy.rawValue,
                globalAuthPolicy: nil,
                rules: context.rules,
                globalRules: nil,
                clientProfile: ruleEngine.clientProfileInfo(bundleId: self.clientBundleId),
                accountAddress: context.accountAddress
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func getServiceInfo(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            let version = Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "unknown"
            let response = ServiceInfoResponse(
                version: version,
                serviceRegistrationStatus: ServiceRegistration.statusDescription(),
                configCorrupted: ruleEngine.configCorrupted
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func getState(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            let effectiveRules = ruleEngine.effectiveRules(for: self.clientBundleId)

            let rateLimits = effectiveRules.rateLimits.map { ruleEngine.stateStore.rateLimitStatus(rule: $0) }
            let spendingLimits = effectiveRules.spendingLimits.map { ruleEngine.stateStore.spendingLimitStatus(rule: $0) }
            let context = ruleEngine.signingContext(for: self.clientBundleId)

            let response = StateResponse(
                rateLimits: rateLimits,
                spendingLimits: spendingLimits,
                clientProfile: ruleEngine.clientProfileInfo(bundleId: self.clientBundleId),
                accountAddress: context.accountAddress
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    @MainActor
    private func resolvedZeroDevProjectId(from explicitProjectId: String?) throws -> String {
        // M-08: App-configured project ID takes priority over client-specified.
        // Prevents agents from redirecting UserOps to attacker-controlled bundlers.
        if let configured = ruleEngine.config.bundlerPreferences.zeroDevProjectId?.trimmingCharacters(in: .whitespacesAndNewlines),
           !configured.isEmpty {
            return configured
        }

        if let explicitProjectId = explicitProjectId?.trimmingCharacters(in: .whitespacesAndNewlines),
           !explicitProjectId.isEmpty {
            return explicitProjectId
        }

        throw NSError(
            domain: "com.bastion.error",
            code: BastionError.invalidInput.rawValue,
            userInfo: [NSLocalizedDescriptionKey: "ZeroDev project ID is not configured in Bastion settings."]
        )
    }

    @MainActor
    private func resolvedSubmissionRequest(_ submission: UserOperationSubmissionRequest?) throws -> UserOperationSubmissionRequest? {
        guard let submission else {
            return nil
        }

        switch submission.provider {
        case .zeroDev:
            return UserOperationSubmissionRequest(
                provider: .zeroDev,
                projectId: try resolvedZeroDevProjectId(from: submission.projectId)
            )
        }
    }

    @MainActor
    private func resolvedEthRPC(chainId: Int, bundler: ZeroDevAPI) -> EthRPC {
        if let endpoint = ruleEngine.config.bundlerPreferences.chainRPCs.first(where: { $0.chainId == chainId }),
           let url = URL(string: endpoint.rpcURL) {
            return EthRPC(rpcURL: url)
        }
        return EthRPC(rpcURL: bundler.rpcURL(chainId: chainId))
    }

    @MainActor
    private func currentClientSmartAccount() throws -> (SmartAccount, ClientSigningContext) {
        let context = ruleEngine.signingContext(for: clientBundleId)
        let publicKey = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
        guard
            let publicKeyX = Data(hexString: publicKey.x),
            let publicKeyY = Data(hexString: publicKey.y)
        else {
            throw BastionError.invalidInput
        }

        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: publicKeyX,
            publicKeyY: publicKeyY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let account = SmartAccount(validator: validator)
        if let accountAddress = context.accountAddress {
            account.setAddress(accountAddress)
        }
        return (account, context)
    }

    private func kernelExecutions(from requestedExecutions: [RequestedExecution]) throws -> [KernelEncoding.Execution] {
        guard !requestedExecutions.isEmpty else {
            throw BastionError.invalidInput
        }

        return try requestedExecutions.map { requested in
            guard KernelEncoding.isValidAddress(requested.target),
                  KernelEncoding.isValidUInt256(requested.value) else {
                throw BastionError.invalidInput
            }
            return KernelEncoding.Execution(
                to: requested.target,
                value: requested.value,
                data: requested.data
            )
        }
    }

    @MainActor
    private func buildUserOperation(from intent: UserOperationIntentRequestEnvelope) async throws -> (UserOperation, UserOperationSubmissionRequest?) {
        let projectId = try resolvedZeroDevProjectId(from: intent.projectId)
        let (account, _) = try currentClientSmartAccount()
        let bundler = ZeroDevAPI(projectId: projectId)
        let rpc = resolvedEthRPC(chainId: intent.chainId, bundler: bundler)
        let executions = try kernelExecutions(from: intent.executions)
        let callData: Data
        if executions.count == 1, let single = executions.first {
            callData = KernelEncoding.executeCalldata(single: single)
        } else {
            callData = KernelEncoding.executeCalldata(batch: executions)
        }

        let op = try await account.buildSponsoredUserOperation(
            callData: callData,
            using: rpc,
            bundler: bundler,
            chainId: intent.chainId
        )
        let submission = intent.submit ? UserOperationSubmissionRequest(projectId: projectId) : nil
        return (op, submission)
    }

    // P0.5: For direct UserOps bound for ZeroDev submission without an existing
    // paymaster, sponsor before the approval prompt. Surfaces bundler rejections
    // early and ensures the user signs a properly gas-estimated operation.
    @MainActor
    private func preflightUserOperation(
        _ op: UserOperation,
        submission: UserOperationSubmissionRequest?
    ) async throws -> UserOperation {
        guard let submission, op.paymaster == nil else { return op }

        let projectId: String
        switch submission.provider {
        case .zeroDev:
            guard let pid = submission.projectId, !pid.isEmpty else { return op }
            projectId = pid
        }

        let bundler = ZeroDevAPI(projectId: projectId)
        let dummySig = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: Data(repeating: 0, count: 32),
            publicKeyY: Data(repeating: 0, count: 32),
            sign: { _ in Data() }
        ).dummySignature
        let dummyRpcOp = UserOperationRPC.from(op, signature: dummySig)
        let sponsored = try await bundler.sponsorUserOperation(
            dummyRpcOp,
            entryPoint: op.entryPoint,
            chainId: op.chainId
        )
        return UserOperation(
            sender: op.sender,
            nonce: op.nonce,
            callData: op.callData,
            factory: op.factory,
            factoryData: op.factoryData,
            verificationGasLimit: sponsored.verificationGasLimit ?? op.verificationGasLimit,
            callGasLimit: sponsored.callGasLimit ?? op.callGasLimit,
            preVerificationGas: sponsored.preVerificationGas ?? op.preVerificationGas,
            maxPriorityFeePerGas: sponsored.maxPriorityFeePerGas ?? op.maxPriorityFeePerGas,
            maxFeePerGas: sponsored.maxFeePerGas ?? op.maxFeePerGas,
            paymaster: sponsored.paymaster,
            paymasterVerificationGasLimit: sponsored.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: sponsored.paymasterPostOpGasLimit,
            paymasterData: sponsored.paymasterData.flatMap { Data(hexString: $0) },
            chainId: op.chainId,
            entryPoint: op.entryPoint,
            entryPointVersion: op.entryPointVersion
        )
    }

    nonisolated func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        let resolvedUserOperationRequest: ResolvedUserOperationRequest?
        let immediateOperation: SigningOperation?
        do {
            let decoder = JSONDecoder()
            switch operationType {
            case "message":
                guard let text = String(data: operationData, encoding: .utf8) else {
                    reply(nil, BastionError.invalidInput.nsError)
                    return
                }
                immediateOperation = .message(text)
                resolvedUserOperationRequest = nil
            case "rawBytes":
                // Expects a hex-encoded 32-byte hash as UTF-8 text (with or without 0x prefix).
                guard let hexString = String(data: operationData, encoding: .utf8),
                      let rawData = Data(hexString: hexString),
                      rawData.count == 32 else {
                    reply(nil, BastionError.invalidInput.nsError)
                    return
                }
                immediateOperation = .rawBytes(rawData)
                resolvedUserOperationRequest = nil
            case "typedData":
                let typed = try decoder.decode(EIP712TypedData.self, from: operationData)
                immediateOperation = .typedData(typed)
                resolvedUserOperationRequest = nil
            case "userOperation":
                if let envelope = try? decoder.decode(UserOperationIntentRequestEnvelope.self, from: operationData) {
                    resolvedUserOperationRequest = .intent(envelope)
                    immediateOperation = nil
                } else if let envelope = try? decoder.decode(UserOperationRequestEnvelope.self, from: operationData) {
                    resolvedUserOperationRequest = .direct(envelope.userOperation, envelope.submission)
                    immediateOperation = nil
                } else {
                    let op = try decoder.decode(UserOperation.self, from: operationData)
                    resolvedUserOperationRequest = .direct(op, nil)
                    immediateOperation = nil
                }
            default:
                reply(nil, BastionError.invalidInput.nsError)
                return
            }
        } catch {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            do {
                let operation: SigningOperation
                let userOperationSubmission: UserOperationSubmissionRequest?
                if let immediateOperation {
                    operation = immediateOperation
                    userOperationSubmission = nil
                } else {
                    guard let resolvedUserOperationRequest else {
                        throw BastionError.invalidInput
                    }
                    switch resolvedUserOperationRequest {
                    case .direct(let userOperation, let submission):
                        let resolvedSub = try self.resolvedSubmissionRequest(submission)
                        let preflightedOp = try await self.preflightUserOperation(userOperation, submission: resolvedSub)
                        operation = .userOperation(preflightedOp)
                        userOperationSubmission = resolvedSub
                    case .intent(let intent):
                        let built = try await self.buildUserOperation(from: intent)
                        operation = .userOperation(built.0)
                        userOperationSubmission = built.1
                    }
                }

                let request = SignRequest(
                    operation: operation,
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: self.clientBundleId,
                    userOperationSubmission: userOperationSubmission
                )
                let result = try await signingManager.processSignRequest(request)
                let jsonData = try JSONEncoder().encode(result)
                reply(jsonData, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    // MARK: - Wallet Group Handlers

    nonisolated func createWalletGroup(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(CreateWalletGroupRequest.self, from: requestData)
                let group = try await self.ruleEngine.createWalletGroup(
                    label: request.label,
                    chainIds: request.chainIds,
                    sharedRules: request.sharedRules ?? .default
                )
                let info = WalletGroupHandlerCodec.info(for: group)
                let data = try JSONEncoder().encode(info)
                reply(data, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func listWalletGroups(
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let groups = self.ruleEngine.listWalletGroups().map(WalletGroupHandlerCodec.info(for:))
                let response = WalletGroupListResponse(groups: groups)
                let data = try JSONEncoder().encode(response)
                reply(data, nil)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func getWalletGroup(
        groupId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            guard let group = self.ruleEngine.walletGroup(id: groupId) else {
                reply(nil, BastionError.invalidInput.nsError)
                return
            }
            do {
                let info = WalletGroupHandlerCodec.info(for: group)
                let data = try JSONEncoder().encode(info)
                reply(data, nil)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func addAgentToGroup(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(AddAgentRequest.self, from: requestData)
                let member = try await self.ruleEngine.addAgentToGroup(
                    groupId: request.groupId,
                    label: request.label,
                    clientProfileId: request.clientProfileId,
                    scopedRules: request.scopedRules ?? .default
                )
                let info = WalletGroupHandlerCodec.info(for: member)
                let data = try JSONEncoder().encode(info)
                reply(data, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func removeAgentFromGroup(
        groupId: String,
        memberId: String,
        txHash: String?,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                try await self.ruleEngine.removeAgentFromGroup(
                    groupId: groupId,
                    memberId: memberId,
                    txHash: txHash
                )
                reply(Data(), nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func updateAgentScope(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(UpdateAgentScopeRequest.self, from: requestData)
                try await self.ruleEngine.updateAgentScope(
                    groupId: request.groupId,
                    memberId: request.memberId,
                    scopedRules: request.scopedRules
                )
                reply(Data(), nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func markAgentInstalled(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(MarkInstalledRequest.self, from: requestData)
                let member = try await self.ruleEngine.markAgentInstalled(
                    groupId: request.groupId,
                    memberId: request.memberId,
                    txHash: request.txHash,
                    validatorAddress: request.validatorAddress
                )
                let info = WalletGroupHandlerCodec.info(for: member)
                let data = try JSONEncoder().encode(info)
                reply(data, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    // MARK: - Phase 2 Handlers

    nonisolated func installAgentOnChain(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(InstallAgentOnChainRequest.self, from: requestData)
                let result = try await self.ruleEngine.installAgentOnChain(
                    groupId: request.groupId,
                    memberId: request.memberId,
                    chainId: request.chainId,
                    projectId: request.projectId,
                    submit: request.submit,
                    waitForReceiptSeconds: request.waitForReceiptSeconds ?? 30
                )
                let info = WalletGroupHandlerCodec.info(for: result)
                let data = try JSONEncoder().encode(info)
                reply(data, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func uninstallAgentOnChain(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(UninstallAgentOnChainRequest.self, from: requestData)
                let result = try await self.ruleEngine.uninstallAgentOnChain(
                    groupId: request.groupId,
                    memberId: request.memberId,
                    chainId: request.chainId,
                    projectId: request.projectId,
                    submit: request.submit,
                    waitForReceiptSeconds: request.waitForReceiptSeconds ?? 30
                )
                let info = WalletGroupHandlerCodec.info(for: result)
                let data = try JSONEncoder().encode(info)
                reply(data, nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    // MARK: - Pairing handshake (XPC entry points)

    nonisolated func startPairing(
        bundleId: String,
        processName: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        // Reject obviously malformed inputs early. The bundleId from a
        // verified XPC client is the real source of truth; this argument
        // exists so the CLI can echo what it thinks it is, allowing the
        // owner to spot a mismatch in the menu bar prompt.
        let bundle = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let process = processName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bundle.isEmpty, bundle.count <= 256, process.count <= 256 else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }
        // Only honor the bundleId we cryptographically verified at connection
        // time. If verification didn't surface a bundleId we fail closed —
        // never trust the wire-supplied value as identity. Mismatch between
        // wire and verified is also a reject signal.
        guard let trustedBundle = self.clientBundleId, !trustedBundle.isEmpty else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }
        if trustedBundle.caseInsensitiveCompare(bundle) != .orderedSame {
            // Surface mismatch as audit (best-effort) and reject. Prevents an
            // agent from spoofing a different identity in the pairing prompt.
            AuditLog.shared.record(AuditEvent(
                type: .ruleViolation,
                dataPrefix: "pair",
                reason: "Pairing rejected — wire bundleId \(bundle) ≠ verified \(trustedBundle)"
            ))
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            let request = PairingBroker.shared.registerIncoming(
                bundleId: trustedBundle,
                processName: process
            )
            let response = PairingHandshakeResponse(
                requestId: request.id.uuidString,
                pairingCode: request.pairingCode,
                expiresAt: request.expiresAt
            )
            do {
                let encoder = JSONEncoder()
                encoder.dateEncodingStrategy = .iso8601
                let data = try encoder.encode(response)
                reply(data, nil)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func pollPairing(
        requestId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard let uuid = UUID(uuidString: requestId) else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }
        Task { @MainActor in
            let outcome = PairingBroker.shared.poll(requestId: uuid)
            let payload: PairingPollResponse
            switch outcome.state {
            case .pending:
                payload = PairingPollResponse(state: .pending, profile: nil, reason: nil)
            case .accepted(let profileId):
                let info = ruleEngine.clientProfileInfo(forId: profileId)
                payload = PairingPollResponse(state: .accepted, profile: info, reason: nil)
            case .rejected:
                payload = PairingPollResponse(state: .rejected, profile: nil, reason: outcome.reason ?? "Owner rejected pairing")
            case .expired:
                payload = PairingPollResponse(state: .expired, profile: nil, reason: outcome.reason ?? "Pairing window elapsed")
            }
            do {
                let encoder = JSONEncoder()
                encoder.dateEncodingStrategy = .iso8601
                let data = try encoder.encode(payload)
                reply(data, nil)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }
}

// MARK: - Wallet Group Codec

/// Converts internal WalletGroup/AgentMembership to the XPC-safe Info types.
/// Centralized so both XPC handlers and tests produce consistent output.
private enum WalletGroupHandlerCodec {
    static func info(for group: WalletGroup) -> WalletGroupInfo {
        let members = group.members.map(info(for:))
        let activeCount = group.members.filter { !$0.installStatus.isRevoked }.count
        return WalletGroupInfo(
            id: group.id,
            label: group.label,
            ownerKeyTag: group.ownerKeyTag,
            accountAddress: group.accountAddress,
            chainIds: group.chainIds,
            sharedRules: group.sharedRules,
            members: members,
            createdAt: iso8601(group.createdAt),
            memberCount: group.members.count,
            activeMemberCount: activeCount
        )
    }

    static func info(for result: RuleEngine.WalletGroupChainResult) -> WalletGroupChainResultInfo {
        WalletGroupChainResultInfo(
            groupId: result.groupId,
            memberId: result.memberId,
            chainId: result.chainId,
            userOp: result.userOpRPC,
            userOpHash: result.userOpHash,
            txHash: result.txHash,
            membership: result.membership.map(info(for:))
        )
    }

    static func info(for member: AgentMembership) -> AgentMembershipInfo {
        AgentMembershipInfo(
            id: member.id,
            label: member.label,
            keyTag: member.keyTag,
            clientProfileId: member.clientProfileId,
            scopedRules: member.scopedRules,
            validatorAddress: member.validatorAddress,
            installStatus: member.installStatus,
            installedAt: member.installedAt.map(iso8601),
            revokedAt: member.revokedAt.map(iso8601)
        )
    }

    private static func iso8601(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}

import Foundation
import Darwin

final class XPCServer: NSObject, NSXPCListenerDelegate {
    static let shared = XPCServer()
    nonisolated static let missingClientProfileReadMessage =
        "Pair this client with Bastion before reading pubkey, rules, or state."
    nonisolated static let trustedAgentBridgeBundleId = "com.bastion.mcp"

    nonisolated static func normalizedPairingDisplayInputs(
        bundleId: String,
        processName: String
    ) -> (bundleId: String, processName: String)? {
        let bundle = bundleId.trimmingCharacters(in: .whitespacesAndNewlines)
        let process = processName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !bundle.isEmpty, !process.isEmpty, bundle.count <= 256, process.count <= 256 else {
            return nil
        }
        return (bundle, process)
    }

    private var listener: NSXPCListener?
    private let ruleEngine = RuleEngine.shared

    /// PR4: Active connections keyed by their verified client bundle id
    /// (or nil for unidentified clients — typically the unsigned dev CLI).
    /// Tracking lets us cut connections from agents that the owner just
    /// removed from the allowlist; otherwise an in-flight XPC connection
    /// could keep submitting requests until the agent process restarts.
    /// Mutated only under `connectionsLock`. Marked `nonisolated` because
    /// the listener delegate callback fires from the XPC queue and
    /// reconcile may be called from any actor.
    private nonisolated let connectionsLock = NSLock()
    private nonisolated(unsafe) var activeConnections: [(connection: NSXPCConnection, bundleId: String?)] = []

    private override init() {
        super.init()
    }

    func start() {
        listener = NSXPCListener(machServiceName: xpcServiceName)
        listener?.delegate = self
        listener?.resume()
        DiagnosticLog.shared.record(
            category: .lifecycle,
            event: "xpc_listener_started",
            message: "XPC listener started",
            context: ["machServiceName": xpcServiceName]
        )
    }

    func stop() {
        listener?.invalidate()
        listener = nil
        DiagnosticLog.shared.record(
            category: .lifecycle,
            event: "xpc_listener_stopped",
            message: "XPC listener stopped",
            context: ["machServiceName": xpcServiceName]
        )
    }

    // MARK: - NSXPCListenerDelegate

    nonisolated func listener(
        _ listener: NSXPCListener,
        shouldAcceptNewConnection newConnection: NSXPCConnection
    ) -> Bool {
        // AC-02 (audit 2026-06-taek): resolve ONE code identity from the peer's
        // audit token (which carries pid + p_idversion) rather than its bare
        // PID, and drive validity / team / identifier / executable-path all
        // from that single SecCode. A bare-PID lookup is vulnerable to the
        // PID-reuse race (CVE-2020-14977 class) and used three independent,
        // non-atomic kernel lookups that could disagree.
        guard let identity = resolveClientIdentity(connection: newConnection),
              Self.isClientSigningInfoAllowed(
                identity.signingInfo,
                validityStatus: identity.validityStatus,
                executablePath: identity.executablePath,
                allowUntrustedDevSignature: Self.shouldAllowUntrustedDevSignature(identity.validityStatus)
              ) else {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .xpc,
                event: "connection_rejected_signature",
                message: "Rejected XPC connection because code-signature verification failed",
                context: ["pid": String(newConnection.processIdentifier)]
            )
            return false
        }

        let clientBundleId = Self.bundleIdentifier(from: identity.signingInfo)
        let clientExecutablePath = identity.executablePath
        let isTrustedAgentBridge = Self.isTrustedAgentBridgeClient(
            bundleId: clientBundleId,
            executablePath: clientExecutablePath
        )
        if !isTrustedAgentBridge,
           let denial = ruleEngine.globalClientAllowlistDenial(bundleId: clientBundleId) {
            NSLog("[XPCServer] Rejecting connection from %@: %@", clientBundleId ?? "<unknown>", denial)
            DiagnosticLog.shared.record(
                level: .warning,
                category: .xpc,
                event: "connection_rejected_allowlist",
                message: denial,
                context: [
                    "pid": String(newConnection.processIdentifier),
                    "bundleId": clientBundleId ?? "<unknown>"
                ]
            )
            return false
        }

        newConnection.exportedInterface = NSXPCInterface(with: BastionXPCProtocol.self)
        newConnection.exportedObject = XPCHandler(
            ruleEngine: ruleEngine,
            clientBundleId: clientBundleId,
            isTrustedAgentBridge: isTrustedAgentBridge,
            activeConnectionCountProvider: { [weak self] in
                self?.activeConnectionCount() ?? 0
            }
        )
        registerConnection(newConnection, bundleId: clientBundleId)
        DiagnosticLog.shared.record(
            category: .xpc,
            event: "connection_accepted",
            message: "Accepted XPC connection",
            context: [
                "pid": String(newConnection.processIdentifier),
                "bundleId": clientBundleId ?? "<unknown>"
            ]
        )
        newConnection.invalidationHandler = { [weak self, weak newConnection] in
            guard let self, let conn = newConnection else { return }
            self.unregisterConnection(conn)
            DiagnosticLog.shared.record(
                category: .xpc,
                event: "connection_invalidated",
                message: "XPC connection invalidated",
                context: ["bundleId": clientBundleId ?? "<unknown>"]
            )
        }
        newConnection.resume()
        return true
    }

    // MARK: - Connection registry

    private nonisolated func registerConnection(_ connection: NSXPCConnection, bundleId: String?) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }
        activeConnections.append((connection, bundleId))
    }

    private nonisolated func unregisterConnection(_ connection: NSXPCConnection) {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }
        activeConnections.removeAll { $0.connection === connection }
    }

    /// PR4: Drop every active connection whose bundle id is no longer
    /// authorized by the supplied rules. Returns the bundle ids that
    /// were cut so the caller can audit.
    @discardableResult
    nonisolated func reconcileConnections(against rules: RuleConfig) -> [String] {
        guard let allowed = rules.allowedClients else { return [] }
        let allowedSet = Set(allowed.map { $0.bundleId.lowercased() })
        connectionsLock.lock()
        let toCut = activeConnections.filter { entry in
            guard !allowedSet.isEmpty else { return true }
            guard let bundle = entry.bundleId else { return true }
            return !allowedSet.contains(bundle.lowercased())
        }
        connectionsLock.unlock()
        for entry in toCut {
            entry.connection.invalidate()
        }
        return toCut.compactMap { $0.bundleId }
    }

    /// PR4: Drop every active connection. Used by emergency lockdown,
    /// where the owner wants to stop signing immediately regardless of
    /// rule contents.
    nonisolated func invalidateAllConnections() {
        connectionsLock.lock()
        let snapshot = activeConnections
        activeConnections.removeAll()
        connectionsLock.unlock()
        for entry in snapshot {
            entry.connection.invalidate()
        }
    }

    /// Test/diagnostic accessor: count of currently registered connections.
    nonisolated func activeConnectionCount() -> Int {
        connectionsLock.lock()
        defer { connectionsLock.unlock() }
        return activeConnections.count
    }

    // MARK: - Client Identification

    /// `auditToken` is a long-standing NSXPCConnection property exposing the
    /// peer's kernel audit token. It is not in the public headers, so we reach
    /// it through a matching `@objc` protocol — the selector and struct-return
    /// ABI line up with the real implementation. The audit token (unlike the
    /// bare PID) embeds `p_idversion`, defeating PID-reuse impersonation.
    @objc private protocol XPCConnectionAuditToken {
        var auditToken: audit_token_t { get }
    }

    /// One resolved code identity for a connecting client, derived from a single
    /// `SecCode` so all downstream checks agree.
    private struct ResolvedClientIdentity {
        let validityStatus: OSStatus
        let signingInfo: [String: Any]
        let executablePath: String?
    }

    private nonisolated func auditToken(of connection: NSXPCConnection) -> audit_token_t? {
        let accessor = unsafeBitCast(connection, to: XPCConnectionAuditToken.self)
        return accessor.auditToken
    }

    /// Build a `SecCode` for the peer from its audit token and extract validity,
    /// signing info, and the main executable path in one shot.
    private nonisolated func resolveClientIdentity(connection: NSXPCConnection) -> ResolvedClientIdentity? {
        guard var token = auditToken(of: connection) else { return nil }
        let tokenData = Data(bytes: &token, count: MemoryLayout<audit_token_t>.size)
        var code: SecCode?
        let attrs = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return nil
        }

        let validityStatus = SecCodeCheckValidity(secCode, [], nil)

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
              let sCode = staticCode else {
            return nil
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(
            sCode,
            SecCSFlags(rawValue: kSecCSSigningInformation),
            &info
        ) == errSecSuccess,
              let signingInfo = info as? [String: Any] else {
            return nil
        }

        // The main executable URL is bound to the same verified code object —
        // no separate proc_pidpath(pid) call (which would re-introduce the PID
        // race for the bridge/sidecar bundled-path check).
        let executablePath: String?
        if let url = signingInfo[kSecCodeInfoMainExecutable as String] as? URL {
            executablePath = url.path
        } else if let path = signingInfo[kSecCodeInfoMainExecutable as String] as? String {
            executablePath = path
        } else {
            var pathURL: CFURL?
            executablePath = SecCodeCopyPath(sCode, [], &pathURL) == errSecSuccess
                ? (pathURL as URL?)?.path
                : nil
        }

        return ResolvedClientIdentity(
            validityStatus: validityStatus,
            signingInfo: signingInfo,
            executablePath: executablePath
        )
    }

    // MARK: - Code Signing Verification

    /// Team ID that signed Bastion.app — only clients signed by the same team are accepted.
    private nonisolated static let requiredTeamID = "926A27BQ7W"
    private nonisolated static let untrustedDevSignatureStatus = OSStatus(CSSMERR_TP_NOT_TRUSTED)

    nonisolated static func shouldAllowUntrustedDevSignature(_ validityStatus: OSStatus) -> Bool {
#if DEBUG
        return validityStatus == untrustedDevSignatureStatus
#else
        return false
#endif
    }

    nonisolated static func bundleIdentifier(from signingInfo: [String: Any]) -> String? {
        if let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String {
            return identifier
        }
        if let plist = signingInfo[kSecCodeInfoPList as String] as? [String: Any],
           let bundleId = plist["CFBundleIdentifier"] as? String {
            return bundleId
        }
        return nil
    }

    nonisolated static func isAllowedTeamIdentifier(_ teamID: String?) -> Bool {
        teamID == Self.requiredTeamID
    }

    nonisolated static func isTrustedAgentBridgeBundleId(_ bundleId: String?) -> Bool {
        guard let bundleId else { return false }
        return bundleId.caseInsensitiveCompare(Self.trustedAgentBridgeBundleId) == .orderedSame
    }

    nonisolated static func isTrustedAgentBridgeClient(
        bundleId: String?,
        executablePath: String?,
        hostBundleURL: URL = Bundle.main.bundleURL
    ) -> Bool {
        guard isTrustedAgentBridgeBundleId(bundleId),
              let executablePath else {
            return false
        }
        let expectedPath = hostBundleURL
            .appendingPathComponent("Contents/MacOS/bastion-mcp")
            .standardizedFileURL
            .path
        return URL(fileURLWithPath: executablePath).standardizedFileURL.path == expectedPath
    }

    nonisolated static func isClientSigningInfoAllowed(
        _ signingInfo: [String: Any],
        validityStatus: OSStatus,
        executablePath: String?,
        allowUntrustedDevSignature: Bool,
        hostBundleURL: URL = Bundle.main.bundleURL
    ) -> Bool {
        let validityAllowed = validityStatus == errSecSuccess
            || (allowUntrustedDevSignature && validityStatus == Self.untrustedDevSignatureStatus)
        guard validityAllowed else {
            return false
        }

        if Self.isAllowedTeamIdentifier(signingInfo[kSecCodeInfoTeamIdentifier as String] as? String) {
            return true
        }

        if signingInfo[kSecCodeInfoTeamIdentifier as String] != nil {
            return false
        }

        guard allowUntrustedDevSignature,
              let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String else {
            return false
        }
        return Self.isAllowedDebugSidecar(
            identifier: identifier,
            executablePath: executablePath,
            hostBundleURL: hostBundleURL
        )
    }

    // L-04: Require both identifier match AND path check. The previous
    // fallback accepted any binary at the CLI path regardless of identity.
    // The code signing identifier for a fat/single-arch CLI tool may be reported
    // with an architecture suffix (e.g. "bastion-cli-arm64") or without one
    // ("bastion-cli"), depending on how the binary was built and signed.
    nonisolated static func isAllowedDebugSidecar(
        identifier: String,
        executablePath: String?,
        hostBundleURL: URL = Bundle.main.bundleURL
    ) -> Bool {
        guard identifier == "bastion-cli" || identifier.hasPrefix("bastion-cli-") else {
            return false
        }
        guard let executablePath,
              let bundledCLI = CLIInstaller.bundledCLIExecutableURL(for: hostBundleURL) else {
            return false
        }
        return URL(fileURLWithPath: executablePath).standardizedFileURL.path
            == bundledCLI.standardizedFileURL.path
    }
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
    private static let notificationProbeIDPattern = #"^[A-Za-z0-9_.-]{1,80}$"#
    private static let notificationProbeRateLimit = 6
    private static let notificationProbeWindowSeconds: TimeInterval = 60.0
    private static let notificationProbeLock = NSLock()
    private static var notificationProbeTimestamps: [Date] = []
    private static let maxMessageBytes = 64 * 1024
    private static let maxRawBytesPayload = 256
    private static let maxStructuredOperationBytes = 512 * 1024
    private static let maxIntentActions = 16
    private static let maxIntentCalldataBytes = 256 * 1024

    private let ruleEngine: RuleEngine
    private let clientBundleId: String?
    private let isTrustedAgentBridge: Bool
    private let activeConnectionCountProvider: () -> Int

    private struct UserOperationNotificationProbePayload {
        let title: String
        let subtitle: String
        let body: String
        let identifier: String
        let userInfo: [String: String]
    }

    nonisolated init(
        ruleEngine: RuleEngine,
        clientBundleId: String?,
        isTrustedAgentBridge: Bool = false,
        activeConnectionCountProvider: @escaping () -> Int
    ) {
        self.ruleEngine = ruleEngine
        self.clientBundleId = clientBundleId
        self.isTrustedAgentBridge = isTrustedAgentBridge
        self.activeConnectionCountProvider = activeConnectionCountProvider
        super.init()
    }

    private nonisolated static func isValidNotificationProbeID(_ probeID: String) -> Bool {
        probeID.range(
            of: notificationProbeIDPattern,
            options: .regularExpression
        ) != nil
    }

    private nonisolated static func userOperationNotificationProbePayload(
        probeID: String
    ) -> UserOperationNotificationProbePayload {
        let transactionHash = "0x" + String(repeating: "7", count: 64)
        let userOpHash = "0x" + String(repeating: "8", count: 64)
        let requestID = "runtime-userop-\(probeID)"
        let request = SignRequest(
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
            timestamp: Date(),
            clientBundleId: "com.bastion.runtime-probe",
            userOperationSubmission: UserOperationSubmissionRequest(
                provider: .zeroDev,
                projectId: "runtime-probe"
            )
        )
        let clientContext = ClientSigningContext(
            bundleId: "com.bastion.runtime-probe",
            profileId: "runtime-probe",
            profileLabel: "Runtime UserOp Probe",
            authPolicy: .open,
            keyTag: "com.bastion.signingkey.client.runtime-probe",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
        return UserOperationNotificationProbePayload(
            title: request.executionMode.confirmedNotificationTitle,
            subtitle: clientContext.displayName,
            body: "Confirmed in transaction \(transactionHash)",
            identifier: SigningManager.notificationIdentifier(
                requestID: request.requestID,
                stage: "confirmed"
            ),
            userInfo: SigningManager.notificationUserInfo(
                request: request,
                clientContext: clientContext,
                stage: "confirmed",
                provider: UserOperationSubmissionProvider.zeroDev.displayName,
                userOpHash: userOpHash,
                transactionHash: transactionHash
            )
        )
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

    @MainActor
    private func enforceGlobalClientAllowlist(bundleId: String? = nil) throws {
        let effectiveBundleId = bundleId ?? clientBundleId
        if let denial = ruleEngine.globalClientAllowlistDenial(bundleId: effectiveBundleId) {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: denial]
            )
        }
    }

    @MainActor
    private func existingClientContext(bundleId: String? = nil) throws -> ClientSigningContext {
        let effectiveBundleId = bundleId ?? clientBundleId
        try enforceGlobalClientAllowlist(bundleId: effectiveBundleId)
        guard let bundleId = effectiveBundleId,
              ruleEngine.clientProfile(bundleId: bundleId) != nil else {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: XPCServer.missingClientProfileReadMessage]
            )
        }
        return ruleEngine.signingContext(for: bundleId, createProfile: false)
    }

    @MainActor
    private func enforceSigningPreflightAllowed(bundleId: String? = nil) throws {
        let effectiveBundleId = bundleId ?? clientBundleId
        try enforceGlobalClientAllowlist(bundleId: effectiveBundleId)
        if let denial = ruleEngine.signingBlockedReason(for: effectiveBundleId) {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: denial]
            )
        }
        let pauseState = ruleEngine.config.pauseState
        if pauseState.lockedDown {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: pauseState.reason ?? "Bastion is locked down"]
            )
        }
        if pauseState.paused {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: pauseState.reason ?? "Bastion is paused"]
            )
        }
    }

    @MainActor
    private func enforceStaticSigningPolicy(operation: SigningOperation, bundleId: String? = nil) throws {
        let effectiveBundleId = bundleId ?? clientBundleId
        try enforceSigningPreflightAllowed(bundleId: effectiveBundleId)
        let context = try existingClientContext(bundleId: effectiveBundleId)
        if case .userOperation(let op) = operation,
           let expected = context.accountAddress,
           op.sender.lowercased() != expected.lowercased() {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "UserOperation sender does not match client account"]
            )
        }

        var effectiveConfig = ruleEngine.config
        effectiveConfig.authPolicy = context.authPolicy
        effectiveConfig.rules = context.rules
        let request = SignRequest(
            operation: operation,
            requestID: UUID().uuidString,
            timestamp: Date(),
            clientBundleId: effectiveBundleId
        )
        switch ruleEngine.validate(request, config: effectiveConfig) {
        case .allowed:
            return
        case .blocked(let reasons), .denied(let reasons):
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: reasons.joined(separator: "; ")]
            )
        }
    }

    private nonisolated func maxPayloadBytes(for operationType: String) -> Int? {
        switch operationType {
        case "message":
            return Self.maxMessageBytes
        case "rawBytes":
            return Self.maxRawBytesPayload
        case "typedData", "userOperation":
            return Self.maxStructuredOperationBytes
        default:
            return nil
        }
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
                try self.enforceSigningPreflightAllowed()
                // Legacy: treat raw 32-byte input as rawBytes signing (no EIP-191 prefix).
                let request = SignRequest(
                    operation: .rawBytes(data),
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: self.clientBundleId
                )
                let result = try await SigningManager.shared.processSignRequest(request)
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
                let context = try self.existingClientContext()
                let raw: PublicKeyResponse
                #if DEBUG
                if let qaRaw = try RuntimeQASigningProvider.shared.publicKeyIfEnabled(keyTag: context.keyTag) {
                    raw = qaRaw
                } else {
                    raw = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
                }
                #else
                raw = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
                #endif
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
            let keyTags = SigningKeyLifecyclePlan.resetRequestedKeyTags(
                config: storedConfig,
                walletGroupKeyTags: ruleEngine.walletGroupKeyTags()
            )
            let deleted = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: keyTags)
            let result = ResetSigningKeysResponse(
                deletedKeyTags: deleted.sorted(),
                requestedKeyTags: keyTags
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

    nonisolated func rotateClientKey(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            let request: RotateClientKeyRequest
            do {
                request = try JSONDecoder().decode(RotateClientKeyRequest.self, from: requestData)
            } catch {
                reply(nil, error)
                return
            }

            do {
                try await AuthManager.shared.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Authorize rotation of this client's signing key"
                )
            } catch {
                reply(nil, BastionError.authFailed.nsError)
                return
            }

            let replacementKeyTag = ClientProfile.makeKeyTag()
            do {
                _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey(keyTag: replacementKeyTag)
                let replacementPublicKey = try SecureEnclaveManager.shared.getPublicKey(keyTag: replacementKeyTag)
                let result = try ruleEngine.rotatePrivateClientKey(
                    profileId: request.profileId,
                    replacementKeyTag: replacementKeyTag,
                    replacementAccountAddress: replacementPublicKey.accountAddress
                )

                AuditLog.shared.record(AuditEvent(
                    type: .keyRotated,
                    dataPrefix: "key.rotate.\(request.profileId.prefix(8))",
                    reason: "Rotated private-client key from \(result.oldKeyTag) to \(result.newKeyTag)"
                ))

                let data = try JSONEncoder().encode(result)
                reply(data, nil)
            } catch {
                _ = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: [replacementKeyTag])
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
            DiagnosticLog.shared.record(
                level: .warning,
                category: .xpc,
                event: "open_ui_rate_limited",
                message: "openUI request exceeded rate limit",
                context: [
                    "target": target,
                    "bundleId": clientBundleId ?? "<unknown>"
                ]
            )
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "openUI rate limit exceeded — max \(Self.openUIRateLimit) calls per \(Int(Self.openUIWindowSeconds)) seconds"]
            ))
            return
        }

        Task { @MainActor in
            guard let uiTarget = ServiceUITarget(rawValue: target),
                  uiTarget.isOpenRequestAllowed else {
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .xpc,
                    event: "open_ui_invalid_target",
                    message: "openUI request used an invalid target",
                    context: [
                        "target": target,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(false, BastionError.invalidInput.nsError)
                return
            }

            ServiceUIBridge.openInCurrentProcess(uiTarget)
            DiagnosticLog.shared.record(
                category: .xpc,
                event: "open_ui_succeeded",
                message: "Opened UI target in service process",
                context: [
                    "target": uiTarget.rawValue,
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(true, nil)
        }
    }

    nonisolated func probeUI(
        target: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
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
            DiagnosticLog.shared.record(
                level: .warning,
                category: .xpc,
                event: "ui_probe_rate_limited",
                message: "UI probe request exceeded openUI rate limit",
                context: [
                    "target": target,
                    "bundleId": clientBundleId ?? "<unknown>"
                ]
            )
            reply(nil, NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "UI probe rate limit exceeded — max \(Self.openUIRateLimit) calls per \(Int(Self.openUIWindowSeconds)) seconds"]
            ))
            return
        }

        Task { @MainActor in
            guard let uiTarget = ServiceUITarget(rawValue: target) else {
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .xpc,
                    event: "ui_probe_invalid_target",
                    message: "UI probe request used an invalid target",
                    context: [
                        "target": target,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, BastionError.invalidInput.nsError)
                return
            }

            let response = await ServiceUIBridge.probeInCurrentProcess(uiTarget)
            do {
                let data = try JSONEncoder().encode(response)
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "ui_probe_succeeded",
                    message: "Probed UI target in service process",
                    context: [
                        "target": response.target,
                        "opened": String(response.opened),
                        "matchedWindowTitle": response.matchedWindowTitle ?? "<none>",
                        "windowCount": String(response.windows.count),
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "ui_probe_encode_failed",
                    message: "Failed to encode UI probe response",
                    context: [
                        "target": target,
                        "error": error.localizedDescription,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func probeSettingsScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let response = try await SettingsScenarioProbe.run(scenario: scenario)
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "settings_scenario_probe_succeeded",
                    message: "Probed Settings presentation scenario in service process",
                    context: [
                        "scenario": response.scenario,
                        "passed": String(response.passed),
                        "details": response.diagnosticContext
                            .map { "\($0.key)=\($0.value)" }
                            .sorted()
                            .joined(separator: ","),
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(response.data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "settings_scenario_probe_failed",
                    message: "Failed to probe Settings presentation scenario",
                    context: [
                        "scenario": scenario,
                        "error": error.localizedDescription,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func probeMenuScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        do {
            let response = try MenuBarScenarioProbe.run(scenario: scenario)
            DiagnosticLog.shared.record(
                category: .xpc,
                event: "menu_scenario_probe_succeeded",
                message: "Probed menu-bar presentation scenario in service process",
                context: [
                    "scenario": response.scenario,
                    "passed": String(response.passed),
                    "details": response.diagnosticContext
                        .map { "\($0.key)=\($0.value)" }
                        .sorted()
                        .joined(separator: ","),
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(response.data, nil)
        } catch {
            DiagnosticLog.shared.record(
                level: .error,
                category: .xpc,
                event: "menu_scenario_probe_failed",
                message: "Failed to probe menu-bar presentation scenario",
                context: [
                    "scenario": scenario,
                    "error": error.localizedDescription,
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(nil, error)
        }
    }

    nonisolated func probeWalletGroupScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        do {
            let response = try WalletGroupScenarioProbe.run(scenario: scenario)
            DiagnosticLog.shared.record(
                category: .xpc,
                event: "wallet_group_scenario_probe_succeeded",
                message: "Probed wallet-group presentation scenario in service process",
                context: [
                    "scenario": response.scenario,
                    "passed": String(response.passed),
                    "details": response.diagnosticContext
                        .map { "\($0.key)=\($0.value)" }
                        .sorted()
                        .joined(separator: ","),
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(response.data, nil)
        } catch {
            DiagnosticLog.shared.record(
                level: .error,
                category: .xpc,
                event: "wallet_group_scenario_probe_failed",
                message: "Failed to probe wallet-group presentation scenario",
                context: [
                    "scenario": scenario,
                    "error": error.localizedDescription,
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(nil, error)
        }
    }

    nonisolated func probeAuditHistoryScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        do {
            let response = try AuditHistoryScenarioProbe.run(scenario: scenario)
            DiagnosticLog.shared.record(
                category: .xpc,
                event: "audit_history_scenario_probe_succeeded",
                message: "Probed audit-history presentation scenario in service process",
                context: [
                    "scenario": response.scenario,
                    "passed": String(response.passed),
                    "details": response.diagnosticContext
                        .map { "\($0.key)=\($0.value)" }
                        .sorted()
                        .joined(separator: ","),
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(response.data, nil)
        } catch {
            DiagnosticLog.shared.record(
                level: .error,
                category: .xpc,
                event: "audit_history_scenario_probe_failed",
                message: "Failed to probe audit-history presentation scenario",
                context: [
                    "scenario": scenario,
                    "error": error.localizedDescription,
                    "bundleId": self.clientBundleId ?? "<unknown>"
                ]
            )
            reply(nil, error)
        }
    }

    nonisolated func probeRuntimeStateScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let response = try await RuntimeStateScenarioProbe.run(scenario: scenario)
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "runtime_state_scenario_probe_succeeded",
                    message: "Probed runtime-state scenario in service process",
                    context: [
                        "scenario": response.scenario,
                        "passed": String(response.passed),
                        "details": response.diagnosticContext
                            .map { "\($0.key)=\($0.value)" }
                            .sorted()
                            .joined(separator: ","),
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(response.data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "runtime_state_scenario_probe_failed",
                    message: "Failed to probe runtime-state scenario",
                    context: [
                        "scenario": scenario,
                        "error": error.localizedDescription,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func probeUpdateScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task {
            do {
                let response = try await UpdateScenarioProbe.run(scenario: scenario)
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "update_scenario_probe_succeeded",
                    message: "Probed update scenario in service process",
                    context: [
                        "scenario": response.scenario,
                        "passed": String(response.passed),
                        "details": response.diagnosticContext
                            .map { "\($0.key)=\($0.value)" }
                            .sorted()
                            .joined(separator: ","),
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(response.data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "update_scenario_probe_failed",
                    message: "Failed to probe update scenario",
                    context: [
                        "scenario": scenario,
                        "error": error.localizedDescription,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func probeKeyLifecycleScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task {
            do {
                let response = try await KeyLifecycleScenarioProbe.run(scenario: scenario)
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "key_lifecycle_scenario_probe_succeeded",
                    message: "Probed key lifecycle scenario in service process",
                    context: [
                        "scenario": response.scenario,
                        "passed": String(response.passed),
                        "details": response.diagnosticContext
                            .map { "\($0.key)=\($0.value)" }
                            .sorted()
                            .joined(separator: ","),
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(response.data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "key_lifecycle_scenario_probe_failed",
                    message: "Failed to probe key lifecycle scenario",
                    context: [
                        "scenario": scenario,
                        "error": error.localizedDescription,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func probeLiveRuntimeScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let response = try await LiveRuntimeScenarioProbe.run(
                    scenario: scenario,
                    activeConnectionCount: self.activeConnectionCountProvider(),
                    clientBundleId: self.clientBundleId
                )
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "live_runtime_scenario_probe_succeeded",
                    message: "Probed live runtime scenario in service process",
                    context: [
                        "scenario": response.scenario,
                        "passed": String(response.passed),
                        "details": response.diagnosticContext
                            .map { "\($0.key)=\($0.value)" }
                            .sorted()
                            .joined(separator: ","),
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(response.data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "live_runtime_scenario_probe_failed",
                    message: "Failed to probe live runtime scenario",
                    context: [
                        "scenario": scenario,
                        "error": error.localizedDescription,
                        "bundleId": self.clientBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func deliverNotificationProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    ) {
        guard Self.isValidNotificationProbeID(probeID) else {
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.invalidInput.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Notification probe ID must be 1-80 characters: letters, numbers, dot, underscore, or dash"]
            ))
            return
        }

        let allowed: Bool = Self.notificationProbeLock.withLock {
            let now = Date()
            let cutoff = now.addingTimeInterval(-Self.notificationProbeWindowSeconds)
            Self.notificationProbeTimestamps.removeAll { $0 < cutoff }
            if Self.notificationProbeTimestamps.count >= Self.notificationProbeRateLimit {
                return false
            }
            Self.notificationProbeTimestamps.append(now)
            return true
        }

        guard allowed else {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .notification,
                event: "notification_probe_rate_limited",
                message: "Lifecycle notification probe request exceeded rate limit",
                context: [
                    "bastionProbeID": probeID,
                    "bundleId": clientBundleId ?? "<unknown>"
                ]
            )
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Notification probe rate limit exceeded — max \(Self.notificationProbeRateLimit) calls per \(Int(Self.notificationProbeWindowSeconds)) seconds"]
            ))
            return
        }

        let identifier = "bastion.lifecycle.\(probeID)"
        DiagnosticLog.shared.record(
            category: .notification,
            event: "notification_probe_requested",
            message: "Lifecycle notification probe requested",
            context: [
                "bastionProbeID": probeID,
                "notificationIdentifier": identifier,
                "bundleId": clientBundleId ?? "<unknown>"
            ]
        )
        BastionNotificationManager.shared.notify(
            title: "Bastion lifecycle probe",
            subtitle: "Click to verify routing",
            body: "Open Audit History through the registered service.",
            identifier: identifier,
            userInfo: [
                "bastionProbeID": probeID,
                "bastionProbe": "lifecycle"
            ]
        )
        reply(true, nil)
    }

    nonisolated func triggerNotificationClickProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    ) {
        guard Self.isValidNotificationProbeID(probeID) else {
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.invalidInput.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Notification probe ID must be 1-80 characters: letters, numbers, dot, underscore, or dash"]
            ))
            return
        }

        let identifier = "bastion.lifecycle.\(probeID)"
        DiagnosticLog.shared.record(
            category: .notification,
            event: "notification_click_probe_requested",
            message: "Lifecycle notification click probe requested",
            context: [
                "bastionProbeID": probeID,
                "notificationIdentifier": identifier,
                "bundleId": clientBundleId ?? "<unknown>"
            ]
        )

        Task {
            let opened = await NotificationClickHandler.handle(
                title: "Bastion lifecycle probe",
                identifier: identifier,
                userInfo: [
                    "bastionProbeID": probeID,
                    "bastionProbe": "lifecycle"
                ],
                actionIdentifier: NotificationClickHandler.defaultActionIdentifier,
                isServiceProcess: CLIInstaller.isRunningAsLaunchAgentService
            )
            reply(opened, nil)
        }
    }

    nonisolated func deliverUserOperationNotificationProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    ) {
        guard Self.isValidNotificationProbeID(probeID) else {
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.invalidInput.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Notification probe ID must be 1-80 characters: letters, numbers, dot, underscore, or dash"]
            ))
            return
        }

        let allowed: Bool = Self.notificationProbeLock.withLock {
            let now = Date()
            let cutoff = now.addingTimeInterval(-Self.notificationProbeWindowSeconds)
            Self.notificationProbeTimestamps.removeAll { $0 < cutoff }
            if Self.notificationProbeTimestamps.count >= Self.notificationProbeRateLimit {
                return false
            }
            Self.notificationProbeTimestamps.append(now)
            return true
        }

        guard allowed else {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .notification,
                event: "userop_notification_probe_rate_limited",
                message: "UserOperation notification probe request exceeded rate limit",
                context: [
                    "bastionProbeID": probeID,
                    "bundleId": clientBundleId ?? "<unknown>"
                ]
            )
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Notification probe rate limit exceeded — max \(Self.notificationProbeRateLimit) calls per \(Int(Self.notificationProbeWindowSeconds)) seconds"]
            ))
            return
        }

        let payload = Self.userOperationNotificationProbePayload(probeID: probeID)
        DiagnosticLog.shared.record(
            category: .notification,
            event: "userop_notification_probe_requested",
            message: "UserOperation result notification probe requested",
            context: [
                "bastionProbeID": probeID,
                "notificationIdentifier": payload.identifier,
                "requestID": payload.userInfo["requestID"] ?? "",
                "stage": payload.userInfo["stage"] ?? "",
                "provider": payload.userInfo["provider"] ?? "",
                "userOpHash": payload.userInfo["userOpHash"] ?? "",
                "bundleId": clientBundleId ?? "<unknown>"
            ]
        )
        BastionNotificationManager.shared.notify(
            title: payload.title,
            subtitle: payload.subtitle,
            body: payload.body,
            identifier: payload.identifier,
            userInfo: payload.userInfo
        )
        reply(true, nil)
    }

    nonisolated func triggerUserOperationNotificationClickProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    ) {
        guard Self.isValidNotificationProbeID(probeID) else {
            reply(false, NSError(
                domain: "com.bastion.error",
                code: BastionError.invalidInput.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Notification probe ID must be 1-80 characters: letters, numbers, dot, underscore, or dash"]
            ))
            return
        }

        let payload = Self.userOperationNotificationProbePayload(probeID: probeID)
        DiagnosticLog.shared.record(
            category: .notification,
            event: "userop_notification_click_probe_requested",
            message: "UserOperation result notification click probe requested",
            context: [
                "bastionProbeID": probeID,
                "notificationIdentifier": payload.identifier,
                "requestID": payload.userInfo["requestID"] ?? "",
                "stage": payload.userInfo["stage"] ?? "",
                "provider": payload.userInfo["provider"] ?? "",
                "userOpHash": payload.userInfo["userOpHash"] ?? "",
                "bundleId": clientBundleId ?? "<unknown>"
            ]
        )

        Task {
            let opened = await NotificationClickHandler.handle(
                title: payload.title,
                identifier: payload.identifier,
                userInfo: payload.userInfo,
                actionIdentifier: NotificationClickHandler.defaultActionIdentifier,
                isServiceProcess: CLIInstaller.isRunningAsLaunchAgentService
            )
            reply(opened, nil)
        }
    }

    nonisolated func getRules(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            do {
                let context = try self.existingClientContext()
                // M-02: Return only the client's effective rules, not the global config.
                // Each client already gets its resolved rules via signingContext.
                let response = RulesResponse(
                    authPolicy: context.authPolicy.rawValue,
                    globalAuthPolicy: nil,
                    rules: context.rules,
                    globalRules: nil,
                    clientProfile: ruleEngine.clientProfileInfo(bundleId: self.clientBundleId, createProfile: false),
                    accountAddress: context.accountAddress
                )
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
            let launchMode: String = {
                switch BastionLaunchController.resolveLaunchMode() {
                case .service: return "service"
                case .relay: return "relay"
                }
            }()
            let response = ServiceInfoResponse(
                version: version,
                serviceRegistrationStatus: ServiceRegistration.statusDescription(),
                configCorrupted: ruleEngine.configCorrupted,
                bundlePath: Bundle.main.bundlePath,
                executablePath: CommandLine.arguments.first ?? "",
                bundleIdentifier: Bundle.main.bundleIdentifier,
                processIdentifier: ProcessInfo.processInfo.processIdentifier,
                launchMode: launchMode,
                machServiceName: xpcServiceName,
                launchAgentPlistName: ServiceRegistration.launchAgentPlistName
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func exportSupportBundle(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let request = try JSONDecoder().decode(SupportBundleRequest.self, from: requestData)
                let service = SupportBundleExporter.currentServiceSnapshot(configCorrupted: ruleEngine.configCorrupted)
                let data = try SupportBundleExporter.makeBundleData(
                    config: ruleEngine.loadConfig(),
                    service: service,
                    request: request
                )
                DiagnosticLog.shared.record(
                    category: .support,
                    event: "support_bundle_exported",
                    message: "Support bundle exported",
                    context: [
                        "maxAuditRecords": String(request.maxAuditRecords ?? 50),
                        "maxDiagnosticEntries": String(request.maxDiagnosticEntries ?? 200),
                        "maxCrashReports": String(request.maxCrashReports ?? 10)
                    ]
                )
                reply(data, nil)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .support,
                    event: "support_bundle_failed",
                    message: error.localizedDescription
                )
                reply(nil, error)
            }
        }
    }

    nonisolated func getState(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            do {
                let context = try self.existingClientContext()
                let effectiveRules = context.rules

                let rateLimits = effectiveRules.rateLimits.map { ruleEngine.stateStore.rateLimitStatus(rule: $0) }
                let spendingLimits = effectiveRules.spendingLimits.map { ruleEngine.stateStore.spendingLimitStatus(rule: $0) }

                let response = StateResponse(
                    rateLimits: rateLimits,
                    spendingLimits: spendingLimits,
                    clientProfile: ruleEngine.clientProfileInfo(bundleId: self.clientBundleId, createProfile: false),
                    accountAddress: context.accountAddress
                )
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
    private func currentClientSmartAccount(bundleId: String? = nil) throws -> (SmartAccount, ClientSigningContext) {
        let effectiveBundleId = bundleId ?? clientBundleId
        try enforceSigningPreflightAllowed(bundleId: effectiveBundleId)
        let context = try existingClientContext(bundleId: effectiveBundleId)
        let publicKey: PublicKeyResponse
        #if DEBUG
        if let qaPublicKey = try RuntimeQASigningProvider.shared.publicKeyIfEnabled(keyTag: context.keyTag) {
            publicKey = qaPublicKey
        } else {
            publicKey = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
        }
        #else
        publicKey = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
        #endif
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
        if let accountAddress = context.accountAddress ?? publicKey.accountAddress {
            account.setAddress(accountAddress)
        }
        return (account, context)
    }

    private func kernelExecutions(from requestedExecutions: [RequestedExecution]) throws -> [KernelEncoding.Execution] {
        guard !requestedExecutions.isEmpty,
              requestedExecutions.count <= Self.maxIntentActions else {
            throw BastionError.invalidInput
        }
        var totalCalldataBytes = 0

        return try requestedExecutions.map { requested in
            guard KernelEncoding.isValidAddress(requested.target),
                  KernelEncoding.isValidUInt256(requested.value),
                  requested.data.count <= Self.maxIntentCalldataBytes else {
                throw BastionError.invalidInput
            }
            totalCalldataBytes += requested.data.count
            guard totalCalldataBytes <= Self.maxIntentCalldataBytes else {
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
    private func buildUserOperation(
        from intent: UserOperationIntentRequestEnvelope,
        bundleId: String? = nil
    ) async throws -> (UserOperation, UserOperationSubmissionRequest?) {
        let effectiveBundleId = bundleId ?? clientBundleId
        let projectId = try resolvedZeroDevProjectId(from: intent.projectId)
        let (account, _) = try currentClientSmartAccount(bundleId: effectiveBundleId)
        let bundler = ZeroDevAPI(projectId: projectId)
        let rpc = resolvedEthRPC(chainId: intent.chainId, bundler: bundler)
        let executions = try kernelExecutions(from: intent.executions)
        let callData: Data
        if executions.count == 1, let single = executions.first {
            callData = KernelEncoding.executeCalldata(single: single)
        } else {
            callData = KernelEncoding.executeCalldata(batch: executions)
        }
        guard let sender = account.address else {
            throw BastionError.invalidInput
        }
        try enforceStaticSigningPolicy(operation: .userOperation(syntheticUserOperation(
            sender: sender,
            callData: callData,
            chainId: intent.chainId
        )), bundleId: effectiveBundleId)

        let op: UserOperation
        do {
            op = try await account.buildSponsoredUserOperation(
                callData: callData,
                using: rpc,
                bundler: bundler,
                chainId: intent.chainId
            )
        } catch {
            throw ProviderFailureDiagnostic.from(
                error: error,
                provider: .zeroDev,
                stage: .sponsorship
            ).nsError
        }
        let submission = intent.submit ? UserOperationSubmissionRequest(projectId: projectId) : nil
        return (op, submission)
    }

    private func syntheticUserOperation(sender: String, callData: Data, chainId: Int) -> UserOperation {
        UserOperation(
            sender: sender,
            nonce: "0x0",
            callData: callData,
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: "0x0",
            maxFeePerGas: "0x0",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: chainId,
            entryPoint: EntryPointAddress.address(for: .v0_7),
            entryPointVersion: .v0_7
        )
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
        let sponsored: SponsorResult
        do {
            sponsored = try await bundler.sponsorUserOperation(
                dummyRpcOp,
                entryPoint: op.entryPoint,
                chainId: op.chainId
            )
        } catch {
            throw ProviderFailureDiagnostic.from(
                error: error,
                provider: submission.provider,
                stage: .sponsorship
            ).nsError
        }
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

    private nonisolated func handleSignStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        effectiveBundleId: String?,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard let maxBytes = maxPayloadBytes(for: operationType),
              operationData.count <= maxBytes else {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .xpc,
                event: "sign_structured_rejected_size",
                message: "Structured signing payload exceeded size limit",
                context: [
                    "operationType": operationType,
                    "bundleId": effectiveBundleId ?? "<unknown>"
                ]
            )
            reply(nil, BastionError.invalidInput.nsError)
            return
        }
        DiagnosticLog.shared.record(
            category: .xpc,
            event: "sign_structured_received",
            message: "Structured signing request received",
            context: [
                "operationType": operationType,
                "bundleId": effectiveBundleId ?? "<unknown>",
                "requestID": requestID
            ]
        )
        let resolvedUserOperationRequest: ResolvedUserOperationRequest?
        let immediateOperation: SigningOperation?
        do {
            let decoder = JSONDecoder()
            switch operationType {
            case "message":
                guard let text = String(data: operationData, encoding: .utf8) else {
                    DiagnosticLog.shared.record(
                        level: .warning,
                        category: .xpc,
                        event: "sign_structured_decode_failed",
                        message: "Message payload was not UTF-8",
                        context: ["operationType": operationType]
                    )
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
                    DiagnosticLog.shared.record(
                        level: .warning,
                        category: .xpc,
                        event: "sign_structured_decode_failed",
                        message: "Raw bytes payload was not a 32-byte hex string",
                        context: ["operationType": operationType]
                    )
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
            DiagnosticLog.shared.record(
                level: .warning,
                category: .xpc,
                event: "sign_structured_decode_failed",
                message: error.localizedDescription,
                context: [
                    "operationType": operationType,
                    "bundleId": effectiveBundleId ?? "<unknown>"
                ]
            )
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            do {
                try self.enforceSigningPreflightAllowed(bundleId: effectiveBundleId)
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
                        try self.enforceStaticSigningPolicy(
                            operation: .userOperation(userOperation),
                            bundleId: effectiveBundleId
                        )
                        let resolvedSub = try self.resolvedSubmissionRequest(submission)
                        let preflightedOp = try await self.preflightUserOperation(userOperation, submission: resolvedSub)
                        operation = .userOperation(preflightedOp)
                        userOperationSubmission = resolvedSub
                    case .intent(let intent):
                        let built = try await self.buildUserOperation(from: intent, bundleId: effectiveBundleId)
                        operation = .userOperation(built.0)
                        userOperationSubmission = built.1
                    }
                }

                let request = SignRequest(
                    operation: operation,
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: effectiveBundleId,
                    userOperationSubmission: userOperationSubmission
                )
                let result = try await SigningManager.shared.processSignRequest(request)
                let jsonData = try JSONEncoder().encode(result)
                DiagnosticLog.shared.record(
                    category: .xpc,
                    event: "sign_structured_succeeded",
                    message: "Structured signing request completed",
                    context: [
                        "operationType": operationType,
                        "bundleId": effectiveBundleId ?? "<unknown>"
                    ]
                )
                reply(jsonData, nil)
            } catch let error as BastionError {
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .xpc,
                    event: "sign_structured_failed",
                    message: error.description,
                    context: [
                        "operationType": operationType,
                        "bundleId": effectiveBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, error.nsError)
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .xpc,
                    event: "sign_structured_failed",
                    message: error.localizedDescription,
                    context: [
                        "operationType": operationType,
                        "bundleId": effectiveBundleId ?? "<unknown>"
                    ]
                )
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        handleSignStructured(
            operationType: operationType,
            operationData: operationData,
            requestID: requestID,
            effectiveBundleId: clientBundleId,
            withReply: reply
        )
    }

    @MainActor
    private func bridgeProfileBundleId(agentProfileId: String) throws -> String {
        guard isTrustedAgentBridge else {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Only the signed Bastion MCP bridge may proxy agent profiles"]
            )
        }
        let trimmed = agentProfileId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let profile = ruleEngine.clientProfile(id: trimmed) else {
            throw NSError(
                domain: "com.bastion.error",
                code: BastionError.ruleViolation.rawValue,
                userInfo: [NSLocalizedDescriptionKey: "Agent profile is not paired with Bastion"]
            )
        }
        return profile.bundleId
    }

    nonisolated func bridgeStartPairing(
        agentIdentifier: String,
        processName: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard isTrustedAgentBridge else {
            reply(nil, BastionError.ruleViolation.nsError)
            return
        }
        guard let inputs = XPCServer.normalizedPairingDisplayInputs(
            bundleId: agentIdentifier,
            processName: processName
        ) else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }

        Task { @MainActor in
            let request = PairingBroker.shared.registerIncoming(
                bundleId: inputs.bundleId,
                processName: inputs.processName
            )
            let response = PairingHandshakeResponse(
                requestId: request.id.uuidString,
                pairingCode: request.pairingCode,
                expiresAt: request.expiresAt
            )
            do {
                let encoder = JSONEncoder()
                encoder.dateEncodingStrategy = .iso8601
                reply(try encoder.encode(response), nil)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func bridgePollPairing(
        requestId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard isTrustedAgentBridge else {
            reply(nil, BastionError.ruleViolation.nsError)
            return
        }
        pollPairing(requestId: requestId, withReply: reply)
    }

    nonisolated func bridgeGetPublicKey(
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let bundleId = try self.bridgeProfileBundleId(agentProfileId: agentProfileId)
                let context = try self.existingClientContext(bundleId: bundleId)
                let raw: PublicKeyResponse
                #if DEBUG
                if let qaRaw = try RuntimeQASigningProvider.shared.publicKeyIfEnabled(keyTag: context.keyTag) {
                    raw = qaRaw
                } else {
                    raw = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
                }
                #else
                raw = try SecureEnclaveManager.shared.getPublicKey(keyTag: context.keyTag)
                #endif
                let result = PublicKeyResponse(
                    x: raw.x,
                    y: raw.y,
                    accountAddress: context.accountAddress ?? raw.accountAddress
                )
                reply(try JSONEncoder().encode(result), nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func bridgeGetRules(
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let bundleId = try self.bridgeProfileBundleId(agentProfileId: agentProfileId)
                let context = try self.existingClientContext(bundleId: bundleId)
                let response = RulesResponse(
                    authPolicy: context.authPolicy.rawValue,
                    globalAuthPolicy: nil,
                    rules: context.rules,
                    globalRules: nil,
                    clientProfile: self.ruleEngine.clientProfileInfo(bundleId: bundleId, createProfile: false),
                    accountAddress: context.accountAddress
                )
                reply(try JSONEncoder().encode(response), nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func bridgeGetState(
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let bundleId = try self.bridgeProfileBundleId(agentProfileId: agentProfileId)
                let context = try self.existingClientContext(bundleId: bundleId)
                let effectiveRules = context.rules
                let rateLimits = effectiveRules.rateLimits.map { self.ruleEngine.stateStore.rateLimitStatus(rule: $0) }
                let spendingLimits = effectiveRules.spendingLimits.map { self.ruleEngine.stateStore.spendingLimitStatus(rule: $0) }
                let response = StateResponse(
                    rateLimits: rateLimits,
                    spendingLimits: spendingLimits,
                    clientProfile: self.ruleEngine.clientProfileInfo(bundleId: bundleId, createProfile: false),
                    accountAddress: context.accountAddress
                )
                reply(try JSONEncoder().encode(response), nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func bridgeGetServiceInfo(
        agentProfileId: String?,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard isTrustedAgentBridge else {
            reply(nil, BastionError.ruleViolation.nsError)
            return
        }
        if let agentProfileId, !agentProfileId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            Task { @MainActor in
                do {
                    _ = try self.bridgeProfileBundleId(agentProfileId: agentProfileId)
                    self.getServiceInfo(withReply: reply)
                } catch {
                    reply(nil, error)
                }
            }
        } else {
            getServiceInfo(withReply: reply)
        }
    }

    nonisolated func bridgeSign(
        data: Data,
        requestID: String,
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        guard data.count == 32 else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }
        Task { @MainActor in
            do {
                let bundleId = try self.bridgeProfileBundleId(agentProfileId: agentProfileId)
                try self.enforceSigningPreflightAllowed(bundleId: bundleId)
                let request = SignRequest(
                    operation: .rawBytes(data),
                    requestID: requestID,
                    timestamp: Date(),
                    clientBundleId: bundleId
                )
                let result = try await SigningManager.shared.processSignRequest(request)
                reply(try JSONEncoder().encode(result), nil)
            } catch let error as BastionError {
                reply(nil, error.nsError)
            } catch {
                reply(nil, Self.bridgedError(error))
            }
        }
    }

    nonisolated func bridgeSignStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        Task { @MainActor in
            do {
                let bundleId = try self.bridgeProfileBundleId(agentProfileId: agentProfileId)
                self.handleSignStructured(
                    operationType: operationType,
                    operationData: operationData,
                    requestID: requestID,
                    effectiveBundleId: bundleId,
                    withReply: reply
                )
            } catch {
                reply(nil, error)
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
                // AC-03 (audit 2026-06-taek): listing every group's account
                // address + member roster is at least as sensitive as viewing a
                // single group, so require the same owner authentication that
                // getWalletGroup enforces. Previously this was ungated and
                // defeated getWalletGroup's biometric gate by enumeration.
                try await AuthManager.shared.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Authenticate to list wallet groups"
                )
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
            do {
                try await AuthManager.shared.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Authenticate to view wallet group"
                )
                guard let group = self.ruleEngine.walletGroup(id: groupId) else {
                    reply(nil, BastionError.invalidInput.nsError)
                    return
                }
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
        guard let inputs = XPCServer.normalizedPairingDisplayInputs(
            bundleId: bundleId,
            processName: processName
        ) else {
            reply(nil, BastionError.invalidInput.nsError)
            return
        }
        let bundle = inputs.bundleId
        let process = inputs.processName
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
        let activeCount = group.members.filter { $0.installStatus.isInstalled }.count
        // XPC read surfaces are for operational status, not internal signing
        // metadata. Do not expose key tags, rule bodies, or profile linkage to
        // arbitrary accepted XPC clients.
        return WalletGroupInfo(
            id: group.id,
            label: group.label,
            ownerKeyTag: nil,
            accountAddress: group.accountAddress,
            chainIds: group.chainIds,
            sharedRules: nil,
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
            keyTag: nil,
            clientProfileId: nil,
            scopedRules: nil,
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

import Foundation

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

    private nonisolated func verifyClientCodeSignature(connection: NSXPCConnection) -> Bool {
        let pid = connection.processIdentifier
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess,
              let secCode = code else {
            return false
        }

        // Require valid code signature
        guard SecCodeCheckValidity(secCode, [], nil) == errSecSuccess else {
            return false
        }

        // Verify the client is signed by the same team
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
              let code = staticCode else {
            return false
        }

        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, [], &info) == errSecSuccess,
              let signingInfo = info as? [String: Any],
              let teamID = signingInfo[kSecCodeInfoTeamIdentifier as String] as? String,
              teamID == Self.requiredTeamID else {
            return false
        }

        return true
    }
}

// Separate handler class for XPC callbacks (runs on XPC queue, not MainActor)
private nonisolated final class XPCHandler: NSObject, BastionXPCProtocol, @unchecked Sendable {
    private let signingManager: SigningManager
    private let ruleEngine: RuleEngine
    private let clientBundleId: String?

    nonisolated init(signingManager: SigningManager, ruleEngine: RuleEngine, clientBundleId: String?) {
        self.signingManager = signingManager
        self.ruleEngine = ruleEngine
        self.clientBundleId = clientBundleId
        super.init()
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
                // Legacy: wrap raw data as a message signing operation
                // TODO: replace with structured signing when CLI sends typed operations
                let request = SignRequest(
                    operation: .message(data.hex),
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
                reply(nil, error)
            }
        }
    }

    nonisolated func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void) {
        do {
            let result = try SecureEnclaveManager.shared.getPublicKey()
            let jsonData = try JSONEncoder().encode(result)
            reply(jsonData, nil)
        } catch {
            reply(nil, error)
        }
    }

    nonisolated func ping(withReply reply: @escaping (Bool) -> Void) {
        reply(true)
    }

    nonisolated func getRules(withReply reply: @escaping (Data?, Error?) -> Void) {
        Task { @MainActor in
            let config = ruleEngine.config
            let response = RulesResponse(
                authPolicy: config.authPolicy.rawValue,
                rules: config.rules
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
            let config = ruleEngine.config

            let rateLimits = config.rules.rateLimits.map { ruleEngine.stateStore.rateLimitStatus(rule: $0) }
            let spendingLimits = config.rules.spendingLimits.map { ruleEngine.stateStore.spendingLimitStatus(rule: $0) }

            let response = StateResponse(
                rateLimits: rateLimits,
                spendingLimits: spendingLimits
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }

    nonisolated func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    ) {
        let operation: SigningOperation
        do {
            let decoder = JSONDecoder()
            switch operationType {
            case "message":
                guard let text = String(data: operationData, encoding: .utf8) else {
                    reply(nil, BastionError.invalidInput.nsError)
                    return
                }
                operation = .message(text)
            case "typedData":
                let typed = try decoder.decode(EIP712TypedData.self, from: operationData)
                operation = .typedData(typed)
            case "userOperation":
                let op = try decoder.decode(UserOperation.self, from: operationData)
                operation = .userOperation(op)
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
                let request = SignRequest(
                    operation: operation,
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
                reply(nil, error)
            }
        }
    }
}

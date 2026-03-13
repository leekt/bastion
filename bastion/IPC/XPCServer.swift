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

        newConnection.exportedInterface = NSXPCInterface(with: BastionXPCProtocol.self)
        newConnection.exportedObject = XPCHandler(signingManager: signingManager, ruleEngine: ruleEngine)
        newConnection.invalidationHandler = {}
        newConnection.resume()
        return true
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

    nonisolated init(signingManager: SigningManager, ruleEngine: RuleEngine) {
        self.signingManager = signingManager
        self.ruleEngine = ruleEngine
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
                let result = try await signingManager.processSignRequest(data: data, requestID: requestID)
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
            let todayCount = StateStore.shared.todayCount()
            let limit = ruleEngine.config.rules.maxTxPerDayWithoutAuth
            let remaining = limit.map { max(0, $0 - todayCount) }
            let response = StateResponse(
                todayCount: todayCount,
                dailyLimit: limit,
                remaining: remaining
            )
            do {
                let jsonData = try JSONEncoder().encode(response)
                reply(jsonData, nil)
            } catch {
                reply(nil, error)
            }
        }
    }
}

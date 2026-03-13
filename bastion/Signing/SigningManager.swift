import Foundation

@Observable
final class SigningManager {
    static let shared = SigningManager()

    enum SigningState {
        case idle
        case pendingApproval(SignRequest)
        case signing
    }

    private(set) var state: SigningState = .idle
    private var pendingContinuation: CheckedContinuation<Bool, Never>?

    private let seManager = SecureEnclaveManager.shared
    private let authManager = AuthManager.shared
    private let ruleEngine = RuleEngine.shared
    private let auditLog = AuditLog.shared
    private let rateLimitStore = RateLimitStore.shared

    private init() {}

    func processSignRequest(data: Data, requestID: String) async throws -> SignResponse {
        let request = SignRequest(data: data, requestID: requestID, timestamp: Date())
        let dataPrefix = String(data.prefix(8).hex.prefix(16))

        let config = ruleEngine.config

        // 1. Check all rules — determine if master key (biometric) is needed
        var requiresMasterKey = false
        var violations: [String] = []

        // Rule check
        let validation = ruleEngine.validate(request, config: config)
        if case .denied(let reasons) = validation {
            requiresMasterKey = true
            violations.append(contentsOf: reasons)
        }

        // Rate limit check
        if let limit = config.rules.maxTxPerDayWithoutAuth {
            let todayCount = rateLimitStore.todayCount()
            if todayCount >= limit {
                requiresMasterKey = true
                violations.append("Daily limit reached (\(todayCount)/\(limit))")
            }
        }

        if requiresMasterKey {
            let reason = violations.joined(separator: "; ")
            auditLog.record(AuditEvent(type: .ruleViolation, dataPrefix: dataPrefix, reason: reason))

            // Show approval popup so user can see what rule is being broken
            state = .pendingApproval(request)

            let approved = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                self.pendingContinuation = continuation
            }

            state = .idle

            guard approved else {
                auditLog.record(AuditEvent(type: .signDenied, dataPrefix: dataPrefix, reason: "user_denied"))
                throw BastionError.userDenied
            }

            // Master key auth (biometric) — non-negotiable for rule overrides
            do {
                try await authManager.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Master key required: \(reason)"
                )
            } catch {
                auditLog.record(AuditEvent(type: .authFailed, dataPrefix: dataPrefix))
                throw BastionError.authFailed
            }
        } else {
            // Within rules — check if explicit approval popup is configured
            if config.rules.requireExplicitApproval {
                state = .pendingApproval(request)

                let approved = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                    self.pendingContinuation = continuation
                }

                state = .idle

                guard approved else {
                    auditLog.record(AuditEvent(type: .signDenied, dataPrefix: dataPrefix, reason: "user_denied"))
                    throw BastionError.userDenied
                }
            }

            // Normal auth policy (could be .open for fully autonomous signing)
            if config.authPolicy != .open {
                do {
                    try await authManager.authenticate(
                        policy: config.authPolicy,
                        reason: "Authorize signing request"
                    )
                } catch {
                    auditLog.record(AuditEvent(type: .authFailed, dataPrefix: dataPrefix))
                    throw BastionError.authFailed
                }
            }
        }

        // Sign with Secure Enclave (Key B)
        state = .signing
        defer { state = .idle }

        let result = try seManager.sign(data: data)

        // Record success and increment tamper-proof counter
        auditLog.record(AuditEvent(type: .signSuccess, dataPrefix: dataPrefix))
        rateLimitStore.increment()

        return result
    }

    func approveCurrentRequest() {
        pendingContinuation?.resume(returning: true)
        pendingContinuation = nil
    }

    func denyCurrentRequest() {
        pendingContinuation?.resume(returning: false)
        pendingContinuation = nil
    }
}

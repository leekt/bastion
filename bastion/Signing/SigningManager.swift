import Foundation

@Observable
final class SigningManager {
    static let shared = SigningManager()

    enum SigningState {
        case idle
        case pendingApproval(ApprovalRequest)
        case signing
    }

    private(set) var state: SigningState = .idle
    private var pendingContinuation: CheckedContinuation<Bool, Never>?

    private let seManager = SecureEnclaveManager.shared
    private let authManager = AuthManager.shared
    private let ruleEngine = RuleEngine.shared
    private let auditLog = AuditLog.shared

    private init() {}

    func processSignRequest(_ request: SignRequest) async throws -> SignResponse {
        let dataPrefix = request.requestID.prefix(8).description

        let config = ruleEngine.config

        // 1. Check all rules — determine if master key (biometric) is needed
        var requiresMasterKey = false
        var violations: [String] = []

        let validation = ruleEngine.validate(request, config: config)
        if case .denied(let reasons) = validation {
            requiresMasterKey = true
            violations.append(contentsOf: reasons)
        }

        if requiresMasterKey {
            let reason = violations.joined(separator: "; ")
            auditLog.record(AuditEvent(type: .ruleViolation, dataPrefix: dataPrefix, reason: reason))

            state = .pendingApproval(ApprovalRequest(
                request: request,
                mode: .ruleOverride(violations)
            ))

            let approved = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                self.pendingContinuation = continuation
            }

            state = .idle

            guard approved else {
                auditLog.record(AuditEvent(type: .signDenied, dataPrefix: dataPrefix, reason: "user_denied"))
                throw BastionError.userDenied
            }

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
            if config.rules.requireExplicitApproval {
                state = .pendingApproval(ApprovalRequest(
                    request: request,
                    mode: .policyReview
                ))

                let approved = await withCheckedContinuation { (continuation: CheckedContinuation<Bool, Never>) in
                    self.pendingContinuation = continuation
                }

                state = .idle

                guard approved else {
                    auditLog.record(AuditEvent(type: .signDenied, dataPrefix: dataPrefix, reason: "user_denied"))
                    throw BastionError.userDenied
                }
            }

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

        // `request.data` is already the Ethereum-standard 32-byte digest for every operation type.
        // Feed that digest directly into the Secure Enclave to avoid double-hashing message requests.
        let hash = request.data
        let raw = try seManager.signDigest(hash: hash)
        let normalizedS = Data(hexString: raw.s).map { P256Curve.normalizeS($0).hex } ?? raw.s
        let result = SignResponse(pubkeyX: raw.pubkeyX, pubkeyY: raw.pubkeyY, r: raw.r, s: normalizedS)

        // Record success — update rate limit and spending counters
        auditLog.record(AuditEvent(type: .signSuccess, dataPrefix: dataPrefix))
        ruleEngine.recordSuccess(request: request, config: config)

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

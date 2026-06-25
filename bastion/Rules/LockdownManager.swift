import Foundation

// Owner-controlled pause and emergency lockdown.
//
// Pause   — quick "I'm AFK" toggle. Rule engine denies every request.
// Lockdown — escalated state. Same denial behaviour, plus the menu bar shows
//            residual on-chain attack surface (active sessions, validators
//            still installed) so the owner knows what they still need to
//            unwind off-chain.
//
// Both states live on BastionConfig.pauseState and persist across restarts.

@MainActor
final class LockdownManager {
    static let shared = LockdownManager()
    private init() {}

    /// Toggle the pause flag. Bypasses biometric — pause is meant to be
    /// instant. Resume requires biometric to mirror updateConfig.
    @discardableResult
    func setPaused(_ paused: Bool, reason: String? = nil) async -> Bool {
        var config = RuleEngine.shared.config
        let was = config.pauseState
        if !paused && (was.paused || was.lockedDown) {
            do {
                try await AuthManager.shared.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Authenticate to resume Bastion signing"
                )
            } catch {
                AuditLog.shared.record(AuditEvent(
                    type: .authFailed,
                    dataPrefix: "pause.off",
                    reason: "Resume signing authentication failed"
                ))
                return false
            }
        }
        config.pauseState.paused = paused
        if paused {
            config.pauseState.pausedAt = Date()
            config.pauseState.reason = reason ?? "Owner paused signing"
        } else {
            config.pauseState.lockedDown = false
            config.pauseState.pausedAt = nil
            config.pauseState.reason = nil
        }
        // For pause we don't want to prompt biometric — write directly through
        // RuleEngine.applyPauseState which skips authentication.
        let persisted = RuleEngine.shared.unsafelyApplyPauseState(config.pauseState)
        // Forensics: record the toggle in the audit log so a post-incident
        // review can see who paused signing and when. Skipped when no real
        // change occurred (idempotent toggle from same state).
        guard was.paused != config.pauseState.paused else { return persisted }
        AuditLog.shared.record(AuditEvent(
            type: .ruleViolation,
            dataPrefix: paused ? "pause.on" : "pause.off",
            reason: paused
                ? "Owner paused signing — \(config.pauseState.reason ?? "no reason given")"
                : "Owner resumed signing"
        ))
        if !persisted {
            AuditLog.shared.record(AuditEvent(
                type: .authFailed,
                dataPrefix: paused ? "pause.on" : "pause.off",
                reason: "Pause state changed in memory but could not be persisted"
            ))
        }
        return persisted
    }

    /// Escalate to lockdown. Implies pause. Revokes all in-memory sessions
    /// and severs every active XPC connection so in-flight agent requests
    /// can't keep arriving while lockdown is engaged.
    @discardableResult
    func enterLockdown(reason: String) async -> Bool {
        let sessionsPersisted = SessionStore.shared.revokeAllFailClosed()
        XPCServer.shared.invalidateAllConnections()
        let was = RuleEngine.shared.config.pauseState.lockedDown
        var pauseState = RuleEngine.shared.config.pauseState
        pauseState.paused = true
        pauseState.lockedDown = true
        pauseState.pausedAt = Date()
        pauseState.reason = reason
        let persisted = RuleEngine.shared.unsafelyApplyPauseState(pauseState)
        guard !was else { return persisted && sessionsPersisted }
        AuditLog.shared.record(AuditEvent(
            type: .ruleViolation,
            dataPrefix: "lockdown.enter",
            reason: "Emergency lockdown engaged — \(reason)"
        ))
        if !persisted {
            AuditLog.shared.record(AuditEvent(
                type: .authFailed,
                dataPrefix: "lockdown.enter",
                reason: "Lockdown changed in memory but could not be persisted"
            ))
        }
        if !sessionsPersisted {
            AuditLog.shared.record(AuditEvent(
                type: .authFailed,
                dataPrefix: "lockdown.enter.sessions",
                reason: "Lockdown revoked sessions in memory but could not persist session revocation"
            ))
        }
        return persisted && sessionsPersisted
    }

    @discardableResult
    func leaveLockdown() async -> Bool {
        let was = RuleEngine.shared.config.pauseState.lockedDown
        guard was else { return true }
        do {
            try await AuthManager.shared.authenticate(
                policy: .biometricOrPasscode,
                reason: "Authenticate to leave Bastion lockdown"
            )
        } catch {
            AuditLog.shared.record(AuditEvent(
                type: .authFailed,
                dataPrefix: "lockdown.leave",
                reason: "Leave-lockdown authentication failed"
            ))
            return false
        }
        var pauseState = RuleEngine.shared.config.pauseState
        pauseState.paused = false
        pauseState.lockedDown = false
        pauseState.pausedAt = nil
        pauseState.reason = nil
        let persisted = RuleEngine.shared.unsafelyApplyPauseState(pauseState)
        AuditLog.shared.record(AuditEvent(
            type: .ruleViolation,
            dataPrefix: "lockdown.leave",
            reason: "Owner left lockdown"
        ))
        if !persisted {
            AuditLog.shared.record(AuditEvent(
                type: .authFailed,
                dataPrefix: "lockdown.leave",
                reason: "Lockdown leave changed in memory but could not be persisted"
            ))
        }
        return persisted
    }

    /// Snapshot of residual on-chain attack surface, for the lockdown UI.
    /// Counts validators that are still marked as `.installed` (i.e. would
    /// still accept signatures from leaked SE keys) plus any active sessions.
    struct ResidualSurface {
        let installedValidators: Int
        let activeSessions: Int
    }

    func residualSurface() -> ResidualSurface {
        let groups = RuleEngine.shared.config.walletGroups
        let installed = groups.flatMap(\.members).filter { member in
            if case .installed = member.installStatus { return true }
            return false
        }.count
        return ResidualSurface(
            installedValidators: installed,
            activeSessions: SessionStore.shared.active().count
        )
    }
}

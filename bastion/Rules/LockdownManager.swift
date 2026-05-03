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
    func setPaused(_ paused: Bool, reason: String? = nil) async {
        var config = RuleEngine.shared.config
        let was = config.pauseState
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
        RuleEngine.shared.unsafelyApplyPauseState(config.pauseState)
        // Forensics: record the toggle in the audit log so a post-incident
        // review can see who paused signing and when. Skipped when no real
        // change occurred (idempotent toggle from same state).
        guard was.paused != config.pauseState.paused else { return }
        AuditLog.shared.record(AuditEvent(
            type: .ruleViolation,
            dataPrefix: paused ? "pause.on" : "pause.off",
            reason: paused
                ? "Owner paused signing — \(config.pauseState.reason ?? "no reason given")"
                : "Owner resumed signing"
        ))
    }

    /// Escalate to lockdown. Implies pause. Revokes all in-memory sessions.
    func enterLockdown(reason: String) async {
        SessionStore.shared.revokeAll()
        let was = RuleEngine.shared.config.pauseState.lockedDown
        var pauseState = RuleEngine.shared.config.pauseState
        pauseState.paused = true
        pauseState.lockedDown = true
        pauseState.pausedAt = Date()
        pauseState.reason = reason
        RuleEngine.shared.unsafelyApplyPauseState(pauseState)
        guard !was else { return }
        AuditLog.shared.record(AuditEvent(
            type: .ruleViolation,
            dataPrefix: "lockdown.enter",
            reason: "Emergency lockdown engaged — \(reason)"
        ))
    }

    func leaveLockdown() async {
        let was = RuleEngine.shared.config.pauseState.lockedDown
        var pauseState = RuleEngine.shared.config.pauseState
        pauseState.paused = false
        pauseState.lockedDown = false
        pauseState.pausedAt = nil
        pauseState.reason = nil
        RuleEngine.shared.unsafelyApplyPauseState(pauseState)
        guard was else { return }
        AuditLog.shared.record(AuditEvent(
            type: .ruleViolation,
            dataPrefix: "lockdown.leave",
            reason: "Owner left lockdown"
        ))
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

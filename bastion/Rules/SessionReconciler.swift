import Foundation

// PR4: Reconciles an `AgentSession` against the rules currently in effect
// for its agent. Sessions are scope grants; if the owner later tightens
// the policy (drops a chain, removes a target, revokes a bundle from the
// client allowlist), any active session that exceeds the new policy must
// either be **downgraded** to the surviving intersection or **revoked**
// outright. Without reconciliation, an attacker who got a 30-minute
// session before a tighten could keep using the old, broader scope until
// the session expires.
//
// The reconciler is pure: no I/O, no actor state, no clock reads. It
// takes a session + the effective rules and returns an `Outcome`. The
// caller (`SessionStore.reconcile`) writes the outcomes back to the
// session list.

nonisolated enum SessionReconciler {

    /// Result of reconciling a single session against the current rules.
    enum Outcome: Sendable, Equatable {
        /// Session is fully within the new policy — keep as-is.
        case unchanged

        /// Session can keep some scope but not all. Caller persists the
        /// narrower session.
        case downgraded(AgentSession, reason: String)

        /// No surviving scope or the agent is no longer authorized at all.
        /// Caller drops the session.
        case revoked(reason: String)
    }

    /// `rules` is the effective rule set for the session's agent — i.e. the
    /// merged group ∩ profile rules already resolved by the rule engine.
    /// Passing the merged shape (rather than the raw config) keeps the
    /// reconciler unaware of wallet-group composition.
    static func reconcile(_ session: AgentSession, against rules: RuleConfig) -> Outcome {
        // 1. allowedClients gate. Nil = "no client restriction"; an empty
        //    list is the deny-all sentinel produced by an unsatisfiable
        //    merge — both bypass this branch on purpose because the gate
        //    enforces "session bundle must be present in a non-empty
        //    explicit allowlist".
        if let allowed = rules.allowedClients, !allowed.isEmpty,
           let bundle = session.clientBundleId {
            let bundleAllowed = allowed.contains {
                $0.bundleId.caseInsensitiveCompare(bundle) == .orderedSame
            }
            if !bundleAllowed {
                return .revoked(reason: "Agent bundle id removed from rules.allowedClients")
            }
        }

        // 2. Chain intersection. A nil rules.allowedChains means "no chain
        //    restriction" so the session keeps everything; otherwise we
        //    intersect.
        let downgradedChains = intersectChains(session.chains, ruleAllowed: rules.allowedChains)
        if !session.chains.isEmpty && downgradedChains.isEmpty {
            return .revoked(reason: "Session chains no longer overlap rules.allowedChains")
        }

        // 3. Target filter. Sessions store a flat allowedTargets list; the
        //    rule engine keys allowedTargets by chain. A target is "still
        //    valid" if it's allowed on at least one of the session's
        //    surviving chains. Nil rules.allowedTargets ⇒ no restriction;
        //    sessions keep everything.
        let downgradedTargets = filterTargets(
            session.allowedTargets,
            chains: downgradedChains,
            ruleAllowedTargets: rules.allowedTargets
        )
        if !session.allowedTargets.isEmpty && downgradedTargets.isEmpty
            && rules.allowedTargets != nil {
            return .revoked(reason: "Session targets no longer overlap rules.allowedTargets")
        }

        let chainsChanged = downgradedChains != session.chains
        let targetsChanged = downgradedTargets != session.allowedTargets

        if !chainsChanged && !targetsChanged {
            return .unchanged
        }

        let updated = AgentSession(
            id: session.id,
            clientLabel: session.clientLabel,
            clientId: session.clientId,
            clientBundleId: session.clientBundleId,
            chains: downgradedChains,
            usdcLimit: session.usdcLimit,
            ethLimit: session.ethLimit,
            allowedTargets: downgradedTargets,
            startedAt: session.startedAt,
            expiresAt: session.expiresAt,
            intent: session.intent
        )
        var reasons: [String] = []
        if chainsChanged {
            reasons.append("chains narrowed to \(downgradedChains.map(String.init).joined(separator: ", "))")
        }
        if targetsChanged {
            reasons.append("targets narrowed (\(session.allowedTargets.count) → \(downgradedTargets.count))")
        }
        return .downgraded(updated, reason: reasons.joined(separator: "; "))
    }

    // MARK: - Helpers

    private static func intersectChains(_ sessionChains: [Int], ruleAllowed: [Int]?) -> [Int] {
        guard let ruleAllowed else { return sessionChains }
        let allowedSet = Set(ruleAllowed)
        return sessionChains.filter(allowedSet.contains)
    }

    private static func filterTargets(
        _ sessionTargets: [String],
        chains: [Int],
        ruleAllowedTargets: [String: [String]]?
    ) -> [String] {
        guard let ruleAllowedTargets, !ruleAllowedTargets.isEmpty else {
            return sessionTargets
        }
        // Build the union of rule-allowed targets across the session's
        // surviving chains. If the rules don't restrict targets for any of
        // them (no key, or empty list), the session targets stay valid.
        var allowed = Set<String>()
        var anyChainRestricted = false
        for chain in chains {
            let key = String(chain)
            if let entries = ruleAllowedTargets[key] {
                anyChainRestricted = true
                for entry in entries {
                    allowed.insert(entry.lowercased())
                }
            }
        }
        if !anyChainRestricted {
            return sessionTargets
        }
        return sessionTargets.filter { allowed.contains($0.lowercased()) }
    }
}

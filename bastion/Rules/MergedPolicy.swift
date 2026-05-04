import Foundation

// PR3 (architectural cleanup): first-class type for wallet-group ∩ member
// rule composition. Replaces the ad-hoc sentinels (`AllowedHours(0, 0)`,
// `allowedClients: []`) that mergeGroupRules used to encode "intersection
// is empty so deny everything" with an explicit `.unsatisfiable` case.
//
// Why this matters:
//
// - The sentinel approach worked but required every consumer of the merge
//   result to know about each sentinel shape (raw value 0..0 meant deny;
//   empty list meant deny). New consumers — UI surfacing the effective
//   merged policy, audit-log records, future tooling — would each have to
//   reproduce that knowledge or risk silently treating a sentinel as a
//   permissive value.
// - With a typed `Constraint<T>` per field, every consumer either handles
//   the unsatisfiable branch explicitly or doesn't compile. The rule
//   engine still flattens the result back into a sentinel-bearing
//   `RuleConfig` for backwards compatibility (so existing validation
//   paths work without sweeping changes), but the *canonical* merge
//   value is `MergedPolicy`.
// - `MergedPolicy.unsatisfiabilityReasons` exposes a list of human
//   strings ("group and agent allowed-hours have no overlap") that the
//   wallet-group panel + audit log can render without re-deriving them
//   from sentinel values.

// MARK: - Per-field constraint

/// A merged constraint for a single rule field. Three states:
/// - `.unrestricted` — neither side imposed a restriction; the field
///   places no bound on requests.
/// - `.restricted(value)` — at least one side restricted; `value` is the
///   non-empty intersection (or fall-through from a single-sided
///   restriction).
/// - `.unsatisfiable(reason)` — both sides restricted and the
///   intersection is empty. Validation must deny without further
///   evaluation. `reason` is an operator-facing explanation.
nonisolated enum MergedConstraint<T: Sendable>: Sendable {
    case unrestricted
    case restricted(T)
    case unsatisfiable(reason: String)
}

// MARK: - Merged policy

nonisolated struct MergedPolicy: Sendable {
    var userOpPosture: SigningPosture
    var rawMessagePosture: SigningPosture
    var typedDataPosture: SigningPosture

    var allowedHours: MergedConstraint<AllowedHours>
    var allowedChains: MergedConstraint<[Int]>
    var allowedTargets: MergedConstraint<[String: [String]]>
    var allowedSelectors: MergedConstraint<[String: [String]]>
    var allowedClients: MergedConstraint<[AllowedClient]>

    /// Union of both sides — never produces unsatisfiable since
    /// extending a deny list always increases coverage.
    var denySelectors: [String]?

    /// Cap-style fields: both rules survive (preserving counter IDs).
    var rateLimits: [RateLimitRule]
    var spendingLimits: [SpendingLimitRule]

    var rawMessageAllowRawSigning: Bool
    var typedDataDomainRules: [TypedDataDomainRule]
    var typedDataStructRules: [TypedDataStructRule]

    /// True iff any field is unsatisfiable. The rule engine short-circuits
    /// to denial when this is set.
    var isUnsatisfiable: Bool {
        !unsatisfiabilityReasons.isEmpty
    }

    /// All operator-facing reasons. Stable order so audit logs and UI
    /// display in a consistent sequence.
    var unsatisfiabilityReasons: [String] {
        var reasons: [String] = []
        appendIfUnsatisfiable(allowedHours, into: &reasons)
        appendIfUnsatisfiable(allowedChains, into: &reasons)
        appendIfUnsatisfiable(allowedTargets, into: &reasons)
        appendIfUnsatisfiable(allowedSelectors, into: &reasons)
        appendIfUnsatisfiable(allowedClients, into: &reasons)
        return reasons
    }

    private func appendIfUnsatisfiable<T>(
        _ constraint: MergedConstraint<T>,
        into reasons: inout [String]
    ) {
        if case .unsatisfiable(let reason) = constraint {
            reasons.append(reason)
        }
    }

    /// Flatten back into a `RuleConfig` for the validation hot path,
    /// which today still consumes the legacy shape. Unsatisfiable fields
    /// retain their sentinel encoding (empty allowlist for clients, etc.)
    /// so downstream validators continue to deny them — but `MergedPolicy`
    /// itself remains the authoritative explanation.
    func toRuleConfig() -> RuleConfig {
        RuleConfig(
            userOpPosture: userOpPosture,
            allowedHours: extractValue(allowedHours, sentinelOnUnsatisfiable: AllowedHours(start: 0, end: 0)),
            allowedChains: extractValue(allowedChains, sentinelOnUnsatisfiable: []),
            allowedTargets: extractValue(allowedTargets, sentinelOnUnsatisfiable: [:]),
            allowedSelectors: extractValue(allowedSelectors, sentinelOnUnsatisfiable: [:]),
            denySelectors: denySelectors,
            allowedClients: extractValue(allowedClients, sentinelOnUnsatisfiable: []),
            rateLimits: rateLimits,
            spendingLimits: spendingLimits,
            rawMessagePolicy: RawMessagePolicy(posture: rawMessagePosture, allowRawSigning: rawMessageAllowRawSigning),
            typedDataPolicy: TypedDataPolicy(
                posture: typedDataPosture,
                domainRules: typedDataDomainRules,
                structRules: typedDataStructRules
            )
        )
    }

    private func extractValue<T>(_ constraint: MergedConstraint<T>, sentinelOnUnsatisfiable: T) -> T? {
        switch constraint {
        case .unrestricted: return nil
        case .restricted(let v): return v
        case .unsatisfiable: return sentinelOnUnsatisfiable
        }
    }
}

// MARK: - Composer

/// Composes a `MergedPolicy` from a wallet-group's `sharedRules` and a
/// member's `scopedRules`. Stateless and `nonisolated` so the rule engine
/// (off-MainActor) can compose without touching engine instance state.
nonisolated enum MergedPolicyComposer {
    static func compose(group: RuleConfig, member: RuleConfig) -> MergedPolicy {
        MergedPolicy(
            userOpPosture: stricterPosture(group.userOpPosture, member.userOpPosture),
            rawMessagePosture: stricterPosture(group.rawMessagePolicy.posture, member.rawMessagePolicy.posture),
            typedDataPosture: stricterPosture(group.typedDataPolicy.posture, member.typedDataPolicy.posture),
            allowedHours: mergeHours(group.allowedHours, member.allowedHours),
            allowedChains: mergeIntList(group.allowedChains, member.allowedChains, fieldName: "allowed chains"),
            allowedTargets: mergeStringDict(group.allowedTargets, member.allowedTargets, fieldName: "allowed targets"),
            allowedSelectors: mergeStringDict(group.allowedSelectors, member.allowedSelectors, fieldName: "allowed selectors"),
            allowedClients: mergeAllowedClients(group.allowedClients, member.allowedClients),
            denySelectors: unionOptionalArrays(group.denySelectors, member.denySelectors),
            rateLimits: group.rateLimits + member.rateLimits,
            spendingLimits: group.spendingLimits + member.spendingLimits,
            rawMessageAllowRawSigning: group.rawMessagePolicy.allowRawSigning && member.rawMessagePolicy.allowRawSigning,
            typedDataDomainRules: group.typedDataPolicy.domainRules + member.typedDataPolicy.domainRules,
            typedDataStructRules: group.typedDataPolicy.structRules + member.typedDataPolicy.structRules
        )
    }

    /// Posture merge: strict-OR on (evaluatesRules, requiresApprovalPopup).
    /// The output is mapped through SigningPosture.from so it lands in
    /// one of the three legal cases — the function-local invariant the
    /// follow-up task (#53) will replace with a typed proof.
    static func stricterPosture(_ a: SigningPosture, _ b: SigningPosture) -> SigningPosture {
        let evaluates = a.evaluatesRules || b.evaluatesRules
        let popup = a.requiresApprovalPopup || b.requiresApprovalPopup
        return SigningPosture.from(enabled: evaluates, requireExplicitApproval: popup)
    }

    private static func mergeHours(_ a: AllowedHours?, _ b: AllowedHours?) -> MergedConstraint<AllowedHours> {
        switch (a, b) {
        case (nil, nil): return .unrestricted
        case (let x?, nil): return .restricted(x)
        case (nil, let x?): return .restricted(x)
        case (let x?, let y?):
            // Same-day windows (start <= end). Cross-midnight windows are
            // left to the validator since reasoning about wrapping
            // intersections is messy; we narrow to whichever side is
            // most restrictive (member, by convention).
            if x.start <= x.end && y.start <= y.end {
                let newStart = max(x.start, y.start)
                let newEnd = min(x.end, y.end)
                if newStart < newEnd {
                    return .restricted(AllowedHours(start: newStart, end: newEnd))
                }
                return .unsatisfiable(reason: "Wallet group and agent allowed-hours have no overlap")
            }
            return .restricted(y)
        }
    }

    private static func mergeIntList(
        _ a: [Int]?,
        _ b: [Int]?,
        fieldName: String
    ) -> MergedConstraint<[Int]> {
        switch (a, b) {
        case (nil, nil): return .unrestricted
        case (let x?, nil): return .restricted(x)
        case (nil, let x?): return .restricted(x)
        case (let x?, let y?):
            let intersected = x.filter(Set(y).contains)
            if intersected.isEmpty {
                return .unsatisfiable(reason: "Wallet group and agent \(fieldName) have no overlap")
            }
            return .restricted(intersected)
        }
    }

    private static func mergeStringDict(
        _ a: [String: [String]]?,
        _ b: [String: [String]]?,
        fieldName: String
    ) -> MergedConstraint<[String: [String]]> {
        switch (a, b) {
        case (nil, nil): return .unrestricted
        case (let x?, nil): return .restricted(x)
        case (nil, let x?): return .restricted(x)
        case (let x?, let y?):
            var out: [String: [String]] = [:]
            var unsatisfiableKeys: [String] = []
            let allKeys = Set(x.keys).union(y.keys)
            for key in allKeys {
                switch (x[key], y[key]) {
                case (nil, nil):
                    continue
                case (let v?, nil), (nil, let v?):
                    out[key] = v
                case (let lv?, let rv?):
                    let rvSet = Set(rv.map { $0.lowercased() })
                    let intersected = lv.filter { rvSet.contains($0.lowercased()) }
                    if intersected.isEmpty {
                        unsatisfiableKeys.append(key)
                    } else {
                        out[key] = intersected
                    }
                }
            }
            if !unsatisfiableKeys.isEmpty {
                return .unsatisfiable(
                    reason: "Wallet group and agent \(fieldName) disagree on \(unsatisfiableKeys.sorted().joined(separator: ", "))"
                )
            }
            return out.isEmpty ? .unrestricted : .restricted(out)
        }
    }

    private static func mergeAllowedClients(
        _ a: [AllowedClient]?,
        _ b: [AllowedClient]?
    ) -> MergedConstraint<[AllowedClient]> {
        switch (a, b) {
        case (nil, nil): return .unrestricted
        case (let x?, nil): return .restricted(x)
        case (nil, let x?): return .restricted(x)
        case (let x?, let y?):
            let ySet = Set(y.map { $0.bundleId.lowercased() })
            let intersected = x.filter { ySet.contains($0.bundleId.lowercased()) }
            if intersected.isEmpty {
                return .unsatisfiable(reason: "Wallet group and agent client allowlists share no bundles")
            }
            return .restricted(intersected)
        }
    }

    private static func unionOptionalArrays(_ a: [String]?, _ b: [String]?) -> [String]? {
        switch (a, b) {
        case (nil, nil): return nil
        case (let x?, nil): return x
        case (nil, let x?): return x
        case (let x?, let y?): return Array(Set(x).union(y))
        }
    }
}

import Foundation

// Deterministic risk scoring for the approval popup.
//
// Not vague AI scoring — pure rule-driven concrete signals. Each signal is a
// distinct enum case with a short label and tone, surfaced as chips in the
// approval popup.

nonisolated struct RiskSignal: Sendable, Identifiable, Hashable {
    enum Tone: String, Sendable, Hashable { case info, warn, danger }
    let id: String
    let tone: Tone
    let label: String
    let detail: String?
}

nonisolated enum RiskScorer {
    /// Computes signals for a request given the rule engine's view of the
    /// world. Pulls from CalldataDecoder, BastionConfig (allowedTargets,
    /// addressBook, allowedHours, highValue) and AuditLog (first interaction).
    static func signals(
        for request: SignRequest,
        config: BastionConfig,
        clientContext: ClientSigningContext
    ) -> [RiskSignal] {
        var signals: [RiskSignal] = []

        // Outside allowed hours
        if let hours = clientContext.rules.allowedHours {
            let nowHour = Calendar.current.component(.hour, from: Date())
            let inWindow: Bool
            if hours.start <= hours.end {
                inWindow = nowHour >= hours.start && nowHour < hours.end
            } else {
                // wraps midnight
                inWindow = nowHour >= hours.start || nowHour < hours.end
            }
            if !inWindow {
                signals.append(RiskSignal(
                    id: "outside-hours",
                    tone: .warn,
                    label: "Outside allowed hours",
                    detail: String(format: "Window: %02d:00–%02d:00", hours.start, hours.end)
                ))
            }
        }

        // userOp-specific signals
        if case .userOperation(let op) = request.operation {
            let decoded = CalldataDecoder.decode(op)
            let leaves = decoded.executions.flatMap(\.allLeafExecutions)

            // Unknown selectors
            if leaves.contains(where: \.hasUnrecognizedCalldata) {
                signals.append(RiskSignal(
                    id: "unknown-selector",
                    tone: .warn,
                    label: "Unknown selector",
                    detail: "Calldata could not be decoded"
                ))
            }

            // High-value
            if let token = leaves.compactMap(\.tokenOperation).first {
                if config.highValue.enabled,
                   let amount = Double(token.amount),
                   amount >= config.highValue.thresholdUsd {
                    signals.append(RiskSignal(
                        id: "high-value",
                        tone: .danger,
                        label: "High value",
                        detail: "≥ \(Int(config.highValue.thresholdUsd)) USD-equivalent"
                    ))
                }

                // Allowance increase (approve > 0)
                if token.kind == .approve,
                   let amount = Double(token.amount), amount > 0 {
                    signals.append(RiskSignal(
                        id: "allowance-increase",
                        tone: .warn,
                        label: "Allowance increase",
                        detail: "Approves a counterparty to spend tokens on your behalf"
                    ))
                }
            }

            // First interaction (target not previously seen in audit log).
            // Best-effort lookup over recent records — not exhaustive history.
            let recentTargets: Set<String> = Set(
                AuditLog.shared
                    .recentRequestRecords(limit: 100)
                    .compactMap(\.request)
                    .flatMap { record in record.details.flatMap { extractAddresses(in: $0) } }
                    .map { $0.lowercased() }
            )
            for leaf in leaves {
                let target = leaf.to.lowercased()
                if !recentTargets.contains(target) {
                    let label: String
                    if let stored = config.label(for: target, chainId: op.chainId) {
                        label = stored
                    } else {
                        label = "First interaction"
                    }
                    signals.append(RiskSignal(
                        id: "first-interaction-\(target.prefix(10))",
                        tone: .info,
                        label: label == "First interaction" ? label : "New target — labelled \(label)",
                        detail: "No prior interactions in last 100 audited requests"
                    ))
                    break // one signal is enough for the chip row
                }
            }

            // New target outside allowlist
            if let allowed = clientContext.rules.allowedTargets {
                let chainKey = String(op.chainId)
                let allowedAddrs = (allowed[chainKey] ?? []).map { $0.lowercased() }
                if !allowedAddrs.isEmpty {
                    if let outside = leaves.map({ $0.to.lowercased() }).first(where: { !allowedAddrs.contains($0) }) {
                        signals.append(RiskSignal(
                            id: "outside-allowlist",
                            tone: .danger,
                            label: "Outside allowlist",
                            detail: "Target \(outside.prefix(10))… is not in the profile's allowed targets"
                        ))
                    }
                }
            }
        }

        return signals
    }

    /// Crude regex-free Ethereum address scanner — looks for 0x followed by
    /// 40 hex chars. Used to mine targets out of audit detail strings without
    /// importing a regex.
    private static func extractAddresses(in text: String) -> [String] {
        var hits: [String] = []
        let lower = text.lowercased()
        var i = lower.startIndex
        while i < lower.endIndex {
            if let prefixRange = lower.range(of: "0x", range: i..<lower.endIndex) {
                let after = prefixRange.upperBound
                let remaining = lower.distance(from: after, to: lower.endIndex)
                if remaining >= 40 {
                    let candidate = lower[after..<lower.index(after, offsetBy: 40)]
                    if candidate.allSatisfy({ $0.isHexDigit }) {
                        hits.append("0x" + String(candidate))
                    }
                }
                i = prefixRange.upperBound
            } else {
                break
            }
        }
        return hits
    }
}

private extension Character {
    var isHexDigit: Bool {
        ("0"..."9").contains(self) || ("a"..."f").contains(self) || ("A"..."F").contains(self)
    }
}

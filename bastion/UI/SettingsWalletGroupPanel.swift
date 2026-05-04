import SwiftUI

// Settings panel — Wallet group view. Lists members of a shared smart account
// and surfaces their on-chain validator status. Extracted from
// RulesSettingsView for clarity; consumed only from RulesSettingsView's
// `mainPanel` switch so kept at file scope (no `private`).

struct WalletGroupPanel: View {
    let group: WalletGroup

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            BastionDivider()
            ScrollView {
                VStack(spacing: 16) {
                    BastionCard {
                        membersSection
                    }
                    unsatisfiabilityBanner
                }
                .padding(.bastionPanelContent)
            }
        }
    }

    /// PR3: surface MergedPolicy.unsatisfiabilityReasons when any active
    /// member's effective rules are unsatisfiable. The owner sees exactly
    /// which constraints disagree (e.g. "Wallet group and agent allowed-hours
    /// have no overlap") instead of having to reason about silent denials.
    @ViewBuilder
    private var unsatisfiabilityBanner: some View {
        let reasons = group.members.compactMap { member -> (label: String, reasons: [String])? in
            // Skip revoked agents — their rules don't apply.
            if member.installStatus.isRevoked { return nil }
            let merged = RuleEngine.shared.mergedPolicy(group: group.sharedRules, member: member.scopedRules)
            guard merged.isUnsatisfiable else { return nil }
            let label = member.label ?? "Agent"
            return (label, merged.unsatisfiabilityReasons)
        }
        if !reasons.isEmpty {
            BastionCard {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.bastionBad)
                        Text("Unsatisfiable merged policy")
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(Color.bastionBad)
                    }
                    Text("These members will be denied any signing request because their scoped rules conflict with the group's shared rules.")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(Array(reasons.enumerated()), id: \.offset) { _, entry in
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.label)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(Color.ink900)
                            ForEach(Array(entry.reasons.enumerated()), id: \.offset) { _, reason in
                                HStack(alignment: .top, spacing: 6) {
                                    Text("·")
                                        .foregroundStyle(Color.bastionBad)
                                    Text(reason)
                                        .font(.system(size: 11.5))
                                        .foregroundStyle(Color.ink700)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .padding(8)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .background(
                            RoundedRectangle(cornerRadius: 6).fill(Color.bastionBadSoft.opacity(0.6))
                        )
                    }
                }
            }
        }
    }

    private var header: some View {
        HStack(spacing: 10) {
            Text(group.label.isEmpty ? "Wallet Group" : group.label)
                .font(.system(size: 18, weight: .semibold))
                .kerning(-0.36)
            BastionChip(label: "Shared smart account", style: .outline)
        }
        .padding(EdgeInsets(top: 18, leading: 28, bottom: 16, trailing: 28))
    }

    private var membersSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            BastionSectionHeader(
                title: "Members",
                subtitle: "Owner is sudo. Each agent has its own validator."
            ) {
                Button("Add agent") {}
                    .bastionButton(.default, size: .small)
            }
            ForEach(group.members) { agent in
                VStack(spacing: 0) {
                    Rectangle().fill(Color.ink150).frame(height: 1)
                    memberRow(agent)
                }
            }
        }
    }

    private func memberRow(_ agent: AgentMembership) -> some View {
        HStack(spacing: 12) {
            agentAvatar(agent)
            VStack(alignment: .leading, spacing: 2) {
                Text(agent.label ?? "Agent").font(.system(size: 13, weight: .medium))
                Text(agent.installStatusLabel)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.ink500)
            }
            Spacer()
            BastionChip(label: agent.installStatusLabel,
                        style: agent.isInstalled ? .ok : .warn)
            Button("Edit scope") {}
                .bastionButton(.ghost, size: .small)
        }
        .padding(.vertical, 14)
    }

    private func agentAvatar(_ agent: AgentMembership) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8).fill(Color.ink100)
            Text(String((agent.label ?? "?").prefix(1)).uppercased())
                .font(.system(size: 12, weight: .semibold))
                .foregroundStyle(Color.ink700)
        }
        .frame(width: 30, height: 30)
    }
}

extension AgentMembership {
    var isInstalled: Bool {
        if case .installed = installStatus { return true }
        return false
    }

    var installStatusLabel: String {
        switch installStatus {
        case .installed: return "Installed"
        case .pending: return "Pending"
        case .revoked: return "Revoked"
        }
    }
}

import SwiftUI

nonisolated enum WalletGroupMemberTone: Equatable, Sendable {
    case ok
    case warn
    case bad

    var chipStyle: BastionChip.Style {
        switch self {
        case .ok: return .ok
        case .warn: return .warn
        case .bad: return .bad
        }
    }
}

nonisolated struct WalletGroupMemberRowPresentation: Equatable, Identifiable, Sendable {
    let id: String
    let label: String
    let avatar: String
    let statusLabel: String
    let statusTone: WalletGroupMemberTone
}

nonisolated struct WalletGroupUnsatisfiableMemberPresentation: Equatable, Identifiable, Sendable {
    let id: String
    let label: String
    let reasons: [String]
}

nonisolated struct WalletGroupPanelPresentation: Equatable, Sendable {
    let title: String
    let badgeLabel: String
    let membersTitle: String
    let membersSubtitle: String
    let emptyMembersTitle: String?
    let emptyMembersMessage: String?
    let memberRows: [WalletGroupMemberRowPresentation]
    let showsAddAgentControl: Bool
    let showsEditScopeControls: Bool
    let unsatisfiableTitle: String?
    let unsatisfiableMessage: String?
    let unsatisfiableMembers: [WalletGroupUnsatisfiableMemberPresentation]

    static func make(_ group: WalletGroup) -> WalletGroupPanelPresentation {
        let memberRows = group.members.map(WalletGroupMemberRowPresentation.make)
        let unsatisfiableMembers = group.members.compactMap { member -> WalletGroupUnsatisfiableMemberPresentation? in
            if member.installStatus.isRevoked { return nil }
            let merged = MergedPolicyComposer.compose(group: group.sharedRules, member: member.scopedRules)
            guard merged.isUnsatisfiable else { return nil }
            return WalletGroupUnsatisfiableMemberPresentation(
                id: member.id,
                label: member.label ?? "Agent",
                reasons: merged.unsatisfiabilityReasons
            )
        }
        return WalletGroupPanelPresentation(
            title: group.label.isEmpty ? "Wallet Group" : group.label,
            badgeLabel: "Shared smart account",
            membersTitle: "Members",
            membersSubtitle: "Owner is sudo. Each agent has its own validator.",
            emptyMembersTitle: memberRows.isEmpty ? "No agent members" : nil,
            emptyMembersMessage: memberRows.isEmpty ? "Pair an agent into this wallet group before it can sign for the shared smart account." : nil,
            memberRows: memberRows,
            showsAddAgentControl: false,
            showsEditScopeControls: false,
            unsatisfiableTitle: unsatisfiableMembers.isEmpty ? nil : "Unsatisfiable merged policy",
            unsatisfiableMessage: unsatisfiableMembers.isEmpty ? nil : "These members will be denied any signing request because their scoped rules conflict with the group's shared rules.",
            unsatisfiableMembers: unsatisfiableMembers
        )
    }
}

nonisolated extension WalletGroupMemberRowPresentation {
    static func make(_ agent: AgentMembership) -> WalletGroupMemberRowPresentation {
        WalletGroupMemberRowPresentation(
            id: agent.id,
            label: agent.label ?? "Agent",
            avatar: String((agent.label ?? "?").prefix(1)).uppercased(),
            statusLabel: agent.installStatusLabel,
            statusTone: agent.statusTone
        )
    }
}

// Settings panel — Wallet group view. Lists members of a shared smart account
// and surfaces their on-chain validator status. Extracted from
// RulesSettingsView for clarity; consumed only from RulesSettingsView's
// `mainPanel` switch so kept at file scope (no `private`).

struct WalletGroupPanel: View {
    let group: WalletGroup
    private var presentation: WalletGroupPanelPresentation {
        WalletGroupPanelPresentation.make(group)
    }

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
        if let title = presentation.unsatisfiableTitle,
           let message = presentation.unsatisfiableMessage {
            BastionCard {
                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 13))
                            .foregroundStyle(Color.bastionBad)
                        Text(title)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundStyle(Color.bastionBad)
                    }
                    Text(message)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                        .fixedSize(horizontal: false, vertical: true)
                    ForEach(presentation.unsatisfiableMembers) { entry in
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
                        .padding(.s)
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
            Text(presentation.title)
                .font(.system(size: 18, weight: .semibold))
                .kerning(-0.36)
            BastionChip(label: presentation.badgeLabel, style: .outline)
        }
        .padding(EdgeInsets(top: 18, leading: 28, bottom: 16, trailing: 28))
    }

    private var membersSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            BastionSectionHeader(
                title: presentation.membersTitle,
                subtitle: presentation.membersSubtitle
            )
            if presentation.memberRows.isEmpty {
                emptyMembersState
            } else {
                ForEach(presentation.memberRows) { agent in
                    VStack(spacing: 0) {
                        Rectangle().fill(Color.ink150).frame(height: 1)
                        memberRow(agent)
                    }
                }
            }
        }
    }

    private var emptyMembersState: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "person.2.slash")
                .font(.system(size: 14))
                .foregroundStyle(Color.ink400)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 3) {
                Text(presentation.emptyMembersTitle ?? "")
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(Color.ink900)
                Text(presentation.emptyMembersMessage ?? "")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(.m)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.ink50)
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.ink150, lineWidth: 1))
        )
    }

    private func memberRow(_ agent: WalletGroupMemberRowPresentation) -> some View {
        HStack(spacing: 12) {
            agentAvatar(agent)
            VStack(alignment: .leading, spacing: 2) {
                Text(agent.label).font(.system(size: 13, weight: .medium))
                Text(agent.statusLabel)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.ink500)
            }
            Spacer()
            BastionChip(label: agent.statusLabel,
                        style: agent.statusTone.chipStyle)
        }
        .padding(.vertical, 14)
    }

    private func agentAvatar(_ agent: WalletGroupMemberRowPresentation) -> some View {
        ZStack {
            RoundedRectangle(cornerRadius: 8).fill(Color.ink100)
            Text(agent.avatar)
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

    var statusChipStyle: BastionChip.Style {
        statusTone.chipStyle
    }

    var statusTone: WalletGroupMemberTone {
        switch installStatus {
        case .installed: return .ok
        case .pending: return .warn
        case .revoked: return .bad
        }
    }

    var installStatusLabel: String {
        switch installStatus {
        case .installed: return "Installed"
        case .pending: return "Pending"
        case .revoked: return "Revoked"
        }
    }
}

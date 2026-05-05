import AppKit
import Combine
import SwiftUI

// Settings window — Bastion v2 redesign.
// Sidebar (Defaults/Clients/Wallet groups + Rule templates) → main panel with
// per-target caps, global cap tiles, auth quick-picker, validator state, and
// an unsaved-changes save bar with diff sheet. Mirrors settings-v2.jsx.

private enum SettingsSelection: Hashable {
    case defaultProfile
    case appPreferences
    case ruleTemplates
    case addressBook
    case policySimulator
    case policyHistory
    case highValueRule
    case client(id: String)
    case walletGroup(id: String)
}

struct RulesSettingsView: View {
    @State private var draftConfig: BastionConfig = .default
    @State private var savedConfig: BastionConfig = .default
    @State private var selection: SettingsSelection = .defaultProfile
    @State private var isSaving = false
    @State private var statusMessage = ""
    @State private var statusIsError = false
    @State private var showDiffSheet = false
    @State private var showPairingFlow = false

    private let ruleEngine = RuleEngine.shared

    var hasUnsavedChanges: Bool {
        guard let a = try? JSONEncoder().encode(draftConfig),
              let b = try? JSONEncoder().encode(savedConfig) else {
            return false
        }
        return a != b
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            HStack(spacing: 0) {
                sidebar.frame(width: 230)
                MacDivider()
                mainPanel
            }

            if hasUnsavedChanges {
                saveBar.transition(.move(edge: .bottom))
            }
        }
        .frame(minWidth: 980, minHeight: 640)
        .background(Color.paper)
        .onAppear { loadConfig() }
        .sheet(isPresented: $showDiffSheet) {
            DiffSheet(diffLines: diffLines(),
                      onCancel: { showDiffSheet = false },
                      onSave: { showDiffSheet = false; persistDraft() })
        }
        .sheet(isPresented: $showPairingFlow) {
            PairingFlowView { result in
                finishPairing(result)
            }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Note: the v2 redesign mock-up assumed a chromeless window and
            // drew a fake "Bastion · Settings" label + decorative traffic
            // lights here. The SwiftUI `Settings` scene gives this window
            // a real macOS title bar, so the fake header used to stack on
            // top of the real one. Killing the fake row removes both
            // visual clutter and the cosmetic "red/yellow/green dots that
            // don't do anything" complaint.
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    SidebarSection(title: "Defaults") {
                        SidebarRow(label: "Default profile", icon: AnyView(ShieldGlyph(size: 13, color: .ink500)),
                                   selected: selection == .defaultProfile) { selection = .defaultProfile }
                        SidebarRow(label: "App preferences", icon: AnyView(GearGlyph(size: 13)),
                                   selected: selection == .appPreferences) { selection = .appPreferences }
                        SidebarRow(label: "Rule templates", icon: AnyView(TemplatesGlyph(size: 13)),
                                   selected: selection == .ruleTemplates) { selection = .ruleTemplates }
                        SidebarRow(label: "High-value rule", icon: AnyView(WarnGlyph(size: 13)),
                                   selected: selection == .highValueRule) { selection = .highValueRule }
                        SidebarRow(label: "Address book", icon: AnyView(BookGlyph(size: 13)),
                                   selected: selection == .addressBook) { selection = .addressBook }
                        SidebarRow(label: "Policy simulator", icon: AnyView(SimulatorGlyph(size: 13)),
                                   selected: selection == .policySimulator) { selection = .policySimulator }
                        SidebarRow(label: "Policy history", icon: AnyView(HistoryGlyph(size: 13)),
                                   selected: selection == .policyHistory) { selection = .policyHistory }
                    }

                    SidebarSection(title: "Clients", trailing: AnyView(
                        Button {
                            showPairingFlow = true
                        } label: { Text("+").font(.system(size: 12)) }
                            .bastionButton(.ghost, size: .small)
                    )) {
                        if draftConfig.clientProfiles.isEmpty {
                            Text("No agents paired yet")
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                        }
                        ForEach(draftConfig.clientProfiles) { profile in
                            SidebarRow(
                                label: profile.label ?? profile.bundleId,
                                sublabel: profile.bundleId,
                                statusDot: .idle,
                                selected: selection == .client(id: profile.id)
                            ) { selection = .client(id: profile.id) }
                        }
                    }

                    SidebarSection(title: "Wallet groups") {
                        if draftConfig.walletGroups.isEmpty {
                            Text("No groups")
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                        }
                        ForEach(draftConfig.walletGroups) { group in
                            SidebarRow(
                                label: group.label.isEmpty ? "Wallet Group" : group.label,
                                icon: AnyView(GroupGlyph(size: 13)),
                                selected: selection == .walletGroup(id: group.id)
                            ) { selection = .walletGroup(id: group.id) }
                        }
                    }
                }
                .padding(.vertical, 4)
            }

            BastionDivider()

            VStack(spacing: 8) {
                Button {
                    AuditHistoryWindowManager.shared.showWindow()
                } label: {
                    HStack {
                        Text("Audit history")
                        Spacer()
                        Text("⌘⇧H")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Color.ink400)
                    }
                    .frame(maxWidth: .infinity)
                }
                .bastionButton(.default)
                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.system(size: 11))
                        .foregroundStyle(statusIsError ? Color.bastionBad : Color.bastionOk)
                        .lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(10)
        }
        .background(Color.ink50)
    }

    // MARK: - Main panel

    @ViewBuilder
    private var mainPanel: some View {
        switch selection {
        case .appPreferences:
            AppPreferencesPanel(
                bundlerPreferences: Binding(
                    get: { draftConfig.bundlerPreferences },
                    set: { draftConfig.bundlerPreferences = $0 }
                )
            )
        case .addressBook:
            AddressBookPanel(addressBook: Binding(
                get: { draftConfig.addressBook },
                set: { draftConfig.addressBook = $0 }
            ))
        case .policySimulator:
            PolicySimulatorView(config: draftConfig)
        case .policyHistory:
            PolicyHistoryPanel(onRestore: restoreVersion)
        case .highValueRule:
            HighValueRulePanel(highValue: Binding(
                get: { draftConfig.highValue },
                set: { draftConfig.highValue = $0 }
            ))
        case .ruleTemplates:
            RuleTemplatesPanel(
                profileCount: draftConfig.clientProfiles.count,
                onApplyToDefault: applyTemplateToDefault,
                onPair: { showPairingFlow = true }
            )
        case .defaultProfile:
            ProfilePanel(
                profileLabel: "Default profile",
                profileSubtitle: "Applies to clients without an explicit profile",
                rulesBinding: Binding(
                    get: { draftConfig.rules },
                    set: { draftConfig.rules = $0 }
                ),
                authPolicyBinding: Binding(
                    get: { draftConfig.authPolicy },
                    set: { draftConfig.authPolicy = $0 }
                ),
                profile: nil,
                onLaunchTestApproval: launchTestApproval,
                onLaunchTestViolation: launchTestViolation
            )
        case .client(let id):
            if let idx = draftConfig.clientProfiles.firstIndex(where: { $0.id == id }) {
                ProfilePanel(
                    profileLabel: draftConfig.clientProfiles[idx].label ?? draftConfig.clientProfiles[idx].bundleId,
                    profileSubtitle: draftConfig.clientProfiles[idx].bundleId,
                    rulesBinding: Binding(
                        get: { draftConfig.clientProfiles[idx].rules },
                        set: { draftConfig.clientProfiles[idx].rules = $0 }
                    ),
                    authPolicyBinding: Binding(
                        get: { draftConfig.clientProfiles[idx].authPolicy ?? draftConfig.authPolicy },
                        set: { draftConfig.clientProfiles[idx].authPolicy = $0 }
                    ),
                    profile: draftConfig.clientProfiles[idx],
                    onLaunchTestApproval: launchTestApproval,
                    onLaunchTestViolation: launchTestViolation
                )
            } else {
                EmptySelection()
            }
        case .walletGroup(let id):
            if let group = draftConfig.walletGroups.first(where: { $0.id == id }) {
                WalletGroupPanel(group: group)
            } else {
                EmptySelection()
            }
        }
    }

    // MARK: - Save bar

    private var saveBar: some View {
        HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text("Unsaved changes")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Color.bastionAccentDeep)
                Text("\(diffLines().count) changes will affect running agents on next request")
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.ink500)
            }
            Spacer()
            Button("Discard") { draftConfig = savedConfig }
                .bastionButton(.default)
            Button("Review diff") { showDiffSheet = true }
                .bastionButton(.default)
            Button(isSaving ? "Saving…" : "Save") { persistDraft() }
                .bastionButton(.primary)
                .disabled(isSaving)
        }
        .padding(EdgeInsets(top: 12, leading: 28, bottom: 12, trailing: 28))
        .background(
            Color.bastionAccentSoft.opacity(0.55)
                .overlay(Color.paper.opacity(0.65))
        )
        .overlay(BastionDivider(), alignment: .top)
    }

    // MARK: - Logic

    private func loadConfig() {
        let cfg = ruleEngine.config
        draftConfig = cfg
        savedConfig = cfg
        if case .client(let id) = selection,
           !cfg.clientProfiles.contains(where: { $0.id == id }) {
            selection = .defaultProfile
        }
    }

    /// Loads a previous policy version into the draft config. The save bar
    /// will appear so the owner can review and confirm — this never restores
    /// silently.
    private func restoreVersion(_ config: BastionConfig) {
        draftConfig = config
        statusMessage = "Loaded version into draft. Review and Save to apply."
        statusIsError = false
    }

    private func persistDraft() {
        isSaving = true
        statusMessage = ""
        let snapshot = draftConfig
        Task {
            do {
                try await ruleEngine.updateConfig(snapshot)
                await MainActor.run {
                    savedConfig = snapshot
                    statusMessage = "Saved"
                    statusIsError = false
                    isSaving = false
                }
            } catch {
                await MainActor.run {
                    statusMessage = "Error: \(error.localizedDescription)"
                    statusIsError = true
                    isSaving = false
                }
            }
        }
    }

    private func launchTestApproval() {
        #if DEBUG
        SigningRequestPanelManager.shared.showRequest(
            SigningRequestPreviewFactory.policyReview(),
            onApprove: {}, onDeny: {}
        )
        #endif
    }

    private func launchTestViolation() {
        #if DEBUG
        SigningRequestPanelManager.shared.showRequest(
            SigningRequestPreviewFactory.ruleOverride(),
            onApprove: {}, onDeny: {}
        )
        #endif
    }

    private func applyTemplateToDefault(_ template: PairingPolicyTemplate) {
        draftConfig.authPolicy = template.authPolicy
        draftConfig.rules = template.rules
        statusMessage = "Applied \(template.title) to the default profile"
        statusIsError = false
        selection = .defaultProfile
    }

    private func finishPairing(_ result: PairingResult) {
        let bundleId = result.bundleId
        guard !bundleId.isEmpty else {
            statusMessage = "Pairing failed: bundle ID is required"
            statusIsError = true
            return
        }

        var rules = result.template.rules
        rules.allowedChains = result.allowedChains.isEmpty ? nil : result.allowedChains

        if let existing = draftConfig.clientProfiles.firstIndex(where: { $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame }) {
            draftConfig.clientProfiles[existing].label = result.displayName.isEmpty ? nil : result.displayName
            draftConfig.clientProfiles[existing].authPolicy = result.template.authPolicy
            draftConfig.clientProfiles[existing].rules = rules
            selection = .client(id: draftConfig.clientProfiles[existing].id)
        } else {
            let profile = ClientProfile(
                bundleId: bundleId,
                label: result.displayName.isEmpty ? nil : result.displayName,
                authPolicy: result.template.authPolicy,
                rules: rules
            )
            draftConfig.clientProfiles.append(profile)
            draftConfig.clientProfiles.sort {
                $0.displayDescription.localizedCaseInsensitiveCompare($1.displayDescription) == .orderedAscending
            }
            selection = .client(id: profile.id)
        }

        statusMessage = "Paired \(result.displayName.isEmpty ? bundleId : result.displayName)"
        statusIsError = false
    }

    private func diffLines() -> [DiffLine] {
        var lines: [DiffLine] = []
        if savedConfig.authPolicy != draftConfig.authPolicy {
            lines.append(DiffLine(removed: "Auth policy: \(savedConfig.authPolicy.displayName)",
                                  added: "Auth policy: \(draftConfig.authPolicy.displayName)"))
        }
        let savedHours = formatHours(savedConfig.rules.allowedHours)
        let draftHours = formatHours(draftConfig.rules.allowedHours)
        if savedHours != draftHours {
            lines.append(DiffLine(removed: "Allowed hours: \(savedHours)",
                                  added: "Allowed hours: \(draftHours)"))
        }
        if savedConfig.rules.spendingLimits.count != draftConfig.rules.spendingLimits.count {
            lines.append(DiffLine(
                removed: "Spending limits: \(savedConfig.rules.spendingLimits.count) rules",
                added: "Spending limits: \(draftConfig.rules.spendingLimits.count) rules"
            ))
        }
        if savedConfig.rules.rateLimits.count != draftConfig.rules.rateLimits.count {
            lines.append(DiffLine(
                removed: "Rate limits: \(savedConfig.rules.rateLimits.count) rules",
                added: "Rate limits: \(draftConfig.rules.rateLimits.count) rules"
            ))
        }
        if savedConfig.rules.rawMessagePolicy.enabled != draftConfig.rules.rawMessagePolicy.enabled {
            lines.append(DiffLine(
                removed: "Raw message signing: \(savedConfig.rules.rawMessagePolicy.enabled ? "on" : "off")",
                added: "Raw message signing: \(draftConfig.rules.rawMessagePolicy.enabled ? "on" : "off")"
            ))
        }
        if savedConfig.rules.typedDataPolicy.enabled != draftConfig.rules.typedDataPolicy.enabled {
            lines.append(DiffLine(
                removed: "EIP-712 typed data: \(savedConfig.rules.typedDataPolicy.enabled ? "on" : "off")",
                added: "EIP-712 typed data: \(draftConfig.rules.typedDataPolicy.enabled ? "on" : "off")"
            ))
        }
        return lines
    }

    private func formatHours(_ hours: AllowedHours?) -> String {
        guard let h = hours else { return "any time" }
        return String(format: "%02d:00–%02d:00", h.start, h.end)
    }
}

// MARK: - MacDivider (vertical 1px hairline)

private struct MacDivider: View {
    var body: some View {
        Rectangle().fill(Color.ink150).frame(width: 1)
    }
}

// MARK: - Sidebar bits

private struct SidebarSection<Content: View>: View {
    let title: String
    var trailing: AnyView? = nil
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                BastionSectionLabel(text: title)
                Spacer()
                if let trailing { trailing }
            }
            .padding(EdgeInsets(top: 8, leading: 12, bottom: 4, trailing: 12))
            content()
        }
        .padding(.bottom, 6)
    }
}

private struct SidebarRow: View {
    let label: String
    var sublabel: String? = nil
    var icon: AnyView? = nil
    var statusDot: StatusDot.State? = nil
    let selected: Bool
    let action: () -> Void

    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let icon {
                    icon.frame(width: 16)
                } else if let dot = statusDot {
                    StatusDot(state: dot)
                        .padding(.horizontal, 4.5)
                } else {
                    Color.clear.frame(width: 16)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(label)
                        .font(.system(size: 12.5, weight: selected ? .medium : .regular))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    if let sublabel {
                        Text(sublabel)
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundStyle(Color.ink500)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(selected ? Color.paper : (hovered ? Color.ink100 : .clear))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(selected ? Color.ink150 : .clear, lineWidth: 1)
                    )
                    .shadow(color: selected ? Color.black.opacity(0.04) : .clear, radius: 1, y: 1)
            )
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .padding(.horizontal, 8)
        .padding(.bottom, 1)
    }
}

private struct GearGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "gear")
            .font(.system(size: size, weight: .regular))
            .foregroundStyle(Color.ink500)
    }
}

private struct GroupGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "person.2.fill")
            .font(.system(size: size * 0.85))
            .foregroundStyle(Color.ink500)
    }
}

private struct TemplatesGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "list.bullet.rectangle.portrait")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct WarnGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "exclamationmark.triangle")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct BookGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "book")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct SimulatorGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "play.rectangle")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct HistoryGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "clock.arrow.circlepath")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct EmptySelection: View {
    var body: some View {
        VStack(spacing: 6) {
            Spacer()
            Text("Selection unavailable").font(.system(size: 14, weight: .medium))
            Text("The item you selected no longer exists.")
                .font(.system(size: 12))
                .foregroundStyle(Color.ink500)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Profile panel (default OR per-client)

private struct ProfilePanel: View {
    let profileLabel: String
    let profileSubtitle: String
    @Binding var rulesBinding: RuleConfig
    @Binding var authPolicyBinding: AuthPolicy
    let profile: ClientProfile?
    let onLaunchTestApproval: () -> Void
    let onLaunchTestViolation: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    operationsCard
                    targetsCard
                    globalCapsCard
                    authCard
                    if let profile { validatorCard(profile: profile) }
                }
                .padding(EdgeInsets(top: 18, leading: 28, bottom: 80, trailing: 28))
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Text(profileLabel)
                        .font(.system(size: 18, weight: .semibold))
                        .kerning(-0.36)
                    BastionChip(label: profileSubtitle, style: .outline)
                    if let profile, let activity = profileActivity(profile) {
                        BastionChip(label: activity.label, style: activity.style,
                                    leading: AnyView(StatusDot(state: activity.dot)))
                    }
                }
                if let profile, let address = accountAddressForProfile(profile) {
                    HStack(spacing: 10) {
                        Text("Account").font(.system(size: 12)).foregroundStyle(Color.ink500)
                        AddressView(address: address)
                    }
                }
            }
            Spacer()
            #if DEBUG
            HStack(spacing: 8) {
                Button("Test approval", action: onLaunchTestApproval)
                    .bastionButton(.default)
                Button("Test violation", action: onLaunchTestViolation)
                    .bastionButton(.danger)
            }
            #endif
        }
        .padding(EdgeInsets(top: 18, leading: 28, bottom: 16, trailing: 28))
    }

    private var operationsCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 0) {
                BastionSectionHeader(
                    title: "Operations",
                    subtitle: "Posture per operation type. Posture replaces the old enable/approve toggle pair so the behaviour you pick is unambiguous."
                )
                PosturePicker(
                    label: "Raw / personal-sign messages",
                    hint: "EIP-191. No chain or contract binding.",
                    binding: Binding(
                        get: { rulesBinding.rawMessagePolicy.posture },
                        set: { rulesBinding.rawMessagePolicy.posture = $0 }
                    )
                )
                BastionDivider()
                PosturePicker(
                    label: "EIP-712 typed data",
                    hint: "Domain allowlist + JSON subset matching enforced below.",
                    binding: Binding(
                        get: { rulesBinding.typedDataPolicy.posture },
                        set: { rulesBinding.typedDataPolicy.posture = $0 }
                    )
                )
                BastionDivider()
                PosturePicker(
                    label: "ERC-4337 user operations",
                    hint: "Calldata-decoded targets and spending caps enforced below.",
                    binding: Binding(
                        get: { rulesBinding.userOpPosture },
                        set: { rulesBinding.userOpPosture = $0 }
                    )
                )
            }
        }
    }

    private var targetsCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(
                    title: "Targets & per-target caps",
                    subtitle: "Decoded inner-call destinations. Each can have its own daily spend cap."
                ) {
                    Button {
                        // backend feature gap — see task #12
                    } label: { Text("Add target").font(.system(size: 12)) }
                        .bastionButton(.default, size: .small)
                }

                if (rulesBinding.allowedTargets ?? [:]).isEmpty {
                    Text("No targets configured. Without an allowlist, every decoded inner-call target is allowed.")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                        .padding(.vertical, 4)
                } else {
                    targetTable
                }
            }
        }
    }

    private var targetTable: some View {
        let entries: [(chainId: Int, addr: String)] = (rulesBinding.allowedTargets ?? [:])
            .flatMap { (chainKey, addrs) -> [(Int, String)] in
                guard let chainId = Int(chainKey) else { return [] }
                return addrs.map { (chainId, $0) }
            }
            .sorted { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }

        return VStack(spacing: 0) {
            HStack {
                Text("Chain").frame(width: 110, alignment: .leading)
                Text("Target").frame(maxWidth: .infinity, alignment: .leading)
                Text("Cap").frame(width: 130, alignment: .leading)
                Text("Used 24h").frame(width: 110, alignment: .leading)
                Color.clear.frame(width: 24)
            }
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(Color.ink500)
            .padding(.bottom, 6)
            BastionDivider()
            ForEach(Array(entries.enumerated()), id: \.offset) { _, row in
                HStack(spacing: 8) {
                    ChainBadge(chainId: row.chainId, size: .small).frame(width: 110, alignment: .leading)
                    AddressView(address: row.addr).frame(maxWidth: .infinity, alignment: .leading)
                    Text("—")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .frame(width: 130, alignment: .leading)
                        .help("Per-target caps require backend support — see task #12")
                    Text("—")
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .frame(width: 110, alignment: .leading)
                    Button {
                        removeTarget(chainId: row.chainId, address: row.addr)
                    } label: { Text("×").font(.system(size: 14)) }
                        .bastionButton(.ghost, size: .small)
                        .frame(width: 24)
                }
                .padding(.vertical, 12)
                Rectangle().fill(Color.ink150).frame(height: 1)
            }
        }
    }

    private var globalCapsCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(
                    title: "Global caps",
                    subtitle: "Apply across all targets. Tightest cap wins."
                )
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    if let usdc = spendingLimit(for: .usdc) {
                        CapTile(label: "Total USDC/day",
                                value: formatAllowance(usdc.allowance, decimals: 6),
                                used: 0, total: tokenAmount(usdc.allowance, decimals: 6),
                                unit: " USDC", warn: false)
                    }
                    if let eth = spendingLimit(for: .eth) {
                        CapTile(label: "Total ETH/day",
                                value: formatAllowance(eth.allowance, decimals: 18),
                                used: 0, total: tokenAmount(eth.allowance, decimals: 18),
                                unit: " ETH", warn: false)
                    }
                    if let rl = rulesBinding.rateLimits.first {
                        CapTile(label: "Signatures/\(RateLimitRule.formatWindow(rl.windowSeconds))",
                                value: "\(rl.maxRequests)",
                                used: 0, total: Double(rl.maxRequests), unit: "")
                    }
                    if let hours = rulesBinding.allowedHours {
                        CapTile(label: "Allowed hours",
                                value: String(format: "%02d:00 – %02d:00", hours.start, hours.end),
                                used: nil, total: nil, unit: "")
                    } else {
                        CapTile(label: "Allowed hours",
                                value: "any time",
                                used: nil, total: nil, unit: "")
                    }
                }
            }
        }
    }

    private var authCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(
                    title: "Authentication policy",
                    subtitle: "When rules pass, what should Bastion do?"
                )
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 8) {
                    AuthOption(
                        label: "Silent",
                        hint: "Sign immediately when rules pass",
                        selected: authPolicyBinding == .open
                    ) { authPolicyBinding = .open }
                    AuthOption(
                        label: "Biometric",
                        hint: "Touch ID required after rules pass",
                        selected: authPolicyBinding == .biometric
                    ) { authPolicyBinding = .biometric }
                    AuthOption(
                        label: "Always confirm",
                        hint: "Owner approves every signature",
                        selected: authPolicyBinding == .biometricOrPasscode
                    ) { authPolicyBinding = .biometricOrPasscode }
                }
                HStack(alignment: .top, spacing: 10) {
                    ShieldGlyph(size: 14, color: .bastionAccentDeep)
                    Text("Rule violations always require owner authentication, regardless of this setting.")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.bastionAccentDeep)
                }
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 8).fill(Color.bastionAccentSoft)
                )
            }
        }
    }

    @ViewBuilder
    private func validatorCard(profile: ClientProfile) -> some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(title: "On-chain validator")
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill(Color.bastionOkSoft)
                        CheckGlyph(size: 16, color: .bastionOk)
                    }
                    .frame(width: 36, height: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Validator key tag")
                            .font(.system(size: 13, weight: .medium))
                        HStack(spacing: 6) {
                            Text("Tag")
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                            Text(profile.keyTag)
                                .font(.system(size: 11.5, design: .monospaced))
                                .foregroundStyle(Color.ink700)
                        }
                    }
                    Spacer()
                }
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 10).fill(Color.ink50)
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.ink150, lineWidth: 1))
                )

                BastionSectionHeader(
                    title: "Revoke",
                    subtitle: "Two distinct actions. Revoke local key destroys the SE key on this Mac. Uninstall on-chain validator submits a UserOp removing the validator module from the smart account."
                )
                HStack(spacing: 8) {
                    Button("Revoke local key") {
                        Task { await revokeLocalKey(profile: profile) }
                    }
                    .bastionButton(.danger, size: .small)

                    Button("Uninstall on-chain validator") {
                        Task {
                            await uninstallOnChain(profile: profile)
                        }
                    }
                    .bastionButton(.danger, size: .small)
                }
            }
        }
    }

    /// Destroys the agent's Secure Enclave key on this Mac. Requires owner
    /// biometric/passcode — without auth a malicious app could synthesize
    /// clicks and permanently delete signing keys.
    private func revokeLocalKey(profile: ClientProfile) async {
        do {
            try await AuthManager.shared.authenticate(
                policy: .biometricOrPasscode,
                reason: "Authorize destruction of \(profile.label ?? profile.bundleId)'s signing key"
            )
        } catch {
            NSLog("[Bastion] Revoke local key cancelled: %@", String(describing: error))
            return
        }
        let removed = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: [profile.keyTag])
        NSLog("[Bastion] Revoked local key for %@ — removed: %@",
              profile.label ?? profile.bundleId,
              removed.joined(separator: ", "))
    }

    private func uninstallOnChain(profile: ClientProfile) async {
        guard let groupId = profile.walletGroupId,
              let memberId = profile.membershipId,
              let group = RuleEngine.shared.config.walletGroups.first(where: { $0.id == groupId }),
              let chainId = group.chainIds.first else {
            NSLog("[Bastion] Uninstall skipped — profile has no wallet group membership or chain")
            return
        }
        do {
            _ = try await RuleEngine.shared.uninstallAgentOnChain(
                groupId: groupId,
                memberId: memberId,
                chainId: chainId,
                projectId: nil,
                submit: true
            )
        } catch {
            NSLog("[Bastion] Uninstall failed: %@", String(describing: error))
        }
    }

    // MARK: - Helpers

    /// Derives an activity chip from the audit log — shows "Active" when the
    /// profile signed something in the last hour, "Idle" otherwise. Returns
    /// nil so the chip is hidden entirely if nothing's ever been signed.
    private struct ActivityChip {
        let label: String
        let style: BastionChip.Style
        let dot: StatusDot.State
    }

    private func profileActivity(_ profile: ClientProfile) -> ActivityChip? {
        let displayName = profile.label ?? profile.bundleId
        let recent = AuditLog.shared.recentRequestRecords(limit: 50)
        let matches = recent.filter { $0.clientDisplayName == displayName }
        guard let last = matches.first?.latestTimestamp else {
            return nil
        }
        let elapsed = Date().timeIntervalSince(last)
        if elapsed < 3600 {
            return ActivityChip(label: "Active", style: .ok, dot: .ok)
        }
        if elapsed < 86_400 {
            return ActivityChip(label: "Idle today", style: .neutral, dot: .idle)
        }
        return ActivityChip(label: "Inactive", style: .neutral, dot: .idle)
    }

    private func accountAddressForProfile(_ profile: ClientProfile) -> String? {
        // Non-creating lookup: if the SE key doesn't exist yet (fresh
        // profile, never signed) we return nil instead of triggering a
        // biometric prompt to materialise one. The header just hides the
        // address until the first real sign creates the key.
        SecureEnclaveManager.shared.getPublicKeyIfExists(keyTag: profile.keyTag)?.accountAddress
    }

    private func spendingLimit(for token: TokenIdentifier) -> SpendingLimitRule? {
        rulesBinding.spendingLimits.first { rule in
            switch (rule.token, token) {
            case (.eth, .eth): return true
            case (.usdc, .usdc): return true
            case (.erc20(let a, let c), .erc20(let b, let d)):
                return a.caseInsensitiveCompare(b) == .orderedSame && c == d
            default: return false
            }
        }
    }

    private func tokenAmount(_ raw: String, decimals: Int) -> Double {
        Double(raw).map { $0 / pow(10, Double(decimals)) } ?? 0
    }

    private func formatAllowance(_ raw: String, decimals: Int) -> String {
        let n = tokenAmount(raw, decimals: decimals)
        if n == n.rounded() && n < 1e9 {
            return String(Int(n))
        }
        return String(format: n < 1 ? "%.4g" : "%.2f", n)
    }

    private func removeTarget(chainId: Int, address: String) {
        let key = String(chainId)
        var allowed = rulesBinding.allowedTargets ?? [:]
        var addrs = allowed[key] ?? []
        addrs.removeAll { $0.caseInsensitiveCompare(address) == .orderedSame }
        if addrs.isEmpty {
            allowed.removeValue(forKey: key)
        } else {
            allowed[key] = addrs
        }
        rulesBinding.allowedTargets = allowed.isEmpty ? nil : allowed
    }
}

// MARK: - CapTile

// Posture picker — three-way SigningPosture selector rendered as a
// macOS-style segmented control. PR2 introduced the picker as three
// individual button pills in a row; polish task #52 redesigns it as a
// single rounded container with one selected segment so it reads as a
// group rather than three loose buttons. The selected segment carries
// the dark fill, unselected segments are paper-on-light with a subtle
// hover state.
private struct PosturePicker: View {
    let label: String
    let hint: String
    @Binding var binding: SigningPosture

    private static let cornerRadius: CGFloat = 7
    private static let segmentHeight: CGFloat = 28

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.system(size: 13)).foregroundStyle(Color.ink900)
                Text(hint).font(.system(size: 12)).foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)
            }
            segmentedControl
        }
        .padding(.vertical, 10)
    }

    private var segmentedControl: some View {
        HStack(spacing: 0) {
            ForEach(Array(SigningPosture.allCases.enumerated()), id: \.element) { index, posture in
                segmentButton(posture: posture)
                if index < SigningPosture.allCases.count - 1 {
                    // Hairline divider between segments — hidden when
                    // either neighbour is selected (the selected pill's
                    // outline already provides the boundary).
                    Rectangle()
                        .fill(Color.ink200)
                        .frame(width: 1, height: 14)
                        .opacity(neighbourSelected(at: index) ? 0 : 1)
                }
            }
        }
        .frame(height: Self.segmentHeight)
        .background(
            RoundedRectangle(cornerRadius: Self.cornerRadius)
                .fill(Color.ink50)
                .overlay(
                    RoundedRectangle(cornerRadius: Self.cornerRadius)
                        .strokeBorder(Color.ink150, lineWidth: 1)
                )
        )
    }

    private func segmentButton(posture: SigningPosture) -> some View {
        let isSelected = binding == posture
        return Button {
            withAnimation(.easeOut(duration: 0.12)) { binding = posture }
        } label: {
            Text(Self.postureShortLabel(posture))
                .font(.system(size: 11.5, weight: isSelected ? .semibold : .medium))
                .foregroundStyle(isSelected ? Color.paper : Color.ink700)
                .frame(maxWidth: .infinity)
                .frame(height: Self.segmentHeight - 4)
                .background(
                    RoundedRectangle(cornerRadius: Self.cornerRadius - 2)
                        .fill(isSelected ? Color.ink900 : .clear)
                        .padding(2)
                )
                .help(posture.hint)
        }
        .buttonStyle(.plain)
    }

    /// True if either segment immediately around index `i` (i.e. i or i+1)
    /// is selected. We hide the inter-segment hairline next to the
    /// selected pill so the pill's own outline stays visually clean.
    private func neighbourSelected(at i: Int) -> Bool {
        let cases = SigningPosture.allCases
        guard i + 1 < cases.count else { return false }
        return binding == cases[i] || binding == cases[i + 1]
    }

    private static func postureShortLabel(_ p: SigningPosture) -> String {
        switch p {
        case .enforceRulesAndAutoSign:           return "Auto-sign"
        case .enforceRulesAndRequireApproval:    return "Always confirm"
        case .requireApprovalWithoutRuleEvaluation: return "Skip rules"
        }
    }
}

private struct CapTile: View {
    let label: String
    let value: String
    var used: Double? = nil
    var total: Double? = nil
    var unit: String = ""
    var warn: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label).font(.system(size: 12)).foregroundStyle(Color.ink500)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(value)
                    .font(.system(size: 17, weight: .semibold, design: .monospaced))
                    .kerning(-0.17)
                Text(unit).font(.system(size: 11.5)).foregroundStyle(Color.ink500)
            }
            if let used, let total, total > 0 {
                BastionQuota(used: used, total: total, label: "Used today", unit: unit)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.ink50)
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.ink150, lineWidth: 1))
        )
    }
}

// MARK: - AuthOption

private struct AuthOption: View {
    let label: String
    let hint: String
    let selected: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .strokeBorder(selected ? Color.ink900 : Color.ink300, lineWidth: 1.5)
                            .frame(width: 14, height: 14)
                        if selected {
                            Circle().fill(Color.ink900).frame(width: 7, height: 7)
                        }
                    }
                    Text(label).font(.system(size: 13, weight: .medium)).foregroundStyle(Color.ink900)
                }
                Text(hint).font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 12, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(selected ? Color.ink50 : Color.paper)
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .strokeBorder(selected ? Color.ink700 : Color.ink150, lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - App preferences panel

private struct AppPreferencesPanel: View {
    @Binding var bundlerPreferences: BundlerPreferences
    @Bindable private var rpcMonitor = RPCHealthMonitor.shared

    private func dotState(for status: RPCStatus) -> StatusDot.State {
        switch status {
        case .ok:   return .ok
        case .warn: return .warn
        case .bad:  return .bad
        case .unknown: return .idle
        }
    }

    private func latencyLabel(_ sample: RPCHealthSample?) -> String {
        guard let sample else { return "not probed" }
        if let latency = sample.latencyMs {
            return "\(latency)ms"
        }
        return sample.error ?? "timeout"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "App preferences",
                subtitle: "ZeroDev project ID + per-chain RPCs."
            )
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    BastionCard {
                        VStack(alignment: .leading, spacing: 6) {
                            BastionSectionHeader(title: "ZeroDev")
                            Text("Project ID")
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                            TextField("zd_proj_…", text: Binding(
                                get: { bundlerPreferences.zeroDevProjectId ?? "" },
                                set: { bundlerPreferences.zeroDevProjectId = $0.isEmpty ? nil : $0 }
                            ))
                            .textFieldStyle(.plain)
                            .font(.system(size: 13, design: .monospaced))
                            .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                            .background(
                                RoundedRectangle(cornerRadius: 7)
                                    .fill(Color.paper)
                                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink200, lineWidth: 1))
                            )
                        }
                    }
                    BastionCard {
                        VStack(alignment: .leading, spacing: 0) {
                            BastionSectionHeader(title: "RPC endpoints") {
                                Button {
                                    // backend feature gap — adding a chain row needs a sheet; tracked
                                } label: { Text("Add chain").font(.system(size: 12)) }
                                    .bastionButton(.default, size: .small)
                            }
                            if bundlerPreferences.chainRPCs.isEmpty {
                                Text("No RPCs configured.")
                                    .font(.system(size: 12))
                                    .foregroundStyle(Color.ink500)
                                    .padding(.vertical, 12)
                            }
                            ForEach(bundlerPreferences.chainRPCs.indices, id: \.self) { idx in
                                Rectangle().fill(Color.ink150).frame(height: 1)
                                HStack(spacing: 12) {
                                    ChainBadge(chainId: bundlerPreferences.chainRPCs[idx].chainId, size: .small)
                                        .frame(width: 130, alignment: .leading)
                                    Text(bundlerPreferences.chainRPCs[idx].rpcURL)
                                        .font(.system(size: 12, design: .monospaced))
                                        .foregroundStyle(Color.ink700)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Spacer()
                                    let sample = rpcMonitor.samples[bundlerPreferences.chainRPCs[idx].chainId]
                                    HStack(spacing: 5) {
                                        StatusDot(state: dotState(for: sample?.status ?? .unknown))
                                        Text(latencyLabel(sample))
                                            .font(.system(size: 11))
                                            .foregroundStyle(Color.ink500)
                                    }
                                }
                                .padding(.vertical, 12)
                            }
                            HStack {
                                Spacer()
                                Button {
                                    rpcMonitor.probeNow()
                                } label: { Text("Probe now").font(.system(size: 11)) }
                                    .bastionButton(.ghost, size: .small)
                            }
                            .padding(.top, 4)
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }
}

// MARK: - Rule templates panel (preset cards)

private struct RuleTemplatesPanel: View {
    let profileCount: Int
    let onApplyToDefault: (PairingPolicyTemplate) -> Void
    let onPair: () -> Void

    private var templates: [PairingPolicyTemplate] {
        PairingPolicyTemplate.allCases.filter { $0 != .custom }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "Rule templates",
                subtitle: "Reusable starting points for new agents. Edit, clone, or create your own."
            ) {
                Button { onPair() } label: { Text("+ New agent").font(.system(size: 12)) }
                    .bastionButton(.primary, size: .small)
            }
            BastionDivider()
            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    ForEach(templates) { template in
                        TemplateCardView(
                            template: template,
                            profileCount: profileCount,
                            onApplyToDefault: { onApplyToDefault(template) },
                            onPair: onPair
                        )
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }

    private struct TemplateCardView: View {
        let template: PairingPolicyTemplate
        let profileCount: Int
        let onApplyToDefault: () -> Void
        let onPair: () -> Void

        var body: some View {
            BastionCard(padding: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    Text(template.title).font(.system(size: 14, weight: .semibold))
                    Text(template.hint).font(.system(size: 12)).foregroundStyle(Color.ink500)
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                        TemplateKV(key: "USDC/DAY", value: metric("USDC"))
                        TemplateKV(key: "ETH/DAY", value: metric("ETH"))
                        TemplateKV(key: "RATE", value: rateMetric)
                        TemplateKV(key: "AUTH", value: template.authPolicy.displayName)
                    }
                    .padding(10)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.ink50)
                            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.ink150, lineWidth: 1))
                    )
                    HStack(spacing: 8) {
                        Button("Apply to default", action: onApplyToDefault)
                            .bastionButton(.default, size: .small)
                        Button("Pair agent", action: onPair)
                            .bastionButton(.ghost, size: .small)
                        Spacer()
                        // Profile→template attribution isn't tracked yet, so a
                        // "Used by N" count would be guessed. Hidden until
                        // ClientProfile gains a templateId reference.
                    }
                }
            }
        }

        private func metric(_ tokenName: String) -> String {
            let token = tokenName == "USDC" ? TokenIdentifier.usdc : TokenIdentifier.eth
            guard let limit = template.rules.spendingLimits.first(where: { rule in
                switch (token, rule.token) {
                case (.usdc, .usdc), (.eth, .eth):
                    return true
                default:
                    return false
                }
            }) else {
                return "-"
            }

            let decimals = tokenName == "USDC" ? 6 : 18
            let raw = Double(limit.allowance) ?? 0
            let amount = raw / pow(10, Double(decimals))
            let formatted = amount == amount.rounded() ? String(Int(amount)) : String(format: "%.4g", amount)
            let window = limit.windowSeconds.map { "/\(RateLimitRule.formatWindow($0))" } ?? ""
            return "\(formatted)\(window)"
        }

        private var rateMetric: String {
            guard let limit = template.rules.rateLimits.first else { return "-" }
            return "\(limit.maxRequests)/\(RateLimitRule.formatWindow(limit.windowSeconds))"
        }
    }

    private struct TemplateKV: View {
        let key: String
        let value: String
        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text(key)
                    .font(.system(size: 10, weight: .semibold))
                    .kerning(0.4)
                    .foregroundStyle(Color.ink500)
                Text(value)
                    .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                    .foregroundStyle(Color.ink900)
            }
        }
    }
}

// MARK: - Address book panel

private struct AddressBookPanel: View {
    @Binding var addressBook: [AddressBookEntry]

    @State private var newAddress: String = ""
    @State private var newLabel: String = ""
    @State private var newChainId: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "Address book",
                subtitle: "Label addresses (Treasury, USDC, Uniswap Router, etc.) to make approvals and audit easier to read."
            )
            BastionDivider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    BastionCard {
                        VStack(alignment: .leading, spacing: 8) {
                            BastionSectionHeader(title: "Add entry")
                            HStack(spacing: 8) {
                                TextField("Address (0x…)", text: $newAddress)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 12, design: .monospaced))
                                TextField("Label", text: $newLabel)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 12))
                                TextField("Chain ID (optional)", text: $newChainId)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 12, design: .monospaced))
                                    .frame(width: 140)
                                Button("Add") { addEntry() }
                                    .bastionButton(.primary, size: .small)
                                    .disabled(newAddress.isEmpty || newLabel.isEmpty)
                            }
                        }
                    }

                    BastionCard {
                        VStack(alignment: .leading, spacing: 0) {
                            BastionSectionHeader(title: "Entries")
                            if addressBook.isEmpty {
                                Text("No labels yet. Add a few above.")
                                    .font(.system(size: 12))
                                    .foregroundStyle(Color.ink500)
                                    .padding(.vertical, 12)
                            }
                            ForEach(addressBook) { entry in
                                Rectangle().fill(Color.ink150).frame(height: 1)
                                HStack(spacing: 12) {
                                    Text(entry.label)
                                        .font(.system(size: 13, weight: .medium))
                                        .frame(width: 160, alignment: .leading)
                                    AddressView(address: entry.address)
                                    if let chain = entry.chainId {
                                        ChainBadge(chainId: chain, size: .small)
                                    } else {
                                        BastionChip(label: "any chain", style: .outline)
                                    }
                                    Spacer()
                                    Button {
                                        addressBook.removeAll { $0.id == entry.id }
                                    } label: { Text("×").font(.system(size: 14)) }
                                        .bastionButton(.ghost, size: .small)
                                }
                                .padding(.vertical, 12)
                            }
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }

    private func addEntry() {
        let trimmedAddress = newAddress.trimmingCharacters(in: .whitespaces)
        let trimmedLabel = newLabel.trimmingCharacters(in: .whitespaces).prefix(64) // bound display length
        // Validate the address looks like an Ethereum 20-byte hex address
        // before storing — labels for malformed strings are misleading and
        // could be used to disguise garbage in the approval popup.
        guard Self.isValidEthAddress(trimmedAddress) else { return }
        let chain = Int(newChainId.trimmingCharacters(in: .whitespaces))
        let entry = AddressBookEntry(
            address: trimmedAddress.lowercased(),
            label: String(trimmedLabel),
            chainId: chain
        )
        addressBook.append(entry)
        newAddress = ""
        newLabel = ""
        newChainId = ""
    }

    private static func isValidEthAddress(_ s: String) -> Bool {
        let stripped = s.hasPrefix("0x") ? String(s.dropFirst(2)) : s
        guard stripped.count == 40 else { return false }
        return stripped.allSatisfy { $0.isHexDigit }
    }
}

// MARK: - High-value rule panel

private struct HighValueRulePanel: View {
    @Binding var highValue: HighValueRule

    @State private var thresholdField: String = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "High-value rule",
                subtitle: "When a transfer exceeds the threshold, the approval popup forces the owner to type a confirmation phrase before signing."
            )
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    BastionCard {
                        VStack(alignment: .leading, spacing: 12) {
                            BastionToggleRow(
                                label: "Enable high-value confirmation",
                                hint: "Owners type a phrase to confirm transfers above the threshold.",
                                isOn: $highValue.enabled
                            )
                            BastionDivider()
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Threshold (USD-equivalent)").font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                                TextField("10000", text: thresholdBinding)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 13, design: .monospaced))
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Confirmation phrase").font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                                TextField("TRANSFER", text: $highValue.confirmationPhrase)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 13, design: .monospaced))
                            }
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .onAppear {
            thresholdField = String(Int(highValue.thresholdUsd))
        }
    }

    private var thresholdBinding: Binding<String> {
        Binding(
            get: { thresholdField.isEmpty ? String(Int(highValue.thresholdUsd)) : thresholdField },
            set: { newValue in
                thresholdField = newValue
                if let parsed = Double(newValue) {
                    highValue.thresholdUsd = parsed
                }
            }
        )
    }
}

// MARK: - Policy version history panel

private struct PolicyHistoryPanel: View {
    let onRestore: (BastionConfig) -> Void

    @State private var versions: [PolicyVersion] = []
    @State private var selectedVersionId: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "Policy history",
                subtitle: "Every saved policy change is snapshotted. Restore an older version with biometric auth."
            )
            BastionDivider()
            ScrollView {
                BastionCard {
                    VStack(alignment: .leading, spacing: 0) {
                        BastionSectionHeader(title: "Saved versions")
                        if versions.isEmpty {
                            Text("No prior versions recorded yet.")
                                .font(.system(size: 12))
                                .foregroundStyle(Color.ink500)
                                .padding(.vertical, 12)
                        }
                        ForEach(versions) { version in
                            Rectangle().fill(Color.ink150).frame(height: 1)
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(version.timestamp.formatted(date: .abbreviated, time: .standard))
                                        .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                                    Text(version.summary)
                                        .font(.system(size: 11))
                                        .foregroundStyle(Color.ink500)
                                }
                                Spacer()
                                Button("Restore") { onRestore(version.config) }
                                    .bastionButton(.default, size: .small)
                            }
                            .padding(.vertical, 12)
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .onAppear {
            versions = ConfigVersionStore.shared.versions()
        }
    }
}

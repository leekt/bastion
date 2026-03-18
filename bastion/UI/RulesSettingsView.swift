import Combine
import SwiftUI

private enum SidebarSelection: Equatable {
    case configuration
    case profile(id: String?) // nil = global default rules
}

private enum ConfigTab: String, CaseIterable {
    case appPreferences  = "App Preferences"
    case clientAllowlist = "Client Allowlist"

    var systemImage: String {
        switch self {
        case .appPreferences:  return "gear.circle"
        case .clientAllowlist: return "person.badge.key"
        }
    }
}

private enum RuleTab: String, CaseIterable {
    case overview      = "Overview"
    case rawMessage    = "Raw / Message"
    case eip712        = "EIP-712"
    case userOperation = "UserOperation"

    var systemImage: String {
        switch self {
        case .overview:      return "list.bullet.rectangle.portrait"
        case .rawMessage:    return "signature"
        case .eip712:        return "doc.text.magnifyingglass"
        case .userOperation: return "cpu"
        }
    }
}

struct RulesSettingsView: View {
    @State private var draftConfig: BastionConfig = .default
    @State private var sidebarSelection: SidebarSelection = .profile(id: nil)
    @State private var selectedConfigTab: ConfigTab = .appPreferences
    @State private var selectedRuleTab: RuleTab = .overview
    @State private var clientAccountAddresses: [String: String] = [:]

    @State private var newAllowedChain = ""
    @State private var newAllowedAccountChain = ""
    @State private var newAllowedAccountAddress = ""
    @State private var newAllowedClientBundleId = ""
    @State private var newAllowedClientLabel = ""
    @State private var newClientBundleId = ""
    @State private var newClientLabel = ""
    @State private var newRPCChainId = ""
    @State private var newRPCURL = ""
    @State private var newTypedDomainLabel = ""
    @State private var newTypedDomainPrimaryType = ""
    @State private var newTypedDomainName = ""
    @State private var newTypedDomainVersion = ""
    @State private var newTypedDomainChainId = ""
    @State private var newTypedDomainVerifyingContract = ""
    @State private var newTypedStructLabel = ""
    @State private var newTypedStructPrimaryType = ""
    @State private var newTypedStructMatcherJSON = "{\n  \n}"
    @State private var newRLMax = ""
    @State private var newRLWindow = "3600"
    @State private var newSLToken = "eth"
    @State private var newSLAllowance = ""
    @State private var newSLWindow = ""
    @State private var newSLErc20Address = ""
    @State private var newSLErc20ChainId = ""

    @State private var isSaving = false
    @State private var statusMessage = ""
    @State private var statusIsError = false

    private let ruleEngine = RuleEngine.shared

    var body: some View {
        NavigationSplitView {
            sidebar
                .navigationSplitViewColumnWidth(min: 248, ideal: 280, max: 312)
        } detail: {
            ZStack {
                backgroundGradient
                    .ignoresSafeArea()

                detailPage
            }
        }
        .navigationSplitViewStyle(.balanced)
        .frame(minWidth: 1180, minHeight: 860)
        .onAppear {
            loadCurrentConfig()
        }
    }

    private var backgroundGradient: some View {
        LinearGradient(
            colors: [
                Color(red: 0.965, green: 0.962, blue: 0.952),
                Color(red: 0.952, green: 0.958, blue: 0.964),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    private var summaryPillColumns: [GridItem] {
        [
            GridItem(.adaptive(minimum: 128), spacing: 8, alignment: .leading),
        ]
    }

    private var sidebar: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.84, green: 0.81, blue: 0.75),
                    Color(red: 0.84, green: 0.88, blue: 0.90),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(alignment: .leading, spacing: 12) {
                VStack(alignment: .leading, spacing: 3) {
                    Text("POLICY WORKSPACE")
                        .font(.caption2.weight(.black))
                        .kerning(1.3)
                        .foregroundStyle(Color(red: 0.45, green: 0.25, blue: 0.14))
                    Text("Bastion")
                        .font(.title2.weight(.bold))
                    Text("Select a profile to edit its rules.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(.horizontal, 14)
                .padding(.top, 14)

                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {

                        // Configuration
                        VStack(alignment: .leading, spacing: 8) {
                            sidebarSectionLabel("Configuration")
                            sidebarRow(
                                title: "App Settings",
                                subtitle: "Bundler project ID, RPC endpoints",
                                accountAddress: nil,
                                systemImage: "gear.circle.fill",
                                isSelected: sidebarSelection == .configuration
                            ) {
                                sidebarSelection = .configuration
                            }
                        }

                        // Global default rules
                        VStack(alignment: .leading, spacing: 8) {
                            sidebarSectionLabel("Default Rules")
                            sidebarRow(
                                title: "Global Defaults",
                                subtitle: "Template copied into new clients",
                                accountAddress: nil,
                                systemImage: "square.stack.3d.up.fill",
                                isSelected: sidebarSelection == .profile(id: nil)
                            ) {
                                sidebarSelection = .profile(id: nil)
                            }
                        }

                        // Per-client profiles
                        VStack(alignment: .leading, spacing: 8) {
                            sidebarSectionLabel("Clients")

                            if clientProfiles.isEmpty {
                                EmptyStateRow(
                                    icon: "person.badge.plus",
                                    title: "No clients yet",
                                    detail: "Profiles appear on first request, or create them below."
                                )
                            } else {
                                ForEach(clientProfiles) { profile in
                                    sidebarRow(
                                        title: profile.displayDescription,
                                        subtitle: profile.bundleId,
                                        accountAddress: clientAccountAddresses[profile.id],
                                        systemImage: "person.crop.rectangle.stack.fill",
                                        isSelected: sidebarSelection == .profile(id: profile.id)
                                    ) {
                                        sidebarSelection = .profile(id: profile.id)
                                    }
                                }
                            }
                        }
                    }
                    .padding(.horizontal, 10)
                }

                sidebarAddProfileForm
            }
        }
        .overlay(alignment: .trailing) {
            Rectangle()
                .fill(Color.white.opacity(0.65))
                .frame(width: 1)
                .ignoresSafeArea()
        }
    }

    private func ruleStatusSubtitle(_ enabled: Bool) -> String {
        enabled ? "Rule-based" : "Require approval"
    }

    @ViewBuilder
    private var detailPage: some View {
        switch sidebarSelection {
        case .configuration:
            configurationPage
        case .profile:
            profileDetailPage
        }
    }

    private var configurationPage: some View {
        VStack(spacing: 0) {
            tabBar(tabs: ConfigTab.allCases, selected: $selectedConfigTab)
            ZStack {
                backgroundGradient.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 14) {
                        switch selectedConfigTab {
                        case .appPreferences:
                            appPreferencesCard
                        case .clientAllowlist:
                            clientAllowlistCard
                        }
                    }
                    .padding(16)
                    .padding(.bottom, 96)
                    .frame(maxWidth: 940, alignment: .leading)
                }
                .safeAreaInset(edge: .bottom) { saveBar }
            }
        }
    }

    // MARK: - Profile detail (tab bar at top + tab content)

    private var profileDetailPage: some View {
        VStack(spacing: 0) {
            tabBar(tabs: RuleTab.allCases, selected: $selectedRuleTab)
            ZStack {
                backgroundGradient.ignoresSafeArea()
                ScrollView {
                    VStack(spacing: 14) {
                        profileTabContent
                    }
                    .padding(16)
                    .padding(.bottom, 96)
                    .frame(maxWidth: 940, alignment: .leading)
                }
                .safeAreaInset(edge: .bottom) { saveBar }
            }
        }
    }

    private func tabBar<T: RawRepresentable & Hashable & CaseIterable>(
        tabs: [T],
        selected: Binding<T>
    ) -> some View where T.RawValue == String {
        HStack(spacing: 0) {
            ForEach(Array(tabs), id: \.self) { tab in
                tabBarButton(label: tab.rawValue, systemImage: tabSystemImage(tab), isSelected: selected.wrappedValue == tab) {
                    selected.wrappedValue = tab
                }
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color.white.opacity(0.5))
                .frame(height: 1)
        }
    }

    private func tabSystemImage<T>(_ tab: T) -> String {
        if let t = tab as? ConfigTab { return t.systemImage }
        if let t = tab as? RuleTab   { return t.systemImage }
        return "circle"
    }

    private func tabBarButton(label: String, systemImage: String, isSelected: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: systemImage)
                    .font(.caption.weight(.semibold))
                Text(label)
                    .font(.subheadline.weight(isSelected ? .semibold : .regular))
            }
            .foregroundStyle(isSelected
                ? Color(red: 0.45, green: 0.25, blue: 0.14)
                : Color.secondary)
            .padding(.horizontal, 14)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(isSelected ? Color(red: 0.45, green: 0.25, blue: 0.14).opacity(0.10) : Color.clear)
            )
            .overlay(alignment: .bottom) {
                if isSelected {
                    Capsule()
                        .fill(Color(red: 0.45, green: 0.25, blue: 0.14))
                        .frame(height: 2.5)
                        .padding(.horizontal, 4)
                        .offset(y: 6)
                }
            }
        }
        .buttonStyle(.plain)
    }

    @ViewBuilder
    private var profileTabContent: some View {
        switch selectedRuleTab {
        case .overview:
            overviewTabContent
        case .rawMessage:
            rawMessageTabContent
        case .eip712:
            eip712TabContent
        case .userOperation:
            userOpTabContent
        }
    }

    private var overviewTabContent: some View {
        VStack(spacing: 14) {
            if selectedClientProfile != nil {
                heroCard
                clientIdentityCard
            }
            authenticationCard
            SettingsCard(
                icon: "list.bullet.rectangle.portrait.fill",
                accent: Color(red: 0.45, green: 0.25, blue: 0.14),
                title: "Rules Summary",
                subtitle: "Read-only snapshot of all signing rules for this profile."
            ) {
                VStack(alignment: .leading, spacing: 12) {
                    LazyVGrid(columns: summaryPillColumns, alignment: .leading, spacing: 8) {
                        SummaryPill(
                            title: "Raw / Message",
                            value: activeRules.rawMessagePolicy.enabled ? "Rule-based" : "Require Approval",
                            tint: Color(red: 0.15, green: 0.36, blue: 0.59)
                        )
                        SummaryPill(
                            title: "EIP-712",
                            value: activeRules.typedDataPolicy.enabled ? "Rule-based" : "Require Approval",
                            tint: Color(red: 0.44, green: 0.31, blue: 0.55)
                        )
                        SummaryPill(
                            title: "UserOperation",
                            value: activeRules.enabled ? "Rule-based" : "Require Approval",
                            tint: Color(red: 0.18, green: 0.45, blue: 0.34)
                        )
                        SummaryPill(
                            title: "Rate Limits",
                            value: "\(activeRules.rateLimits.count)",
                            tint: Color(red: 0.52, green: 0.33, blue: 0.18)
                        )
                        SummaryPill(
                            title: "Spend Limits",
                            value: "\(activeRules.spendingLimits.count)",
                            tint: Color(red: 0.21, green: 0.47, blue: 0.33)
                        )
                        if selectedClientProfile == nil {
                            SummaryPill(
                                title: "Clients",
                                value: "\(clientProfiles.count)",
                                tint: Color(red: 0.11, green: 0.39, blue: 0.63)
                            )
                        }
                    }
                }
            }
            if selectedClientProfile == nil {
                defaultScopeCard
            }
        }
    }

    private var rawMessageTabContent: some View {
        SettingsCard(
            icon: "signature",
            accent: Color(red: 0.15, green: 0.36, blue: 0.59),
            title: "Raw / Message Signing",
            subtitle: "Controls whether the CLI can request raw personal-sign payloads."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                Toggle("Enable rule-based signing for raw messages", isOn: rawMessageEnabledBinding)
                    .toggleStyle(.switch)
                    .font(.headline)

                Text(rawMessageEnabledBinding.wrappedValue
                    ? "Rule-based signing is active. Raw message requests proceed directly to the authentication gate."
                    : "Require-signing mode. Every raw message request triggers explicit biometric or passcode authentication.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var eip712TabContent: some View {
        let ruleEnabled = activeRules.typedDataPolicy.enabled
        return VStack(spacing: 14) {
            SettingsCard(
                icon: "doc.text.magnifyingglass",
                accent: Color(red: 0.44, green: 0.31, blue: 0.55),
                title: "EIP-712 Signing",
                subtitle: "Controls whether the CLI can request typed-data signatures."
            ) {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Enable rule-based EIP-712 signing", isOn: typedDataEnabledBinding)
                        .toggleStyle(.switch)
                        .font(.headline)

                    Text(ruleEnabled
                        ? "Rule-based signing is active. EIP-712 requests that pass domain and struct rules proceed to the authentication gate."
                        : "Require-signing mode. Every EIP-712 request triggers explicit authentication — domain and struct rules are not evaluated.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            typedDataCard
                .disabled(!ruleEnabled)
                .opacity(ruleEnabled ? 1 : 0.45)
        }
    }

    private var userOpTabContent: some View {
        let ruleEnabled = activeRules.enabled
        return VStack(spacing: 14) {
            SettingsCard(
                icon: "cpu.fill",
                accent: Color(red: 0.18, green: 0.45, blue: 0.34),
                title: "UserOperation Signing",
                subtitle: "Controls whether the CLI can autonomously submit UserOperations."
            ) {
                VStack(alignment: .leading, spacing: 12) {
                    Toggle("Enable rule-based UserOperation signing", isOn: rulesEnabledBinding)
                        .toggleStyle(.switch)
                        .font(.headline)

                    Text(ruleEnabled
                        ? "Rule-based signing is active. All checks below must pass before the UserOperation reaches the authentication gate."
                        : "Require-signing mode. Every UserOperation request triggers explicit authentication — no rule checks are applied.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }
            Group {
                accessControlsCard
                rateLimitCard
                spendingLimitCard
            }
            .disabled(!ruleEnabled)
            .opacity(ruleEnabled ? 1 : 0.45)
        }
    }

    private var appPreferencesCard: some View {
        SettingsCard(
            icon: "paperplane.circle",
            accent: Color(red: 0.17, green: 0.40, blue: 0.58),
            title: "App Preferences",
            subtitle: "Global submit/build settings used when clients do not pass a bundler override."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                TextField("ZeroDev Project ID", text: zeroDevProjectIdBinding)
                    .textFieldStyle(.roundedBorder)
                    .font(.system(.body, design: .monospaced))

                Text("Bastion-managed UserOp builds and submit flows use this project ID by default. CLI `--project-id` stays as an optional override for debugging.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if let projectId = draftConfig.bundlerPreferences.zeroDevProjectId, !projectId.isEmpty {
                    SettingsKeyValueRow(label: "Configured", value: projectId)
                } else {
                    EmptyStateRow(
                        icon: "exclamationmark.triangle",
                        title: "No bundler project configured",
                        detail: "High-level `bastion eth userOp --op ...` requests will fail until a ZeroDev project ID is stored here."
                    )
                }

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Chain RPC Endpoints")

                    Text("Bastion uses these URLs for `eth_call`, `eth_getCode`, `getNonce`, and fee estimation before signing. If a chain is not configured here, Bastion falls back to the bundler endpoint.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    if configuredRPCEndpoints.isEmpty {
                        EmptyStateRow(
                            icon: "network",
                            title: "No custom RPC endpoints",
                            detail: "Add per-chain RPC URLs if you want Bastion read calls to avoid the bundler endpoint."
                        )
                    } else {
                        VStack(spacing: 10) {
                            ForEach(configuredRPCEndpoints) { endpoint in
                                HStack(alignment: .firstTextBaseline, spacing: 12) {
                                    Text(ChainConfig.name(for: endpoint.chainId))
                                        .font(.subheadline.weight(.semibold))
                                        .frame(width: 130, alignment: .leading)

                                    Text("#\(endpoint.chainId)")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                        .frame(width: 60, alignment: .leading)

                                    Text(endpoint.rpcURL)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)

                                    removeButton {
                                        removeRPCPreference(endpoint)
                                    }
                                }
                                .padding(12)
                                .background(cardRowBackground)
                            }
                        }
                    }

                    HStack(spacing: 10) {
                        TextField("Chain ID", text: $newRPCChainId)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 120)

                        TextField("https://rpc.example.org", text: $newRPCURL)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))

                        Button("Add RPC") {
                            addRPCPreference()
                        }
                        .buttonStyle(.bordered)
                        .disabled(!canAddRPCPreference)
                    }
                }
            }
        }
    }

    private var heroCard: some View {
        SettingsCard(
            icon: "shield.lefthalf.filled.badge.checkmark",
            accent: Color(red: 0.82, green: 0.46, blue: 0.16),
            title: selectedClientProfile?.displayDescription ?? "Client Policy",
            subtitle: "\(selectedClientProfile?.bundleId ?? "") · Client-specific auth mode, account, and rule overrides."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                if let selectedClientProfile {
                    scopeDescriptorRow(
                        label: "Bundle ID",
                        value: selectedClientProfile.bundleId,
                        monospaced: true
                    )
                }

                LazyVGrid(columns: summaryPillColumns, alignment: .leading, spacing: 8) {
                    SummaryPill(
                        title: "UserOp Rules",
                        value: activeRules.enabled ? "Rule-based" : "Require Approval",
                        tint: activeRules.enabled ? .green : .orange
                    )
                    SummaryPill(
                        title: "Limits",
                        value: "\(activeRules.rateLimits.count + activeRules.spendingLimits.count)",
                        tint: Color(red: 0.52, green: 0.33, blue: 0.18)
                    )
                    if let accountAddress = activeAccountAddress {
                        SummaryPill(
                            title: "Account",
                            value: shortAddress(accountAddress),
                            tint: Color(red: 0.59, green: 0.27, blue: 0.19)
                        )
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var scopeSummaryCard: some View {
        EmptyView()
    }

    private func scopeDescriptorRow(label: String, value: String, monospaced: Bool = false) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Text(label.uppercased())
                .font(.caption2.weight(.black))
                .kerning(0.8)
                .foregroundStyle(.secondary)
                .frame(width: 72, alignment: .leading)

            Text(value)
                .font(monospaced ? .system(.caption, design: .monospaced) : .caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
    }

    private var authenticationCard: some View {
        SettingsCard(
            icon: "lock.shield",
            accent: Color(red: 0.13, green: 0.38, blue: 0.60),
            title: "Authentication",
            subtitle: "What you must prove before each signature is produced, after all rules pass."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                Picker("Auth Policy", selection: authPolicyBinding) {
                    ForEach(AuthPolicy.allCases, id: \.self) { policy in
                        Text(policy.displayName).tag(policy)
                    }
                }
                .pickerStyle(.segmented)

                Text(authFootnote)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Divider()

                Toggle("Show approval panel for every UserOperation", isOn: requireExplicitApprovalBinding)
                    .toggleStyle(.switch)

                Text("When on, Bastion shows a confirmation panel for each UserOp even when all rules pass. When off, UserOps that pass rules are signed silently without interrupting the agent.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var rawMessageCard: some View {
        SettingsCard(
            icon: "signature",
            accent: Color(red: 0.15, green: 0.36, blue: 0.59),
            title: "Raw / Message Signing",
            subtitle: "Simple binary policy for personal-sign style requests."
        ) {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Allow raw or personal message signing", isOn: rawMessageEnabledBinding)
                    .toggleStyle(.switch)

                Text("This mode stays intentionally binary: either the client may request raw or personal-sign payloads, or Bastion blocks them outright.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var typedDataCard: some View {
        SettingsCard(
            icon: "network.badge.shield.half.filled",
            accent: Color(red: 0.44, green: 0.31, blue: 0.55),
            title: "EIP-712 Domain & Struct Rules",
            subtitle: "Allowlist typed-data by domain fields and primary-type JSON matchers."
        ) {
            VStack(alignment: .leading, spacing: 14) {
                Toggle("Require explicit approval for matching EIP-712 requests", isOn: typedDataApprovalBinding)
                    .toggleStyle(.switch)

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Allowed Domains")

                    if activeRules.typedDataPolicy.domainRules.isEmpty {
                        EmptyStateRow(
                            icon: "network.badge.shield.half.filled",
                            title: "No domain rules",
                            detail: "If this stays empty, any domain is allowed while EIP-712 signing is enabled."
                        )
                    } else {
                        VStack(spacing: 10) {
                            ForEach(activeRules.typedDataPolicy.domainRules) { rule in
                                HStack(alignment: .top, spacing: 12) {
                                    VStack(alignment: .leading, spacing: 3) {
                                        Text(rule.displayDescription)
                                            .font(.subheadline.weight(.semibold))
                                        Text(domainRuleDescription(rule))
                                            .font(.caption)
                                            .foregroundStyle(.secondary)
                                            .fixedSize(horizontal: false, vertical: true)
                                    }

                                    Spacer()

                                    removeButton {
                                        removeTypedDataDomainRule(rule)
                                    }
                                }
                                .padding(12)
                                .background(cardRowBackground)
                            }
                        }
                    }

                    VStack(spacing: 10) {
                        HStack(spacing: 10) {
                            TextField("Label (optional)", text: $newTypedDomainLabel)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 180)
                            TextField("Primary Type", text: $newTypedDomainPrimaryType)
                                .textFieldStyle(.roundedBorder)
                            TextField("Domain Name", text: $newTypedDomainName)
                                .textFieldStyle(.roundedBorder)
                            TextField("Version", text: $newTypedDomainVersion)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 100)
                        }

                        HStack(spacing: 10) {
                            TextField("Chain ID", text: $newTypedDomainChainId)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 120)
                            TextField("Verifying Contract", text: $newTypedDomainVerifyingContract)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))
                            Button("Add Domain Rule") {
                                addTypedDataDomainRule()
                            }
                            .buttonStyle(.bordered)
                            .disabled(!canAddTypedDataDomainRule)
                        }
                    }
                }

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Struct Matchers")

                    Text("`matcherJSON` is matched as an exact subset against the EIP-712 `message` object. Leave fields out if you do not want to pin them.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    if activeRules.typedDataPolicy.structRules.isEmpty {
                        EmptyStateRow(
                            icon: "curlybraces.square",
                            title: "No struct matchers",
                            detail: "If this stays empty, any struct payload is allowed once the domain rule matches."
                        )
                    } else {
                        VStack(spacing: 10) {
                            ForEach(activeRules.typedDataPolicy.structRules) { rule in
                                VStack(alignment: .leading, spacing: 6) {
                                    HStack(alignment: .top) {
                                        VStack(alignment: .leading, spacing: 2) {
                                            Text(rule.displayDescription)
                                                .font(.subheadline.weight(.semibold))
                                            Text("Primary type: \(rule.primaryType)")
                                                .font(.caption)
                                                .foregroundStyle(.secondary)
                                        }

                                        Spacer()

                                        removeButton {
                                            removeTypedDataStructRule(rule)
                                        }
                                    }

                                    Text(rule.matcherJSON)
                                        .font(.system(.caption, design: .monospaced))
                                        .textSelection(.enabled)
                                        .padding(10)
                                        .frame(maxWidth: .infinity, alignment: .leading)
                                        .background(Color.white.opacity(0.55))
                                        .clipShape(RoundedRectangle(cornerRadius: 12, style: .continuous))
                                }
                                .padding(12)
                                .background(cardRowBackground)
                            }
                        }
                    }

                    VStack(alignment: .leading, spacing: 10) {
                        HStack(spacing: 10) {
                            TextField("Label (optional)", text: $newTypedStructLabel)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 180)
                            TextField("Primary Type", text: $newTypedStructPrimaryType)
                                .textFieldStyle(.roundedBorder)
                        }

                        TextEditor(text: $newTypedStructMatcherJSON)
                            .font(.system(.body, design: .monospaced))
                            .frame(minHeight: 120)
                            .padding(8)
                            .background(Color.white.opacity(0.7))
                            .clipShape(RoundedRectangle(cornerRadius: 14, style: .continuous))

                        HStack {
                            Button("Add Struct Rule") {
                                addTypedDataStructRule()
                            }
                            .buttonStyle(.bordered)
                            .disabled(!canAddTypedDataStructRule)

                            Spacer()
                        }
                    }
                }
            }
        }
    }

    private var clientAllowlistCard: some View {
        SettingsCard(
            icon: "person.badge.key.fill",
            accent: Color(red: 0.30, green: 0.20, blue: 0.50),
            title: "Client Allowlist",
            subtitle: "Restrict which apps may request signatures, matched by code-signed bundle ID."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                Text("If the list is empty, any process verified by Bastion's team ID (926A27BQ7W) can request a signature.")
                    .font(.caption)
                    .foregroundStyle(.secondary)

                if allowedClientEntries.isEmpty {
                    EmptyStateRow(
                        icon: "person.badge.key",
                        title: "No allowlist — all verified apps can sign",
                        detail: "Add bundle IDs below to restrict signing to specific apps."
                    )
                } else {
                    VStack(spacing: 10) {
                        ForEach(allowedClientEntries) { client in
                            HStack(alignment: .firstTextBaseline, spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    if let label = client.label {
                                        Text(label)
                                            .font(.subheadline.weight(.semibold))
                                    }
                                    Text(client.bundleId)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(client.label == nil ? .primary : .secondary)
                                }
                                Spacer()
                                removeButton { removeAllowedClient(client) }
                            }
                            .padding(12)
                            .background(cardRowBackground)
                        }
                    }
                }

                HStack(spacing: 10) {
                    TextField("com.example.agent", text: $newAllowedClientBundleId)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))
                    TextField("Label (optional)", text: $newAllowedClientLabel)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 180)
                    Button("Add") { addAllowedClient() }
                        .buttonStyle(.bordered)
                        .disabled(!canAddAllowedClient)
                }
            }
        }
    }

    private var accessControlsCard: some View {
        SettingsCard(
            icon: "slider.horizontal.3",
            accent: Color(red: 0.18, green: 0.45, blue: 0.34),
            title: "Access Controls",
            subtitle: "Restrict when and to which targets UserOperations may be signed."
        ) {
            VStack(alignment: .leading, spacing: 14) {
                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Allowed Hours")

                    Toggle("Restrict signing to a time window", isOn: allowedHoursEnabledBinding)
                        .toggleStyle(.switch)

                    if activeRules.allowedHours != nil {
                        HStack(spacing: 14) {
                            Picker("Start", selection: allowedHoursStartBinding) {
                                ForEach(0..<24, id: \.self) { hour in
                                    Text(String(format: "%02d:00", hour)).tag(hour)
                                }
                            }
                            .pickerStyle(.menu)

                            Picker("End", selection: allowedHoursEndBinding) {
                                ForEach(0..<24, id: \.self) { hour in
                                    Text(String(format: "%02d:00", hour)).tag(hour)
                                }
                            }
                            .pickerStyle(.menu)

                            Text("Time window uses the local macOS clock.")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                    } else {
                        EmptyStateRow(
                            icon: "clock.badge.checkmark",
                            title: "No time restriction — signing allowed at any hour",
                            detail: "Enable to restrict signing to a specific time window, e.g. business hours only."
                        )
                    }
                }

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Allowed Chains")

                    if allowedChains.isEmpty {
                        EmptyStateRow(
                            icon: "point.3.connected.trianglepath.dotted",
                            title: "No chain filter — requests for any network are allowed",
                            detail: "Add chain IDs to restrict signing to specific networks."
                        )
                    } else {
                        LazyVGrid(
                            columns: [GridItem(.adaptive(minimum: 170), spacing: 8, alignment: .leading)],
                            alignment: .leading,
                            spacing: 8
                        ) {
                            ForEach(allowedChains, id: \.self) { chainId in
                                RemovableChip(
                                    title: ChainConfig.name(for: chainId),
                                    subtitle: "#\(chainId)",
                                    tint: Color(red: 0.11, green: 0.39, blue: 0.63)
                                ) {
                                    removeAllowedChain(chainId)
                                }
                            }
                        }
                    }

                    HStack(spacing: 10) {
                        TextField("Chain ID", text: $newAllowedChain)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 120)

                        Button("Add Chain") {
                            addAllowedChain()
                        }
                        .buttonStyle(.bordered)
                        .disabled(!canAddAllowedChain)

                        Spacer()
                    }
                }

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Allowed Targets")

                    Text("Matches decoded inner-call destinations from Kernel execute() calldata. If Bastion cannot inspect a UserOp while this allowlist is enabled, the request is blocked.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    if allowedAccountEntries.isEmpty {
                        EmptyStateRow(
                            icon: "person.crop.rectangle.stack",
                            title: "No target filter — requests may call any contract or address",
                            detail: "Add chain/address pairs to restrict signing to specific destination contracts."
                        )
                    } else {
                        VStack(spacing: 10) {
                            ForEach(allowedAccountEntries) { entry in
                                HStack(alignment: .firstTextBaseline, spacing: 12) {
                                    Text(entry.chainDisplayName)
                                        .font(.subheadline.weight(.semibold))
                                        .frame(width: 130, alignment: .leading)

                                    Text(entry.address)
                                        .font(.system(.body, design: .monospaced))
                                        .textSelection(.enabled)
                                        .frame(maxWidth: .infinity, alignment: .leading)

                                    removeButton {
                                        removeAllowedAccount(entry)
                                    }
                                }
                                .padding(12)
                                .background(cardRowBackground)
                            }
                        }
                    }

                    HStack(spacing: 10) {
                        TextField("Chain ID", text: $newAllowedAccountChain)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 120)

                        TextField("0x target address", text: $newAllowedAccountAddress)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(.body, design: .monospaced))

                        Button("Add Target") {
                            addAllowedAccount()
                        }
                        .buttonStyle(.bordered)
                        .disabled(!canAddAllowedAccount)
                    }
                }
            }
        }
    }

    private var defaultScopeCard: some View {
        SettingsCard(
            icon: "person.crop.rectangle.stack",
            accent: Color(red: 0.48, green: 0.34, blue: 0.16),
            title: "Default Client Template",
            subtitle: "New clients inherit a copy of this auth policy and rule set the first time they connect."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                LazyVGrid(columns: summaryPillColumns, alignment: .leading, spacing: 8) {
                    SummaryPill(
                        title: "Profiles",
                        value: "\(clientProfiles.count)",
                        tint: Color(red: 0.11, green: 0.39, blue: 0.63)
                    )
                    SummaryPill(
                        title: "Raw",
                        value: draftConfig.rules.rawMessagePolicy.enabled ? "Allowed" : "Blocked",
                        tint: Color(red: 0.15, green: 0.36, blue: 0.59)
                    )
                    SummaryPill(
                        title: "Typed",
                        value: draftConfig.rules.typedDataPolicy.enabled ? "Allowed" : "Blocked",
                        tint: Color(red: 0.44, green: 0.31, blue: 0.55)
                    )
                    SummaryPill(
                        title: "UserOp",
                        value: draftConfig.rules.enabled ? "Enabled" : "Paused",
                        tint: Color(red: 0.18, green: 0.45, blue: 0.34)
                    )
                    SummaryPill(
                        title: "Bundler",
                        value: draftConfig.bundlerPreferences.zeroDevProjectId == nil ? "Unset" : "Configured",
                        tint: draftConfig.bundlerPreferences.zeroDevProjectId == nil
                            ? Color.gray
                            : Color(red: 0.17, green: 0.40, blue: 0.58)
                    )
                    SummaryPill(
                        title: "RPCs",
                        value: "\(draftConfig.bundlerPreferences.chainRPCs.count)",
                        tint: Color(red: 0.14, green: 0.47, blue: 0.34)
                    )
                }

                if clientProfiles.isEmpty {
                    EmptyStateRow(
                        icon: "person.badge.plus",
                        title: "No client profiles yet",
                        detail: "The first request from a new bundle ID will clone this page into a dedicated client policy."
                    )
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        sectionLabel("Existing Overrides")
                        ForEach(clientProfiles) { profile in
                            scopeRow(
                                title: profile.displayDescription,
                                subtitle: "Own auth policy, rules, key, and account",
                                bundleId: profile.bundleId,
                                accountAddress: clientAccountAddresses[profile.id],
                                isSelected: false,
                                onSelect: {
                                    sidebarSelection = .profile(id: profile.id)
                                },
                                onReset: nil,
                                onRemove: nil
                            )
                        }
                    }
                }
            }
        }
    }

    private var clientIdentityCard: some View {
        SettingsCard(
            icon: "person.text.rectangle",
            accent: Color(red: 0.48, green: 0.34, blue: 0.16),
            title: "Client Identity",
            subtitle: "This page edits the full policy snapshot for the selected client."
        ) {
            if let profile = selectedClientProfile {
                VStack(alignment: .leading, spacing: 10) {
                    TextField("Display Label", text: profileLabelBinding)
                        .textFieldStyle(.roundedBorder)

                    SettingsKeyValueRow(label: "Bundle ID", value: profile.bundleId)

                    if let account = clientAccountAddresses[profile.id] {
                        SettingsKeyValueRow(label: "Account", value: account)
                    }

                    SettingsKeyValueRow(label: "Key Tag", value: profile.keyTag)

                    HStack(spacing: 10) {
                        Button("Reset from Default") {
                            resetProfileRules(profile)
                        }
                        .buttonStyle(.bordered)

                        Button(role: .destructive) {
                            removeClientProfile(profile)
                        } label: {
                            Text("Remove Client")
                        }
                        .buttonStyle(.bordered)

                        Spacer()
                    }
                }
            }
        }
    }

    private var rateLimitCard: some View {
        SettingsCard(
            icon: "speedometer",
            accent: Color(red: 0.55, green: 0.29, blue: 0.18),
            title: "Rate Limits",
            subtitle: "Throttle autonomous signing frequency."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                if activeRules.rateLimits.isEmpty {
                    EmptyStateRow(
                        icon: "gauge.with.dots.needle.bottom.0percent",
                        title: "No rate limits — unlimited signing requests are allowed",
                        detail: "Add a window to cap how many UserOperations can be signed in a given period."
                    )
                } else {
                    VStack(spacing: 10) {
                        ForEach(activeRules.rateLimits) { rule in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(rule.displayDescription)
                                        .font(.subheadline.weight(.semibold))
                                    Text("Rejects the \(rule.maxRequests + 1)th request within any \(formatWindow(rule.windowSeconds)) window")
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }

                                Spacer()

                                removeButton {
                                    removeRateLimit(rule)
                                }
                            }
                            .padding(12)
                            .background(cardRowBackground)
                        }
                    }
                }

                HStack(spacing: 10) {
                    TextField("Max requests", text: $newRLMax)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 140)

                    Picker("Window", selection: $newRLWindow) {
                        Text("Per minute").tag("60")
                        Text("Per hour").tag("3600")
                        Text("Per day").tag("86400")
                        Text("Per week").tag("604800")
                    }
                    .pickerStyle(.menu)

                    Button("Add Limit") {
                        addRateLimit()
                    }
                    .buttonStyle(.bordered)
                    .disabled(!canAddRateLimit)

                    Spacer()
                }
            }
        }
    }

    private var spendingLimitCard: some View {
        SettingsCard(
            icon: "banknote",
            accent: Color(red: 0.21, green: 0.47, blue: 0.33),
            title: "Spending Limits",
            subtitle: "Direct native value and direct ERC-20 transfer budgets."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(Color(red: 0.72, green: 0.43, blue: 0.11))
                    Text("Complex protocol calls can still move assets indirectly. Treat these budgets as direct-call enforcement, then pair them with target allowlists or explicit approval for protocol-heavy flows.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Color.white.opacity(0.55))
                )

                if activeRules.spendingLimits.isEmpty {
                    EmptyStateRow(
                        icon: "wallet.bifold",
                        title: "No spending limits — direct transfers of any amount are allowed",
                        detail: "Add token budgets to cap how much can be transferred in direct calls per time window."
                    )
                } else {
                    VStack(spacing: 10) {
                        ForEach(activeRules.spendingLimits) { rule in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(rule.displayDescription)
                                        .font(.subheadline.weight(.semibold))
                                    Text(rule.token.displayName)
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }

                                Spacer()

                                removeButton {
                                    removeSpendingLimit(rule)
                                }
                            }
                            .padding(12)
                            .background(cardRowBackground)
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 10) {
                    HStack(spacing: 10) {
                        Picker("Token", selection: $newSLToken) {
                            Text("ETH").tag("eth")
                            Text("USDC").tag("usdc")
                            Text("ERC-20").tag("erc20")
                        }
                        .pickerStyle(.segmented)
                        .frame(maxWidth: 280)

                        Spacer()
                    }

                    if newSLToken == "erc20" {
                        HStack(spacing: 10) {
                            TextField("Token address", text: $newSLErc20Address)
                                .textFieldStyle(.roundedBorder)
                                .font(.system(.body, design: .monospaced))

                            TextField("Chain ID", text: $newSLErc20ChainId)
                                .textFieldStyle(.roundedBorder)
                                .frame(width: 120)
                        }
                    }

                    HStack(spacing: 10) {
                        TextField(newSLToken == "eth" ? "Amount in wei (e.g. 1000000000000000000 = 1 ETH)" : "Amount in token base units (e.g. 1000000 = 1 USDC)", text: $newSLAllowance)
                            .textFieldStyle(.roundedBorder)

                        TextField("Reset window in seconds (blank = lifetime)", text: $newSLWindow)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 260)

                        Button("Add Budget") {
                            addSpendingLimit()
                        }
                        .buttonStyle(.bordered)
                        .disabled(!canAddSpendingLimit)
                    }
                }
            }
        }
    }

    private var sidebarAddProfileForm: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("NEW CLIENT PROFILE")
                .font(.caption2.weight(.black))
                .kerning(1.1)
                .foregroundStyle(Color(red: 0.45, green: 0.25, blue: 0.14))

            TextField("Bundle ID", text: $newClientBundleId)
                .textFieldStyle(.roundedBorder)
                .font(.system(.caption, design: .monospaced))

            TextField("Label (optional)", text: $newClientLabel)
                .textFieldStyle(.roundedBorder)

            HStack(spacing: 8) {
                Button("Create") {
                    addClientProfile()
                }
                .buttonStyle(.borderedProminent)
                .disabled(!canAddClientProfile)

                Button("Reload") {
                    loadCurrentConfig()
                }
                .buttonStyle(.bordered)
                .disabled(isSaving)
            }
        }
        .padding(.top, 12)
        .overlay(alignment: .top) {
            Rectangle()
                .fill(Color.white.opacity(0.7))
                .frame(height: 1)
        }
        .padding(.horizontal, 12)
        .padding(.bottom, 12)
    }

    private var saveBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Rule changes require biometric or passcode confirmation.")
                    .font(.caption.weight(.semibold))

                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundStyle(statusIsError ? .red : .green)
                } else {
                    Text("Saving updates the Keychain-backed policy in place. Existing fields stay intact unless this screen edits them.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
            }

            Spacer()

            Button("Reload") {
                loadCurrentConfig()
            }
            .buttonStyle(.bordered)
            .disabled(isSaving)

            Button("Save Rules") {
                saveConfig()
            }
            .buttonStyle(.borderedProminent)
            .disabled(isSaving)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 10)
        .background(.ultraThinMaterial)
    }

    private var authPolicyBinding: Binding<AuthPolicy> {
        Binding(
            get: {
                if let index = selectedClientProfileIndex {
                    return draftConfig.clientProfiles[index].authPolicy ?? draftConfig.authPolicy
                }
                return draftConfig.authPolicy
            },
            set: { newValue in
                if let index = selectedClientProfileIndex {
                    draftConfig.clientProfiles[index].authPolicy = newValue
                } else {
                    draftConfig.authPolicy = newValue
                }
            }
        )
    }

    private var zeroDevProjectIdBinding: Binding<String> {
        Binding(
            get: { draftConfig.bundlerPreferences.zeroDevProjectId ?? "" },
            set: { newValue in
                let trimmedValue = trimmed(newValue)
                draftConfig.bundlerPreferences.zeroDevProjectId = trimmedValue.isEmpty ? nil : trimmedValue
            }
        )
    }

    private var configuredRPCEndpoints: [ChainRPCPreference] {
        draftConfig.bundlerPreferences.chainRPCs
    }

    private var profileLabelBinding: Binding<String> {
        Binding(
            get: { selectedClientProfile?.label ?? "" },
            set: { newValue in
                guard let index = selectedClientProfileIndex else { return }
                let value = trimmed(newValue)
                draftConfig.clientProfiles[index].label = value.isEmpty ? nil : value
            }
        )
    }

    private var rulesEnabledBinding: Binding<Bool> {
        Binding(
            get: { activeRules.enabled },
            set: { newValue in
                updateActiveRules { $0.enabled = newValue }
            }
        )
    }

    private var requireExplicitApprovalBinding: Binding<Bool> {
        Binding(
            get: { activeRules.requireExplicitApproval },
            set: { newValue in
                updateActiveRules { $0.requireExplicitApproval = newValue }
            }
        )
    }

    private var rawMessageEnabledBinding: Binding<Bool> {
        Binding(
            get: { activeRules.rawMessagePolicy.enabled },
            set: { newValue in
                updateActiveRules { $0.rawMessagePolicy.enabled = newValue }
            }
        )
    }

    private var typedDataEnabledBinding: Binding<Bool> {
        Binding(
            get: { activeRules.typedDataPolicy.enabled },
            set: { newValue in
                updateActiveRules { $0.typedDataPolicy.enabled = newValue }
            }
        )
    }

    private var typedDataApprovalBinding: Binding<Bool> {
        Binding(
            get: { activeRules.typedDataPolicy.requireExplicitApproval },
            set: { newValue in
                updateActiveRules { $0.typedDataPolicy.requireExplicitApproval = newValue }
            }
        )
    }

    private var allowedHoursEnabledBinding: Binding<Bool> {
        Binding(
            get: { activeRules.allowedHours != nil },
            set: { enabled in
                updateActiveRules {
                    $0.allowedHours = enabled
                        ? ($0.allowedHours ?? AllowedHours(start: 9, end: 18))
                        : nil
                }
            }
        )
    }

    private var allowedHoursStartBinding: Binding<Int> {
        Binding(
            get: { activeRules.allowedHours?.start ?? 9 },
            set: { start in
                let currentEnd = activeRules.allowedHours?.end ?? 18
                updateActiveRules {
                    $0.allowedHours = AllowedHours(start: start, end: currentEnd)
                }
            }
        )
    }

    private var allowedHoursEndBinding: Binding<Int> {
        Binding(
            get: { activeRules.allowedHours?.end ?? 18 },
            set: { end in
                let currentStart = activeRules.allowedHours?.start ?? 9
                updateActiveRules {
                    $0.allowedHours = AllowedHours(start: currentStart, end: end)
                }
            }
        )
    }

    private var authFootnote: String {
        switch authPolicyBinding.wrappedValue {
        case .open:
            return "No authentication required — requests that pass rules are signed immediately with no prompt. Only use this when your rules are strict enough on their own."
        case .passcode:
            return "Your login password is required before each signature. Touch ID will not satisfy this prompt."
        case .biometric:
            return "Touch ID is required before each signature. Passcode fallback is disabled — if biometrics are unavailable the request is rejected."
        case .biometricOrPasscode:
            return "Touch ID or your login password is required before each signature. Recommended for daily use."
        }
    }

    private var allowedChains: [Int] {
        (activeRules.allowedChains ?? []).sorted()
    }

    private var clientProfiles: [ClientProfile] {
        draftConfig.clientProfiles
    }

    private var allowedClientEntries: [AllowedClient] {
        (activeRules.allowedClients ?? []).sorted { $0.bundleId < $1.bundleId }
    }

    private var allowedAccountEntries: [AllowedAccountEntry] {
        let entries = (activeRules.allowedTargets ?? [:]).flatMap { chainKey, addresses in
            addresses.map { AllowedAccountEntry(chainKey: chainKey, address: $0) }
        }

        return entries.sorted {
            if $0.sortKey == $1.sortKey {
                return $0.address.lowercased() < $1.address.lowercased()
            }
            return $0.sortKey < $1.sortKey
        }
    }

    private var canAddAllowedClient: Bool {
        !trimmed(newAllowedClientBundleId).isEmpty
    }

    private var canAddAllowedChain: Bool {
        Int(trimmed(newAllowedChain)) != nil
    }

    private var canAddAllowedAccount: Bool {
        isChainKey(trimmed(newAllowedAccountChain)) && isHexAddress(trimmed(newAllowedAccountAddress))
    }

    private var canAddClientProfile: Bool {
        !trimmed(newClientBundleId).isEmpty
    }

    private var canAddRPCPreference: Bool {
        Int(trimmed(newRPCChainId)) != nil && isValidRPCURL(newRPCURL)
    }

    private var canAddTypedDataDomainRule: Bool {
        !trimmed(newTypedDomainPrimaryType).isEmpty ||
            !trimmed(newTypedDomainName).isEmpty ||
            !trimmed(newTypedDomainVersion).isEmpty ||
            !trimmed(newTypedDomainChainId).isEmpty ||
            !trimmed(newTypedDomainVerifyingContract).isEmpty
    }

    private var canAddTypedDataStructRule: Bool {
        !trimmed(newTypedStructPrimaryType).isEmpty && isValidJSON(newTypedStructMatcherJSON)
    }

    private var canAddRateLimit: Bool {
        Int(trimmed(newRLMax)) != nil
    }

    private var canAddSpendingLimit: Bool {
        guard !trimmed(newSLAllowance).isEmpty else { return false }
        if newSLToken == "erc20" {
            return isHexAddress(trimmed(newSLErc20Address)) && isChainKey(trimmed(newSLErc20ChainId))
        }
        return true
    }

    private var cardRowBackground: some View {
        RoundedRectangle(cornerRadius: 16, style: .continuous)
            .fill(Color.white.opacity(0.7))
    }

    private var activeRules: RuleConfig {
        if let index = selectedClientProfileIndex {
            return draftConfig.clientProfiles[index].rules
        }
        return draftConfig.rules
    }

    private var selectedClientProfileIndex: Int? {
        guard case .profile(let id) = sidebarSelection, let id else { return nil }
        return draftConfig.clientProfiles.firstIndex { $0.id == id }
    }

    private var selectedClientProfile: ClientProfile? {
        guard let index = selectedClientProfileIndex else { return nil }
        return draftConfig.clientProfiles[index]
    }

    private var activeScopeTitle: String {
        selectedClientProfile?.displayDescription ?? "Global Defaults"
    }

    private var activeAccountAddress: String? {
        guard let selectedClientProfile else { return nil }
        return clientAccountAddresses[selectedClientProfile.id]
    }

    private func sectionLabel(_ title: String) -> some View {
        Text(title)
            .font(.headline)
    }

    private func sidebarSectionLabel(_ title: String) -> some View {
        Text(title.uppercased())
            .font(.caption2.weight(.semibold))
            .foregroundStyle(.secondary)
            .padding(.horizontal, 6)
    }

    private func sidebarRow(
        title: String,
        subtitle: String,
        accountAddress: String?,
        systemImage: String,
        isSelected: Bool,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: systemImage)
                    .foregroundStyle(isSelected ? Color(red: 0.45, green: 0.25, blue: 0.14) : .secondary)
                    .frame(width: 18, height: 18)
                    .padding(.top, 2)

                VStack(alignment: .leading, spacing: 3) {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(.primary)
                    Text(subtitle)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    if let accountAddress {
                        Text(shortAddress(accountAddress))
                            .font(.caption2.monospaced())
                            .foregroundStyle(.secondary)
                    }
                }

                Spacer()
            }
            .padding(10)
            .background(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .fill(isSelected ? Color.white.opacity(0.92) : Color.white.opacity(0.58))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .stroke(
                        isSelected
                            ? Color(red: 0.45, green: 0.25, blue: 0.14).opacity(0.28)
                            : Color.clear,
                        lineWidth: 1
                    )
            )
            .overlay(alignment: .leading) {
                Capsule(style: .continuous)
                    .fill(isSelected ? Color(red: 0.45, green: 0.25, blue: 0.14) : .clear)
                    .frame(width: 4)
                    .padding(.vertical, 8)
            }
        }
        .buttonStyle(.plain)
    }

    private func removeButton(action: @escaping () -> Void) -> some View {
        Button(role: .destructive, action: action) {
            Image(systemName: "trash")
        }
        .buttonStyle(.borderless)
    }

    private func loadCurrentConfig() {
        let config = ruleEngine.config
        draftConfig = config
        if case .profile(let id) = sidebarSelection, let id,
           !config.clientProfiles.contains(where: { $0.id == id }) {
            sidebarSelection = .profile(id: nil)
        }
        refreshAccountAddresses()
        clearTransientInputs()
        clearStatus()
    }

    private func saveConfig() {
        isSaving = true
        clearStatus()

        Task {
            do {
                try await ruleEngine.updateConfig(draftConfig)
                setStatus("Saved", isError: false)
            } catch {
                setStatus("Error: \(error.localizedDescription)", isError: true)
            }
            isSaving = false
        }
    }

    private func addAllowedClient() {
        let bundleId = trimmed(newAllowedClientBundleId)
        guard !bundleId.isEmpty else { return }

        let exists = (activeRules.allowedClients ?? []).contains {
            $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame
        }
        if !exists {
            let label = trimmed(newAllowedClientLabel)
            updateActiveRules {
                var clients = $0.allowedClients ?? []
                clients.append(AllowedClient(
                    id: UUID().uuidString,
                    bundleId: bundleId,
                    label: label.isEmpty ? nil : label
                ))
                $0.allowedClients = clients.sorted { $0.bundleId < $1.bundleId }
            }
        }
        newAllowedClientBundleId = ""
        newAllowedClientLabel = ""
        clearStatus()
    }

    private func removeAllowedClient(_ client: AllowedClient) {
        updateActiveRules {
            var clients = $0.allowedClients ?? []
            clients.removeAll { $0.id == client.id }
            $0.allowedClients = clients.isEmpty ? nil : clients
        }
    }

    private func addAllowedChain() {
        guard let chainId = Int(trimmed(newAllowedChain)) else {
            setStatus("Enter a valid numeric chain ID.", isError: true)
            return
        }

        var chains = Set(activeRules.allowedChains ?? [])
        chains.insert(chainId)
        updateActiveRules { $0.allowedChains = chains.isEmpty ? nil : chains.sorted() }
        newAllowedChain = ""
        clearStatus()
    }

    private func removeAllowedChain(_ chainId: Int) {
        var chains = activeRules.allowedChains ?? []
        chains.removeAll { $0 == chainId }
        updateActiveRules { $0.allowedChains = chains.isEmpty ? nil : chains.sorted() }
    }

    private func addAllowedAccount() {
        let chainKey = trimmed(newAllowedAccountChain)
        let address = normalizedAddress(newAllowedAccountAddress)

        guard isChainKey(chainKey), isHexAddress(address) else {
            setStatus("Enter a valid chain ID and target address.", isError: true)
            return
        }

        var targets = activeRules.allowedTargets ?? [:]
        var accounts = targets[chainKey] ?? []

        if !accounts.contains(where: { $0.caseInsensitiveCompare(address) == .orderedSame }) {
            accounts.append(address)
            accounts.sort { $0.lowercased() < $1.lowercased() }
            targets[chainKey] = accounts
        }

        updateActiveRules { $0.allowedTargets = targets.isEmpty ? nil : targets }
        newAllowedAccountChain = ""
        newAllowedAccountAddress = ""
        clearStatus()
    }

    private func removeAllowedAccount(_ entry: AllowedAccountEntry) {
        guard var targets = activeRules.allowedTargets else { return }
        var accounts = targets[entry.chainKey] ?? []
        accounts.removeAll { $0.caseInsensitiveCompare(entry.address) == .orderedSame }
        if accounts.isEmpty {
            targets.removeValue(forKey: entry.chainKey)
        } else {
            targets[entry.chainKey] = accounts
        }
        updateActiveRules { $0.allowedTargets = targets.isEmpty ? nil : targets }
    }

    private func addClientProfile() {
        let bundleId = trimmed(newClientBundleId)
        guard !bundleId.isEmpty else {
            setStatus("Bundle ID is required.", isError: true)
            return
        }

        let exists = draftConfig.clientProfiles.contains { $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame }
        if !exists {
            draftConfig.clientProfiles.append(ClientProfile(
                bundleId: bundleId,
                label: trimmed(newClientLabel).isEmpty ? nil : trimmed(newClientLabel),
                authPolicy: draftConfig.authPolicy,
                rules: clonedClientRules(from: draftConfig.rules)
            ))
            draftConfig.clientProfiles.sort {
                $0.bundleId.localizedCaseInsensitiveCompare($1.bundleId) == .orderedAscending
            }
            if let added = draftConfig.clientProfiles.first(where: { $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame }) {
                sidebarSelection = .profile(id: added.id)
            }
            refreshAccountAddresses()
        }

        newClientBundleId = ""
        newClientLabel = ""
        clearStatus()
    }

    private func addRPCPreference() {
        guard let chainId = Int(trimmed(newRPCChainId)), isValidRPCURL(newRPCURL) else {
            setStatus("Enter a valid chain ID and HTTP(S) RPC URL.", isError: true)
            return
        }

        let rpcURL = trimmed(newRPCURL)
        draftConfig.bundlerPreferences.chainRPCs.removeAll { $0.chainId == chainId }
        draftConfig.bundlerPreferences.chainRPCs.append(
            ChainRPCPreference(chainId: chainId, rpcURL: rpcURL)
        )
        draftConfig.bundlerPreferences.chainRPCs.sort { $0.chainId < $1.chainId }
        newRPCChainId = ""
        newRPCURL = ""
        clearStatus()
    }

    private func removeRPCPreference(_ endpoint: ChainRPCPreference) {
        draftConfig.bundlerPreferences.chainRPCs.removeAll { $0.chainId == endpoint.chainId }
    }

    private func resetProfileRules(_ profile: ClientProfile) {
        guard let index = draftConfig.clientProfiles.firstIndex(where: { $0.id == profile.id }) else {
            return
        }
        draftConfig.clientProfiles[index].authPolicy = draftConfig.authPolicy
        draftConfig.clientProfiles[index].rules = clonedClientRules(from: draftConfig.rules)
        clearStatus()
    }

    private func removeClientProfile(_ profile: ClientProfile) {
        draftConfig.clientProfiles.removeAll { $0.id == profile.id }
        clientAccountAddresses.removeValue(forKey: profile.id)
        if sidebarSelection == .profile(id: profile.id) {
            sidebarSelection = .profile(id: nil)
        }
    }

    private func addRateLimit() {
        guard let max = Int(trimmed(newRLMax)),
              let window = Int(newRLWindow) else {
            setStatus("Rate limits require a request count and a window.", isError: true)
            return
        }

        updateActiveRules {
            $0.rateLimits.append(RateLimitRule(
                id: UUID().uuidString,
                maxRequests: max,
                windowSeconds: window
            ))
        }
        newRLMax = ""
        clearStatus()
    }

    private func removeRateLimit(_ rule: RateLimitRule) {
        updateActiveRules {
            $0.rateLimits.removeAll { $0.id == rule.id }
        }
    }

    private func addSpendingLimit() {
        guard let token = spendingToken() else {
            setStatus("Enter a valid token configuration before adding a budget.", isError: true)
            return
        }

        let window = trimmed(newSLWindow).isEmpty ? nil : Int(trimmed(newSLWindow))
        if !trimmed(newSLWindow).isEmpty && window == nil {
            setStatus("Reset window must be numeric when provided.", isError: true)
            return
        }

        updateActiveRules {
            $0.spendingLimits.append(SpendingLimitRule(
                id: UUID().uuidString,
                token: token,
                allowance: trimmed(newSLAllowance),
                windowSeconds: window
            ))
        }

        newSLAllowance = ""
        newSLWindow = ""
        newSLErc20Address = ""
        newSLErc20ChainId = ""
        clearStatus()
    }

    private func removeSpendingLimit(_ rule: SpendingLimitRule) {
        updateActiveRules {
            $0.spendingLimits.removeAll { $0.id == rule.id }
        }
    }

    private func spendingToken() -> TokenIdentifier? {
        switch newSLToken {
        case "eth":
            return .eth
        case "usdc":
            return .usdc
        case "erc20":
            guard let chainId = Int(trimmed(newSLErc20ChainId)) else { return nil }
            let address = normalizedAddress(newSLErc20Address)
            guard isHexAddress(address) else { return nil }
            return .erc20(address: address, chainId: chainId)
        default:
            return nil
        }
    }

    private func setStatus(_ message: String, isError: Bool) {
        statusMessage = message
        statusIsError = isError
    }

    private func clearStatus() {
        statusMessage = ""
        statusIsError = false
    }

    private func formatWindow(_ seconds: Int) -> String {
        switch seconds {
        case 60: return "1 minute"
        case 3600: return "1 hour"
        case 86400: return "1 day"
        case 604800: return "1 week"
        default:
            if seconds % 86400 == 0 { return "\(seconds / 86400) days" }
            if seconds % 3600 == 0 { return "\(seconds / 3600) hours" }
            if seconds % 60 == 0 { return "\(seconds / 60) minutes" }
            return "\(seconds)s"
        }
    }

    private func clearTransientInputs() {
        newAllowedChain = ""
        newAllowedAccountChain = ""
        newAllowedAccountAddress = ""
        newAllowedClientBundleId = ""
        newAllowedClientLabel = ""
        newClientBundleId = ""
        newClientLabel = ""
        newRPCChainId = ""
        newRPCURL = ""
        newTypedDomainLabel = ""
        newTypedDomainPrimaryType = ""
        newTypedDomainName = ""
        newTypedDomainVersion = ""
        newTypedDomainChainId = ""
        newTypedDomainVerifyingContract = ""
        newTypedStructLabel = ""
        newTypedStructPrimaryType = ""
        newTypedStructMatcherJSON = "{\n  \n}"
        newRLMax = ""
        newRLWindow = "3600"
        newSLToken = "eth"
        newSLAllowance = ""
        newSLWindow = ""
        newSLErc20Address = ""
        newSLErc20ChainId = ""
    }

    private func trimmed(_ text: String) -> String {
        text.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func isValidRPCURL(_ value: String) -> Bool {
        let trimmedValue = trimmed(value)
        guard let url = URL(string: trimmedValue),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil else {
            return false
        }
        return true
    }

    private func updateActiveRules(_ update: (inout RuleConfig) -> Void) {
        if let index = selectedClientProfileIndex {
            update(&draftConfig.clientProfiles[index].rules)
        } else {
            update(&draftConfig.rules)
        }
        // Keep sidebar status subtitles in sync
        _ = draftConfig
    }

    private func refreshAccountAddresses() {
        var addresses: [String: String] = [:]
        for profile in draftConfig.clientProfiles {
            if let address = ruleEngine.accountAddress(for: profile) {
                addresses[profile.id] = address
            }
        }
        clientAccountAddresses = addresses
    }

    private func clonedClientRules(from template: RuleConfig) -> RuleConfig {
        var cloned = template
        cloned.allowedClients = nil
        cloned.rateLimits = template.rateLimits.map {
            RateLimitRule(id: UUID().uuidString, maxRequests: $0.maxRequests, windowSeconds: $0.windowSeconds)
        }
        cloned.spendingLimits = template.spendingLimits.map {
            SpendingLimitRule(id: UUID().uuidString, token: $0.token, allowance: $0.allowance, windowSeconds: $0.windowSeconds)
        }
        return cloned
    }

    private func addTypedDataDomainRule() {
        let chainIdText = trimmed(newTypedDomainChainId)
        let verifyingContractText = trimmed(newTypedDomainVerifyingContract)

        if !chainIdText.isEmpty && Int(chainIdText) == nil {
            setStatus("Typed-data chain ID must be numeric.", isError: true)
            return
        }
        if !verifyingContractText.isEmpty && !isHexAddress(verifyingContractText) {
            setStatus("Typed-data verifying contract must be a valid address.", isError: true)
            return
        }

        updateActiveRules {
            $0.typedDataPolicy.domainRules.append(TypedDataDomainRule(
                id: UUID().uuidString,
                label: trimmed(newTypedDomainLabel).isEmpty ? nil : trimmed(newTypedDomainLabel),
                primaryType: trimmed(newTypedDomainPrimaryType).isEmpty ? nil : trimmed(newTypedDomainPrimaryType),
                name: trimmed(newTypedDomainName).isEmpty ? nil : trimmed(newTypedDomainName),
                version: trimmed(newTypedDomainVersion).isEmpty ? nil : trimmed(newTypedDomainVersion),
                chainId: Int(chainIdText),
                verifyingContract: verifyingContractText.isEmpty ? nil : normalizedAddress(verifyingContractText)
            ))
        }

        newTypedDomainLabel = ""
        newTypedDomainPrimaryType = ""
        newTypedDomainName = ""
        newTypedDomainVersion = ""
        newTypedDomainChainId = ""
        newTypedDomainVerifyingContract = ""
        clearStatus()
    }

    private func removeTypedDataDomainRule(_ rule: TypedDataDomainRule) {
        updateActiveRules {
            $0.typedDataPolicy.domainRules.removeAll { $0.id == rule.id }
        }
    }

    private func addTypedDataStructRule() {
        guard isValidJSON(newTypedStructMatcherJSON) else {
            setStatus("Struct matcher must be valid JSON.", isError: true)
            return
        }

        updateActiveRules {
            $0.typedDataPolicy.structRules.append(TypedDataStructRule(
                id: UUID().uuidString,
                label: trimmed(newTypedStructLabel).isEmpty ? nil : trimmed(newTypedStructLabel),
                primaryType: trimmed(newTypedStructPrimaryType),
                matcherJSON: normalizedJSON(newTypedStructMatcherJSON)
            ))
        }

        newTypedStructLabel = ""
        newTypedStructPrimaryType = ""
        newTypedStructMatcherJSON = "{\n  \n}"
        clearStatus()
    }

    private func removeTypedDataStructRule(_ rule: TypedDataStructRule) {
        updateActiveRules {
            $0.typedDataPolicy.structRules.removeAll { $0.id == rule.id }
        }
    }

    private func normalizedAddress(_ text: String) -> String {
        let value = trimmed(text)
        guard !value.isEmpty else { return value }
        if value.hasPrefix("0x") || value.hasPrefix("0X") {
            return "0x" + value.dropFirst(2)
        }
        return "0x" + value
    }

    private func isChainKey(_ text: String) -> Bool {
        Int(text) != nil
    }

    private func isHexAddress(_ text: String) -> Bool {
        let value = normalizedAddress(text)
        guard value.count == 42, value.hasPrefix("0x") else { return false }
        return value.dropFirst(2).allSatisfy { $0.isHexDigit }
    }

    private func shortAddress(_ address: String) -> String {
        guard address.count > 14 else {
            return address
        }
        return "\(address.prefix(10))...\(address.suffix(4))"
    }

    private func domainRuleDescription(_ rule: TypedDataDomainRule) -> String {
        var parts: [String] = []
        if let primaryType = trimmedOrNil(rule.primaryType) {
            parts.append("type=\(primaryType)")
        }
        if let name = trimmedOrNil(rule.name) {
            parts.append("name=\(name)")
        }
        if let version = trimmedOrNil(rule.version) {
            parts.append("version=\(version)")
        }
        if let chainId = rule.chainId {
            parts.append("chain=\(chainId)")
        }
        if let verifyingContract = trimmedOrNil(rule.verifyingContract) {
            parts.append("verifying=\(verifyingContract)")
        }
        return parts.isEmpty ? "Matches any domain" : parts.joined(separator: " · ")
    }

    private func trimmedOrNil(_ text: String?) -> String? {
        guard let text else { return nil }
        let trimmed = trimmed(text)
        return trimmed.isEmpty ? nil : trimmed
    }

    private func isValidJSON(_ text: String) -> Bool {
        guard let data = text.data(using: .utf8) else {
            return false
        }
        return (try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])) != nil
    }

    private func normalizedJSON(_ text: String) -> String {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
              let normalized = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
              let string = String(data: normalized, encoding: .utf8) else {
            return text
        }
        return string
    }

    private func scopeRow(
        title: String,
        subtitle: String,
        bundleId: String?,
        accountAddress: String?,
        isSelected: Bool,
        onSelect: @escaping () -> Void,
        onReset: (() -> Void)?,
        onRemove: (() -> Void)?
    ) -> some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                if let bundleId {
                    Text(bundleId)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                }
                if let accountAddress {
                    Text("Account: \(accountAddress)")
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 8) {
                Button(isSelected ? "Editing" : "Edit") {
                    onSelect()
                }
                .buttonStyle(.borderedProminent)
                .controlSize(.small)

                if let onReset {
                    Button("Reset from Global") {
                        onReset()
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }

                if let onRemove {
                    Button(role: .destructive) {
                        onRemove()
                    } label: {
                        Text("Remove")
                    }
                    .buttonStyle(.bordered)
                    .controlSize(.small)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(isSelected ? Color(red: 0.82, green: 0.46, blue: 0.16).opacity(0.12) : Color.white.opacity(0.7))
        )
    }
}

struct AuditHistoryView: View {
    @State private var historyRequests: [AuditRequestRecord] = []
    @State private var selectedHistoryRequestID: String?
    private let refreshTimer = Timer.publish(every: 2, on: .main, in: .common).autoconnect()

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [
                    Color(red: 0.965, green: 0.962, blue: 0.952),
                    Color(red: 0.952, green: 0.958, blue: 0.964),
                ],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 14) {
                historyHeroCard

                HSplitView {
                    historyListCard
                        .frame(minWidth: 330, idealWidth: 360, maxWidth: 420)
                    historyDetailCard
                        .frame(minWidth: 440)
                }
            }
            .padding(16)
            .frame(maxWidth: 1180, alignment: .leading)
        }
        .frame(minWidth: 980, minHeight: 720)
        .onAppear {
            refreshHistory()
        }
        .onReceive(refreshTimer) { _ in
            refreshHistory()
        }
    }

    private var selectedHistoryRequest: AuditRequestRecord? {
        guard let selectedHistoryRequestID else {
            return historyRequests.first
        }
        return historyRequests.first { $0.id == selectedHistoryRequestID } ?? historyRequests.first
    }

    private var requestCountToday: Int {
        let startOfDay = Calendar.current.startOfDay(for: Date())
        return historyRequests.filter { record in
            guard let date = record.latestTimestamp else { return false }
            return date >= startOfDay
        }.count
    }

    private var confirmedRequestCount: Int {
        historyRequests.filter { record in
            record.events.contains(where: { $0.type == .userOpReceiptSuccess })
        }.count
    }

    private var blockedRequestCount: Int {
        historyRequests.filter { record in
            guard let latestType = record.latestEvent?.type else { return false }
            switch latestType {
            case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed, .userOpReceiptTimeout:
                return true
            case .signSuccess, .userOpSubmitted, .userOpReceiptSuccess:
                return false
            }
        }.count
    }

    private var historyHeroCard: some View {
        SettingsCard(
            icon: "clock.badge.checkmark",
            accent: Color(red: 0.11, green: 0.39, blue: 0.63),
            title: "Audit History",
            subtitle: "Client activity, payload details, and Bastion decisions."
        ) {
            HStack(spacing: 10) {
                SummaryPill(
                    title: "Requests",
                    value: "\(historyRequests.count)",
                    tint: Color(red: 0.11, green: 0.39, blue: 0.63)
                )
                SummaryPill(
                    title: "Today",
                    value: "\(requestCountToday)",
                    tint: Color(red: 0.18, green: 0.45, blue: 0.34)
                )
                SummaryPill(
                    title: "Confirmed",
                    value: "\(confirmedRequestCount)",
                    tint: Color(red: 0.12, green: 0.39, blue: 0.63)
                )
                SummaryPill(
                    title: "Blocked",
                    value: "\(blockedRequestCount)",
                    tint: Color(red: 0.72, green: 0.43, blue: 0.11)
                )

                Spacer()

                Button("Reload History") {
                    refreshHistory()
                }
                .buttonStyle(.bordered)
            }
        }
    }

    private var historyListCard: some View {
        SettingsCard(
            icon: "list.bullet.rectangle.portrait",
            accent: Color(red: 0.18, green: 0.45, blue: 0.34),
            title: "Requests",
            subtitle: "One row per request, newest first"
        ) {
            if historyRequests.isEmpty {
                EmptyStateRow(
                    icon: "clock.arrow.trianglehead.counterclockwise.rotate.90",
                    title: "No requests yet",
                    detail: "Requests that reach Bastion will appear here after they are approved, denied, or escalated."
                )
            } else {
                ScrollView {
                    VStack(spacing: 8) {
                        ForEach(historyRequests, id: \.id) { record in
                            historyRow(record)
                        }
                    }
                }
            }
        }
    }

    private var historyDetailCard: some View {
        SettingsCard(
            icon: "doc.text.magnifyingglass",
            accent: Color(red: 0.55, green: 0.29, blue: 0.18),
            title: selectedHistoryRequest?.operationTitle ?? "Request Detail",
            subtitle: selectedHistoryRequest?.latestReason ?? "Decoded request metadata, client identity, digest, payloads, and request lifecycle."
        ) {
            if let record = selectedHistoryRequest {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        SettingsKeyValueRow(label: "Latest Status", value: record.latestResultLabel)
                        SettingsKeyValueRow(label: "Last Updated", value: formattedTimestamp(record.latestEvent))
                        SettingsKeyValueRow(label: "Client", value: record.clientDisplayName)

                        if let bundleId = record.client?.bundleId {
                            SettingsKeyValueRow(label: "Bundle ID", value: bundleId)
                        }
                        if let accountAddress = record.client?.accountAddress {
                            SettingsKeyValueRow(label: "Account", value: accountAddress)
                        }
                        if let request = record.request {
                            SettingsKeyValueRow(label: "Request ID", value: record.requestID)
                            SettingsKeyValueRow(label: "Kind", value: request.operationKind)
                            SettingsKeyValueRow(label: "Summary", value: request.summary)
                            SettingsCodeBlock(title: "Digest", value: request.digestHex)

                            if !request.details.isEmpty {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Decoded Details")
                                        .font(.headline)
                                    ForEach(Array(request.details.enumerated()), id: \.offset) { _, detail in
                                        SettingsCodeBlock(title: nil, value: detail)
                                    }
                                }
                            }

                            if let payloads = request.payloads, !payloads.isEmpty {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("Raw Payloads")
                                        .font(.headline)
                                    ForEach(payloads) { payload in
                                        SettingsCodeBlock(title: payload.title, value: payload.value)
                                    }
                                }
                            }
                        }

                        if let submission = record.latestSubmission {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Latest Bundler Status")
                                    .font(.headline)
                                SettingsKeyValueRow(label: "Provider", value: submission.provider)
                                SettingsKeyValueRow(label: "Status", value: submission.status)
                                if let userOpHash = submission.userOpHash {
                                    SettingsCodeBlock(title: "UserOp Hash", value: userOpHash)
                                }
                                if let transactionHash = submission.transactionHash {
                                    SettingsCodeBlock(title: "Transaction Hash", value: transactionHash)
                                }
                                if let detail = submission.detail, !detail.isEmpty {
                                    SettingsCodeBlock(title: "Bundler Detail", value: detail)
                                }
                            }
                        }

                        if let progress = requestProgress(for: record) {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Request Progress")
                                    .font(.headline)

                                ProgressView(value: progress.fraction)
                                    .tint(progress.color)

                                HStack(spacing: 8) {
                                    ForEach(progress.steps, id: \.title) { step in
                                        historyProgressChip(step)
                                    }
                                }

                                Text(progress.message)
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                            }
                        }

                        VStack(alignment: .leading, spacing: 8) {
                            Text("Request Timeline")
                                .font(.headline)
                            ForEach(record.events, id: \.id) { event in
                                historyTimelineRow(event)
                            }
                        }
                    }
                }
            } else {
                EmptyStateRow(
                    icon: "doc.text.magnifyingglass",
                    title: "Select an event",
                    detail: "Pick a request from the left to inspect the full audit detail."
                )
            }
        }
    }

    private func historyRow(_ record: AuditRequestRecord) -> some View {
        Button {
            selectedHistoryRequestID = record.id
        } label: {
            VStack(alignment: .leading, spacing: 8) {
                HStack(alignment: .top, spacing: 10) {
                    Image(systemName: iconForEvent(record.latestEvent?.type))
                        .foregroundStyle(colorForEvent(record.latestEvent?.type))
                        .frame(width: 18, height: 18)
                        .padding(.top, 2)

                    VStack(alignment: .leading, spacing: 2) {
                        Text(record.operationTitle)
                            .font(.subheadline.weight(.semibold))
                            .frame(maxWidth: .infinity, alignment: .leading)
                        Text(record.clientDisplayName)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }

                    Spacer(minLength: 0)

                    Text(formattedTimestamp(record.latestEvent))
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                Text(record.summary)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)

                Text(statusSummary(for: record))
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(colorForEvent(record.latestEvent?.type))
            }
            .padding(11)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(selectedHistoryRequestID == record.id ? Color(red: 0.82, green: 0.46, blue: 0.16).opacity(0.16) : Color.white.opacity(0.68))
            )
        }
        .buttonStyle(.plain)
    }

    private func refreshHistory() {
        historyRequests = AuditLog.shared.recentRequestRecords(limit: 300)
        if let selectedHistoryRequestID,
           historyRequests.contains(where: { $0.id == selectedHistoryRequestID }) {
            return
        }
        if selectedHistoryRequestID == nil || !historyRequests.isEmpty {
            selectedHistoryRequestID = historyRequests.first?.id
        }
    }

    private func formattedTimestamp(_ event: AuditEvent?) -> String {
        if let date = event?.timestampDate {
            return date.formatted(date: .abbreviated, time: .shortened)
        }
        return event?.timestamp ?? "Unknown"
    }

    private func statusSummary(for record: AuditRequestRecord) -> String {
        let labels = record.events.map(\.resultLabel)
        return labels.joined(separator: " -> ")
    }

    private func historyTimelineRow(_ event: AuditEvent) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .center, spacing: 8) {
                Image(systemName: iconForEvent(event.type))
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(colorForEvent(event.type))
                    .frame(width: 16, height: 16)

                Text(event.resultLabel)
                    .font(.subheadline.weight(.semibold))

                Spacer(minLength: 0)

                Text(formattedTimestamp(event))
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            if let detail = event.submission?.detail, !detail.isEmpty {
                SettingsCodeBlock(title: nil, value: detail)
            }

            if let transactionHash = event.submission?.transactionHash {
                SettingsCodeBlock(title: "Transaction Hash", value: transactionHash)
            }

            if let userOpHash = event.submission?.userOpHash, event.type != .userOpReceiptSuccess {
                SettingsCodeBlock(title: "UserOp Hash", value: userOpHash)
            }

            if let reason = event.reason, !reason.isEmpty {
                SettingsCodeBlock(title: "Reason", value: reason)
            }
        }
        .padding(.vertical, 4)
    }

    private func requestProgress(for record: AuditRequestRecord) -> AuditRequestProgress? {
        guard record.request?.operationKind == "user_operation" else {
            return nil
        }

        let types = Set(record.events.map(\.type))
        let signed = types.contains(.signSuccess)
        let submitted = types.contains(.userOpSubmitted)
        let confirmed = types.contains(.userOpReceiptSuccess)
        let failed = types.contains(.userOpSendFailed) || types.contains(.userOpReceiptFailed) || types.contains(.userOpReceiptTimeout)
        let blocked = types.contains(.signDenied) || types.contains(.ruleViolation) || types.contains(.authFailed)

        let steps = [
            AuditRequestProgress.Step(title: "Signed", state: signed ? .done : (blocked ? .failed : .pending)),
            AuditRequestProgress.Step(title: "Submitted", state: confirmed || submitted ? .done : (failed ? .failed : .pending)),
            AuditRequestProgress.Step(title: "Confirmed", state: confirmed ? .done : (failed ? .failed : .pending)),
        ]

        let fraction: Double
        let message: String
        let color: Color

        if confirmed {
            fraction = 1.0
            message = "The UserOperation has been included on-chain."
            color = Color(red: 0.18, green: 0.45, blue: 0.34)
        } else if failed {
            fraction = submitted ? (2.0 / 3.0) : (1.0 / 3.0)
            message = record.latestReason ?? "The request stopped before confirmation."
            color = Color(red: 0.68, green: 0.24, blue: 0.20)
        } else if submitted {
            fraction = 2.0 / 3.0
            message = "Submitted to the bundler and waiting for a receipt."
            color = Color(red: 0.12, green: 0.39, blue: 0.63)
        } else if signed {
            fraction = 1.0 / 3.0
            message = "Signed locally and preparing submission."
            color = Color(red: 0.72, green: 0.43, blue: 0.11)
        } else {
            fraction = 0
            message = record.latestReason ?? "Waiting for approval."
            color = Color.secondary
        }

        return AuditRequestProgress(
            fraction: fraction,
            message: message,
            color: color,
            steps: steps
        )
    }

    private func historyProgressChip(_ step: AuditRequestProgress.Step) -> some View {
        let tint: Color
        switch step.state {
        case .done:
            tint = Color(red: 0.18, green: 0.45, blue: 0.34)
        case .failed:
            tint = Color(red: 0.68, green: 0.24, blue: 0.20)
        case .pending:
            tint = Color.black.opacity(0.45)
        }

        return Text(step.title)
            .font(.caption2.weight(.semibold))
            .padding(.horizontal, 8)
            .padding(.vertical, 4)
            .background(
                Capsule(style: .continuous)
                    .fill(tint.opacity(step.state == .pending ? 0.07 : 0.13))
            )
            .foregroundStyle(tint)
    }

    private func colorForEvent(_ type: AuditEvent.EventType?) -> Color {
        switch type {
        case .signSuccess?:
            return Color(red: 0.18, green: 0.45, blue: 0.34)
        case .signDenied?:
            return Color(red: 0.68, green: 0.24, blue: 0.20)
        case .ruleViolation?:
            return Color(red: 0.72, green: 0.43, blue: 0.11)
        case .authFailed?:
            return Color(red: 0.55, green: 0.29, blue: 0.18)
        case .userOpSubmitted?:
            return Color(red: 0.12, green: 0.39, blue: 0.63)
        case .userOpSendFailed?:
            return Color(red: 0.72, green: 0.20, blue: 0.18)
        case .userOpReceiptSuccess?:
            return Color(red: 0.18, green: 0.45, blue: 0.34)
        case .userOpReceiptFailed?:
            return Color(red: 0.62, green: 0.23, blue: 0.18)
        case .userOpReceiptTimeout?:
            return Color(red: 0.56, green: 0.39, blue: 0.11)
        case nil:
            return .secondary
        }
    }

    private func iconForEvent(_ type: AuditEvent.EventType?) -> String {
        switch type {
        case .signSuccess?:
            return "checkmark.circle.fill"
        case .signDenied?:
            return "xmark.circle.fill"
        case .ruleViolation?:
            return "exclamationmark.triangle.fill"
        case .authFailed?:
            return "hand.raised.slash.fill"
        case .userOpSubmitted?:
            return "paperplane.circle.fill"
        case .userOpSendFailed?:
            return "paperplane.fill"
        case .userOpReceiptSuccess?:
            return "checkmark.seal.fill"
        case .userOpReceiptFailed?:
            return "xmark.seal.fill"
        case .userOpReceiptTimeout?:
            return "clock.badge.exclamationmark"
        case nil:
            return "clock"
        }
    }
}

private struct AuditRequestProgress {
    enum StepState {
        case pending
        case done
        case failed
    }

    struct Step {
        let title: String
        let state: StepState
    }

    let fraction: Double
    let message: String
    let color: Color
    let steps: [Step]
}

private struct AllowedAccountEntry: Identifiable {
    let chainKey: String
    let address: String

    var id: String {
        "\(chainKey.lowercased())|\(address.lowercased())"
    }

    var sortKey: Int {
        Int(chainKey) ?? .max
    }

    var chainDisplayName: String {
        if let chainId = Int(chainKey) {
            return "\(ChainConfig.name(for: chainId)) #\(chainId)"
        }
        return chainKey
    }
}

private struct SettingsCard<Content: View>: View {
    let icon: String
    let accent: Color
    let title: String
    let subtitle: String
    let content: Content

    init(
        icon: String,
        accent: Color,
        title: String,
        subtitle: String,
        @ViewBuilder content: () -> Content
    ) {
        self.icon = icon
        self.accent = accent
        self.title = title
        self.subtitle = subtitle
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(alignment: .firstTextBaseline, spacing: 8) {
                Image(systemName: icon)
                    .font(.caption.weight(.bold))
                    .foregroundStyle(accent)
                    .frame(width: 14)

                Text(title.uppercased())
                    .font(.caption2.weight(.black))
                    .kerning(1.1)
                    .foregroundStyle(accent)

                Spacer(minLength: 0)
            }
            .padding(.bottom, 4)

            if !subtitle.isEmpty {
                Text(subtitle)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.bottom, 10)
            }

            content
                .padding(.bottom, 14)

            Rectangle()
                .fill(accent.opacity(0.16))
                .frame(height: 1)
        }
        .padding(.horizontal, 2)
    }
}

private struct SummaryPill: View {
    let title: String
    let value: String
    let tint: Color

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)

            Text(value)
                .font(.subheadline.weight(.semibold))
                .lineLimit(1)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(tint.opacity(0.08))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .stroke(tint.opacity(0.10), lineWidth: 1)
        )
    }
}

private struct EmptyStateRow: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.caption.weight(.semibold))
                .foregroundStyle(Color(red: 0.45, green: 0.25, blue: 0.14))
                .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(detail)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer()
        }
        .padding(.vertical, 6)
    }
}

private struct RemovableChip: View {
    let title: String
    let subtitle: String
    let tint: Color
    let onRemove: () -> Void

    var body: some View {
        HStack(spacing: 8) {
            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.caption.weight(.semibold))
                Text(subtitle)
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            }

            Button(role: .destructive, action: onRemove) {
                Image(systemName: "xmark")
                    .font(.caption.weight(.bold))
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 5)
        .background(
            Capsule(style: .continuous)
                .fill(tint.opacity(0.07))
        )
        .overlay(
            Capsule(style: .continuous)
                .stroke(tint.opacity(0.10), lineWidth: 1)
        )
    }
}

private struct SettingsKeyValueRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text(label.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 92, alignment: .leading)

            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 4)
    }
}

private struct SettingsCodeBlock: View {
    let title: String?
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let title {
                Text(title.uppercased())
                    .font(.caption2.weight(.semibold))
                    .foregroundStyle(.secondary)
            }

            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Color.white.opacity(0.55))
                )
        }
    }
}

import SwiftUI

struct RulesSettingsView: View {
    @State private var draftConfig: BastionConfig = .default

    @State private var newAllowedChain = ""
    @State private var newAllowedAccountChain = ""
    @State private var newAllowedAccountAddress = ""
    @State private var newClientBundleId = ""
    @State private var newClientLabel = ""
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
        ZStack {
            backgroundGradient
                .ignoresSafeArea()

            ScrollView {
                VStack(spacing: 18) {
                    heroCard
                    authenticationCard
                    accessControlsCard
                    clientCard
                    rateLimitCard
                    spendingLimitCard
                }
                .padding(24)
                .padding(.bottom, 112)
            }
        }
        .safeAreaInset(edge: .bottom) {
            saveBar
        }
        .frame(minWidth: 760, minHeight: 860)
        .onAppear {
            loadCurrentConfig()
        }
    }

    private var backgroundGradient: some View {
        LinearGradient(
            colors: [
                Color(red: 0.96, green: 0.94, blue: 0.89),
                Color(red: 0.92, green: 0.95, blue: 0.97),
                Color(red: 0.98, green: 0.97, blue: 0.94),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    private var heroCard: some View {
        SettingsCard(
            icon: "shield.lefthalf.filled.badge.checkmark",
            accent: Color(red: 0.82, green: 0.46, blue: 0.16),
            title: "Bastion Rules",
            subtitle: "Define who can request signatures, when they can request them, and how aggressively Bastion should interrupt."
        ) {
            HStack(spacing: 12) {
                SummaryPill(
                    title: "Status",
                    value: draftConfig.rules.enabled ? "Active" : "Paused",
                    tint: draftConfig.rules.enabled ? .green : .gray
                )
                SummaryPill(
                    title: "Auth",
                    value: draftConfig.authPolicy.displayName,
                    tint: Color(red: 0.11, green: 0.39, blue: 0.63)
                )
                SummaryPill(
                    title: "Clients",
                    value: "\(draftConfig.rules.allowedClients?.count ?? 0)",
                    tint: Color(red: 0.14, green: 0.47, blue: 0.34)
                )
                SummaryPill(
                    title: "Limits",
                    value: "\(draftConfig.rules.rateLimits.count + draftConfig.rules.spendingLimits.count)",
                    tint: Color(red: 0.52, green: 0.33, blue: 0.18)
                )
            }
        }
    }

    private var authenticationCard: some View {
        SettingsCard(
            icon: "lock.shield",
            accent: Color(red: 0.13, green: 0.38, blue: 0.60),
            title: "Authentication",
            subtitle: "This policy applies after the request clears the configured rules."
        ) {
            VStack(alignment: .leading, spacing: 14) {
                Picker("Auth Policy", selection: authPolicyBinding) {
                    ForEach(AuthPolicy.allCases, id: \.self) { policy in
                        Text(policy.displayName).tag(policy)
                    }
                }
                .pickerStyle(.segmented)

                Text(authFootnote)
                    .font(.caption)
                    .foregroundStyle(.secondary)

                Toggle("Require explicit approval even when the request is within policy", isOn: requireExplicitApprovalBinding)
                    .toggleStyle(.switch)
            }
        }
    }

    private var accessControlsCard: some View {
        SettingsCard(
            icon: "slider.horizontal.3",
            accent: Color(red: 0.18, green: 0.45, blue: 0.34),
            title: "Access Controls",
            subtitle: "Scope which chains, accounts, and time windows can request autonomous signing."
        ) {
            VStack(alignment: .leading, spacing: 20) {
                Toggle("Enable rule enforcement", isOn: rulesEnabledBinding)
                    .toggleStyle(.switch)

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Allowed Hours")

                    Toggle("Restrict signing to a time window", isOn: allowedHoursEnabledBinding)
                        .toggleStyle(.switch)

                    if draftConfig.rules.allowedHours != nil {
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
                            title: "No time restriction",
                            detail: "Signing is allowed across the full day."
                        )
                    }
                }

                Divider()

                VStack(alignment: .leading, spacing: 10) {
                    sectionLabel("Allowed Chains")

                    if allowedChains.isEmpty {
                        EmptyStateRow(
                            icon: "point.3.connected.trianglepath.dotted",
                            title: "All chains allowed",
                            detail: "Add chain IDs if you want Bastion to reject requests outside a specific set."
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

                    Text("Matches inner execution targets decoded from Kernel execute() calldata on each chain.")
                        .font(.caption)
                        .foregroundStyle(.secondary)

                    if allowedAccountEntries.isEmpty {
                        EmptyStateRow(
                            icon: "person.crop.rectangle.stack",
                            title: "All targets allowed",
                            detail: "Add chain/target pairs if you want autonomous signing limited to specific destination contracts or EOAs."
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

    private var clientCard: some View {
        SettingsCard(
            icon: "desktopcomputer.trianglebadge.exclamationmark",
            accent: Color(red: 0.48, green: 0.34, blue: 0.16),
            title: "Allowed XPC Clients",
            subtitle: "By default any binary signed by your team can connect. Add bundle IDs here if you want a tighter allowlist."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                if allowedClients.isEmpty {
                    EmptyStateRow(
                        icon: "person.2.slash",
                        title: "No client allowlist",
                        detail: "Team ID verification is still enforced, but no per-client restriction is configured."
                    )
                } else {
                    VStack(spacing: 10) {
                        ForEach(allowedClients) { client in
                            HStack(alignment: .top, spacing: 12) {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(client.displayDescription)
                                        .font(.subheadline.weight(.semibold))
                                    Text(client.bundleId)
                                        .font(.system(.caption, design: .monospaced))
                                        .foregroundStyle(.secondary)
                                        .textSelection(.enabled)
                                }

                                Spacer()

                                removeButton {
                                    removeClient(client)
                                }
                            }
                            .padding(12)
                            .background(cardRowBackground)
                        }
                    }
                }

                HStack(spacing: 10) {
                    TextField("Bundle ID", text: $newClientBundleId)
                        .textFieldStyle(.roundedBorder)
                        .font(.system(.body, design: .monospaced))

                    TextField("Label (optional)", text: $newClientLabel)
                        .textFieldStyle(.roundedBorder)
                        .frame(width: 180)

                    Button("Add Client") {
                        addClient()
                    }
                    .buttonStyle(.bordered)
                    .disabled(!canAddClient)
                }
            }
        }
    }

    private var rateLimitCard: some View {
        SettingsCard(
            icon: "speedometer",
            accent: Color(red: 0.55, green: 0.29, blue: 0.18),
            title: "Rate Limits",
            subtitle: "Throttle how frequently Bastion may sign before it forces a manual override."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                if draftConfig.rules.rateLimits.isEmpty {
                    EmptyStateRow(
                        icon: "gauge.with.dots.needle.bottom.0percent",
                        title: "No rate limits configured",
                        detail: "Add one or more windows to slow down autonomous signing."
                    )
                } else {
                    VStack(spacing: 10) {
                        ForEach(draftConfig.rules.rateLimits) { rule in
                            HStack {
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(rule.displayDescription)
                                        .font(.subheadline.weight(.semibold))
                                    Text("Window: \(rule.windowSeconds)s")
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
            subtitle: "Direct native transfers plus ERC-20 transfer/approve/transferFrom calls are enforced from decoded Kernel execute() calldata."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(Color(red: 0.72, green: 0.43, blue: 0.11))
                    Text("Complex protocol calls can still move assets indirectly. Treat these limits as direct-call enforcement, not full semantic simulation.")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(Color.white.opacity(0.55))
                )

                if draftConfig.rules.spendingLimits.isEmpty {
                    EmptyStateRow(
                        icon: "wallet.bifold",
                        title: "No spending limits configured",
                        detail: "Add caps if you want a stored budget model in the config."
                    )
                } else {
                    VStack(spacing: 10) {
                        ForEach(draftConfig.rules.spendingLimits) { rule in
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
                        TextField("Allowance (smallest unit)", text: $newSLAllowance)
                            .textFieldStyle(.roundedBorder)

                        TextField("Reset window in seconds (optional)", text: $newSLWindow)
                            .textFieldStyle(.roundedBorder)
                            .frame(width: 220)

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

    private var saveBar: some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text("Rule changes require biometric or passcode confirmation.")
                    .font(.subheadline.weight(.semibold))

                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.caption)
                        .foregroundStyle(statusIsError ? .red : .green)
                } else {
                    Text("Hidden config fields are preserved unless this screen explicitly edits them.")
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
        .padding(.horizontal, 24)
        .padding(.vertical, 16)
        .background(.ultraThinMaterial)
    }

    private var authPolicyBinding: Binding<AuthPolicy> {
        Binding(
            get: { draftConfig.authPolicy },
            set: { draftConfig.authPolicy = $0 }
        )
    }

    private var rulesEnabledBinding: Binding<Bool> {
        Binding(
            get: { draftConfig.rules.enabled },
            set: { draftConfig.rules.enabled = $0 }
        )
    }

    private var requireExplicitApprovalBinding: Binding<Bool> {
        Binding(
            get: { draftConfig.rules.requireExplicitApproval },
            set: { draftConfig.rules.requireExplicitApproval = $0 }
        )
    }

    private var allowedHoursEnabledBinding: Binding<Bool> {
        Binding(
            get: { draftConfig.rules.allowedHours != nil },
            set: { enabled in
                draftConfig.rules.allowedHours = enabled
                    ? (draftConfig.rules.allowedHours ?? AllowedHours(start: 9, end: 18))
                    : nil
            }
        )
    }

    private var allowedHoursStartBinding: Binding<Int> {
        Binding(
            get: { draftConfig.rules.allowedHours?.start ?? 9 },
            set: { start in
                let currentEnd = draftConfig.rules.allowedHours?.end ?? 18
                draftConfig.rules.allowedHours = AllowedHours(start: start, end: currentEnd)
            }
        )
    }

    private var allowedHoursEndBinding: Binding<Int> {
        Binding(
            get: { draftConfig.rules.allowedHours?.end ?? 18 },
            set: { end in
                let currentStart = draftConfig.rules.allowedHours?.start ?? 9
                draftConfig.rules.allowedHours = AllowedHours(start: currentStart, end: end)
            }
        )
    }

    private var authFootnote: String {
        switch draftConfig.authPolicy {
        case .open:
            return "No local authentication after a request clears policy. Use this only if the surrounding rules are strict."
        case .passcode:
            return "macOS uses owner authentication here, so biometrics may still satisfy the prompt depending on system state."
        case .biometric:
            return "Touch ID or other enrolled biometrics are required for each allowed request."
        case .biometricOrPasscode:
            return "Any owner authentication works. This is the most flexible setting for daily use."
        }
    }

    private var allowedChains: [Int] {
        (draftConfig.rules.allowedChains ?? []).sorted()
    }

    private var allowedClients: [AllowedClient] {
        draftConfig.rules.allowedClients ?? []
    }

    private var allowedAccountEntries: [AllowedAccountEntry] {
        let entries = (draftConfig.rules.allowedTargets ?? [:]).flatMap { chainKey, addresses in
            addresses.map { AllowedAccountEntry(chainKey: chainKey, address: $0) }
        }

        return entries.sorted {
            if $0.sortKey == $1.sortKey {
                return $0.address.lowercased() < $1.address.lowercased()
            }
            return $0.sortKey < $1.sortKey
        }
    }

    private var canAddAllowedChain: Bool {
        Int(trimmed(newAllowedChain)) != nil
    }

    private var canAddAllowedAccount: Bool {
        isChainKey(trimmed(newAllowedAccountChain)) && isHexAddress(trimmed(newAllowedAccountAddress))
    }

    private var canAddClient: Bool {
        !trimmed(newClientBundleId).isEmpty
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

    private func sectionLabel(_ title: String) -> some View {
        Text(title)
            .font(.headline)
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

    private func addAllowedChain() {
        guard let chainId = Int(trimmed(newAllowedChain)) else {
            setStatus("Enter a valid numeric chain ID.", isError: true)
            return
        }

        var chains = Set(draftConfig.rules.allowedChains ?? [])
        chains.insert(chainId)
        draftConfig.rules.allowedChains = chains.isEmpty ? nil : chains.sorted()
        newAllowedChain = ""
        clearStatus()
    }

    private func removeAllowedChain(_ chainId: Int) {
        var chains = draftConfig.rules.allowedChains ?? []
        chains.removeAll { $0 == chainId }
        draftConfig.rules.allowedChains = chains.isEmpty ? nil : chains.sorted()
    }

    private func addAllowedAccount() {
        let chainKey = trimmed(newAllowedAccountChain)
        let address = normalizedAddress(newAllowedAccountAddress)

        guard isChainKey(chainKey), isHexAddress(address) else {
            setStatus("Enter a valid chain ID and target address.", isError: true)
            return
        }

        var targets = draftConfig.rules.allowedTargets ?? [:]
        var accounts = targets[chainKey] ?? []

        if !accounts.contains(where: { $0.caseInsensitiveCompare(address) == .orderedSame }) {
            accounts.append(address)
            accounts.sort { $0.lowercased() < $1.lowercased() }
            targets[chainKey] = accounts
        }

        draftConfig.rules.allowedTargets = targets.isEmpty ? nil : targets
        newAllowedAccountChain = ""
        newAllowedAccountAddress = ""
        clearStatus()
    }

    private func removeAllowedAccount(_ entry: AllowedAccountEntry) {
        guard var targets = draftConfig.rules.allowedTargets else { return }
        var accounts = targets[entry.chainKey] ?? []
        accounts.removeAll { $0.caseInsensitiveCompare(entry.address) == .orderedSame }
        if accounts.isEmpty {
            targets.removeValue(forKey: entry.chainKey)
        } else {
            targets[entry.chainKey] = accounts
        }
        draftConfig.rules.allowedTargets = targets.isEmpty ? nil : targets
    }

    private func addClient() {
        let bundleId = trimmed(newClientBundleId)
        guard !bundleId.isEmpty else {
            setStatus("Bundle ID is required.", isError: true)
            return
        }

        var clients = draftConfig.rules.allowedClients ?? []
        let exists = clients.contains { $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame }
        if !exists {
            clients.append(AllowedClient(
                id: UUID().uuidString,
                bundleId: bundleId,
                label: trimmed(newClientLabel).isEmpty ? nil : trimmed(newClientLabel)
            ))
        }

        draftConfig.rules.allowedClients = clients.isEmpty ? nil : clients
        newClientBundleId = ""
        newClientLabel = ""
        clearStatus()
    }

    private func removeClient(_ client: AllowedClient) {
        var clients = draftConfig.rules.allowedClients ?? []
        clients.removeAll { $0.id == client.id }
        draftConfig.rules.allowedClients = clients.isEmpty ? nil : clients
    }

    private func addRateLimit() {
        guard let max = Int(trimmed(newRLMax)),
              let window = Int(newRLWindow) else {
            setStatus("Rate limits require a request count and a window.", isError: true)
            return
        }

        draftConfig.rules.rateLimits.append(RateLimitRule(
            id: UUID().uuidString,
            maxRequests: max,
            windowSeconds: window
        ))
        newRLMax = ""
        clearStatus()
    }

    private func removeRateLimit(_ rule: RateLimitRule) {
        draftConfig.rules.rateLimits.removeAll { $0.id == rule.id }
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

        draftConfig.rules.spendingLimits.append(SpendingLimitRule(
            id: UUID().uuidString,
            token: token,
            allowance: trimmed(newSLAllowance),
            windowSeconds: window
        ))

        newSLAllowance = ""
        newSLWindow = ""
        newSLErc20Address = ""
        newSLErc20ChainId = ""
        clearStatus()
    }

    private func removeSpendingLimit(_ rule: SpendingLimitRule) {
        draftConfig.rules.spendingLimits.removeAll { $0.id == rule.id }
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

    private func clearTransientInputs() {
        newAllowedChain = ""
        newAllowedAccountChain = ""
        newAllowedAccountAddress = ""
        newClientBundleId = ""
        newClientLabel = ""
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
        VStack(alignment: .leading, spacing: 18) {
            HStack(alignment: .top, spacing: 14) {
                ZStack {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(accent.opacity(0.15))
                        .frame(width: 48, height: 48)

                    Image(systemName: icon)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(accent)
                }

                VStack(alignment: .leading, spacing: 4) {
                    Text(title)
                        .font(.title3.weight(.bold))
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer()
            }

            content
        }
        .padding(22)
        .background(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .fill(Color.white.opacity(0.74))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 24, style: .continuous)
                .stroke(Color.white.opacity(0.55), lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.06), radius: 16, x: 0, y: 10)
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
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(tint.opacity(0.12))
        )
    }
}

private struct EmptyStateRow: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: icon)
                .font(.title3)
                .foregroundStyle(.secondary)
                .frame(width: 32)

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
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(Color.white.opacity(0.55))
        )
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
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .background(
            Capsule(style: .continuous)
                .fill(tint.opacity(0.12))
        )
    }
}

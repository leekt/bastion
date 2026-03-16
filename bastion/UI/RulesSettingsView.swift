import SwiftUI

struct RulesSettingsView: View {
    @State private var authPolicy: AuthPolicy = .biometricOrPasscode
    @State private var requireExplicitApproval = false
    @State private var rulesEnabled = true
    @State private var allowedChains = ""

    // Allowed clients
    @State private var allowedClients: [AllowedClient] = []
    @State private var newClientBundleId = ""
    @State private var newClientLabel = ""

    // Rate limits
    @State private var rateLimits: [RateLimitRule] = []
    @State private var newRLMax = ""
    @State private var newRLWindow = "3600"

    // Spending limits
    @State private var spendingLimits: [SpendingLimitRule] = []
    @State private var newSLToken = "eth"
    @State private var newSLAllowance = ""
    @State private var newSLWindow = ""
    @State private var newSLErc20Address = ""
    @State private var newSLErc20ChainId = ""

    @State private var isSaving = false
    @State private var statusMessage = ""

    private let ruleEngine = RuleEngine.shared

    var body: some View {
        Form {
            Section("Authentication") {
                Picker("Auth Policy", selection: $authPolicy) {
                    ForEach(AuthPolicy.allCases, id: \.self) { policy in
                        Text(policy.displayName).tag(policy)
                    }
                }
                .pickerStyle(.radioGroup)

                Text("Saving requires biometric or passcode authentication.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Section("General") {
                Toggle("Rules Enabled", isOn: $rulesEnabled)
                Toggle("Require Explicit Approval", isOn: $requireExplicitApproval)
                    .disabled(!rulesEnabled)
                TextField("Allowed Chains (comma-separated IDs)", text: $allowedChains)
                    .disabled(!rulesEnabled)
            }

            // Allowed Clients
            Section("Allowed XPC Clients") {
                if allowedClients.isEmpty {
                    Text("All signed clients accepted (team ID verified)")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                ForEach(allowedClients) { client in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(client.displayDescription)
                            Text(client.bundleId)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Spacer()
                        Button(role: .destructive) {
                            allowedClients.removeAll { $0.id == client.id }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }

                HStack {
                    TextField("Bundle ID (e.g. com.bastion.cli)", text: $newClientBundleId)
                        .font(.system(.body, design: .monospaced))
                    TextField("Label (optional)", text: $newClientLabel)
                        .frame(width: 120)
                    Button("Add") {
                        guard !newClientBundleId.isEmpty else { return }
                        allowedClients.append(AllowedClient(
                            id: UUID().uuidString,
                            bundleId: newClientBundleId,
                            label: newClientLabel.isEmpty ? nil : newClientLabel
                        ))
                        newClientBundleId = ""
                        newClientLabel = ""
                    }
                    .disabled(newClientBundleId.isEmpty)
                }
            }
            .disabled(!rulesEnabled)

            // Rate Limits
            Section("Rate Limits") {
                ForEach(rateLimits) { rule in
                    HStack {
                        Text(rule.displayDescription)
                        Spacer()
                        Button(role: .destructive) {
                            rateLimits.removeAll { $0.id == rule.id }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }

                HStack {
                    TextField("Max requests", text: $newRLMax)
                        .frame(width: 100)
                    Picker("Window", selection: $newRLWindow) {
                        Text("Per minute").tag("60")
                        Text("Per hour").tag("3600")
                        Text("Per day").tag("86400")
                        Text("Per week").tag("604800")
                    }
                    .frame(width: 140)
                    Button("Add") {
                        if let max = Int(newRLMax), let window = Int(newRLWindow) {
                            rateLimits.append(RateLimitRule(
                                id: UUID().uuidString,
                                maxRequests: max,
                                windowSeconds: window
                            ))
                            newRLMax = ""
                        }
                    }
                    .disabled(Int(newRLMax) == nil)
                }
            }
            .disabled(!rulesEnabled)

            // Spending Limits
            Section("Spending Limits") {
                ForEach(spendingLimits) { rule in
                    HStack {
                        Text(rule.displayDescription)
                        Spacer()
                        Button(role: .destructive) {
                            spendingLimits.removeAll { $0.id == rule.id }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }

                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        Picker("Token", selection: $newSLToken) {
                            Text("ETH").tag("eth")
                            Text("USDC").tag("usdc")
                            Text("ERC-20").tag("erc20")
                        }
                        .frame(width: 120)

                        TextField("Allowance (smallest unit)", text: $newSLAllowance)
                    }

                    if newSLToken == "erc20" {
                        HStack {
                            TextField("Token address (0x...)", text: $newSLErc20Address)
                                .font(.system(.body, design: .monospaced))
                            TextField("Chain ID", text: $newSLErc20ChainId)
                                .frame(width: 80)
                        }
                    }

                    HStack {
                        TextField("Reset window (seconds, empty = lifetime)", text: $newSLWindow)
                        Button("Add") {
                            addSpendingLimit()
                        }
                        .disabled(newSLAllowance.isEmpty)
                    }
                }
            }
            .disabled(!rulesEnabled)

            // Save
            Section {
                HStack {
                    Spacer()
                    if !statusMessage.isEmpty {
                        Text(statusMessage)
                            .font(.caption)
                            .foregroundStyle(statusMessage.contains("Error") ? .red : .green)
                    }
                    Button("Save") {
                        saveConfig()
                    }
                    .disabled(isSaving)
                    .buttonStyle(.borderedProminent)
                }
            }
        }
        .formStyle(.grouped)
        .frame(width: 550, height: 800)
        .onAppear { loadCurrentConfig() }
    }

    private func addSpendingLimit() {
        let token: TokenIdentifier
        switch newSLToken {
        case "eth": token = .eth
        case "usdc": token = .usdc
        case "erc20":
            guard !newSLErc20Address.isEmpty, let chainId = Int(newSLErc20ChainId) else { return }
            token = .erc20(address: newSLErc20Address, chainId: chainId)
        default: return
        }

        spendingLimits.append(SpendingLimitRule(
            id: UUID().uuidString,
            token: token,
            allowance: newSLAllowance,
            windowSeconds: Int(newSLWindow)
        ))
        newSLAllowance = ""
        newSLWindow = ""
        newSLErc20Address = ""
        newSLErc20ChainId = ""
    }

    private func loadCurrentConfig() {
        let config = ruleEngine.config
        authPolicy = config.authPolicy
        rulesEnabled = config.rules.enabled
        requireExplicitApproval = config.rules.requireExplicitApproval
        allowedChains = config.rules.allowedChains?.map(String.init).joined(separator: ", ") ?? ""
        allowedClients = config.rules.allowedClients ?? []
        rateLimits = config.rules.rateLimits
        spendingLimits = config.rules.spendingLimits
    }

    private func saveConfig() {
        isSaving = true
        statusMessage = ""

        let chains: [Int]? = {
            let parts = allowedChains.split(separator: ",").compactMap { Int($0.trimmingCharacters(in: .whitespaces)) }
            return parts.isEmpty ? nil : parts
        }()

        let newRules = RuleConfig(
            enabled: rulesEnabled,
            requireExplicitApproval: requireExplicitApproval,
            allowedHours: nil,
            allowedChains: chains,
            allowedTargets: nil,
            allowedClients: allowedClients.isEmpty ? nil : allowedClients,
            rateLimits: rateLimits,
            spendingLimits: spendingLimits
        )

        let newConfig = BastionConfig(
            authPolicy: authPolicy,
            rules: newRules
        )

        Task {
            do {
                try await ruleEngine.updateConfig(newConfig)
                statusMessage = "Saved"
            } catch {
                statusMessage = "Error: \(error.localizedDescription)"
            }
            isSaving = false
        }
    }
}

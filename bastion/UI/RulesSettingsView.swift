import SwiftUI

struct RulesSettingsView: View {
    @State private var authPolicy: AuthPolicy = .biometricOrPasscode
    @State private var requireExplicitApproval = true
    @State private var maxAmountPerTx = ""
    @State private var dailyLimit = ""
    @State private var whitelistOnly = false
    @State private var whitelist: [String] = []
    @State private var newAddress = ""
    @State private var maxTxPerHour = ""
    @State private var rulesEnabled = true

    @State private var isSaving = false
    @State private var statusMessage = ""

    private let ruleEngine = RuleEngine.shared

    var body: some View {
        Form {
            // Section 1: Auth Policy
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

            // Section 2: Rules
            Section("Rules") {
                Toggle("Rules Enabled", isOn: $rulesEnabled)

                Toggle("Require Explicit Approval", isOn: $requireExplicitApproval)
                    .disabled(!rulesEnabled)

                TextField("Max Amount Per Tx (optional)", text: $maxAmountPerTx)
                    .disabled(!rulesEnabled)

                TextField("Daily Limit (optional)", text: $dailyLimit)
                    .disabled(!rulesEnabled)

                TextField("Max Tx Per Hour (optional)", text: $maxTxPerHour)
                    .disabled(!rulesEnabled)
            }

            // Section 3: Whitelist
            Section("Whitelist") {
                Toggle("Whitelist Only", isOn: $whitelistOnly)
                    .disabled(!rulesEnabled)

                ForEach(whitelist, id: \.self) { address in
                    HStack {
                        Text(address)
                            .font(.system(.body, design: .monospaced))
                            .lineLimit(1)
                        Spacer()
                        Button(role: .destructive) {
                            whitelist.removeAll { $0 == address }
                        } label: {
                            Image(systemName: "trash")
                        }
                    }
                }

                HStack {
                    TextField("Add address (0x...)", text: $newAddress)
                        .font(.system(.body, design: .monospaced))
                    Button("Add") {
                        let trimmed = newAddress.trimmingCharacters(in: .whitespaces)
                        if !trimmed.isEmpty && !whitelist.contains(trimmed) {
                            whitelist.append(trimmed)
                            newAddress = ""
                        }
                    }
                    .disabled(newAddress.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }

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
        .frame(width: 500, height: 600)
        .onAppear { loadCurrentConfig() }
    }

    private func loadCurrentConfig() {
        let config = ruleEngine.config
        authPolicy = config.authPolicy
        rulesEnabled = config.rules.enabled
        requireExplicitApproval = config.rules.requireExplicitApproval
        maxAmountPerTx = config.rules.maxAmountPerTx ?? ""
        dailyLimit = config.rules.dailyLimit ?? ""
        whitelistOnly = config.rules.whitelistOnly
        whitelist = config.rules.whitelist
        maxTxPerHour = config.rules.maxTxPerHour.map(String.init) ?? ""
    }

    private func saveConfig() {
        isSaving = true
        statusMessage = ""

        let newRules = RuleConfig(
            enabled: rulesEnabled,
            requireExplicitApproval: requireExplicitApproval,
            maxAmountPerTx: maxAmountPerTx.isEmpty ? nil : maxAmountPerTx,
            dailyLimit: dailyLimit.isEmpty ? nil : dailyLimit,
            whitelistOnly: whitelistOnly,
            whitelist: whitelist,
            allowedHours: nil,
            maxTxPerHour: Int(maxTxPerHour)
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

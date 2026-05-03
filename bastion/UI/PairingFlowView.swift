import SwiftUI

struct PairingResult {
    let displayName: String
    let bundleId: String
    let template: PairingPolicyTemplate
    let allowedChains: [Int]
}

enum PairingPolicyTemplate: String, CaseIterable, Identifiable {
    case conservative
    case readOnly
    case treasury
    case custom

    var id: String { rawValue }

    var title: String {
        switch self {
        case .conservative: return "Conservative DeFi"
        case .readOnly: return "Read-only signer"
        case .treasury: return "Treasury custodian"
        case .custom: return "Start from scratch"
        }
    }

    var hint: String {
        switch self {
        case .conservative:
            return "Audited targets, modest spend caps, biometric review for exceptions."
        case .readOnly:
            return "Typed-data and message auth flows. UserOperations stay review-gated."
        case .treasury:
            return "High-cap single counterparty work. Every signature requires approval."
        case .custom:
            return "Create an empty profile and configure each rule manually."
        }
    }

    var authPolicy: AuthPolicy {
        switch self {
        case .conservative, .readOnly:
            return .biometric
        case .treasury:
            return .biometricOrPasscode
        case .custom:
            return .biometricOrPasscode
        }
    }

    var compactRules: String {
        switch self {
        case .conservative: return "USDC 50/day · 60/hour"
        case .readOnly: return "UserOp review · 200/hour"
        case .treasury: return "USDC 10000/day · always confirm"
        case .custom: return "blank"
        }
    }

    var rules: RuleConfig {
        switch self {
        case .conservative:
            return RuleConfig(
                enabled: true,
                requireExplicitApproval: false,
                allowedHours: nil,
                allowedChains: [8453, 84532],
                allowedTargets: nil,
                allowedClients: nil,
                rateLimits: [RateLimitRule(id: UUID().uuidString, maxRequests: 60, windowSeconds: 3600)],
                spendingLimits: [
                    SpendingLimitRule(id: UUID().uuidString, token: .usdc, allowance: "50000000", windowSeconds: 86400),
                    SpendingLimitRule(id: UUID().uuidString, token: .eth, allowance: "20000000000000000", windowSeconds: 86400),
                ],
                rawMessagePolicy: RawMessagePolicy(enabled: true, allowRawSigning: false),
                typedDataPolicy: .default
            )
        case .readOnly:
            return RuleConfig(
                enabled: false,
                requireExplicitApproval: true,
                allowedHours: nil,
                allowedChains: [8453, 84532],
                allowedTargets: nil,
                allowedClients: nil,
                rateLimits: [RateLimitRule(id: UUID().uuidString, maxRequests: 200, windowSeconds: 3600)],
                spendingLimits: [
                    SpendingLimitRule(id: UUID().uuidString, token: .usdc, allowance: "0", windowSeconds: 86400),
                    SpendingLimitRule(id: UUID().uuidString, token: .eth, allowance: "0", windowSeconds: 86400),
                ],
                rawMessagePolicy: RawMessagePolicy(enabled: true, allowRawSigning: false),
                typedDataPolicy: TypedDataPolicy(
                    enabled: true,
                    requireExplicitApproval: false,
                    domainRules: [],
                    structRules: []
                )
            )
        case .treasury:
            return RuleConfig(
                enabled: true,
                requireExplicitApproval: true,
                allowedHours: AllowedHours(start: 9, end: 18),
                allowedChains: [1, 8453],
                allowedTargets: nil,
                allowedClients: nil,
                rateLimits: [RateLimitRule(id: UUID().uuidString, maxRequests: 10, windowSeconds: 3600)],
                spendingLimits: [
                    SpendingLimitRule(id: UUID().uuidString, token: .usdc, allowance: "10000000000", windowSeconds: 86400),
                    SpendingLimitRule(id: UUID().uuidString, token: .eth, allowance: "5000000000000000000", windowSeconds: 86400),
                ],
                rawMessagePolicy: RawMessagePolicy(enabled: false, allowRawSigning: false),
                typedDataPolicy: TypedDataPolicy(
                    enabled: true,
                    requireExplicitApproval: true,
                    domainRules: [],
                    structRules: []
                )
            )
        case .custom:
            return .default
        }
    }
}

struct PairingFlowView: View {
    @Environment(\.dismiss) private var dismiss

    /// Optional incoming handshake from PairingBroker. When set, the bundle
    /// ID + pairing code + process name are pulled from the live request and
    /// the bundle ID field becomes read-only — the operator can only confirm
    /// or cancel, not invent identity. When nil (e.g. opened from Settings
    /// "+ New agent" without a CLI in flight), the form is fully editable
    /// for manually creating a profile that the operator will pair later.
    let pending: PendingPairingRequest?
    let onFinish: (PairingResult) -> Void

    @State private var step = 0
    @State private var displayName: String
    @State private var bundleId: String
    @State private var selectedTemplate: PairingPolicyTemplate = .conservative
    @State private var selectedChains: Set<Int> = [8453]

    private var pairingCode: String? { pending?.pairingCode }
    private var processName: String? { pending?.processName }

    init(pending: PendingPairingRequest? = nil, onFinish: @escaping (PairingResult) -> Void) {
        self.pending = pending
        self.onFinish = onFinish
        _displayName = State(initialValue: pending?.processName ?? "")
        _bundleId = State(initialValue: pending?.bundleId ?? "")
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            BastionDivider()
            content
                .frame(minHeight: 380)
                .padding(22)
            BastionDivider()
            footer
        }
        .frame(width: 520)
        .background(Color.paper)
        .clipShape(RoundedRectangle(cornerRadius: BastionTokens.windowRadius))
        .overlay(
            RoundedRectangle(cornerRadius: BastionTokens.windowRadius)
                .strokeBorder(Color.ink150, lineWidth: 1)
        )
    }

    private var header: some View {
        HStack(spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7).fill(Color.ink900)
                ShieldGlyph(size: 14, color: .white, filled: true)
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text("Pair new agent")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.ink900)
                Text("Step \(step + 1) of 4")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ink500)
            }

            Spacer()

            HStack(spacing: 4) {
                ForEach(0..<4, id: \.self) { index in
                    Capsule()
                        .fill(index <= step ? Color.ink900 : Color.ink200)
                        .frame(width: 16, height: 4)
                }
            }
        }
        .padding(EdgeInsets(top: 14, leading: 18, bottom: 14, trailing: 18))
        .background(Color.ink50)
    }

    @ViewBuilder
    private var content: some View {
        switch step {
        case 0:
            handshakeStep
        case 1:
            templateStep
        case 2:
            chainsStep
        default:
            installStep
        }
    }

    private var handshakeStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            stepTitle(
                pending != nil ? "Incoming pair request" : "New agent",
                pending != nil
                    ? "Confirm that these details match the agent terminal before creating a signing profile."
                    : "Create a profile for an agent that will pair later. Bundle ID is the macOS code-signing identifier of the calling process."
            )

            VStack(alignment: .leading, spacing: 10) {
                if let processName {
                    KVRow(key: "Process", keyWidth: 110) {
                        Text(processName)
                            .font(.system(size: 12, design: .monospaced))
                    }
                }
                KVRow(key: "Bundle ID", keyWidth: 110) {
                    if pending != nil {
                        // Bundle ID is cryptographically verified by the XPC layer
                        // for live handshakes — never let the operator edit it.
                        Text(bundleId)
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(Color.ink700)
                    } else {
                        TextField("com.example.agent", text: $bundleId)
                            .textFieldStyle(.roundedBorder)
                            .font(.system(size: 12, design: .monospaced))
                    }
                }
                if let pairingCode {
                    KVRow(key: "Pairing code", keyWidth: 110) {
                        Text(pairingCode)
                            .font(.system(size: 18, weight: .semibold, design: .monospaced))
                            .tracking(1.2)
                    }
                }
                KVRow(key: "Display name", keyWidth: 110) {
                    TextField("Agent name", text: $displayName)
                        .textFieldStyle(.roundedBorder)
                }
            }
            .padding(14)
            .background(panelBackground)

            pairingNotice("The pairing code must match what the CLI printed. If it does not match, cancel this request.")
        }
    }

    private var templateStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            stepTitle("Start from a policy template", "Pick a starting point. You can edit every rule after pairing.")

            VStack(spacing: 8) {
                ForEach(PairingPolicyTemplate.allCases) { template in
                    Button {
                        selectedTemplate = template
                    } label: {
                        HStack(alignment: .top, spacing: 12) {
                            Image(systemName: selectedTemplate == template ? "largecircle.fill.circle" : "circle")
                                .foregroundStyle(selectedTemplate == template ? Color.ink900 : Color.ink300)
                                .frame(width: 18)
                                .padding(.top, 2)
                            VStack(alignment: .leading, spacing: 3) {
                                Text(template.title)
                                    .font(.system(size: 13, weight: .medium))
                                    .foregroundStyle(Color.ink900)
                                Text(template.hint)
                                    .font(.system(size: 12))
                                    .foregroundStyle(Color.ink500)
                                    .fixedSize(horizontal: false, vertical: true)
                            }
                            Spacer()
                            Text(template.compactRules)
                                .font(.system(size: 10.5, design: .monospaced))
                                .foregroundStyle(Color.ink500)
                                .multilineTextAlignment(.trailing)
                        }
                        .padding(12)
                        .background(
                            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                .fill(selectedTemplate == template ? Color.ink50 : Color.paper)
                                .overlay(
                                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                        .strokeBorder(selectedTemplate == template ? Color.ink700 : Color.ink150, lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var chainsStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            stepTitle("Allowed chains", "Requests for chains outside this list will require owner review.")

            VStack(spacing: 7) {
                ForEach([8453, 84532, 1, 11155111, 10, 42161], id: \.self) { chainId in
                    Button {
                        if selectedChains.contains(chainId) {
                            selectedChains.remove(chainId)
                        } else {
                            selectedChains.insert(chainId)
                        }
                    } label: {
                        HStack(spacing: 12) {
                            Image(systemName: selectedChains.contains(chainId) ? "checkmark.square.fill" : "square")
                                .foregroundStyle(selectedChains.contains(chainId) ? Color.ink900 : Color.ink300)
                                .frame(width: 18)
                            ChainBadge(chainId: chainId, size: .small)
                            Spacer()
                            Text(chainHint(for: chainId))
                                .font(.system(size: 12))
                                .foregroundStyle(Color.ink500)
                        }
                        .padding(10)
                        .background(
                            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                .fill(selectedChains.contains(chainId) ? Color.ink50 : Color.paper)
                                .overlay(
                                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                        .strokeBorder(selectedChains.contains(chainId) ? Color.ink700 : Color.ink150, lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
        }
    }

    private var installStep: some View {
        VStack(alignment: .leading, spacing: 14) {
            stepTitle("Install validator", "Each agent gets a scoped P256 validator on the smart account, so permissions are visible and revocable.")

            VStack(alignment: .leading, spacing: 10) {
                KVRow(key: "Pairing", keyWidth: 110) {
                    Text(displayName)
                        .font(.system(size: 13, weight: .medium))
                }
                KVRow(key: "Template", keyWidth: 110) {
                    Text(selectedTemplate.title)
                        .font(.system(size: 13, weight: .medium))
                }
                KVRow(key: "Chains", keyWidth: 110) {
                    Text(selectedChains.sorted().map { ChainConfig.name(for: $0) }.joined(separator: ", "))
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink700)
                }
            }
            .padding(14)
            .background(panelBackground)

            // The dialog itself only creates the local profile + SE key. The
            // on-chain install is a separate flow (groups install-agent or
            // the Settings validator card) — these rows describe what
            // *will* happen once the operator triggers it, so we mark them
            // as upcoming rather than fake-completed.
            VStack(alignment: .leading, spacing: 10) {
                installRow("Generate Secure Enclave key", done: false)
                installRow("Owner authorizes validator install", done: false)
                installRow("Submit install UserOp via ZeroDev bundler", done: false)
                installRow("Confirmation appears in Audit History", done: false)
            }
        }
    }

    private var footer: some View {
        HStack {
            Button {
                if step == 0 {
                    dismiss()
                } else {
                    step -= 1
                }
            } label: {
                Text(step == 0 ? "Cancel" : "Back")
            }
            .bastionButton(.ghost, size: .small)

            Spacer()

            Button {
                if step < 3 {
                    step += 1
                } else {
                    let result = PairingResult(
                        displayName: displayName.trimmingCharacters(in: .whitespacesAndNewlines),
                        bundleId: bundleId.trimmingCharacters(in: .whitespacesAndNewlines),
                        template: selectedTemplate,
                        allowedChains: selectedChains.sorted()
                    )
                    onFinish(result)
                    dismiss()
                }
            } label: {
                Text(step < 3 ? "Continue" : "Finish")
            }
            .bastionButton(.primary)
            .disabled(!canContinue)
            .opacity(canContinue ? 1 : 0.45)
        }
        .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
        .background(Color.ink50)
    }

    private var canContinue: Bool {
        !displayName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !bundleId.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty &&
        !selectedChains.isEmpty
    }

    private var panelBackground: some View {
        RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
            .fill(Color.ink50)
            .overlay(
                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                    .strokeBorder(Color.ink150, lineWidth: 1)
            )
    }

    private func stepTitle(_ title: String, _ subtitle: String) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(title)
                .font(.system(size: 17, weight: .semibold))
                .foregroundStyle(Color.ink900)
            Text(subtitle)
                .font(.system(size: 13))
                .foregroundStyle(Color.ink500)
                .fixedSize(horizontal: false, vertical: true)
        }
    }

    private func pairingNotice(_ text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            ShieldGlyph(size: 14, color: .bastionAccentDeep)
                .padding(.top, 2)
            Text(text)
                .font(.system(size: 12))
                .foregroundStyle(Color.bastionAccentDeep)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                .fill(Color.bastionAccentSoft)
        )
    }

    private func installRow(_ label: String, done: Bool) -> some View {
        HStack(spacing: 10) {
            ZStack {
                Circle()
                    .fill(done ? Color.bastionOk : Color.ink150)
                if done {
                    CheckGlyph(size: 10, color: .white)
                } else {
                    Circle().fill(Color.ink300).frame(width: 7, height: 7)
                }
            }
            .frame(width: 18, height: 18)
            Text(label)
                .font(.system(size: 13))
                .foregroundStyle(done ? Color.ink900 : Color.ink500)
        }
    }

    private func chainHint(for chainId: Int) -> String {
        switch chainId {
        case 8453: return "low fees"
        case 84532, 11155111: return "testnet"
        case 1: return "mainnet"
        case 10, 42161: return "L2"
        default: return "#\(chainId)"
        }
    }
}

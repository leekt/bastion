import SwiftUI

// Policy simulator. Pastes a UserOperation JSON, evaluates it against the
// supplied (possibly-draft) BastionConfig, and shows which rules would
// pass/fail. Helps owners reason about edits before saving.

struct PolicySimulatorView: View {
    let config: BastionConfig
    @State private var pasted: String = ""
    @State private var result: SimulationResult? = nil
    @State private var error: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "Policy simulator",
                subtitle: "Paste a UserOperation JSON to see whether the current policy would allow it."
            )
            BastionDivider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    // Defensive: ScrollView+VStack centers short content vertically
                    // on macOS unless the inner stack pins to topLeading.
                    BastionCard {
                        VStack(alignment: .leading, spacing: 8) {
                            BastionSectionHeader(title: "UserOperation JSON")
                            TextEditor(text: $pasted)
                                .font(.system(size: 12, design: .monospaced))
                                .frame(minHeight: 220)
                                .padding(8)
                                .background(
                                    RoundedRectangle(cornerRadius: 7)
                                        .fill(Color.ink50)
                                        .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink150, lineWidth: 1))
                                )
                            HStack {
                                Button("Paste sample", action: pasteSample)
                                    .bastionButton(.ghost, size: .small)
                                Spacer()
                                Button("Evaluate", action: evaluate)
                                    .bastionButton(.primary, size: .small)
                            }
                        }
                    }

                    if let error {
                        Text(error)
                            .font(.system(size: 12))
                            .foregroundStyle(Color.bastionBad)
                            .padding(.horizontal, 4)
                    }

                    if let result {
                        BastionCard {
                            VStack(alignment: .leading, spacing: 12) {
                                HStack(spacing: 8) {
                                    BastionChip(
                                        label: result.allowed ? "ALLOWED" : "BLOCKED",
                                        style: result.allowed ? .ok : .bad
                                    )
                                    Text(result.summary)
                                        .font(.system(size: 13, weight: .medium))
                                }
                                if !result.reasons.isEmpty {
                                    LabelXS(text: "Reasons")
                                    ForEach(Array(result.reasons.enumerated()), id: \.offset) { _, reason in
                                        HStack(alignment: .top, spacing: 8) {
                                            Circle().fill(Color.bastionBad).frame(width: 4, height: 4).padding(.top, 6)
                                            Text(reason)
                                                .font(.system(size: 12))
                                                .foregroundStyle(Color.ink700)
                                                .fixedSize(horizontal: false, vertical: true)
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }

    private func pasteSample() {
        pasted = #"""
        {
          "sender": "0x4c7a3df6c0e2db14ab39a8f4c98e1d5a3e89b21d",
          "nonce": "0x1",
          "callData": "0xe9ae5c530000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060",
          "chainId": 8453,
          "entryPointVersion": "v0.7"
        }
        """#
    }

    private func evaluate() {
        error = nil
        result = nil
        guard let data = pasted.data(using: .utf8) else {
            error = "Empty input"
            return
        }
        do {
            let op = try JSONDecoder().decode(SimulatedUserOpInput.self, from: data)
            // Build a SignRequest using the decoded fields. We can't fully
            // reconstruct the on-the-wire UserOperation for hashing without
            // every packed field, so we fall back to a synthetic message
            // operation when essentials are missing.
            let request = SignRequest(
                operation: op.toOperation(),
                requestID: "simulator-\(UUID().uuidString)",
                timestamp: Date(),
                clientBundleId: nil
            )
            let validation = RuleEngine.shared.validate(request, config: config)
            switch validation {
            case .allowed:
                result = SimulationResult(allowed: true, summary: "Rule engine would sign this silently or after configured auth.", reasons: [])
            case .denied(let reasons):
                result = SimulationResult(allowed: false, summary: "Rule engine would block this and require owner override.", reasons: reasons)
            }
        } catch {
            self.error = "Could not decode UserOperation JSON: \(error.localizedDescription)"
        }
    }
}

private struct SimulationResult {
    let allowed: Bool
    let summary: String
    let reasons: [String]
}

/// Minimal subset of UserOperation fields the simulator can read out of a
/// pasted JSON blob. Anything missing from the input is filled with safe
/// defaults; the rule engine still gets enough to evaluate target/spend rules.
private struct SimulatedUserOpInput: Codable {
    let sender: String
    let nonce: String?
    let callData: String?
    let chainId: Int
    let entryPointVersion: String?

    func toOperation() -> SigningOperation {
        let op = UserOperation(
            sender: sender,
            nonce: nonce ?? "0x0",
            callData: Data(hexString: callData ?? "0x") ?? Data(),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: "0x0",
            maxFeePerGas: "0x0",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: chainId,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: EntryPointVersion(rawValue: entryPointVersion ?? "v0.7") ?? .v0_7
        )
        return .userOperation(op)
    }
}

import SwiftUI

// Policy simulator. Pastes a UserOperation JSON, evaluates it against the
// supplied (possibly-draft) BastionConfig, and shows which rules would
// pass/fail. Helps owners reason about edits before saving.

struct PolicySimulatorView: View {
    let config: BastionConfig
    @State private var pasted: String = ""
    @State private var result: PolicySimulationResult? = nil
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
                                .padding(.s)
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
                                    .disabled(!canEvaluate)
                                    .opacity(canEvaluate ? 1 : 0.45)
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
                                    BastionSectionLabel(text: "Reasons")
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

    private var canEvaluate: Bool {
        PolicySimulatorEvaluator.canEvaluate(pasted)
    }

    private func pasteSample() {
        error = nil
        result = nil
        pasted = PolicySimulatorEvaluator.sampleUserOperationJSON
    }

    private func evaluate() {
        switch PolicySimulatorEvaluator.evaluate(pasted, config: config) {
        case .result(let result):
            error = nil
            self.result = result
        case .error(let message):
            result = nil
            error = message
        }
    }
}

nonisolated struct PolicySimulationResult: Equatable, Sendable {
    let allowed: Bool
    let summary: String
    let reasons: [String]
}

nonisolated enum PolicySimulatorEvaluation: Equatable, Sendable {
    case result(PolicySimulationResult)
    case error(String)
}

nonisolated enum PolicySimulatorEvaluator {
    static let emptyInputError = "Empty input"
    static let decodeErrorPrefix = "Could not decode UserOperation JSON: "
    static let invalidCallDataError = "callData must be a hex string."
    static let invalidEntryPointVersionError = "entryPointVersion must be v0.7, v0.8, or v0.9."

    static var sampleUserOperationJSON: String {
        let callData = KernelEncoding.executeCalldata(
            single: .init(
                to: "0x0000000000000000000000000000000000000001",
                value: 0,
                data: Data()
            )
        )
        return #"""
        {
          "sender": "0x4c7a3df6c0e2db14ab39a8f4c98e1d5a3e89b21d",
          "nonce": "0x1",
          "callData": "0x\#(callData.hex)",
          "chainId": 8453,
          "entryPointVersion": "v0.7"
        }
        """#
    }

    static func canEvaluate(_ input: String) -> Bool {
        !input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }

    static func evaluate(
        _ input: String,
        config: BastionConfig,
        engine: RuleEngine = .shared,
        requestID: String = "simulator-\(UUID().uuidString)",
        timestamp: Date = Date()
    ) -> PolicySimulatorEvaluation {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, let data = trimmed.data(using: .utf8) else {
            return .error(emptyInputError)
        }

        do {
            let op = try JSONDecoder().decode(SimulatedUserOpInput.self, from: data)
            let request = SignRequest(
                operation: try op.toOperation(),
                requestID: requestID,
                timestamp: timestamp,
                clientBundleId: nil
            )
            let validation = engine.validate(request, config: config)
            switch validation {
            case .allowed:
                return .result(PolicySimulationResult(allowed: true, summary: "Rule engine would sign this silently or after configured auth.", reasons: []))
            case .blocked(let reasons):
                return .result(PolicySimulationResult(allowed: false, summary: "Rule engine would hard-block this request.", reasons: reasons))
            case .denied(let reasons):
                return .result(PolicySimulationResult(allowed: false, summary: "Rule engine would block this and require owner override.", reasons: reasons))
            }
        } catch {
            return .error("\(decodeErrorPrefix)\(error.localizedDescription)")
        }
    }
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

    func toOperation() throws -> SigningOperation {
        let decodedCallData: Data
        if let callData {
            guard let data = Data(hexString: callData) else {
                throw PolicySimulatorInputError.invalidCallData
            }
            decodedCallData = data
        } else {
            decodedCallData = Data()
        }

        let decodedEntryPointVersion: EntryPointVersion
        if let entryPointVersion {
            guard let version = EntryPointVersion(rawValue: entryPointVersion) else {
                throw PolicySimulatorInputError.invalidEntryPointVersion
            }
            decodedEntryPointVersion = version
        } else {
            decodedEntryPointVersion = .v0_7
        }

        let op = UserOperation(
            sender: sender,
            nonce: nonce ?? "0x0",
            callData: decodedCallData,
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
            entryPointVersion: decodedEntryPointVersion
        )
        return .userOperation(op)
    }
}

private enum PolicySimulatorInputError: LocalizedError {
    case invalidCallData
    case invalidEntryPointVersion

    var errorDescription: String? {
        switch self {
        case .invalidCallData:
            return PolicySimulatorEvaluator.invalidCallDataError
        case .invalidEntryPointVersion:
            return PolicySimulatorEvaluator.invalidEntryPointVersionError
        }
    }
}

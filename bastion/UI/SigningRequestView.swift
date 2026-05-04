import AppKit
import Combine
import SwiftUI

// Redesigned signing approval popup.
// 420pt wide, two flavors: policyReview (decoded action headline) and ruleOverride (red violations).
// Mirrors approval.jsx from the design bundle.

struct SigningRequestView: View {
    let approval: ApprovalRequest
    let onApprove: () -> Void
    let onDeny: () -> Void

    @State private var remainingSeconds: Int = 60
    @State private var showRaw: Bool = false
    @State private var authStage: AuthStage = .idle
    @State private var confirmationText: String = ""

    private let initialCountdown = 60
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private enum AuthStage { case idle, authing, done }

    private var request: SignRequest { approval.request }
    private var isOverride: Bool {
        if case .ruleOverride = approval.mode { return true }
        return false
    }

    var body: some View {
        ZStack {
            backgroundDesktop
            popup
        }
        .frame(minWidth: 460, minHeight: 560)
        .onReceive(timer) { _ in
            guard authStage == .idle else { return }
            if remainingSeconds > 0 { remainingSeconds -= 1 } else { onDeny() }
        }
    }

    // MARK: - Desktop background

    private var backgroundDesktop: some View {
        LinearGradient(
            colors: [Color.bastionDesktopTop, Color.bastionDesktopBottom],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
        .ignoresSafeArea()
    }

    // MARK: - Popup

    private var popup: some View {
        VStack(spacing: 0) {
            header
            BastionDivider()
            if let intent = request.intent { intentPanel(intent: intent) }
            decodedAction
            if let classification = permitClassification {
                permitWarningPanel(classification: classification)
            }
            if !riskSignals.isEmpty { riskSignalsPanel }
            if isOverride { violationsPanel }
            if hasUnrecognizedCalldata { unknownCalldataPanel }
            if let phrase = typedConfirmationPhrase { typedConfirmationPanel(phrase: phrase) }
            rawDigest
            BastionDivider()
            footer
        }
        .frame(width: 420)
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.windowRadius).fill(Color.paper)
        )
        .overlay(
            RoundedRectangle(cornerRadius: BastionTokens.windowRadius)
                .strokeBorder(Color.ink150, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: BastionTokens.windowRadius))
        .shadow(color: Color.black.opacity(0.22), radius: 30, y: 24)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7)
                    .fill(isOverride ? Color.bastionBadSoft : Color.ink900)
                ShieldGlyph(size: 15, color: isOverride ? Color.bastionBad : .white, filled: !isOverride)
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(isOverride ? "Rule violation" : "Approve signing request")
                    .font(.system(size: 13, weight: .semibold))
                    .kerning(-0.13)
                HStack(spacing: 4) {
                    Text("from").foregroundStyle(Color.ink500)
                    Text(approval.clientContext.displayName)
                        .foregroundStyle(Color.ink700)
                        .fontWeight(.medium)
                }
                .font(.system(size: 11))
            }

            Spacer()

            Text(timeString)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(remainingSeconds < 10 ? Color.bastionBad : Color.ink500)
        }
        .padding(EdgeInsets(top: 14, leading: 16, bottom: 12, trailing: 16))
    }

    private var timeString: String {
        String(format: "%02d:%02d", remainingSeconds / 60, remainingSeconds % 60)
    }

    // MARK: - Decoded action

    private var decodedAction: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabelXS(text: "Decoded action").padding(.bottom, 2)

            Text(headline)
                .font(.system(size: 22, weight: .semibold, design: .monospaced))
                .kerning(-0.44)
                .foregroundStyle(Color.ink900)
                .lineLimit(2)
                .truncationMode(.tail)
                .padding(.bottom, 4)

            VStack(alignment: .leading, spacing: 6) {
                ForEach(headlineRows.indices, id: \.self) { i in
                    let row = headlineRows[i]
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(row.key)
                            .font(.system(size: 11.5))
                            .foregroundStyle(Color.ink500)
                            .frame(width: 60, alignment: .leading)
                        row.value
                    }
                }
            }
            .padding(.top, 4)
        }
        .padding(EdgeInsets(top: 16, leading: 16, bottom: 12, trailing: 16))
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private struct HeadlineRow {
        let key: String
        let value: AnyView
    }

    private var headline: String {
        switch request.operation {
        case .message(let text):
            let preview = text.count > 36 ? "\(text.prefix(36))…" : text
            return "Sign message: \"\(preview)\""
        case .rawBytes(let data):
            return "Sign 0x\(data.prefix(6).hex)…"
        case .typedData(let typed):
            return "Sign \(typed.domain.name ?? "EIP-712") · \(typed.primaryType)"
        case .userOperation(let op):
            let decoded = CalldataDecoder.decode(op)
            return userOpHeadline(decoded: decoded)
        }
    }

    private func userOpHeadline(decoded: CalldataDecoder.DecodedUserOp) -> String {
        let leaves = decoded.executions.flatMap(\.allLeafExecutions)
        if let firstToken = leaves.compactMap(\.tokenOperation).first {
            let kindWord: String
            switch firstToken.kind {
            case .transfer: kindWord = "Send"
            case .approve: kindWord = "Approve"
            case .transferFrom: kindWord = "Transfer"
            }
            return "\(kindWord) \(firstToken.amount)"
        }
        if leaves.contains(where: { $0.value != "0" }) {
            return "Native transfer"
        }
        return decoded.executions.first?.functionName.map { "Call \($0)" } ?? "Contract call"
    }

    private var decodedUserOperation: CalldataDecoder.DecodedUserOp? {
        guard case .userOperation(let op) = request.operation else { return nil }
        return CalldataDecoder.decode(op)
    }

    private var flattenedExecutions: [CalldataDecoder.DecodedExecution] {
        decodedUserOperation?.executions.flatMap(\.allLeafExecutions) ?? []
    }

    private var hasUnrecognizedCalldata: Bool {
        flattenedExecutions.contains(where: \.hasUnrecognizedCalldata)
    }

    private var typedConfirmationPhrase: String? {
        guard case .ruleOverride(let reasons) = approval.mode else { return nil }
        let risky = reasons.contains { reason in
            let lower = reason.lowercased()
            return lower.contains("spending limit") ||
                   lower.contains("high-value") ||
                   lower.contains("exceeded")
        }
        return risky ? "SIGN" : nil
    }

    private var canSubmitApproval: Bool {
        guard let phrase = typedConfirmationPhrase else { return true }
        return confirmationText == phrase
    }

    private var headlineRows: [HeadlineRow] {
        var rows: [HeadlineRow] = []
        switch request.operation {
        case .userOperation(let op):
            let decoded = CalldataDecoder.decode(op)
            if let firstLeaf = decoded.executions.flatMap(\.allLeafExecutions).first {
                let target: String
                if let tokenOp = firstLeaf.tokenOperation, let to = tokenOp.counterparty {
                    target = to
                } else {
                    target = firstLeaf.to
                }
                let toView: AnyView
                if let label = RuleEngine.shared.config.label(for: target, chainId: op.chainId) {
                    toView = AnyView(
                        HStack(spacing: 6) {
                            Text(label)
                                .font(.system(size: 12, weight: .medium))
                                .foregroundStyle(Color.ink900)
                            AddressView(address: target, muted: true)
                        }
                    )
                } else {
                    toView = AnyView(AddressView(address: target))
                }
                rows.append(HeadlineRow(key: "To", value: toView))
            }
            rows.append(HeadlineRow(
                key: "From",
                value: AnyView(AddressView(address: approval.clientContext.accountAddress ?? op.sender, muted: true))
            ))
            rows.append(HeadlineRow(
                key: "On",
                value: AnyView(ChainBadge(chainId: op.chainId, size: .small))
            ))
            if let submission = request.userOperationSubmission {
                rows.append(HeadlineRow(
                    key: "Submit",
                    value: AnyView(
                        Text(submission.provider.displayName)
                            .font(.system(size: 12))
                            .foregroundStyle(Color.ink700)
                    )
                ))
            }
        case .typedData(let typed):
            if let chainId = typed.domain.chainId {
                rows.append(HeadlineRow(key: "On", value: AnyView(ChainBadge(chainId: chainId, size: .small))))
            }
            if let verifier = typed.domain.verifyingContract {
                rows.append(HeadlineRow(key: "Verifier", value: AnyView(AddressView(address: verifier))))
            }
            if let bundle = approval.clientContext.accountAddress {
                rows.append(HeadlineRow(key: "From", value: AnyView(AddressView(address: bundle, muted: true))))
            }
        case .message:
            if let bundle = approval.clientContext.accountAddress {
                rows.append(HeadlineRow(key: "From", value: AnyView(AddressView(address: bundle, muted: true))))
            }
            rows.append(HeadlineRow(
                key: "Type",
                value: AnyView(Text("EIP-191 personal-sign").font(.system(size: 12)).foregroundStyle(Color.ink700))
            ))
        case .rawBytes:
            rows.append(HeadlineRow(
                key: "Type",
                value: AnyView(Text("Raw bytes — no Ethereum prefix").font(.system(size: 12)).foregroundStyle(Color.ink700))
            ))
        }

        if let preflight = approval.preflightResult, let estimate = preflight.gasEstimate {
            rows.append(HeadlineRow(
                key: "Max fee",
                value: AnyView(
                    HStack(spacing: 4) {
                        Text(formatGas(estimate.callGasLimit))
                            .font(.system(size: 12, design: .monospaced))
                            .foregroundStyle(Color.ink700)
                        Text("· bundler accepted")
                            .font(.system(size: 12))
                            .foregroundStyle(Color.ink500)
                    }
                )
            ))
        }

        return rows
    }

    private func formatGas(_ hex: String) -> String {
        let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        guard let v = UInt64(s, radix: 16) else { return hex }
        let nf = NumberFormatter(); nf.numberStyle = .decimal
        return "\(nf.string(from: NSNumber(value: v)) ?? "\(v)") gas"
    }

    // MARK: - Violations

    @ViewBuilder
    private var violationsPanel: some View {
        if case .ruleOverride(let reasons) = approval.mode {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    CloseGlyph(size: 11, color: .bastionBad)
                    Text("Rules broken")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Color.bastionBad)
                }
                .padding(.bottom, 2)
                ForEach(Array(reasons.enumerated()), id: \.offset) { _, reason in
                    HStack(alignment: .top, spacing: 8) {
                        Circle().fill(Color.bastionBad).frame(width: 4, height: 4).padding(.top, 6)
                        Text(reason)
                            .font(.system(size: 12))
                            .foregroundStyle(Color.bastionBad)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
            .background(
                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                    .fill(Color.bastionBadSoft)
                    .overlay(
                        RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                            .strokeBorder(Color.bastionBad.opacity(0.25), lineWidth: 1)
                    )
            )
            .padding(.horizontal, 16).padding(.bottom, 14)
        }
    }

    // MARK: - Edge-state warnings

    @ViewBuilder
    private var unknownCalldataPanel: some View {
        if let execution = flattenedExecutions.first(where: \.hasUnrecognizedCalldata) {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .semibold))
                    Text("Unrecognized contract call")
                        .font(.system(size: 11, weight: .semibold))
                }
                .foregroundStyle(Color.bastionWarn)

                Text("Bastion could not decode this calldata. Approve only if you recognize the target and selector.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.bastionWarn)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 6) {
                    KVRow(key: "Target", keyWidth: 62) {
                        AddressView(address: execution.to)
                    }
                    if let selector = execution.selector {
                        KVRow(key: "Selector", keyWidth: 62) {
                            Text("0x\(selector.hex)")
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(Color.ink700)
                        }
                    }
                    KVRow(key: "On", keyWidth: 62) {
                        ChainBadge(chainId: requestChainId ?? 0, size: .small)
                    }
                    if !execution.rawCalldata.isEmpty {
                        KVRow(key: "Calldata", keyWidth: 62) {
                            Text("0x\(BastionFormat.shortHex(execution.rawCalldata.hex, head: 14, tail: 10))")
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(Color.ink700)
                                .lineLimit(1)
                        }
                    }
                }
            }
            .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
            .background(
                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                    .fill(Color.bastionWarnSoft)
                    .overlay(
                        RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                            .strokeBorder(Color.bastionWarn.opacity(0.25), lineWidth: 1)
                    )
            )
            .padding(.horizontal, 16).padding(.bottom, 14)
        }
    }

    private func typedConfirmationPanel(phrase: String) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Extra confirmation required")
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.bastionBad)
            Text("This override changes a spend or limit boundary. Type \(phrase) to continue.")
                .font(.system(size: 12))
                .foregroundStyle(Color.bastionBad)
                .fixedSize(horizontal: false, vertical: true)
            TextField("Type \(phrase)", text: $confirmationText)
                .textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .fill(Color.paper)
                        .overlay(
                            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                .strokeBorder(canSubmitApproval ? Color.bastionOk : Color.ink200, lineWidth: 1)
                        )
                )
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                .fill(Color.bastionBadSoft)
        )
        .padding(.horizontal, 16).padding(.bottom, 14)
    }

    private var requestChainId: Int? {
        switch request.operation {
        case .userOperation(let op):
            return op.chainId
        case .typedData(let typed):
            return typed.domain.chainId
        case .message, .rawBytes:
            return nil
        }
    }

    // MARK: - Intent panel

    private func intentPanel(intent: String) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Text("“")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(Color.ink400)
            Text(intent)
                .font(.system(size: 12.5, weight: .medium))
                .italic()
                .foregroundStyle(Color.ink700)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(EdgeInsets(top: 12, leading: 16, bottom: 0, trailing: 16))
    }

    // MARK: - Permit classifier (PR5)

    /// PR5: detect ERC-2612 / Permit2 / ERC-7702 typed-data shapes that
    /// grant on-chain spending or execution authority. The result drives
    /// the loud red panel below the headline so the owner can see
    /// exactly what they're authorising — most permit-style messages
    /// look innocuous in raw form but actually unlock unbounded later
    /// transfers.
    private var permitClassification: PermitClassification? {
        guard case .typedData(let typed) = request.operation else { return nil }
        return PermitClassifier.classify(typed)
    }

    @ViewBuilder
    private func permitWarningPanel(classification: PermitClassification) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.bastionBad)
                Text(classification.label)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Color.bastionBad)
                Spacer(minLength: 0)
                if classification.grantsLastingAllowance {
                    BastionChip(label: "Lasting allowance", style: .bad)
                }
            }
            Text(permitWarningExplanation(for: classification))
                .font(.system(size: 12))
                .foregroundStyle(Color.bastionBad)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(permitFieldRows(classification), id: \.key) { row in
                    KVRow(key: row.key, keyWidth: 70) {
                        row.value
                    }
                }
            }
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                .fill(Color.bastionBadSoft)
                .overlay(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .strokeBorder(Color.bastionBad.opacity(0.3), lineWidth: 1)
                )
        )
        .padding(.horizontal, 16).padding(.bottom, 14)
    }

    private func permitWarningExplanation(for classification: PermitClassification) -> String {
        switch classification {
        case .erc2612:
            return "Signing this lets the spender pull tokens from your account at any point before the deadline — without another approval. Verify the spender, amount, and deadline match what you expect."
        case .permit2Single, .permit2Batch:
            return "This grants Uniswap Permit2 allowance off-chain. The spender can transfer up to the listed amount until expiration, with no further on-chain step."
        case .permit2TransferFrom:
            return "Permit2 one-shot transfer authorization. The spender can pull this exact amount once before the deadline."
        case .erc7702Delegation:
            return "ERC-7702 set-code authorization installs delegate code on your EOA. Anything that delegate runs (including draining) executes with your account's authority."
        }
    }

    private struct PermitRow { let key: String; let value: AnyView }

    private func permitFieldRows(_ classification: PermitClassification) -> [PermitRow] {
        switch classification {
        case .erc2612(let spender, let amount, let deadline, let token):
            var rows: [PermitRow] = []
            if let token {
                rows.append(PermitRow(key: "Token", value: AnyView(AddressView(address: token, muted: true))))
            }
            rows.append(PermitRow(key: "Spender", value: AnyView(AddressView(address: spender))))
            rows.append(PermitRow(key: "Amount", value: AnyView(monoText(amount))))
            rows.append(PermitRow(key: "Deadline", value: AnyView(monoText(formatExpiry(deadline)))))
            return rows
        case .permit2Single(let token, let spender, let amount, let expiration, let nonce):
            return [
                PermitRow(key: "Token", value: AnyView(AddressView(address: token, muted: true))),
                PermitRow(key: "Spender", value: AnyView(AddressView(address: spender))),
                PermitRow(key: "Amount", value: AnyView(monoText(amount))),
                PermitRow(key: "Expires", value: AnyView(monoText(formatExpiry(expiration)))),
                PermitRow(key: "Nonce", value: AnyView(monoText(nonce))),
            ]
        case .permit2Batch(let spender, let tokens, let amounts, let expiration):
            var rows: [PermitRow] = [
                PermitRow(key: "Spender", value: AnyView(AddressView(address: spender))),
                PermitRow(key: "Earliest", value: AnyView(monoText(formatExpiry(expiration)))),
            ]
            for (idx, token) in tokens.enumerated() {
                let amount = idx < amounts.count ? amounts[idx] : "?"
                rows.append(PermitRow(
                    key: "Token \(idx + 1)",
                    value: AnyView(
                        HStack(spacing: 6) {
                            AddressView(address: token, muted: true)
                            Text("·").foregroundStyle(Color.ink400)
                            monoText(amount)
                        }
                    )
                ))
            }
            return rows
        case .permit2TransferFrom(let token, let spender, let amount, let deadline):
            return [
                PermitRow(key: "Token", value: AnyView(AddressView(address: token, muted: true))),
                PermitRow(key: "Spender", value: AnyView(AddressView(address: spender))),
                PermitRow(key: "Amount", value: AnyView(monoText(amount))),
                PermitRow(key: "Deadline", value: AnyView(monoText(formatExpiry(deadline)))),
            ]
        case .erc7702Delegation(let delegate, let chainId, let nonce):
            return [
                PermitRow(key: "Delegate", value: AnyView(AddressView(address: delegate))),
                PermitRow(key: "Chain", value: AnyView(monoText(chainId))),
                PermitRow(key: "Nonce", value: AnyView(monoText(nonce))),
            ]
        }
    }

    private func monoText(_ s: String) -> some View {
        Text(s)
            .font(.system(size: 12, design: .monospaced))
            .foregroundStyle(Color.ink900)
    }

    /// Formats a uint256-as-string deadline/expiration. Treats values
    /// that fit in Int64 as unix seconds and renders relative time;
    /// returns the raw string otherwise so we never mis-display huge
    /// adversarial numbers.
    private func formatExpiry(_ raw: String) -> String {
        guard let seconds = Int64(raw),
              seconds > 0,
              seconds < 4_000_000_000 else {
            return raw
        }
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))
        let formatter = RelativeDateTimeFormatter()
        formatter.unitsStyle = .full
        return formatter.localizedString(for: date, relativeTo: Date())
    }

    // MARK: - Risk signals

    private var riskSignals: [RiskSignal] {
        RiskScorer.signals(
            for: request,
            config: RuleEngine.shared.config,
            clientContext: approval.clientContext
        )
    }

    private var riskSignalsPanel: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabelXS(text: "Risk signals")
            // Use LazyVGrid as a poor man's wrapping flow — adaptive columns
            // give us wrap-by-width without a custom Layout.
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 110), spacing: 6)], alignment: .leading, spacing: 6) {
                ForEach(riskSignals) { signal in
                    BastionChip(
                        label: signal.label,
                        style: chipStyle(for: signal.tone)
                    )
                    .help(signal.detail ?? signal.label)
                }
            }
        }
        .padding(EdgeInsets(top: 0, leading: 16, bottom: 12, trailing: 16))
    }

    private func chipStyle(for tone: RiskSignal.Tone) -> BastionChip.Style {
        switch tone {
        case .info:   return .accent
        case .warn:   return .warn
        case .danger: return .bad
        }
    }

    // MARK: - Raw digest

    private var rawDigest: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button {
                withAnimation(.easeOut(duration: 0.18)) { showRaw.toggle() }
            } label: {
                HStack(spacing: 6) {
                    Text(showRaw ? "▾" : "▸")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                    Text(showRaw ? "Hide raw digest" : "Show raw digest")
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                }
            }
            .buttonStyle(.plain)

            if showRaw {
                Text("0x\(request.data.hex)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.ink700)
                    .lineLimit(nil)
                    .multilineTextAlignment(.leading)
                    .padding(EdgeInsets(top: 8, leading: 10, bottom: 8, trailing: 10))
                    .background(
                        RoundedRectangle(cornerRadius: 6)
                            .fill(Color.ink50)
                            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.ink150, lineWidth: 1))
                    )
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(EdgeInsets(top: 0, leading: 16, bottom: 12, trailing: 16))
    }

    // MARK: - Footer

    private var footer: some View {
        VStack(spacing: 0) {
            switch authStage {
            case .authing:
                HStack(spacing: 10) {
                    TouchIDGlyph(size: 32, pulsing: true)
                    Text("Touch ID to \(isOverride ? "override" : "authorize")…")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.ink700)
                }
                .padding(.vertical, 8)
            case .done:
                HStack(spacing: 8) {
                    CheckGlyph(size: 14, color: .bastionOk)
                    Text("Signed · returning signature to \(approval.clientContext.displayName)")
                        .font(.system(size: 13))
                        .foregroundStyle(Color.bastionOk)
                }
                .padding(.vertical, 8)
            case .idle:
                idleFooter
            }
        }
        .frame(maxWidth: .infinity)
        .padding(EdgeInsets(top: 12, leading: 16, bottom: 14, trailing: 16))
        .background(Color.ink50)
    }

    private var idleFooter: some View {
        VStack(spacing: 10) {
            HStack(spacing: 6) {
                LockGlyph(size: 11, color: .ink500)
                Text(isOverride ? "Owner authentication required" : "Signature stays in Secure Enclave")
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ink500)
            }
            .frame(maxWidth: .infinity)

            HStack(spacing: 8) {
                Button(action: onDeny) {
                    Text("Deny").frame(maxWidth: .infinity)
                }
                .keyboardShortcut(.escape)
                .bastionButton(.default)

                Button(action: primaryTapped) {
                    Text(isOverride ? "Override & Sign" : "Approve")
                        .frame(maxWidth: .infinity)
                }
                .bastionButton(isOverride ? .danger : .primary)
                .keyboardShortcut(.return, modifiers: [])
                .disabled(!canSubmitApproval)
                .opacity(canSubmitApproval ? 1 : 0.45)
                .frame(maxWidth: .infinity)
            }
        }
    }

    private func primaryTapped() {
        guard canSubmitApproval else { return }
        // Minimal animation flourish — the Secure Enclave / AuthManager actually drives the
        // biometric prompt at the call site; we just stage the visual feedback.
        withAnimation { authStage = .authing }
        // Trigger upstream approval in parallel — caller is responsible for closing the panel,
        // which races against our 'done' state. The 'done' label is purely visual filler if
        // the panel takes a beat to close.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.05) {
            onApprove()
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.9) {
            withAnimation { authStage = .done }
        }
    }
}

// MARK: - Panel Manager

@MainActor
final class SigningRequestPanelManager {
    static let shared = SigningRequestPanelManager()
    private var panel: NSPanel?

    private init() {}

    func showRequest(_ approval: ApprovalRequest, onApprove: @escaping () -> Void, onDeny: @escaping () -> Void) {
        closePanel()

        let view = SigningRequestView(
            approval: approval,
            onApprove: { [weak self] in
                onApprove()
                self?.closePanel()
            },
            onDeny: { [weak self] in
                onDeny()
                self?.closePanel()
            }
        )

        let hostingView = NSHostingView(rootView: view)

        let newPanel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: 480, height: 560),
            styleMask: [.titled, .closable, .fullSizeContentView, .nonactivatingPanel],
            backing: .buffered,
            defer: false
        )
        newPanel.contentView = hostingView
        newPanel.title = "Bastion Approval"
        newPanel.titleVisibility = .hidden
        newPanel.titlebarAppearsTransparent = true
        newPanel.isMovableByWindowBackground = true
        newPanel.level = .floating
        newPanel.center()
        newPanel.isFloatingPanel = true
        newPanel.becomesKeyOnlyIfNeeded = false
        newPanel.hidesOnDeactivate = false
        newPanel.isOpaque = false
        newPanel.backgroundColor = .clear
        newPanel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        NSApplication.shared.activate(ignoringOtherApps: true)
        newPanel.makeKeyAndOrderFront(nil)
        newPanel.orderFrontRegardless()
        NSRunningApplication.current.activate(options: [.activateIgnoringOtherApps, .activateAllWindows])

        self.panel = newPanel
    }

    func closePanel() {
        panel?.close()
        panel = nil
    }
}

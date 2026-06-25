import AppKit
import Combine
import SwiftUI

// Redesigned signing approval popup.
// 420pt wide, two flavors: policyReview (decoded action headline) and ruleOverride (red violations).
// Mirrors approval.jsx from the design bundle.

nonisolated enum SigningRequestAuthStage: Equatable, Sendable {
    case idle
    case authing
    case done
    case denied
}

nonisolated enum SigningRequestActionTiming {
    static let approveCallbackDelay: TimeInterval = 0.05
    static let doneFlashDelay: TimeInterval = 0.9
    static let denyCallbackDelay: TimeInterval = 0.45

    static func shouldApply(scheduledGeneration: UInt64, currentGeneration: UInt64) -> Bool {
        scheduledGeneration == currentGeneration
    }
}

struct SigningRequestPanelChrome: Equatable {
    static let current = SigningRequestPanelChrome(
        cardWidth: 420,
        detailScrollMaxHeight: 392,
        styleMask: [.borderless, .nonactivatingPanel],
        hasNativeShadow: false,
        hasClearBackground: true,
        usesTransparentHostView: true,
        usesNativeTitlebar: false,
        usesNativeCloseButton: false
    )

    let cardWidth: CGFloat
    let detailScrollMaxHeight: CGFloat
    let styleMask: NSWindow.StyleMask
    let hasNativeShadow: Bool
    let hasClearBackground: Bool
    let usesTransparentHostView: Bool
    let usesNativeTitlebar: Bool
    let usesNativeCloseButton: Bool

    func contentRect(fitting size: NSSize) -> NSRect {
        NSRect(x: 0, y: 0, width: cardWidth, height: max(1, ceil(size.height)))
    }
}

nonisolated struct ApprovalPreviewWindowCandidate: Equatable, Sendable {
    let id: Int
    let isApprovalPanel: Bool
}

nonisolated enum ApprovalPreviewWindowHidingPlan {
    static func windowIDsToHide(
        primary: ApprovalPreviewWindowCandidate?,
        allWindows: [ApprovalPreviewWindowCandidate]
    ) -> [Int] {
        var ordered = [ApprovalPreviewWindowCandidate]()
        if let primary {
            ordered.append(primary)
        }
        ordered.append(contentsOf: allWindows)

        var seen = Set<Int>()
        var hidden = [Int]()
        for candidate in ordered {
            guard seen.insert(candidate.id).inserted else { continue }
            guard !candidate.isApprovalPanel else { continue }
            hidden.append(candidate.id)
        }
        return hidden
    }
}

@MainActor
enum ApprovalPreviewWindowHider {
    static let approvalPanelTitle = "Bastion Approval"

    static func hideHostWindowsBeforePreview(primary: NSWindow?) {
        hideHostWindowsBeforePreview(primary: primary, allWindows: NSApp.windows)
    }

    static func hideHostWindowsBeforePreview(primary: NSWindow?, allWindows: [NSWindow]) {
        for window in orderedHostWindows(primary: primary, allWindows: allWindows) {
            guard window.title != approvalPanelTitle else { continue }
            window.orderOut(nil)
        }
    }

    private static func orderedHostWindows(primary: NSWindow?, allWindows: [NSWindow]) -> [NSWindow] {
        var ordered = [NSWindow]()
        if let primary {
            ordered.append(primary)
        }
        ordered.append(contentsOf: allWindows)

        var seen = Set<ObjectIdentifier>()
        var result = [NSWindow]()
        for window in ordered {
            guard seen.insert(ObjectIdentifier(window)).inserted else { continue }
            result.append(window)
        }
        return result
    }
}

nonisolated struct SigningRequestPresentation: Equatable, Sendable {
    let accessibilityLabel: String
    let headerTitle: String
    let operationKindLabel: String
    let modeLabel: String
    let clientDisplayName: String
    let countdownLabel: String
    let countdownAccessibilityLabel: String
    let rawDigestButtonTitle: String
    let rawDigestHex: String
    let idleAssurance: String
    let denyButtonTitle: String
    let denyAccessibilityLabel: String
    let denyAccessibilityHint: String
    let primaryButtonTitle: String
    let primaryAccessibilityLabel: String
    let primaryAccessibilityHint: String
    let authingText: String
    let doneText: String
    let deniedText: String
    let canSubmitApproval: Bool
    let canTriggerPrimary: Bool

    static func make(
        approval: ApprovalRequest,
        remainingSeconds: Int,
        showRaw: Bool,
        authStage: SigningRequestAuthStage,
        confirmationText: String
    ) -> SigningRequestPresentation {
        let isOverride = approval.mode.isOverride
        let mode = approval.request.executionMode
        let client = approval.clientContext.displayName
        let canSubmit = canSubmitApproval(
            approval: approval,
            confirmationText: confirmationText
        )
        let primaryTitle = primaryButtonTitle(isOverride: isOverride, mode: mode)
        return SigningRequestPresentation(
            accessibilityLabel: isOverride ? "Rule violation, owner authentication required" : "Signing request approval",
            headerTitle: isOverride ? "Rule violation" : "Approve request",
            operationKindLabel: approval.request.operationKindLabel,
            modeLabel: mode.label,
            clientDisplayName: client,
            countdownLabel: String(format: "%02d:%02d", remainingSeconds / 60, remainingSeconds % 60),
            countdownAccessibilityLabel: "Auto-deny in \(remainingSeconds) seconds",
            rawDigestButtonTitle: showRaw ? "Hide raw digest" : "Show raw digest",
            rawDigestHex: "0x\(approval.request.data.hex)",
            idleAssurance: idleAssurance(isOverride: isOverride, mode: mode),
            denyButtonTitle: "Deny",
            denyAccessibilityLabel: "Deny signing request",
            denyAccessibilityHint: "Reject this request from \(client) without signing.",
            primaryButtonTitle: primaryTitle,
            primaryAccessibilityLabel: primaryAccessibilityLabel(isOverride: isOverride, mode: mode),
            primaryAccessibilityHint: isOverride
                ? "Authorize this request even though it violates configured rules. Owner authentication required."
                : primaryAccessibilityHint(mode: mode, clientDisplayName: client),
            authingText: "Touch ID to \(authingVerb(isOverride: isOverride, mode: mode))…",
            doneText: doneText(mode: mode, clientDisplayName: client),
            deniedText: "Denied · \(client) will see a rejection",
            canSubmitApproval: canSubmit,
            canTriggerPrimary: canTriggerPrimary(authStage: authStage, canSubmitApproval: canSubmit)
        )
    }

    static func canTriggerPrimary(authStage: SigningRequestAuthStage, canSubmitApproval: Bool) -> Bool {
        authStage == .idle && canSubmitApproval
    }

    static func requiredConfirmationPhrase(for approval: ApprovalRequest) -> String? {
        let phrase: String?
        if let explicit = approval.typedConfirmationPhrase {
            phrase = explicit
        } else if case .ruleOverride(let reasons) = approval.mode {
            let risky = reasons.contains { reason in
                let lower = reason.lowercased()
                return lower.contains("spending limit") ||
                       lower.contains("high-value") ||
                       lower.contains("exceeded")
            }
            phrase = risky ? "SIGN" : nil
        } else {
            phrase = nil
        }
        guard let phrase else { return nil }
        let trimmed = phrase.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? HighValueRule.default.confirmationPhrase : trimmed
    }

    static func canSubmitApproval(approval: ApprovalRequest, confirmationText: String) -> Bool {
        guard let required = requiredConfirmationPhrase(for: approval) else { return true }
        return confirmationText.trimmingCharacters(in: .whitespacesAndNewlines) == required
    }

    private static func primaryButtonTitle(isOverride: Bool, mode: RequestExecutionMode) -> String {
        if isOverride {
            return mode == .approveAndSend ? "Override + Send" : "Override & Sign"
        }
        return mode.actionLabel
    }

    private static func primaryAccessibilityLabel(isOverride: Bool, mode: RequestExecutionMode) -> String {
        if isOverride {
            return mode == .approveAndSend ? "Override rules and submit UserOperation" : "Override rules and sign"
        }
        return mode == .approveAndSend ? "Approve and send UserOperation" : "Approve signing request"
    }

    private static func primaryAccessibilityHint(mode: RequestExecutionMode, clientDisplayName: String) -> String {
        switch mode {
        case .signOnly:
            return "Sign this request from \(clientDisplayName)."
        case .approveAndSend:
            return "Sign this UserOperation and submit it through the configured provider."
        }
    }

    private static func idleAssurance(isOverride: Bool, mode: RequestExecutionMode) -> String {
        if isOverride {
            return "Owner authentication required"
        }
        switch mode {
        case .signOnly:
            return "Signature stays in Secure Enclave"
        case .approveAndSend:
            return "Secure Enclave signs before provider submission"
        }
    }

    private static func authingVerb(isOverride: Bool, mode: RequestExecutionMode) -> String {
        if isOverride {
            return mode == .approveAndSend ? "override and send" : "override"
        }
        return mode == .approveAndSend ? "approve and send" : "authorize"
    }

    private static func doneText(mode: RequestExecutionMode, clientDisplayName: String) -> String {
        switch mode {
        case .signOnly:
            return "Signed · returning signature to \(clientDisplayName)"
        case .approveAndSend:
            return "Signed · submitting via provider"
        }
    }
}

nonisolated struct SigningViolationPresentation: Equatable, Sendable {
    let title: String
    let reasons: [String]

    static func make(approval: ApprovalRequest) -> SigningViolationPresentation? {
        guard case .ruleOverride(let reasons) = approval.mode else { return nil }
        return SigningViolationPresentation(title: "Rules broken", reasons: reasons)
    }
}

nonisolated struct SigningTypedConfirmationPresentation: Equatable, Sendable {
    let title: String
    let message: String
    let placeholder: String
    let requiredPhrase: String
    let isSatisfied: Bool

    static func make(
        approval: ApprovalRequest,
        confirmationText: String
    ) -> SigningTypedConfirmationPresentation? {
        guard let phrase = SigningRequestPresentation.requiredConfirmationPhrase(for: approval) else {
            return nil
        }
        return SigningTypedConfirmationPresentation(
            title: "Extra confirmation required",
            message: "This request changes a spend or limit boundary. Type \(phrase) to continue.",
            placeholder: "Type \(phrase)",
            requiredPhrase: phrase,
            isSatisfied: SigningRequestPresentation.canSubmitApproval(
                approval: approval,
                confirmationText: confirmationText
            )
        )
    }
}

nonisolated struct SigningPreflightPresentation: Equatable, Sendable {
    let title: String
    let diagnosis: String
    let traceWarning: String?
    let recommendationRows: [SigningPreflightRecommendationPresentation]
    let exportButtonTitle: String
    let isExporting: Bool
    let exportStatus: String?
    let exportError: String?
    let severity: PreflightResult.Severity

    static func make(
        preflight: PreflightResult,
        isExporting: Bool,
        exportStatus: String? = nil,
        exportError: String?
    ) -> SigningPreflightPresentation {
        let title: String
        if preflight.passed {
            title = preflight.hasWarnings ? "Preflight passed with warnings" : "Preflight passed"
        } else if let aaError = preflight.aaError {
            title = "Preflight failed · \(aaError)"
        } else {
            title = "Preflight failed"
        }

        return SigningPreflightPresentation(
            title: title,
            diagnosis: preflight.diagnosis,
            traceWarning: preflight.traceWarning,
            recommendationRows: preflight.recommendations.enumerated().map {
                SigningPreflightRecommendationPresentation(id: $0.offset, text: $0.element)
            },
            exportButtonTitle: isExporting ? "Exporting…" : "Export debug",
            isExporting: isExporting,
            exportStatus: exportStatus,
            exportError: exportError,
            severity: preflight.severity
        )
    }
}

nonisolated struct SigningPreflightRecommendationPresentation: Identifiable, Equatable, Sendable {
    let id: Int
    let text: String
}

nonisolated struct SigningPreflightExportState: Equatable, Sendable {
    var status: String?
    var error: String?
    var isExporting = false

    mutating func beginExport() -> Bool {
        guard !isExporting else { return false }
        isExporting = true
        status = nil
        error = nil
        return true
    }

    mutating func cancelExport() {
        isExporting = false
    }

    mutating func succeed(url: URL) {
        status = "Exported \(url.lastPathComponent)"
        error = nil
        isExporting = false
    }

    mutating func fail(_ error: Error) {
        status = nil
        self.error = "Export failed: \(error.localizedDescription)"
        isExporting = false
    }

    mutating func unavailable() {
        status = nil
        error = "Debug export unavailable for this request"
        isExporting = false
    }
}

nonisolated struct SigningUnknownCalldataPresentation: Equatable, Sendable {
    let title: String
    let message: String
    let target: String
    let selectorHex: String?
    let chainId: Int
    let calldataHex: String?

    static func make(approval: ApprovalRequest) -> SigningUnknownCalldataPresentation? {
        guard case .userOperation(let op) = approval.request.operation else { return nil }
        let decoded = CalldataDecoder.decode(op)
        guard let execution = decoded.executions
            .flatMap(\.allLeafExecutions)
            .first(where: \.hasUnrecognizedCalldata)
        else {
            return nil
        }

        return SigningUnknownCalldataPresentation(
            title: "Unrecognized contract call",
            message: "Bastion could not decode this calldata. Approve only if you recognize the target and selector.",
            target: execution.to,
            selectorHex: execution.selector.map { "0x\($0.hex)" },
            chainId: op.chainId,
            calldataHex: execution.rawCalldata.isEmpty
                ? nil
                : "0x\(BastionFormat.shortHex(execution.rawCalldata.hex, head: 14, tail: 10))"
        )
    }
}

nonisolated struct SigningPermitWarningPresentation: Equatable, Sendable {
    enum RowValue: Equatable, Sendable {
        case address(value: String, muted: Bool)
        case text(String)
        case expiry(String)
        case tokenAmount(token: String, amount: String)
    }

    struct Row: Equatable, Sendable {
        let key: String
        let value: RowValue
    }

    let label: String
    let explanation: String
    let showsLastingAllowance: Bool
    let rows: [Row]

    var accessibilityLabel: String { label }
    var accessibilityHint: String { explanation }

    static func make(classification: PermitClassification) -> SigningPermitWarningPresentation {
        SigningPermitWarningPresentation(
            label: classification.label,
            explanation: explanation(for: classification),
            showsLastingAllowance: classification.grantsLastingAllowance,
            rows: rows(for: classification)
        )
    }

    private static func explanation(for classification: PermitClassification) -> String {
        switch classification {
        case .erc2612:
            return "Signing this lets the spender pull tokens from your account at any point before the deadline — without another approval. Verify the spender, amount, and deadline match what you expect."
        case .permit2Single, .permit2Batch:
            return "This grants Uniswap Permit2 allowance off-chain. The spender can transfer up to the listed amount until expiration, with no further on-chain step."
        case .permit2TransferFrom, .permit2BatchTransferFrom:
            return "Permit2 one-shot transfer authorization. The spender can pull this exact amount once before the deadline."
        case .erc7702Delegation:
            return "ERC-7702 set-code authorization installs delegate code on your EOA. Anything that delegate runs (including draining) executes with your account's authority."
        }
    }

    private static func rows(for classification: PermitClassification) -> [Row] {
        switch classification {
        case .erc2612(let spender, let amount, let deadline, let token):
            var rows: [Row] = []
            if let token {
                rows.append(Row(key: "Token", value: .address(value: token, muted: true)))
            }
            rows.append(Row(key: "Spender", value: .address(value: spender, muted: false)))
            rows.append(Row(key: "Amount", value: .text(amount)))
            rows.append(Row(key: "Deadline", value: .expiry(deadline)))
            return rows
        case .permit2Single(let token, let spender, let amount, let expiration, let nonce):
            return [
                Row(key: "Token", value: .address(value: token, muted: true)),
                Row(key: "Spender", value: .address(value: spender, muted: false)),
                Row(key: "Amount", value: .text(amount)),
                Row(key: "Expires", value: .expiry(expiration)),
                Row(key: "Nonce", value: .text(nonce)),
            ]
        case .permit2Batch(let spender, let tokens, let amounts, let expiration):
            var rows: [Row] = [
                Row(key: "Spender", value: .address(value: spender, muted: false)),
                Row(key: "Earliest", value: .expiry(expiration)),
            ]
            for (index, token) in tokens.enumerated() {
                let amount = index < amounts.count ? amounts[index] : "?"
                rows.append(Row(
                    key: "Token \(index + 1)",
                    value: .tokenAmount(token: token, amount: amount)
                ))
            }
            return rows
        case .permit2TransferFrom(let token, let spender, let amount, let deadline):
            return [
                Row(key: "Token", value: .address(value: token, muted: true)),
                Row(key: "Spender", value: .address(value: spender, muted: false)),
                Row(key: "Amount", value: .text(amount)),
                Row(key: "Deadline", value: .expiry(deadline)),
            ]
        case .permit2BatchTransferFrom(let tokens, let amounts, let spender, let deadline):
            var rows: [Row] = [
                Row(key: "Spender", value: .address(value: spender, muted: false)),
                Row(key: "Deadline", value: .expiry(deadline)),
            ]
            for (index, token) in tokens.enumerated() {
                let amount = index < amounts.count ? amounts[index] : "?"
                rows.append(Row(
                    key: "Token \(index + 1)",
                    value: .tokenAmount(token: token, amount: amount)
                ))
            }
            return rows
        case .erc7702Delegation(let delegate, let chainId, let nonce):
            return [
                Row(key: "Delegate", value: .address(value: delegate, muted: false)),
                Row(key: "Chain", value: .text(chainId)),
                Row(key: "Nonce", value: .text(nonce)),
            ]
        }
    }
}

nonisolated struct SigningRequestDecodedPresentation: Equatable, Sendable {
    enum RowValue: Equatable, Sendable {
        case address(value: String, muted: Bool, label: String?)
        case chain(Int)
        case flow(RequestExecutionMode)
        case text(value: String, monospace: Bool)
    }

    struct Row: Equatable, Sendable {
        let key: String
        let value: RowValue
    }

    let headline: String
    let rows: [Row]

    static func make(approval: ApprovalRequest, config: BastionConfig) -> SigningRequestDecodedPresentation {
        let request = approval.request
        var rows: [Row] = []

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
                let label = config.label(for: target, chainId: op.chainId)
                rows.append(Row(
                    key: "To",
                    value: .address(value: target, muted: label != nil, label: label)
                ))
            }
            rows.append(Row(
                key: "From",
                value: .address(value: approval.clientContext.accountAddress ?? op.sender, muted: true, label: nil)
            ))
            rows.append(Row(key: "On", value: .chain(op.chainId)))
            if let submission = request.userOperationSubmission {
                rows.append(Row(
                    key: "Submit",
                    value: .text(value: submission.provider.displayName, monospace: false)
                ))
            }
            if let preflight = approval.preflightResult, let estimate = preflight.gasEstimate {
                rows.append(Row(
                    key: "Max fee",
                    value: .text(value: "\(formatGas(estimate.callGasLimit)) · bundler accepted", monospace: false)
                ))
            }
            rows.append(Row(key: "Flow", value: .flow(request.executionMode)))
            return SigningRequestDecodedPresentation(
                headline: userOpHeadline(decoded: decoded),
                rows: rows
            )

        case .typedData(let typed):
            if let chainId = typed.domain.chainId {
                rows.append(Row(key: "On", value: .chain(chainId)))
            }
            if let verifier = typed.domain.verifyingContract {
                rows.append(Row(key: "Verifier", value: .address(value: verifier, muted: false, label: nil)))
            }
            if let bundle = approval.clientContext.accountAddress {
                rows.append(Row(key: "From", value: .address(value: bundle, muted: true, label: nil)))
            }
            rows.append(Row(key: "Flow", value: .flow(request.executionMode)))
            return SigningRequestDecodedPresentation(
                headline: "Sign \(typed.domain.name ?? "EIP-712") · \(typed.primaryType)",
                rows: rows
            )

        case .message(let text):
            if let bundle = approval.clientContext.accountAddress {
                rows.append(Row(key: "From", value: .address(value: bundle, muted: true, label: nil)))
            }
            rows.append(Row(key: "Type", value: .text(value: "EIP-191 personal-sign", monospace: false)))
            rows.append(Row(key: "Flow", value: .flow(request.executionMode)))
            let preview = text.count > 36 ? "\(text.prefix(36))…" : text
            return SigningRequestDecodedPresentation(
                headline: "Sign message: \"\(preview)\"",
                rows: rows
            )

        case .rawBytes(let data):
            rows.append(Row(key: "Type", value: .text(value: "Raw bytes — no Ethereum prefix", monospace: false)))
            rows.append(Row(key: "Flow", value: .flow(request.executionMode)))
            return SigningRequestDecodedPresentation(
                headline: "Sign 0x\(data.prefix(6).hex)…",
                rows: rows
            )
        }
    }

    private static func userOpHeadline(decoded: CalldataDecoder.DecodedUserOp) -> String {
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

    private static func formatGas(_ hex: String) -> String {
        let s = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        guard let v = UInt64(s, radix: 16) else { return hex }
        let formatter = NumberFormatter()
        formatter.numberStyle = .decimal
        return "\(formatter.string(from: NSNumber(value: v)) ?? "\(v)") gas"
    }
}

nonisolated extension ApprovalMode {
    var isOverride: Bool {
        if case .ruleOverride = self { return true }
        return false
    }
}

struct SigningRequestView: View {
    let approval: ApprovalRequest
    let onApprove: () -> Void
    let onDeny: () -> Void

    @State private var remainingSeconds: Int = 60
    @State private var showRaw: Bool = false
    @State private var authStage: AuthStage = .idle
    @State private var confirmationText: String = ""
    @State private var preflightExportState = SigningPreflightExportState()
    @State private var actionGeneration: UInt64 = 0

    private let initialCountdown = 60
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    /// Display states for the footer. `.denied` is the brief
    /// confirmation flash after the owner clicks Deny — without it the
    /// popup vanished instantly and the owner had no visual proof their
    /// click landed.
    private typealias AuthStage = SigningRequestAuthStage

    private var request: SignRequest { approval.request }
    private var isOverride: Bool {
        approval.mode.isOverride
    }
    private var presentation: SigningRequestPresentation {
        SigningRequestPresentation.make(
            approval: approval,
            remainingSeconds: remainingSeconds,
            showRaw: showRaw,
            authStage: authStage,
            confirmationText: confirmationText
        )
    }
    private var violationPresentation: SigningViolationPresentation? {
        SigningViolationPresentation.make(approval: approval)
    }
    private var typedConfirmationPresentation: SigningTypedConfirmationPresentation? {
        SigningTypedConfirmationPresentation.make(
            approval: approval,
            confirmationText: confirmationText
        )
    }
    private var preflightPresentation: SigningPreflightPresentation? {
        guard let preflight = approval.preflightResult else { return nil }
        return SigningPreflightPresentation.make(
            preflight: preflight,
            isExporting: preflightExportState.isExporting,
            exportStatus: preflightExportState.status,
            exportError: preflightExportState.error
        )
    }
    private var unknownCalldataPresentation: SigningUnknownCalldataPresentation? {
        SigningUnknownCalldataPresentation.make(approval: approval)
    }
    private var decodedPresentation: SigningRequestDecodedPresentation {
        SigningRequestDecodedPresentation.make(
            approval: approval,
            config: RuleEngine.shared.config
        )
    }

    var body: some View {
        let chrome = SigningRequestPanelChrome.current
        popup
        .frame(width: chrome.cardWidth)
        .onReceive(timer) { _ in
            guard authStage == .idle else { return }
            if remainingSeconds > 0 { remainingSeconds -= 1 } else { denyTapped() }
        }
    }

    // MARK: - Popup

    private var popup: some View {
        VStack(spacing: 0) {
            header
            BastionDivider()
            scrollableContent
            BastionDivider()
            footer
        }
        .frame(width: SigningRequestPanelChrome.current.cardWidth)
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.windowRadius).fill(Color.paper)
        )
        .overlay(
            RoundedRectangle(cornerRadius: BastionTokens.windowRadius)
                .strokeBorder(Color.ink150, lineWidth: 1)
        )
        .clipShape(RoundedRectangle(cornerRadius: BastionTokens.windowRadius))
        .shadow(color: Color.black.opacity(0.22), radius: 30, y: 24)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(presentation.accessibilityLabel)
    }

    private var scrollableContent: some View {
        ScrollView(.vertical) {
            VStack(spacing: 0) {
                if let intent = request.intent { intentPanel(intent: intent) }
                decodedAction
                preflightPanel
                if let classification = permitClassification {
                    permitWarningPanel(classification: classification)
                }
                if !riskSignals.isEmpty { riskSignalsPanel }
                if isOverride { violationsPanel }
                if hasUnrecognizedCalldata { unknownCalldataPanel }
                if let phrase = requiredConfirmationPhrase { typedConfirmationPanel(phrase: phrase) }
                rawDigest
            }
        }
        .frame(maxHeight: SigningRequestPanelChrome.current.detailScrollMaxHeight)
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            ZStack {
                RoundedRectangle(cornerRadius: 7)
                    .fill(isOverride ? Color.bastionBadSoft : Color.ink900)
                // Use Color.paper (not literal .white) so the glyph stays
                // visible in dark mode, where ink900 inverts to off-white
                // and the literal-white shield would vanish into the fill.
                // paper inverts the opposite direction (white in light,
                // dark gray in dark) so contrast holds in both themes.
                ShieldGlyph(size: 15, color: isOverride ? Color.bastionBad : .paper, filled: !isOverride)
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(presentation.headerTitle)
                        .font(.system(size: 13, weight: .semibold))
                        .kerning(-0.13)
                    BastionChip(label: presentation.operationKindLabel, style: .neutral)
                    RequestModeChip(mode: request.executionMode)
                }
                HStack(spacing: 4) {
                    Text("from").foregroundStyle(Color.ink500)
                    Text(presentation.clientDisplayName)
                        .foregroundStyle(Color.ink700)
                        .fontWeight(.medium)
                }
                .font(.system(size: 11))
            }

            Spacer()

            Text(presentation.countdownLabel)
                .font(.system(size: 11, design: .monospaced))
                .foregroundStyle(remainingSeconds < 10 ? Color.bastionBad : Color.ink500)
                .accessibilityLabel(presentation.countdownAccessibilityLabel)
        }
        .padding(EdgeInsets(top: 14, leading: 16, bottom: 12, trailing: 16))
    }

    private var timeString: String {
        presentation.countdownLabel
    }

    // MARK: - Decoded action

    private var decodedAction: some View {
        VStack(alignment: .leading, spacing: 6) {
            BastionSectionLabel(text: "Decoded action").padding(.bottom, 2)

            Text(decodedPresentation.headline)
                .font(.system(size: 18, weight: .semibold, design: .monospaced))
                .foregroundStyle(Color.ink900)
                .lineLimit(2)
                .truncationMode(.tail)
                .padding(.bottom, 2)

            VStack(alignment: .leading, spacing: 6) {
                ForEach(decodedPresentation.rows.indices, id: \.self) { i in
                    let row = decodedPresentation.rows[i]
                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                        Text(row.key)
                            .font(.system(size: 11.5))
                            .foregroundStyle(Color.ink500)
                            .frame(width: 60, alignment: .leading)
                        decodedRowValue(row.value)
                    }
                }
            }
            .padding(.top, 4)
        }
        .padding(EdgeInsets(top: 12, leading: 16, bottom: 10, trailing: 16))
        .frame(maxWidth: .infinity, alignment: .leading)
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
        SigningRequestPresentation.requiredConfirmationPhrase(for: approval)
    }

    private var canSubmitApproval: Bool {
        presentation.canSubmitApproval
    }

    private var requiredConfirmationPhrase: String? {
        typedConfirmationPhrase
    }

    @ViewBuilder
    private func decodedRowValue(_ value: SigningRequestDecodedPresentation.RowValue) -> some View {
        switch value {
        case .address(let address, let muted, let label):
            if let label {
                HStack(spacing: 6) {
                    Text(label)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(Color.ink900)
                    AddressView(address: address, muted: true)
                }
            } else {
                AddressView(address: address, muted: muted)
            }
        case .chain(let chainId):
            ChainBadge(chainId: chainId, size: .small)
        case .flow(let mode):
            HStack(spacing: 6) {
                RequestModeChip(mode: mode)
                Text(mode.compactDetail)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .lineLimit(1)
            }
        case .text(let text, let monospace):
            Text(text)
                .font(.system(size: 12, design: monospace ? .monospaced : .default))
                .foregroundStyle(Color.ink700)
        }
    }

    // MARK: - Violations

    @ViewBuilder
    private var violationsPanel: some View {
        if let presentation = violationPresentation {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    CloseGlyph(size: 11, color: .bastionBad)
                    Text(presentation.title)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(Color.bastionBad)
                }
                .padding(.bottom, 2)
                ForEach(Array(presentation.reasons.enumerated()), id: \.offset) { _, reason in
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
    private var preflightPanel: some View {
        if let preflight = approval.preflightResult,
           let presentation = preflightPresentation {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    StatusDot(state: preflightDotState(presentation.severity))
                    Text(presentation.title)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundStyle(preflightColor(presentation.severity))
                    Spacer()
                    Button(presentation.exportButtonTitle) { exportPreflightDebug(preflight) }
                        .bastionButton(.ghost, size: .small)
                        .disabled(presentation.isExporting)
                }
                Text(presentation.diagnosis)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink700)
                    .fixedSize(horizontal: false, vertical: true)
                if let traceWarning = presentation.traceWarning {
                    Text(traceWarning)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(preflightColor(presentation.severity))
                        .fixedSize(horizontal: false, vertical: true)
                }
                ForEach(presentation.recommendationRows) { recommendation in
                    Text(recommendation.text)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Color.ink500)
                        .fixedSize(horizontal: false, vertical: true)
                }
                if let exportStatus = presentation.exportStatus {
                    Text(exportStatus)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Color.bastionOk)
                }
                if let exportError = presentation.exportError {
                    Text(exportError)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(Color.bastionBad)
                }
            }
            .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
            .background(
                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                    .fill(preflightBackground(presentation.severity))
                    .overlay(
                        RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                            .strokeBorder(preflightColor(presentation.severity).opacity(0.22), lineWidth: 1)
                    )
            )
            .padding(.horizontal, 16).padding(.bottom, 12)
        }
    }

    private func preflightDotState(_ severity: PreflightResult.Severity) -> StatusDot.State {
        switch severity {
        case .success: return .ok
        case .warning: return .warn
        case .error: return .bad
        }
    }

    private func preflightColor(_ severity: PreflightResult.Severity) -> Color {
        switch severity {
        case .success: return .bastionOk
        case .warning: return .bastionWarn
        case .error: return .bastionBad
        }
    }

    private func preflightBackground(_ severity: PreflightResult.Severity) -> Color {
        switch severity {
        case .success: return Color.bastionOk.opacity(0.08)
        case .warning: return Color.bastionWarnSoft
        case .error: return Color.bastionBadSoft
        }
    }

    private func exportPreflightDebug(_ preflight: PreflightResult) {
        guard preflightExportState.beginExport() else { return }
        guard case .userOperation(let op) = request.operation,
              let data = PreflightSimulator.shared.debugBundle(op: op, signature: nil, result: preflight) else {
            preflightExportState.unavailable()
            return
        }

        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = "bastion-preflight-\(request.requestID.prefix(8)).json"
        savePanel.canCreateDirectories = true
        savePanel.title = "Export preflight debug bundle"
        savePanel.begin { response in
            guard response == .OK, let url = savePanel.url else {
                DispatchQueue.main.async { preflightExportState.cancelExport() }
                return
            }
            do {
                try data.write(to: url, options: .atomic)
                DispatchQueue.main.async {
                    preflightExportState.succeed(url: url)
                }
            } catch {
                DispatchQueue.main.async {
                    preflightExportState.fail(error)
                }
            }
        }
    }

    @ViewBuilder
    private var unknownCalldataPanel: some View {
        if let presentation = unknownCalldataPresentation {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .semibold))
                    Text(presentation.title)
                        .font(.system(size: 11, weight: .semibold))
                }
                .foregroundStyle(Color.bastionWarn)

                Text(presentation.message)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.bastionWarn)
                    .fixedSize(horizontal: false, vertical: true)

                VStack(alignment: .leading, spacing: 6) {
                    KVRow(key: "Target", keyWidth: 62) {
                        AddressView(address: presentation.target)
                    }
                    if let selectorHex = presentation.selectorHex {
                        KVRow(key: "Selector", keyWidth: 62) {
                            Text(selectorHex)
                                .font(.system(size: 12, design: .monospaced))
                                .foregroundStyle(Color.ink700)
                        }
                    }
                    KVRow(key: "On", keyWidth: 62) {
                        ChainBadge(chainId: presentation.chainId, size: .small)
                    }
                    if let calldataHex = presentation.calldataHex {
                        KVRow(key: "Calldata", keyWidth: 62) {
                            Text(calldataHex)
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
        let presentation = typedConfirmationPresentation ?? SigningTypedConfirmationPresentation(
            title: "Extra confirmation required",
            message: "This request changes a spend or limit boundary. Type \(phrase) to continue.",
            placeholder: "Type \(phrase)",
            requiredPhrase: phrase,
            isSatisfied: canSubmitApproval
        )
        return VStack(alignment: .leading, spacing: 8) {
            Text(presentation.title)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(Color.bastionBad)
            Text(presentation.message)
                .font(.system(size: 12))
                .foregroundStyle(Color.bastionBad)
                .fixedSize(horizontal: false, vertical: true)
            TextField(presentation.placeholder, text: $confirmationText)
                .textFieldStyle(.plain)
                .font(.system(size: 13, design: .monospaced))
                .padding(10)
                .background(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .fill(Color.paper)
                        .overlay(
                            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                .strokeBorder(presentation.isSatisfied ? Color.bastionOk : Color.ink200, lineWidth: 1)
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
        let presentation = SigningPermitWarningPresentation.make(classification: classification)
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.shield.fill")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(Color.bastionBad)
                Text(presentation.label)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(Color.bastionBad)
                Spacer(minLength: 0)
                if presentation.showsLastingAllowance {
                    BastionChip(label: "Lasting allowance", style: .bad)
                }
            }
            Text(presentation.explanation)
                .font(.system(size: 12))
                .foregroundStyle(Color.bastionBad)
                .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                ForEach(presentation.rows, id: \.key) { row in
                    KVRow(key: row.key, keyWidth: 70) {
                        permitRowValue(row.value)
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
        .accessibilityElement(children: .contain)
        .accessibilityLabel(presentation.accessibilityLabel)
        .accessibilityHint(presentation.accessibilityHint)
    }

    @ViewBuilder
    private func permitRowValue(_ value: SigningPermitWarningPresentation.RowValue) -> some View {
        switch value {
        case .address(let address, let muted):
            AddressView(address: address, muted: muted)
        case .text(let text):
            monoText(text)
        case .expiry(let raw):
            monoText(formatExpiry(raw))
        case .tokenAmount(let token, let amount):
            HStack(spacing: 6) {
                AddressView(address: token, muted: true)
                Text("·").foregroundStyle(Color.ink400)
                monoText(amount)
            }
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
            BastionSectionLabel(text: "Risk signals")
            // Use LazyVGrid as a poor man's wrapping flow — adaptive columns
            // give us wrap-by-width without a custom Layout.
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 110), spacing: 6)], alignment: .leading, spacing: 6) {
                ForEach(riskSignals) { signal in
                    BastionChip(
                        label: signal.label,
                        style: chipStyle(for: signal.tone)
                    )
                    .help(signal.detail ?? signal.label)
                    .accessibilityLabel(signal.label)
                    .accessibilityHint(signal.detail ?? signal.label)
                }
            }
            .frame(maxWidth: .infinity, alignment: .topLeading)
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
                    Text(presentation.rawDigestButtonTitle)
                        .font(.system(size: 11))
                        .foregroundStyle(Color.ink500)
                }
            }
            .buttonStyle(.plain)

            if showRaw {
                Text(presentation.rawDigestHex)
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
                    Text(presentation.authingText)
                        .font(.system(size: 13))
                        .foregroundStyle(Color.ink700)
                }
                .padding(.vertical, 8)
            case .done:
                HStack(spacing: 8) {
                    CheckGlyph(size: 14, color: .bastionOk)
                    Text(presentation.doneText)
                        .font(.system(size: 13))
                        .foregroundStyle(Color.bastionOk)
                }
                .padding(.vertical, 8)
            case .denied:
                HStack(spacing: 8) {
                    CloseGlyph(size: 13, color: .bastionBad)
                    Text(presentation.deniedText)
                        .font(.system(size: 13))
                        .foregroundStyle(Color.bastionBad)
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
                Text(idleAssurance)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ink500)
            }
            .frame(maxWidth: .infinity)

            HStack(spacing: 8) {
                Button(action: denyTapped) {
                    Text("Deny").frame(maxWidth: .infinity)
                }
                .keyboardShortcut(.escape)
                .bastionButton(.default)
                .accessibilityLabel("Deny signing request")
                .accessibilityHint("Reject this request from \(approval.clientContext.displayName) without signing.")

                Button(action: primaryTapped) {
                    Text(primaryButtonLabel)
                        .frame(maxWidth: .infinity)
                }
                .bastionButton(isOverride ? .danger : .primary)
                .keyboardShortcut(.return, modifiers: [])
                .disabled(!canSubmitApproval)
                .opacity(canSubmitApproval ? 1 : 0.45)
                .frame(maxWidth: .infinity)
                .accessibilityLabel(primaryAccessibilityLabel)
                .accessibilityHint(isOverride
                    ? "Authorize this request even though it violates configured rules. Owner authentication required."
                    : primaryAccessibilityHint)
            }
        }
    }

    private var authingVerb: String {
        presentation.authingText
    }

    private var doneMessage: String {
        presentation.doneText
    }

    private var idleAssurance: String {
        presentation.idleAssurance
    }

    private var primaryButtonLabel: String {
        presentation.primaryButtonTitle
    }

    private var primaryAccessibilityLabel: String {
        presentation.primaryAccessibilityLabel
    }

    private var primaryAccessibilityHint: String {
        presentation.primaryAccessibilityHint
    }

    private func primaryTapped() {
        guard presentation.canTriggerPrimary else { return }
        actionGeneration &+= 1
        let generation = actionGeneration
        // Minimal animation flourish — the Secure Enclave / AuthManager actually drives the
        // biometric prompt at the call site; we just stage the visual feedback.
        withAnimation { authStage = .authing }
        // Trigger upstream approval in parallel — caller is responsible for closing the panel,
        // which races against our 'done' state. The 'done' label is purely visual filler if
        // the panel takes a beat to close.
        DispatchQueue.main.asyncAfter(deadline: .now() + SigningRequestActionTiming.approveCallbackDelay) {
            if SigningRequestActionTiming.shouldApply(
                scheduledGeneration: generation,
                currentGeneration: actionGeneration
            ) {
                onApprove()
            }
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + SigningRequestActionTiming.doneFlashDelay) {
            if SigningRequestActionTiming.shouldApply(
                scheduledGeneration: generation,
                currentGeneration: actionGeneration
            ) {
                withAnimation { authStage = .done }
            }
        }
    }

    /// Polish (#49): show a brief red "Denied" footer flash before the
    /// caller closes the panel. Otherwise the popup vanished as soon as
    /// the user clicked Deny and they had no visual proof their click
    /// landed — the same ambiguity that made the "Test Approval popup
    /// disappears instantly" bug so confusing.
    private func denyTapped() {
        guard authStage == .idle else { return }
        actionGeneration &+= 1
        let generation = actionGeneration
        withAnimation { authStage = .denied }
        // Hold the denied flash long enough to register, then call
        // upstream — the caller closes the panel.
        DispatchQueue.main.asyncAfter(deadline: .now() + SigningRequestActionTiming.denyCallbackDelay) {
            if SigningRequestActionTiming.shouldApply(
                scheduledGeneration: generation,
                currentGeneration: actionGeneration
            ) {
                onDeny()
            }
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
        let chrome = SigningRequestPanelChrome.current
        if chrome.usesTransparentHostView {
            hostingView.wantsLayer = true
            hostingView.layer?.backgroundColor = NSColor.clear.cgColor
            hostingView.layer?.isOpaque = false
        }
        let fittingSize = NSSize(
            width: chrome.cardWidth,
            height: max(1, ceil(hostingView.fittingSize.height))
        )
        hostingView.frame = NSRect(origin: .zero, size: fittingSize)

        let newPanel = NSPanel(
            contentRect: chrome.contentRect(fitting: fittingSize),
            styleMask: chrome.styleMask,
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
        newPanel.hasShadow = chrome.hasNativeShadow
        newPanel.backgroundColor = chrome.hasClearBackground ? .clear : .windowBackgroundColor
        newPanel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]
        NSApplication.shared.activate(ignoringOtherApps: true)
        newPanel.makeKeyAndOrderFront(nil)
        newPanel.orderFrontRegardless()

        self.panel = newPanel
    }

    func closePanel() {
        panel?.close()
        panel = nil
    }
}

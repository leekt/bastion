import AppKit
import SwiftUI
import Combine

struct SigningRequestView: View {
    let approval: ApprovalRequest
    let onApprove: () -> Void
    let onDeny: () -> Void

    @State private var remainingSeconds: Int = 60

    private let initialCountdownSeconds = 60
    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    private var request: SignRequest {
        approval.request
    }

    private var presentation: SigningRequestPresentation {
        SigningRequestPresentation(approval: approval)
    }

    var body: some View {
        ZStack {
            backgroundGradient
                .ignoresSafeArea()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    headerSection
                    approvalBanner
                    preflightBanner
                    operationSection
                    requestContextSection
                }
                .frame(maxWidth: 860, alignment: .leading)
                .padding(16)
                .padding(.bottom, 84)
            }
        }
        .safeAreaInset(edge: .bottom) {
            actionBar
        }
        .frame(minWidth: 760, minHeight: 520)
        .onReceive(timer) { _ in
            if remainingSeconds > 0 {
                remainingSeconds -= 1
            } else {
                onDeny()
            }
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

    private var headerSection: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: headerIcon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(approvalAccent)
                    .frame(width: 22, height: 22)

                VStack(alignment: .leading, spacing: 3) {
                    Text(operationTitle)
                        .font(.title3.weight(.semibold))
                    Text(heroSubtitle)
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }

                Spacer(minLength: 12)

                Text(approvalModeLabel.uppercased())
                    .font(.caption2.weight(.black))
                    .kerning(1)
                    .foregroundStyle(approvalAccent)
            }

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 132), spacing: 8)], alignment: .leading, spacing: 8) {
                ApprovalPill(
                    title: "Request",
                    value: requestKindLabel,
                    tint: headerColor
                )
                ApprovalPill(
                    title: "Client",
                    value: shortClientLabel,
                    tint: Color(red: 0.18, green: 0.45, blue: 0.34)
                )
                if let accountAddress = approval.clientContext.accountAddress {
                    ApprovalPill(
                        title: "Account",
                        value: shortAddress(accountAddress),
                        tint: Color(red: 0.59, green: 0.27, blue: 0.19)
                    )
                }
                ApprovalPill(
                    title: "Timeout",
                    value: "\(remainingSeconds)s",
                    tint: countdownColor
                )
            }
        }
        .padding(.bottom, 10)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color.black.opacity(0.08))
                .frame(height: 1)
        }
    }

    @ViewBuilder
    private var approvalBanner: some View {
        switch approval.mode {
        case .policyReview:
            EmptyView()
        case .ruleOverride(let reasons):
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .foregroundStyle(approvalAccent)
                    Text("Rule Override")
                        .font(.subheadline.weight(.semibold))
                    Spacer()
                }

                ForEach(Array(reasons.enumerated()), id: \.offset) { index, reason in
                    HStack(alignment: .top, spacing: 10) {
                        Text("\(index + 1).")
                            .font(.caption.weight(.semibold))
                            .foregroundStyle(.secondary)
                            .frame(width: 18, alignment: .leading)

                        Text(reason)
                            .font(.caption)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(.bottom, 10)
            .overlay(alignment: .bottom) {
                Rectangle()
                    .fill(Color.black.opacity(0.08))
                    .frame(height: 1)
            }
        }
    }

    @ViewBuilder
    private var preflightBanner: some View {
        if let preflight = approval.preflightResult {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 8) {
                    Image(systemName: preflightIcon(preflight))
                        .foregroundStyle(preflightColor(preflight))
                        .font(.system(size: 13, weight: .semibold))
                    Text("Preflight Simulation")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(preflightColor(preflight))
                    Spacer()
                    if preflight.passed, let estimate = preflight.gasEstimate {
                        Text("~\(formattedGas(estimate.callGasLimit)) gas")
                            .font(.caption.monospacedDigit())
                            .foregroundStyle(.secondary)
                    }
                    if let aaError = preflight.aaError {
                        Text(aaError)
                            .font(.caption.weight(.semibold).monospaced())
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Color.red.opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
                            .foregroundStyle(Color.red)
                    }
                }

                Text(preflight.diagnosis)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)

                if !preflight.staticWarnings.isEmpty {
                    ForEach(preflight.staticWarnings, id: \.self) { warning in
                        Label(warning, systemImage: "exclamationmark.triangle")
                            .font(.caption)
                            .foregroundStyle(Color.orange)
                    }
                }

                if !preflight.passed, !preflight.recommendations.isEmpty {
                    DisclosureGroup("Recommendations") {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(Array(preflight.recommendations.enumerated()), id: \.offset) { i, rec in
                                HStack(alignment: .top, spacing: 8) {
                                    Text("\(i + 1).")
                                        .font(.caption.weight(.semibold))
                                        .foregroundStyle(.secondary)
                                        .frame(width: 18, alignment: .leading)
                                    Text(rec)
                                        .font(.caption)
                                        .fixedSize(horizontal: false, vertical: true)
                                }
                            }
                        }
                        .padding(.top, 4)
                    }
                    .font(.caption.weight(.medium))
                }
            }
            .padding(12)
            .background(preflightBackground(preflight), in: RoundedRectangle(cornerRadius: 8))
            .overlay(
                RoundedRectangle(cornerRadius: 8)
                    .strokeBorder(preflightColor(preflight).opacity(0.25), lineWidth: 1)
            )
        }
    }

    private func preflightIcon(_ result: PreflightResult) -> String {
        switch result.severity {
        case .success: return "checkmark.shield.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .error:   return "xmark.shield.fill"
        }
    }

    private func preflightColor(_ result: PreflightResult) -> Color {
        switch result.severity {
        case .success: return Color(red: 0.18, green: 0.55, blue: 0.34)
        case .warning: return Color.orange
        case .error:   return Color.red
        }
    }

    private func preflightBackground(_ result: PreflightResult) -> Color {
        switch result.severity {
        case .success: return Color(red: 0.18, green: 0.55, blue: 0.34).opacity(0.06)
        case .warning: return Color.orange.opacity(0.06)
        case .error:   return Color.red.opacity(0.06)
        }
    }

    private func formattedGas(_ hexGas: String) -> String {
        let s = hexGas.hasPrefix("0x") ? String(hexGas.dropFirst(2)) : hexGas
        if let value = UInt64(s, radix: 16) {
            let formatter = NumberFormatter()
            formatter.numberStyle = .decimal
            return formatter.string(from: NSNumber(value: value)) ?? hexGas
        }
        return hexGas
    }

    private var operationSection: some View {
        ApprovalCard(
            icon: "signature",
            accent: headerColor,
            title: "Payload",
            subtitle: operationSubtitle
        ) {
            operationDetails
        }
    }

    @ViewBuilder
    private var operationDetails: some View {
        switch request.operation {
        case .message(let text):
            VStack(alignment: .leading, spacing: 12) {
                ApprovalKeyValueRow(label: "Type", value: "EIP-191 Personal Message")
                ApprovalKeyValueRow(label: "Encoding", value: text.hasPrefix("0x") ? "Hex payload" : "UTF-8 text")
                ApprovalCodeBlock(title: "Message", value: text)
            }
        case .rawBytes(let data):
            VStack(alignment: .leading, spacing: 12) {
                ApprovalKeyValueRow(label: "Type", value: "Raw Bytes")
                ApprovalKeyValueRow(label: "Prefix", value: "None — signed directly without any Ethereum prefix")
                ApprovalCodeBlock(title: "Payload", value: "0x" + data.hex)
            }
        case .typedData(let typed):
            VStack(alignment: .leading, spacing: 12) {
                ApprovalKeyValueRow(label: "Type", value: "EIP-712 Typed Data")
                ApprovalKeyValueRow(label: "Primary Type", value: typed.primaryType)
                if let name = typed.domain.name {
                    ApprovalKeyValueRow(label: "App", value: name)
                }
                if let version = typed.domain.version {
                    ApprovalKeyValueRow(label: "Version", value: version)
                }
                if let chainId = typed.domain.chainId {
                    ApprovalKeyValueRow(label: "Chain", value: "\(ChainConfig.name(for: chainId)) (\(chainId))")
                }
                if let verifyingContract = typed.domain.verifyingContract {
                    ApprovalCodeBlock(title: "Verifying Contract", value: verifyingContract)
                }
                if !typedDataMessagePreview.isEmpty {
                    VStack(alignment: .leading, spacing: 10) {
                        sectionLabel("Message Fields")
                        VStack(spacing: 10) {
                            ForEach(typedDataMessagePreview, id: \.label) { entry in
                                ApprovalKeyValueRow(label: entry.label, value: entry.value)
                            }
                        }
                    }
                }
            }
        case .userOperation(let op):
            let decoded = CalldataDecoder.decode(op)
            VStack(alignment: .leading, spacing: 12) {
                ApprovalKeyValueRow(label: "Type", value: decoded.isDeployment ? "Deployment UserOperation" : "UserOperation")
                ApprovalKeyValueRow(label: "Chain", value: "\(decoded.chainName) (\(op.chainId))")
                ApprovalKeyValueRow(label: "EntryPoint", value: op.entryPointVersion.rawValue)
                ApprovalCodeBlock(title: "Smart Account", value: decoded.sender)
                if decoded.isDeployment, let factory = op.factory {
                    ApprovalCodeBlock(title: "Factory", value: factory)
                }

                if decoded.executions.isEmpty {
                    ApprovalEmptyState(
                        icon: "questionmark.app.dashed",
                        title: "No decoded execution",
                        detail: "Bastion could not find user-visible execution details in this payload."
                    )
                    ApprovalCodeBlock(title: "Call Data", value: "0x" + op.callData.hex)
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        sectionLabel(decoded.executions.count == 1 ? "Decoded Action" : "Decoded Actions")

                        ForEach(Array(decoded.executions.enumerated()), id: \.offset) { index, execution in
                            ApprovalActionCard(
                                index: index + 1,
                                title: executionTitle(execution),
                                detail: execution.description
                            )
                        }
                    }
                }
            }
        }
    }

    private var requestContextSection: some View {
        ApprovalCard(
            icon: "rectangle.stack.badge.person.crop",
            accent: Color(red: 0.18, green: 0.45, blue: 0.34),
            title: "Request Context",
            subtitle: "Client identity, timestamp, request ID, and exact digest."
        ) {
            VStack(alignment: .leading, spacing: 10) {
                ApprovalKeyValueRow(label: "Client", value: approval.clientContext.displayName)
                if let bundleId = approval.clientContext.bundleId {
                    ApprovalKeyValueRow(label: "Bundle ID", value: bundleId)
                }
                if let accountAddress = approval.clientContext.accountAddress {
                    ApprovalKeyValueRow(label: "Account", value: accountAddress)
                }
                if let submission = request.userOperationSubmission {
                    ApprovalKeyValueRow(
                        label: "Post-Approval",
                        value: "Submit to \(submission.provider.displayName)"
                    )
                }
                ApprovalKeyValueRow(label: "Request ID", value: request.requestID)
                ApprovalKeyValueRow(
                    label: "Time",
                    value: request.timestamp.formatted(date: .abbreviated, time: .standard)
                )
                ApprovalCodeBlock(title: "Digest", value: "0x" + request.data.hex)
            }
        }
    }

    private var actionBar: some View {
        HStack(spacing: 14) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 8) {
                    Image(systemName: "clock")
                        .foregroundStyle(countdownColor)
                    Text("Auto-deny in \(remainingSeconds) seconds")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(countdownColor)
                }

                ProgressView(value: countdownProgress)
                    .tint(countdownColor)
                    .frame(width: 220)
            }

            Spacer()

            Button(action: onDeny) {
                Text("Deny")
                    .frame(width: 110)
            }
            .keyboardShortcut(.escape)
            .controlSize(.regular)
            .buttonStyle(.bordered)

            Button(action: onApprove) {
                Text(approveLabel)
                    .frame(width: 156)
            }
            .controlSize(.regular)
            .buttonStyle(.borderedProminent)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(.ultraThinMaterial)
    }

    private var typedDataMessagePreview: [(label: String, value: String)] {
        presentation.typedDataMessagePreview
    }

    private var headerIcon: String {
        presentation.headerIcon
    }

    private var headerColor: Color {
        switch request.operation {
        case .message, .rawBytes:
            return Color(red: 0.13, green: 0.38, blue: 0.60)
        case .typedData:
            return Color(red: 0.44, green: 0.31, blue: 0.55)
        case .userOperation:
            return Color(red: 0.72, green: 0.43, blue: 0.11)
        }
    }

    private var approvalAccent: Color {
        switch approval.mode {
        case .policyReview:
            return Color(red: 0.18, green: 0.45, blue: 0.34)
        case .ruleOverride:
            return Color(red: 0.72, green: 0.43, blue: 0.11)
        }
    }

    private var heroSubtitle: String {
        presentation.heroSubtitle
    }

    private var approvalModeLabel: String {
        presentation.approvalModeLabel
    }

    private var approveLabel: String {
        presentation.approveLabel
    }

    private var requestKindLabel: String {
        presentation.requestKindLabel
    }

    private var operationTitle: String {
        presentation.operationTitle
    }

    private var operationSubtitle: String {
        presentation.operationSubtitle
    }

    private var shortClientLabel: String {
        presentation.shortClientLabel
    }

    private func shortAddress(_ address: String) -> String {
        guard address.count > 14 else {
            return address
        }
        return "\(address.prefix(10))...\(address.suffix(4))"
    }

    private var countdownColor: Color {
        remainingSeconds <= 10
            ? Color(red: 0.68, green: 0.24, blue: 0.20)
            : Color(red: 0.52, green: 0.33, blue: 0.18)
    }

    private var countdownProgress: Double {
        Double(remainingSeconds) / Double(initialCountdownSeconds)
    }

    private func sectionLabel(_ title: String) -> some View {
        Text(title)
            .font(.subheadline.weight(.semibold))
    }

    private func executionTitle(_ execution: CalldataDecoder.DecodedExecution) -> String {
        if execution.tokenOperation != nil {
            return "Token Call"
        }
        return execution.value != "0" ? "Native Transfer" : "Contract Call"
    }
}

nonisolated struct SigningRequestPresentation: Sendable {
    let approval: ApprovalRequest

    private var request: SignRequest {
        approval.request
    }

    var heroSubtitle: String {
        if request.requiresUserOperationSubmission {
            switch approval.mode {
            case .policyReview:
                return "Review the payload carefully. Bastion will sign it and immediately submit the UserOperation to the configured bundler."
            case .ruleOverride:
                return "This request exceeded the current rules. If you continue, Bastion will override the policy and submit the signed UserOperation."
            }
        }

        switch approval.mode {
        case .policyReview:
            return "Review the exact payload, then continue with the configured authentication policy."
        case .ruleOverride:
            return "This request exceeded the current rules. Review the payload carefully before overriding."
        }
    }

    var approvalModeLabel: String {
        switch approval.mode {
        case .policyReview:
            return "Within Policy"
        case .ruleOverride:
            return "Override"
        }
    }

    var approveLabel: String {
        switch approval.mode {
        case .policyReview:
            return request.requiresUserOperationSubmission ? "Approve & Send" : "Approve"
        case .ruleOverride:
            return request.requiresUserOperationSubmission ? "Override & Send" : "Override & Approve"
        }
    }

    var requestKindLabel: String {
        switch request.operation {
        case .message:
            return "Raw Message"
        case .rawBytes:
            return "Raw Bytes"
        case .typedData:
            return "Typed Data"
        case .userOperation:
            return "UserOp"
        }
    }

    var operationTitle: String {
        switch request.operation {
        case .message:
            return "Raw Message Review"
        case .rawBytes:
            return "Raw Bytes Review"
        case .typedData:
            return "Typed Data Review"
        case .userOperation:
            return "UserOp Review"
        }
    }

    var operationSubtitle: String {
        switch request.operation {
        case .message:
            return "The payload below will be wrapped with the Ethereum personal-sign prefix before verification."
        case .rawBytes:
            return "The 32-byte payload below will be signed directly — no EIP-191 or EIP-712 prefix is applied."
        case .typedData:
            return "Bastion hashes this payload with the EIP-712 domain separator and structured message fields."
        case .userOperation:
            if let submission = request.userOperationSubmission {
                return "Bastion is showing the decoded execution details and will send the signed UserOperation to \(submission.provider.displayName) after approval."
            }
            return "Bastion is showing the decoded execution details, not just the smart-account envelope."
        }
    }

    var shortClientLabel: String {
        approval.clientContext.shortBundleName
    }

    var headerIcon: String {
        switch approval.mode {
        case .policyReview:
            return "checkmark.shield.fill"
        case .ruleOverride:
            return "exclamationmark.shield.fill"
        }
    }

    var typedDataMessagePreview: [(label: String, value: String)] {
        guard case .typedData(let typed) = request.operation else { return [] }
        return typed.message
            .keys
            .sorted()
            .prefix(6)
            .map { key in
                (label: key, value: Self.renderTypedDataValue(typed.message[key]?.value))
            }
    }

    private static func renderTypedDataValue(_ value: Any?) -> String {
        guard let value else { return "null" }

        switch value {
        case let string as String:
            return string
        case let int as Int:
            return String(int)
        case let bool as Bool:
            return bool ? "true" : "false"
        case let double as Double:
            return String(double)
        case let array as [Any]:
            let preview = array.prefix(4).map { renderTypedDataValue($0) }.joined(separator: ", ")
            return array.count > 4 ? "[\(preview), ...]" : "[\(preview)]"
        case let dict as [String: Any]:
            if let data = try? JSONSerialization.data(withJSONObject: dict, options: [.sortedKeys]),
               let text = String(data: data, encoding: .utf8) {
                return text
            }
            return String(describing: dict)
        default:
            return String(describing: value)
        }
    }
}

private struct ApprovalCard<Content: View>: View {
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
                    .padding(.bottom, 8)
            }

            content
                .padding(.bottom, 10)

            Rectangle()
                .fill(accent.opacity(0.16))
                .frame(height: 1)
        }
        .padding(.horizontal, 2)
    }
}

private struct ApprovalPill: View {
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
        .padding(.vertical, 4)
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

private struct ApprovalKeyValueRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack(alignment: .top, spacing: 14) {
            Text(label.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)
                .frame(width: 86, alignment: .leading)

            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.vertical, 3)
    }
}

private struct ApprovalCodeBlock: View {
    let title: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title.uppercased())
                .font(.caption2.weight(.semibold))
                .foregroundStyle(.secondary)

            Text(value)
                .font(.system(.caption, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(7)
                .background(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(Color.black.opacity(0.035))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .stroke(Color.black.opacity(0.04), lineWidth: 1)
                )
        }
    }
}

private struct ApprovalActionCard: View {
    let index: Int
    let title: String
    let detail: String

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Text("\(index)")
                .font(.caption2.weight(.bold))
                .foregroundStyle(.secondary)
                .frame(width: 18, height: 18)
                .background(
                    RoundedRectangle(cornerRadius: 5, style: .continuous)
                        .fill(Color.black.opacity(0.04))
                )

            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)

                Text(detail)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            Spacer(minLength: 0)
        }
        .padding(.vertical, 6)
        .overlay(alignment: .bottom) {
            Rectangle()
                .fill(Color.black.opacity(0.06))
                .frame(height: 1)
        }
    }
}

private struct ApprovalEmptyState: View {
    let icon: String
    let title: String
    let detail: String

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: icon)
                .font(.caption.weight(.semibold))
                .foregroundStyle(.secondary)
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
            contentRect: NSRect(x: 0, y: 0, width: 780, height: 580),
            styleMask: [.titled, .closable, .fullSizeContentView],
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

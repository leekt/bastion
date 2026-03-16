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
                VStack(spacing: 18) {
                    heroCard
                    approvalStateCard
                    operationCard
                    metadataCard
                    digestCard
                }
                .padding(24)
                .padding(.bottom, 132)
            }
        }
        .safeAreaInset(edge: .bottom) {
            actionBar
        }
        .frame(minWidth: 560, minHeight: 720)
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
                Color(red: 0.96, green: 0.94, blue: 0.89),
                Color(red: 0.92, green: 0.95, blue: 0.97),
                Color(red: 0.98, green: 0.97, blue: 0.94),
            ],
            startPoint: .topLeading,
            endPoint: .bottomTrailing
        )
    }

    private var heroCard: some View {
        ApprovalCard(
            icon: headerIcon,
            accent: approvalAccent,
            title: "Signing Approval",
            subtitle: heroSubtitle
        ) {
            HStack(spacing: 12) {
                ApprovalPill(
                    title: "Mode",
                    value: approvalModeLabel,
                    tint: approvalAccent
                )
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
                ApprovalPill(
                    title: "Timeout",
                    value: "\(remainingSeconds)s",
                    tint: remainingSeconds <= 10
                        ? Color(red: 0.68, green: 0.24, blue: 0.20)
                        : Color(red: 0.52, green: 0.33, blue: 0.18)
                )
            }
        }
    }

    @ViewBuilder
    private var approvalStateCard: some View {
        switch approval.mode {
        case .policyReview:
            ApprovalCard(
                icon: "hand.raised.fill",
                accent: Color(red: 0.13, green: 0.38, blue: 0.60),
                title: "Manual Review Enabled",
                subtitle: "This request matched the current rules, but Bastion is configured to require an explicit approval step."
            ) {
                Text("Approving continues with the auth policy selected in Rules Settings. Denying ends the request immediately.")
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        case .ruleOverride(let reasons):
            ApprovalCard(
                icon: "exclamationmark.triangle.fill",
                accent: Color(red: 0.72, green: 0.43, blue: 0.11),
                title: "Rule Override Required",
                subtitle: "Bastion blocked this request under the current policy. Approving will continue with owner authentication."
            ) {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(reasons.enumerated()), id: \.offset) { index, reason in
                        HStack(alignment: .top, spacing: 10) {
                            Text("\(index + 1).")
                                .font(.caption.weight(.semibold))
                                .foregroundStyle(.secondary)
                                .frame(width: 16, alignment: .leading)

                            Text(reason)
                                .font(.subheadline)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                        .padding(12)
                        .background(cardRowBackground)
                    }
                }
            }
        }
    }

    private var operationCard: some View {
        ApprovalCard(
            icon: "signature",
            accent: headerColor,
            title: operationTitle,
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
                ApprovalKeyValueRow(label: "Type", value: decoded.isDeployment ? "UserOperation (deployment)" : "UserOperation")
                ApprovalKeyValueRow(label: "Chain", value: "\(decoded.chainName) (\(op.chainId))")
                ApprovalCodeBlock(title: "Smart Account", value: decoded.sender)
                ApprovalKeyValueRow(label: "EntryPoint", value: op.entryPointVersion.rawValue)
                if decoded.isDeployment, let factory = op.factory {
                    ApprovalCodeBlock(title: "Factory", value: factory)
                }

                if decoded.executions.isEmpty {
                    ApprovalEmptyState(
                        icon: "questionmark.app.dashed",
                        title: "No decoded execution",
                        detail: "Bastion could not find user-visible execution details in this payload."
                    )
                } else {
                    VStack(alignment: .leading, spacing: 10) {
                        sectionLabel(decoded.executions.count == 1 ? "Action" : "Actions")

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

    private var metadataCard: some View {
        ApprovalCard(
            icon: "tray.full.fill",
            accent: Color(red: 0.18, green: 0.45, blue: 0.34),
            title: "Request Metadata",
            subtitle: "These fields identify who asked Bastion to sign and when the request was created."
        ) {
            VStack(alignment: .leading, spacing: 12) {
                ApprovalKeyValueRow(label: "Client", value: request.clientBundleId ?? "Unknown client")
                ApprovalKeyValueRow(label: "Request ID", value: request.requestID)
                ApprovalKeyValueRow(
                    label: "Time",
                    value: request.timestamp.formatted(date: .abbreviated, time: .standard)
                )
            }
        }
    }

    private var digestCard: some View {
        ApprovalCard(
            icon: "number.square.fill",
            accent: Color(red: 0.48, green: 0.34, blue: 0.16),
            title: "Digest To Sign",
            subtitle: "This is the 32-byte Ethereum digest Bastion sends to the Secure Enclave."
        ) {
            ApprovalCodeBlock(title: "Digest", value: "0x" + request.data.hex)
        }
    }

    private var actionBar: some View {
        VStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                HStack {
                    Image(systemName: "clock")
                        .foregroundStyle(countdownColor)
                    Text("Auto-deny in \(remainingSeconds) seconds")
                        .font(.subheadline.weight(.semibold))
                        .foregroundStyle(countdownColor)
                    Spacer()
                }

                ProgressView(value: countdownProgress)
                    .tint(countdownColor)
            }

            HStack(spacing: 14) {
                Button(action: onDeny) {
                    Text("Deny")
                        .frame(maxWidth: .infinity)
                }
                .keyboardShortcut(.escape)
                .controlSize(.large)
                .buttonStyle(.bordered)

                Button(action: onApprove) {
                    Text(approveLabel)
                        .frame(maxWidth: .infinity)
                }
                .keyboardShortcut(.return)
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(.horizontal, 24)
        .padding(.vertical, 18)
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
        case .message:
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

    private var countdownColor: Color {
        remainingSeconds <= 10
            ? Color(red: 0.68, green: 0.24, blue: 0.20)
            : Color(red: 0.52, green: 0.33, blue: 0.18)
    }

    private var countdownProgress: Double {
        Double(remainingSeconds) / Double(initialCountdownSeconds)
    }

    private var cardRowBackground: some View {
        RoundedRectangle(cornerRadius: 16, style: .continuous)
            .fill(Color.white.opacity(0.55))
    }

    private func sectionLabel(_ title: String) -> some View {
        Text(title)
            .font(.headline)
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
        switch approval.mode {
        case .policyReview:
            return "Review the request details before Bastion applies your configured authentication policy."
        case .ruleOverride:
            return "This request exceeded the current rules. Review the payload carefully before overriding the policy."
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
            return "Approve"
        case .ruleOverride:
            return "Override & Approve"
        }
    }

    var requestKindLabel: String {
        switch request.operation {
        case .message:
            return "Message"
        case .typedData:
            return "Typed Data"
        case .userOperation:
            return "UserOp"
        }
    }

    var operationTitle: String {
        switch request.operation {
        case .message:
            return "Personal Message"
        case .typedData:
            return "Typed Data Review"
        case .userOperation:
            return "UserOperation Review"
        }
    }

    var operationSubtitle: String {
        switch request.operation {
        case .message:
            return "The payload below will be wrapped using the Ethereum personal-sign prefix before verification."
        case .typedData:
            return "Bastion hashes this payload using the EIP-712 domain separator and structured message rules."
        case .userOperation:
            return "Bastion is showing the decoded Kernel execution details, not just the smart-account envelope."
        }
    }

    var shortClientLabel: String {
        guard let bundleId = request.clientBundleId, !bundleId.isEmpty else {
            return "Unknown"
        }
        return bundleId.split(separator: ".").last.map(String.init) ?? bundleId
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
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(tint.opacity(0.12))
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
                .frame(width: 120, alignment: .leading)

            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(Color.white.opacity(0.55))
        )
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
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(12)
                .background(
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(Color.white.opacity(0.55))
                )
        }
    }
}

private struct ApprovalActionCard: View {
    let index: Int
    let title: String
    let detail: String

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Action \(index)")
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Spacer()
                Text(title)
                    .font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
            }

            Text(detail)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(Color.white.opacity(0.55))
        )
    }
}

private struct ApprovalEmptyState: View {
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

// MARK: - Panel Manager

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
            contentRect: NSRect(x: 0, y: 0, width: 560, height: 720),
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
        newPanel.orderFrontRegardless()
        NSApp.activate(ignoringOtherApps: true)

        self.panel = newPanel
    }

    func closePanel() {
        panel?.close()
        panel = nil
    }
}

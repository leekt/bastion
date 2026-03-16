import SwiftUI
import Combine

struct SigningRequestView: View {
    let request: SignRequest
    let onApprove: () -> Void
    let onDeny: () -> Void

    @State private var remainingSeconds: Int = 60

    private let timer = Timer.publish(every: 1, on: .main, in: .common).autoconnect()

    var body: some View {
        VStack(spacing: 20) {
            // Header
            HStack {
                Image(systemName: headerIcon)
                    .font(.title)
                    .foregroundStyle(headerColor)
                Text("Signing Request")
                    .font(.title2.bold())
                Spacer()
            }

            Divider()

            // Request details
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    operationDetails
                }
            }

            Spacer()

            // Countdown
            HStack {
                Image(systemName: "clock")
                    .foregroundStyle(remainingSeconds <= 10 ? .red : .secondary)
                Text("Auto-deny in \(remainingSeconds)s")
                    .font(.caption)
                    .foregroundStyle(remainingSeconds <= 10 ? .red : .secondary)
                Spacer()
            }

            // Buttons
            HStack(spacing: 16) {
                Button(action: onDeny) {
                    Text("Deny")
                        .frame(maxWidth: .infinity)
                }
                .keyboardShortcut(.escape)
                .controlSize(.large)

                Button(action: onApprove) {
                    Text("Approve")
                        .frame(maxWidth: .infinity)
                }
                .keyboardShortcut(.return)
                .controlSize(.large)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(24)
        .frame(width: 420, height: 400)
        .onReceive(timer) { _ in
            if remainingSeconds > 0 {
                remainingSeconds -= 1
            } else {
                onDeny()
            }
        }
    }

    // MARK: - Operation-specific details

    @ViewBuilder
    private var operationDetails: some View {
        switch request.operation {
        case .message(let text):
            DetailRow(label: "Type", value: "Personal Message")
            DetailRow(label: "Message", value: text.count > 200 ? "\(text.prefix(200))..." : text)

        case .typedData(let typed):
            DetailRow(label: "Type", value: "EIP-712 Typed Data")
            if let name = typed.domain.name {
                DetailRow(label: "App", value: name)
            }
            if let chainId = typed.domain.chainId {
                DetailRow(label: "Chain", value: ChainConfig.name(for: chainId))
            }
            DetailRow(label: "Primary Type", value: typed.primaryType)

        case .userOperation(let op):
            userOpDetails(op)
        }

        DetailRow(label: "Request ID", value: request.requestID)
        DetailRow(
            label: "Time",
            value: request.timestamp.formatted(date: .omitted, time: .standard)
        )
    }

    @ViewBuilder
    private func userOpDetails(_ op: UserOperation) -> some View {
        let decoded = CalldataDecoder.decode(op)

        DetailRow(label: "Type", value: decoded.isDeployment ? "UserOperation (deploy)" : "UserOperation")
        DetailRow(label: "Chain", value: decoded.chainName)
        DetailRow(label: "Account", value: decoded.sender)

        if decoded.executions.isEmpty {
            DetailRow(label: "Action", value: "No execution data")
        } else {
            ForEach(Array(decoded.executions.enumerated()), id: \.offset) { index, exec in
                VStack(alignment: .leading, spacing: 2) {
                    if decoded.executions.count > 1 {
                        Text("Action \(index + 1)")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    } else {
                        Text("Action")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                    Text(exec.description)
                        .font(.system(.body, design: .monospaced))
                        .textSelection(.enabled)
                        .lineLimit(3)
                }
            }
        }
    }

    // MARK: - Header styling

    private var headerIcon: String {
        switch request.operation {
        case .message: return "envelope.fill"
        case .typedData: return "doc.text.fill"
        case .userOperation: return "arrow.up.right.circle.fill"
        }
    }

    private var headerColor: Color {
        switch request.operation {
        case .message: return .blue
        case .typedData: return .purple
        case .userOperation: return .orange
        }
    }
}

private struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.caption)
                .foregroundStyle(.secondary)
            Text(value)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .lineLimit(2)
        }
    }
}

// MARK: - Panel Manager

final class SigningRequestPanelManager {
    static let shared = SigningRequestPanelManager()
    private var panel: NSPanel?

    private init() {}

    func showRequest(_ request: SignRequest, onApprove: @escaping () -> Void, onDeny: @escaping () -> Void) {
        closePanel()

        let view = SigningRequestView(
            request: request,
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
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 400),
            styleMask: [.titled, .closable, .nonactivatingPanel, .hudWindow],
            backing: .buffered,
            defer: false
        )
        newPanel.contentView = hostingView
        newPanel.title = "Bastion - Signing Request"
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

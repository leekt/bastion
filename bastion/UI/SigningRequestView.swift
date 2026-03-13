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
                Image(systemName: "lock.open.fill")
                    .font(.title)
                    .foregroundStyle(.orange)
                Text("Signing Request")
                    .font(.title2.bold())
                Spacer()
            }

            Divider()

            // Request details
            VStack(alignment: .leading, spacing: 12) {
                DetailRow(label: "Request ID", value: request.requestID)
                DetailRow(
                    label: "Data",
                    value: String(request.data.hex.prefix(32)) + "..."
                )
                DetailRow(
                    label: "Time",
                    value: request.timestamp.formatted(date: .omitted, time: .standard)
                )
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
        .frame(width: 420, height: 320)
        .onReceive(timer) { _ in
            if remainingSeconds > 0 {
                remainingSeconds -= 1
            } else {
                onDeny()
            }
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
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 320),
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

#if !BASTION_HELPER
import AppKit
import Foundation
import SwiftUI

@main
struct BastionApp: App {
    @State private var appState: AppState

    init() {
        let state = AppState()
        _appState = State(initialValue: state)
    }

    var body: some Scene {
        MenuBarExtra("Bastion", systemImage: appState.menuBarManager.iconName) {
            MenuBarContentView()
        }

        Settings {
            RulesSettingsView()
        }
    }
}

@Observable
@MainActor
final class AppState {
    let menuBarManager = MenuBarManager()
    let launchMode: BastionLaunchMode

    private let serviceRuntime = BastionServiceRuntime()
    private let relayRuntime = BastionRelayRuntime()

    init() {
        CLIInstaller.installIfNeeded()
        ServiceRegistration.registerAndExitIfRequested()
        launchMode = BastionLaunchController.resolveLaunchMode()

        if launchMode == .service {
            serviceRuntime.start(menuBarManager: menuBarManager)
        } else {
            relayRuntime.start()
        }
    }
}

struct MenuBarContentView: View {
    var body: some View {
        let recentRequests = AuditLog.shared.recentRequestRecords(limit: 5)

        if RuleEngine.shared.configCorrupted {
            Label("Rules config corrupt — reset to defaults", systemImage: "exclamationmark.triangle.fill")
                .foregroundStyle(.red)
            Divider()
        }

        if recentRequests.isEmpty {
            Text("No recent activity")
                .foregroundStyle(.secondary)
        } else {
            ForEach(recentRequests, id: \.id) { record in
                let time = String(record.latestEvent?.timestamp.prefix(19) ?? "")
                    .replacingOccurrences(of: "T", with: " ")
                Label(
                    "\(time) \(record.operationTitle) · \(record.latestResultLabel)",
                    systemImage: iconForEvent(record.latestEvent?.type ?? .signSuccess)
                )
            }
        }

        Divider()

        Label("Service: \(ServiceRegistration.statusDescription())", systemImage: "circle.fill")
            .foregroundStyle(.secondary)

        if let pubkey = try? SecureEnclaveManager.shared.getPublicKey() {
            let full = "0x04\(pubkey.x)\(pubkey.y)"
            let short = "\(full.prefix(10))...\(full.suffix(6))"
            Button("Public Key: \(short)") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(full, forType: .string)
            }
            .help("Click to copy full public key")
        }

        Divider()

        Menu("Preview Approval UI") {
            Button("Policy Review Sample") {
                SigningRequestPanelManager.shared.showRequest(
                    SigningRequestPreviewFactory.policyReview(),
                    onApprove: {},
                    onDeny: {}
                )
            }

            Button("Rule Override Sample") {
                SigningRequestPanelManager.shared.showRequest(
                    SigningRequestPreviewFactory.ruleOverride(),
                    onApprove: {},
                    onDeny: {}
                )
            }
        }

        Divider()

        Button("Audit History...") {
            AuditHistoryWindowManager.shared.showWindow()
        }

        Divider()

        SettingsLink {
            Text("Rules Settings...")
        }

        Divider()

        Button("Quit Bastion") {
            NSApplication.shared.terminate(nil)
        }
        .keyboardShortcut("q")
    }

    private func iconForEvent(_ type: AuditEvent.EventType) -> String {
        switch type {
        case .signPending:   return "lock.open"
        case .signSuccess:   return "checkmark.circle"
        case .signDenied:    return "xmark.circle"
        case .ruleViolation: return "exclamationmark.triangle"
        case .authFailed:    return "xmark.shield"
        case .userOpSubmitted: return "paperplane.circle"
        case .userOpSendFailed: return "paperplane.circle.fill"
        case .userOpReceiptSuccess: return "checkmark.seal"
        case .userOpReceiptFailed: return "xmark.seal"
        case .userOpReceiptTimeout: return "clock.badge.exclamationmark"
        case .preflightCompleted: return "shield.lefthalf.filled"
        case .keyReset: return "key.slash"
        }
    }
}
#endif

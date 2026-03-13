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
final class AppState {
    let menuBarManager = MenuBarManager()

    private let xpcServer = XPCServer.shared
    private let ruleEngine = RuleEngine.shared

    init() {
        ruleEngine.loadConfigOnStartup()

        do { _ = try SecureEnclaveManager.shared.loadOrCreateConfigKey() } catch {}
        do { _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey() } catch {}
        do { _ = try SecureEnclaveManager.shared.loadOrCreateStateKey() } catch {}

        menuBarManager.startObserving()
        xpcServer.start()
        CLIInstaller.installIfNeeded()
    }
}

struct MenuBarContentView: View {
    var body: some View {
        let recentEvents = AuditLog.shared.recentEvents(limit: 5)

        if recentEvents.isEmpty {
            Text("No recent activity")
                .foregroundStyle(.secondary)
        } else {
            ForEach(Array(recentEvents.reversed().enumerated()), id: \.offset) { _, event in
                let time = String(event.timestamp.prefix(19))
                    .replacingOccurrences(of: "T", with: " ")
                Label(
                    "\(time) \(event.type.rawValue)",
                    systemImage: iconForEvent(event.type)
                )
            }
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
        case .signSuccess:   return "checkmark.circle"
        case .signDenied:    return "xmark.circle"
        case .ruleViolation: return "exclamationmark.triangle"
        case .authFailed:    return "xmark.shield"
        }
    }
}

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
            MenuBarPanelView()
        }
        .menuBarExtraStyle(.window)

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

        // v9: kick off periodic RPC health probes so the App Preferences panel
        // and menu bar status reflect actual reachability rather than guesses.
        RPCHealthMonitor.shared.startMonitoring()
    }
}

#endif

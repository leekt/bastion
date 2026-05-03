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
        // M-08: Migrate any pre-data-protection-keychain items off the
        // legacy macOS keychain BEFORE anything else touches Keychain.
        // The legacy keychain bakes a per-item code-signature ACL that
        // breaks every time we re-sign the dev build, producing the
        // "wants to use 'com.bastion'" prompt cascade.
        KeychainStore.migrateLegacyItems()

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

        // v9: warm the SessionStore at launch so persisted sessions land in
        // SessionSnapshotStore *before* the first XPC sign request. Without
        // this, a sign request that arrives between launch and the first
        // menu bar render would bypass any persisted session scope.
        _ = SessionStore.shared
    }
}

#endif

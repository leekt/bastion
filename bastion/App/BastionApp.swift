#if !BASTION_HELPER
import AppKit
import Foundation
import SwiftUI

@main
struct BastionApp: App {
    @NSApplicationDelegateAdaptor(BastionAppDelegate.self) private var appDelegate
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

final class BastionAppDelegate: NSObject, NSApplicationDelegate {
    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        BastionUserQuitController.applicationShouldTerminate { message in
            let alert = NSAlert()
            alert.alertStyle = .warning
            alert.messageText = "Bastion Could Not Quit"
            alert.informativeText = message
            alert.addButton(withTitle: "OK")
            alert.runModal()
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
        launchMode = BastionAppLauncher.launch(
            serviceRuntime: serviceRuntime,
            relayRuntime: relayRuntime,
            menuBarManager: menuBarManager
        )
    }
}

#endif

#if BASTION_HELPER
import AppKit
import Foundation

@main
enum BastionAgentMain {
    static func main() {
        let application = NSApplication.shared
        let delegate = BastionAgentAppDelegate()
        application.setActivationPolicy(.accessory)
        application.delegate = delegate
        application.run()
    }
}

@MainActor
private final class BastionAgentAppDelegate: NSObject, NSApplicationDelegate {
    private let serviceRuntime = BastionServiceRuntime()
    private let approvalPresenter = MenuBarManager()

    func applicationDidFinishLaunching(_ notification: Notification) {
        serviceRuntime.start(menuBarManager: approvalPresenter)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
#endif

#if BASTION_HELPER
import AppKit
import Foundation

// NOTE: bastion-helper is not currently the registered SMAppService launch target.
// BundleProgram = Contents/MacOS/bastion (main binary) is the registered job.
// An attempt to move service ownership here failed with EX_CONFIG (78) / spawn failed.
// The menu bar UI lives in the main binary under #if !BASTION_HELPER.
// This entry point is the intended form for when helper ownership is eventually proven
// and re-enabled: background-only service runner, no menu bar or status item.

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

    func applicationDidFinishLaunching(_ notification: Notification) {
        serviceRuntime.start()
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        false
    }
}
#endif

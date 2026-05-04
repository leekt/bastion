import AppKit
import SwiftUI

@MainActor
final class AuditHistoryWindowManager {
    static let shared = AuditHistoryWindowManager()

    private var window: NSWindow?

    private init() {}

    func showWindow() {
        if let window {
            NSApplication.shared.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            return
        }

        let hostingController = NSHostingController(rootView: AuditHistoryView())

        // No `.fullSizeContentView` here on purpose — the v2 mock used it
        // to host a custom in-content title bar (`MacTrafficLights` + a
        // "Bastion · Audit history" label) that we removed in PR #38. With
        // that flag set, the wrapped NSScrollView inside SwiftUI's `List`
        // applied its own ~28pt content inset matching the title bar's
        // intrusion (on top of the safe-area inset SwiftUI already
        // applied), producing the giant empty band above the column
        // header that survived every padding tweak in #42–#45. Plain
        // titled-window style → opaque OS title bar above content, no
        // double-counted inset.
        let newWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        newWindow.contentViewController = hostingController
        newWindow.title = "Audit History"
        newWindow.isReleasedWhenClosed = false
        newWindow.center()
        newWindow.setFrameAutosaveName("BastionAuditHistoryWindow")

        NotificationCenter.default.addObserver(
            forName: NSWindow.willCloseNotification,
            object: newWindow,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                self?.window = nil
            }
        }

        self.window = newWindow
        NSApplication.shared.activate(ignoringOtherApps: true)
        newWindow.makeKeyAndOrderFront(nil)
        newWindow.orderFrontRegardless()
    }
}

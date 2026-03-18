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

        let hostingView = NSHostingView(rootView: AuditHistoryView())

        let newWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 1180, height: 760),
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        newWindow.contentView = hostingView
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

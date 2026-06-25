import AppKit
import SwiftUI

@MainActor
final class DiagnosticsWindowManager {
    static let shared = DiagnosticsWindowManager()

    private var window: NSWindow?

    private init() {}

    func showWindow() {
        if let window {
            NSApplication.shared.activate(ignoringOtherApps: true)
            window.makeKeyAndOrderFront(nil)
            window.orderFrontRegardless()
            return
        }

        let hostingController = NSHostingController(rootView: DiagnosticsSupportView())
        let newWindow = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 680),
            styleMask: [.titled, .closable, .miniaturizable, .resizable],
            backing: .buffered,
            defer: false
        )
        newWindow.contentViewController = hostingController
        newWindow.title = "Diagnostics"
        newWindow.isReleasedWhenClosed = false
        newWindow.center()
        newWindow.setFrameAutosaveName("BastionDiagnosticsWindow")

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

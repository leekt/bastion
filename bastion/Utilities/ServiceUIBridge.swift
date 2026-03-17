import AppKit
import Foundation

enum ServiceUITarget: String {
    case settings
    case auditHistory
}

enum ServiceUIBridge {
    @MainActor
    static func openInCurrentProcess(_ target: ServiceUITarget) {
        NSApplication.shared.activate(ignoringOtherApps: true)

        switch target {
        case .settings:
            NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
        case .auditHistory:
            AuditHistoryWindowManager.shared.showWindow()
        }
    }

    static func requestOpen(_ target: ServiceUITarget) async -> Bool {
        for _ in 0..<30 {
            if await sendOpenRequest(target) {
                return true
            }
            try? await Task.sleep(for: .milliseconds(150))
        }
        return false
    }

    private static func sendOpenRequest(_ target: ServiceUITarget) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: xpcServiceName, options: [])
            connection.remoteObjectInterface = NSXPCInterface(with: BastionXPCProtocol.self)

            let lock = NSLock()
            var didFinish = false

            func finish(_ result: Bool) {
                lock.lock()
                defer { lock.unlock() }

                guard !didFinish else {
                    return
                }

                didFinish = true
                connection.invalidationHandler = nil
                connection.interruptionHandler = nil
                connection.invalidate()
                continuation.resume(returning: result)
            }

            connection.invalidationHandler = {
                finish(false)
            }
            connection.interruptionHandler = {
                finish(false)
            }

            connection.resume()

            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                finish(false)
            }) as? BastionXPCProtocol else {
                finish(false)
                return
            }

            proxy.openUI(target: target.rawValue) { success, error in
                finish(success && error == nil)
            }

            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1.0) {
                finish(false)
            }
        }
    }
}

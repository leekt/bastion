import AppKit
import Foundation

enum BastionLaunchMode {
    case service
    case relay
}

enum BastionLaunchController {
    static func resolveLaunchMode() -> BastionLaunchMode {
        CLIInstaller.isRunningAsLaunchAgentService ? .service : .relay
    }
}

@MainActor
final class BastionServiceRuntime {
    private let xpcServer: XPCServer
    private let ruleEngine: RuleEngine

    init() {
        self.xpcServer = .shared
        self.ruleEngine = .shared
    }

    init(
        xpcServer: XPCServer,
        ruleEngine: RuleEngine
    ) {
        self.xpcServer = xpcServer
        self.ruleEngine = ruleEngine
    }

    func start(menuBarManager: MenuBarManager? = nil) {
        BastionNotificationManager.shared.configureIfNeeded()
        menuBarManager?.startObserving()
        xpcServer.start()
        ruleEngine.loadConfigOnStartup()
        warmSecureEnclaveKey()
    }

    private func warmSecureEnclaveKey() {
        DispatchQueue.global(qos: .utility).async {
            do {
                _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey()
            } catch {}
        }
    }
}

@MainActor
final class BastionRelayRuntime {
    func start(target: ServiceUITarget = .auditHistory) {
        ServiceRegistration.registerIfNeeded()

        Task { @MainActor in
            await handoffToServiceInstance(target: target)
        }
    }

    private func handoffToServiceInstance(target: ServiceUITarget) async {
        let success = await ServiceUIBridge.requestOpen(target)
        if success {
            try? await Task.sleep(for: .milliseconds(150))
            NSApplication.shared.terminate(nil)
            return
        }

        presentServiceUnavailableAlert()
    }

    private func presentServiceUnavailableAlert() {
        NSApplication.shared.activate(ignoringOtherApps: true)

        let alert = NSAlert()
        alert.alertStyle = .warning
        alert.messageText = "Bastion Background Service Unavailable"
#if DEBUG
        alert.informativeText = """
        Bastion could not reach the registered background service.

        Rebuild and restart the signed service with:
        ./scripts/dev-rebuild-signed.sh
        """
#else
        alert.informativeText = """
        Bastion could not reach the registered background service.

        Relaunch Bastion. If the problem persists, reinstall the app.
        """
#endif
        alert.addButton(withTitle: "OK")
        alert.runModal()
        NSApplication.shared.terminate(nil)
    }
}

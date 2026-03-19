import AppKit
import Darwin
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
    private var lockFD: Int32 = -1

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
        guard acquireServiceLock() else {
            NSLog("Another Bastion service instance is already running. Exiting.")
            exit(0)
        }

        BastionNotificationManager.shared.configureIfNeeded()
        menuBarManager?.startObserving()
        xpcServer.start()
        ruleEngine.loadConfigOnStartup()
        warmSecureEnclaveKey()
    }

    private func acquireServiceLock() -> Bool {
        guard let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            NSLog("BastionServiceRuntime: could not resolve Application Support directory; skipping lock")
            return true
        }

        let bastionDir = appSupport.appendingPathComponent("Bastion", isDirectory: true)
        let lockPath = bastionDir.appendingPathComponent("service.lock").path

        do {
            try FileManager.default.createDirectory(at: bastionDir, withIntermediateDirectories: true)
        } catch {
            NSLog("BastionServiceRuntime: could not create Bastion support directory (%@); skipping lock", error.localizedDescription)
            return true
        }

        let fd = Darwin.open(lockPath, O_CREAT | O_RDWR, mode_t(0o600))
        guard fd >= 0 else {
            NSLog("BastionServiceRuntime: could not open lock file at %@; skipping lock", lockPath)
            return true
        }

        let result = flock(fd, LOCK_EX | LOCK_NB)
        if result == 0 {
            lockFD = fd
            return true
        }

        if errno == EWOULDBLOCK {
            Darwin.close(fd)
            return false
        }

        NSLog("BastionServiceRuntime: flock returned unexpected errno %d; skipping lock", errno)
        lockFD = fd
        return true
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
        // Don't attempt XPC handoff or show alerts when running under XCTest.
        guard ProcessInfo.processInfo.environment["XCTestBundlePath"] == nil else { return }

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

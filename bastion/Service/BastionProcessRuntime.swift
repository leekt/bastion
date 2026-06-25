import AppKit
import Darwin
import Foundation

enum BastionLaunchMode {
    case service
    case relay
}

enum BastionLaunchController {
    static func resolveLaunchMode() -> BastionLaunchMode {
        resolveLaunchMode(
            isRunningAsLaunchAgentService: CLIInstaller.isRunningAsLaunchAgentService
        )
    }

    static func resolveLaunchMode(isRunningAsLaunchAgentService: Bool) -> BastionLaunchMode {
        isRunningAsLaunchAgentService ? .service : .relay
    }
}

@MainActor
enum BastionUserQuitController {
    struct Actions {
        var isRunningAsLaunchAgentService: @MainActor () -> Bool = {
            CLIInstaller.isRunningAsLaunchAgentService
        }
        var hasUserRequestedShutdown: @MainActor () -> Bool = {
            ServiceRegistration.hasUserRequestedShutdown()
        }
        var recordUserRequestedShutdown: @MainActor () -> Void = {
            ServiceRegistration.recordUserRequestedShutdown()
        }
        var clearUserRequestedShutdown: @MainActor () -> Void = {
            ServiceRegistration.clearUserRequestedShutdown()
        }
        var statusDescription: @MainActor () -> String = {
            ServiceRegistration.statusDescription()
        }
        var unregisterForUserQuit: @MainActor () throws -> String = {
            let status = try ServiceRegistration.unregisterForUserQuit()
            return ServiceRegistration.statusDescription(for: status)
        }
        var recordQuitRequested: @MainActor (_ statusBeforeQuit: String, _ statusAfterUnregister: String) -> Void = {
            statusBeforeQuit,
            statusAfterUnregister in
            DiagnosticLog.shared.record(
                category: .lifecycle,
                event: "user_quit_requested",
                message: "User requested Bastion quit",
                context: [
                    "serviceRegistrationStatusBeforeQuit": statusBeforeQuit,
                    "serviceRegistrationStatusAfterUnregister": statusAfterUnregister,
                ]
            )
        }
        var recordQuitFailed: @MainActor (_ message: String) -> Void = { message in
            DiagnosticLog.shared.record(
                level: .error,
                category: .lifecycle,
                event: "user_quit_unregister_failed",
                message: message
            )
        }
        var terminateApplication: @MainActor () -> Void = {
            NSApplication.shared.terminate(nil)
        }
    }

    nonisolated static func shouldAllowImmediateTermination(
        isRunningAsLaunchAgentService: Bool,
        userRequestedShutdown: Bool
    ) -> Bool {
        !isRunningAsLaunchAgentService || userRequestedShutdown
    }

    @discardableResult
    static func requestQuit(
        actions: Actions = Actions(),
        onFailure: ((String) -> Void)? = nil
    ) -> Bool {
        actions.recordUserRequestedShutdown()
        do {
            let statusBeforeQuit = actions.statusDescription()
            let statusAfterUnregister = try actions.unregisterForUserQuit()
            actions.recordQuitRequested(statusBeforeQuit, statusAfterUnregister)
            actions.terminateApplication()
            return true
        } catch {
            actions.clearUserRequestedShutdown()
            let message = ServiceRegistration.userQuitFailureMessage(error)
            actions.recordQuitFailed(message)
            onFailure?(message)
            return false
        }
    }

    static func applicationShouldTerminate(
        actions: Actions = Actions(),
        onFailure: ((String) -> Void)? = nil
    ) -> NSApplication.TerminateReply {
        if shouldAllowImmediateTermination(
            isRunningAsLaunchAgentService: actions.isRunningAsLaunchAgentService(),
            userRequestedShutdown: actions.hasUserRequestedShutdown()
        ) {
            return .terminateNow
        }

        requestQuit(actions: actions, onFailure: onFailure)
        return .terminateCancel
    }
}

@MainActor
enum BastionAppLauncher {
    struct Actions {
        var migrateLegacyKeychainItems: @MainActor () -> Void = {
            KeychainStore.migrateLegacyItems()
        }
        var installCLIIfNeeded: @MainActor () -> Void = {
            CLIInstaller.installIfNeeded()
        }
        var registerAndExitIfRequested: @MainActor () -> Void = {
            ServiceRegistration.registerAndExitIfRequested()
        }
        var resolveLaunchMode: @MainActor () -> BastionLaunchMode = {
            BastionLaunchController.resolveLaunchMode()
        }
        var shouldExitForUserRequestedShutdown: @MainActor (BastionLaunchMode) -> Bool = { mode in
            ServiceRegistration.shouldExitServiceLaunchForUserShutdown(
                isRunningAsLaunchAgentService: mode == .service,
                userRequestedShutdown: ServiceRegistration.hasUserRequestedShutdown()
            )
        }
        var stopRelaunchedServiceForUserRequestedShutdown: @MainActor () -> Void = {
            DiagnosticLog.shared.record(
                category: .lifecycle,
                event: "user_quit_relaunch_suppressed",
                message: "Bastion service relaunched after an explicit user quit; shutting down without starting UI or XPC",
                context: [
                    "launchAgentLabel": ServiceRegistration.launchAgentLabel,
                    "launchAgentDomain": ServiceRegistration.launchAgentDomain
                ]
            )
            do {
                _ = try ServiceRegistration.unregisterForUserQuit()
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .lifecycle,
                    event: "user_quit_relaunch_shutdown_failed",
                    message: ServiceRegistration.userQuitFailureMessage(error)
                )
            }
            NSApplication.shared.terminate(nil)
        }
        var clearUserRequestedShutdownForInteractiveLaunch: @MainActor (BastionLaunchMode) -> Void = { mode in
            if mode == .relay {
                ServiceRegistration.clearUserRequestedShutdown()
            }
        }
        var warmSessionStore: @MainActor () -> Void = {
            _ = SessionStore.shared
        }
        var startServiceRuntime: @MainActor (BastionServiceRuntime, MenuBarManager) -> Void = { runtime, menuBarManager in
            runtime.start(menuBarManager: menuBarManager)
        }
        var startRelayRuntime: @MainActor (BastionRelayRuntime) -> Void = { runtime in
            runtime.start()
        }
        var startRPCHealthMonitoring: @MainActor () -> Void = {
            RPCHealthMonitor.shared.startMonitoring()
        }
        var startReleaseUpdateMonitor: @MainActor () -> Void = {
            ReleaseUpdateMonitor.shared.startIfConfigured()
        }
    }

    @discardableResult
    static func launch(
        serviceRuntime: BastionServiceRuntime,
        relayRuntime: BastionRelayRuntime,
        menuBarManager: MenuBarManager,
        actions: Actions = Actions()
    ) -> BastionLaunchMode {
        // M-08: Migrate pre-data-protection-keychain items before any other
        // startup path touches Keychain; the legacy per-item ACL is brittle
        // across signed dev builds.
        actions.migrateLegacyKeychainItems()
        actions.installCLIIfNeeded()
        actions.registerAndExitIfRequested()

        let launchMode = actions.resolveLaunchMode()
        if actions.shouldExitForUserRequestedShutdown(launchMode) {
            actions.stopRelaunchedServiceForUserRequestedShutdown()
            return launchMode
        }
        actions.clearUserRequestedShutdownForInteractiveLaunch(launchMode)

        // v9: warm persisted sessions before service XPC accepts requests.
        actions.warmSessionStore()

        if launchMode == .service {
            actions.startServiceRuntime(serviceRuntime, menuBarManager)
        } else {
            actions.startRelayRuntime(relayRuntime)
        }

        // Keep status/update background services running in both service and
        // relay launches; relay exits after handoff when it can reach service.
        actions.startRPCHealthMonitoring()
        actions.startReleaseUpdateMonitor()
        return launchMode
    }
}

final class BastionServiceLock {
    private let lockPath: String
    private var lockFD: Int32 = -1

    init(lockURL: URL) {
        self.lockPath = lockURL.path
    }

    static func defaultLock() -> BastionServiceLock? {
        guard let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            NSLog("BastionServiceRuntime: could not resolve Application Support directory; refusing to start without duplicate-instance lock")
            DiagnosticLog.shared.record(
                level: .error,
                category: .lifecycle,
                event: "service_lock_directory_missing",
                message: "Could not resolve Application Support directory for service lock"
            )
            return nil
        }

        let lockURL = appSupport
            .appendingPathComponent("Bastion", isDirectory: true)
            .appendingPathComponent("service.lock")
        return BastionServiceLock(lockURL: lockURL)
    }

    func acquire() -> Bool {
        if lockFD >= 0 {
            return true
        }

        let directory = URL(fileURLWithPath: lockPath).deletingLastPathComponent()
        do {
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        } catch {
            NSLog("BastionServiceRuntime: could not create Bastion support directory (%@); refusing to start without duplicate-instance lock", error.localizedDescription)
            DiagnosticLog.shared.record(
                level: .error,
                category: .lifecycle,
                event: "service_lock_directory_create_failed",
                message: error.localizedDescription
            )
            return false
        }

        let fd = Darwin.open(lockPath, O_CREAT | O_RDWR, mode_t(0o600))
        guard fd >= 0 else {
            NSLog("BastionServiceRuntime: could not open lock file at %@; refusing to start without duplicate-instance lock", lockPath)
            DiagnosticLog.shared.record(
                level: .error,
                category: .lifecycle,
                event: "service_lock_open_failed",
                message: "Could not open service lock"
            )
            return false
        }

        let result = flock(fd, LOCK_EX | LOCK_NB)
        if result == 0 {
            lockFD = fd
            return true
        }

        if errno == EWOULDBLOCK {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .lifecycle,
                event: "service_lock_already_owned",
                message: "Another service process already owns the service lock"
            )
            Darwin.close(fd)
            return false
        }

        NSLog("BastionServiceRuntime: flock returned unexpected errno %d; refusing to start without duplicate-instance lock", errno)
        DiagnosticLog.shared.record(
            level: .error,
            category: .lifecycle,
            event: "service_lock_flock_failed",
            message: "flock returned unexpected errno",
            context: ["errno": String(errno)]
        )
        Darwin.close(fd)
        return false
    }

    func release() {
        guard lockFD >= 0 else { return }
        flock(lockFD, LOCK_UN)
        Darwin.close(lockFD)
        lockFD = -1
    }

    deinit {
        release()
    }
}

@MainActor
final class BastionServiceRuntime {
    struct Actions {
        var loadConfigOnStartup: @MainActor (RuleEngine) -> Void = { ruleEngine in
            ruleEngine.loadConfigOnStartup()
        }
        var warmSessionStore: @MainActor () -> Void = {
            _ = SessionStore.shared
        }
        var configureNotifications: @MainActor () -> Void = {
            BastionNotificationManager.shared.configureIfNeeded()
        }
        var startMenuBarObserving: @MainActor (MenuBarManager) -> Void = { menuBarManager in
            menuBarManager.startObserving()
        }
        var startXPCServer: @MainActor (XPCServer) -> Void = { xpcServer in
            xpcServer.start()
        }
        var warmSecureEnclaveKey: @MainActor () -> Void = {
            DispatchQueue.global(qos: .utility).async {
                do {
                    _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey()
                } catch {}
            }
        }
    }

    private let xpcServer: XPCServer
    private let ruleEngine: RuleEngine
    private let serviceLock: BastionServiceLock?
    private let actions: Actions

    init(actions: Actions = Actions()) {
        self.xpcServer = .shared
        self.ruleEngine = .shared
        self.serviceLock = BastionServiceLock.defaultLock()
        self.actions = actions
    }

    init(
        xpcServer: XPCServer,
        ruleEngine: RuleEngine,
        serviceLock: BastionServiceLock? = BastionServiceLock.defaultLock(),
        actions: Actions = Actions()
    ) {
        self.xpcServer = xpcServer
        self.ruleEngine = ruleEngine
        self.serviceLock = serviceLock
        self.actions = actions
    }

    func start(menuBarManager: MenuBarManager? = nil) {
        guard serviceLock?.acquire() == true else {
            NSLog("Another Bastion service instance is already running. Exiting.")
            DiagnosticLog.shared.record(
                level: .warning,
                category: .lifecycle,
                event: "service_duplicate_exit",
                message: "Another Bastion service instance is already running"
            )
            exit(0)
        }

        DiagnosticLog.shared.record(
            category: .lifecycle,
            event: "service_starting",
            message: "Bastion service runtime starting",
            context: ["pid": String(ProcessInfo.processInfo.processIdentifier)]
        )
        actions.loadConfigOnStartup(ruleEngine)
        // Load persisted session grants into SessionSnapshotStore before XPC
        // accepts requests; an empty snapshot means "no session constraints".
        actions.warmSessionStore()
        actions.configureNotifications()
        if let menuBarManager {
            actions.startMenuBarObserving(menuBarManager)
        }
        actions.startXPCServer(xpcServer)
        actions.warmSecureEnclaveKey()
        DiagnosticLog.shared.record(
            category: .lifecycle,
            event: "service_started",
            message: "Bastion service runtime started"
        )
    }
}

@MainActor
final class BastionRelayRuntime {
    nonisolated static let successfulHandoffTerminationDelay: Duration = .milliseconds(150)

    func start(target: ServiceUITarget = .auditHistory) {
        // Don't attempt XPC handoff or show alerts when running under XCTest.
        guard ProcessInfo.processInfo.environment["XCTestBundlePath"] == nil else { return }

        DiagnosticLog.shared.record(
            category: .lifecycle,
            event: "relay_starting",
            message: "Bastion relay runtime starting",
            context: ["target": target.rawValue]
        )
        ServiceRegistration.registerIfNeeded()

        Task { @MainActor in
            await handoffToServiceInstance(target: target)
        }
    }

    private func handoffToServiceInstance(target: ServiceUITarget) async {
        let route = ServiceUIRoutePlanner.relayLaunchRoute(target: target)
        let success: Bool
        switch route {
        case .openInCurrentProcess(let target):
            ServiceUIBridge.openInCurrentProcess(target)
            success = true
        case .requestServiceOpen(let target):
            success = await ServiceUIBridge.requestOpen(target)
        }
        if success {
            DiagnosticLog.shared.record(
                category: .lifecycle,
                event: "relay_handoff_succeeded",
                message: "Relay handed UI request to service",
                context: ["target": target.rawValue]
            )
            guard await Self.shouldTerminateAfterSuccessfulHandoff() else {
                return
            }
            NSApplication.shared.terminate(nil)
            return
        }

        DiagnosticLog.shared.record(
            level: .error,
            category: .lifecycle,
            event: "relay_handoff_failed",
            message: "Relay could not reach service",
            context: ["target": target.rawValue]
        )
        presentServiceUnavailableAlert()
    }

    nonisolated static func shouldTerminateAfterSuccessfulHandoff(
        delay: Duration = successfulHandoffTerminationDelay,
        sleep: (Duration) async throws -> Void = { delay in
            try await Task.sleep(for: delay)
        }
    ) async -> Bool {
        do {
            try await sleep(delay)
        } catch {
            return false
        }
        return !Task.isCancelled
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

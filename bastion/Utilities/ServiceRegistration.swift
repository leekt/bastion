import Foundation
import ServiceManagement

enum ServiceRegistration {
    static let launchAgentLabel = CLIInstaller.launchAgentLabel
    static let launchAgentPlistName = "\(launchAgentLabel).plist"
    static let userRequestedShutdownDefaultsKey = "BastionUserRequestedShutdown"
    static var launchAgentDomain: String { "gui/\(getuid())/\(launchAgentLabel)" }

    struct RegistrationDriver {
        let currentStatus: () -> SMAppService.Status
        let register: () throws -> Void
        let unregister: () throws -> Void
    }

    struct UserQuitDriver {
        let currentStatus: () -> SMAppService.Status
        let unregister: () throws -> Void
        let isLaunchAgentLoaded: (String) -> Bool
        let bootoutLaunchAgent: (String) throws -> Void
    }

    struct LaunchctlFailure: LocalizedError {
        let arguments: [String]
        let terminationStatus: Int32
        let output: String

        var errorDescription: String? {
            let command = (["launchctl"] + arguments).joined(separator: " ")
            let details = output.trimmingCharacters(in: .whitespacesAndNewlines)
            if details.isEmpty {
                return "\(command) exited \(terminationStatus)"
            }
            return "\(command) exited \(terminationStatus): \(details)"
        }
    }

    private static var appService: SMAppService {
        SMAppService.agent(plistName: launchAgentPlistName)
    }

    static func registerIfNeeded() {
        guard shouldAttemptAutoRegistration(
            isRunningAsLaunchAgentService: CLIInstaller.isRunningAsLaunchAgentService,
            isStableInstalledBundleLocation: CLIInstaller.isStableInstalledBundleLocation
        ) else {
            return
        }

        Task(priority: .utility) { @MainActor in
            do {
                let status = try register()
                DiagnosticLog.shared.record(
                    category: .lifecycle,
                    event: "service_auto_registration_completed",
                    message: autoRegistrationSuccessMessage(status: status),
                    context: autoRegistrationDiagnosticContext(status: status)
                )
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .lifecycle,
                    event: "service_auto_registration_failed",
                    message: autoRegistrationFailureMessage(error),
                    context: autoRegistrationDiagnosticContext(error: error)
                )
            }
        }
    }

    static func shouldAttemptAutoRegistration(
        isRunningAsLaunchAgentService: Bool,
        isStableInstalledBundleLocation: Bool
    ) -> Bool {
        !isRunningAsLaunchAgentService && isStableInstalledBundleLocation
    }

    static func shouldUnregisterBeforeUserQuit(status: SMAppService.Status) -> Bool {
        switch status {
        case .enabled:
            return true
        case .notRegistered, .requiresApproval, .notFound:
            return false
        @unknown default:
            return false
        }
    }

    static func shouldCheckLaunchctlBeforeUserQuit(
        statusBeforeQuit: SMAppService.Status,
        isRunningAsLaunchAgentService: Bool
    ) -> Bool {
        isRunningAsLaunchAgentService || shouldUnregisterBeforeUserQuit(status: statusBeforeQuit)
    }

    static func recordUserRequestedShutdown(defaults: UserDefaults = .standard) {
        defaults.set(true, forKey: userRequestedShutdownDefaultsKey)
        _ = defaults.synchronize()
    }

    static func clearUserRequestedShutdown(defaults: UserDefaults = .standard) {
        defaults.removeObject(forKey: userRequestedShutdownDefaultsKey)
        _ = defaults.synchronize()
    }

    static func hasUserRequestedShutdown(defaults: UserDefaults = .standard) -> Bool {
        defaults.bool(forKey: userRequestedShutdownDefaultsKey)
    }

    static func shouldExitServiceLaunchForUserShutdown(
        isRunningAsLaunchAgentService: Bool,
        userRequestedShutdown: Bool
    ) -> Bool {
        isRunningAsLaunchAgentService && userRequestedShutdown
    }

    static func autoRegistrationSuccessMessage(status: SMAppService.Status) -> String {
        "Bastion background service auto-registration completed with status \(statusDescription(for: status))."
    }

    static func autoRegistrationFailureMessage(_ error: Error) -> String {
        "Bastion background service auto-registration failed: \(error.localizedDescription)"
    }

    static func autoRegistrationDiagnosticContext(
        status: SMAppService.Status? = nil,
        error: Error? = nil,
        isRunningAsLaunchAgentService: Bool = CLIInstaller.isRunningAsLaunchAgentService,
        isStableInstalledBundleLocation: Bool = CLIInstaller.isStableInstalledBundleLocation
    ) -> [String: String] {
        var context = [
            "launchAgentLabel": launchAgentLabel,
            "launchAgentDomain": launchAgentDomain,
            "launchAgentPlistName": launchAgentPlistName,
            "isRunningAsLaunchAgentService": String(isRunningAsLaunchAgentService),
            "isStableInstalledBundleLocation": String(isStableInstalledBundleLocation),
        ]
        if let status {
            context["serviceRegistrationStatus"] = statusDescription(for: status)
        }
        if let error {
            context["error"] = error.localizedDescription
        }
        return context
    }

    @discardableResult
    static func register(forceRefresh: Bool = false) throws -> SMAppService.Status {
        let service = appService
        return try register(forceRefresh: forceRefresh, driver: registrationDriver(for: service))
    }

    @discardableResult
    static func register(forceRefresh: Bool, driver: RegistrationDriver) throws -> SMAppService.Status {
        if forceRefresh, shouldRefreshRegistrationBeforeRegister(status: driver.currentStatus()) {
            try driver.unregister()
        }

        switch driver.currentStatus() {
        case .enabled:
            return .enabled
        case .requiresApproval, .notFound, .notRegistered:
            try driver.register()
            return driver.currentStatus()
        @unknown default:
            try driver.register()
            return driver.currentStatus()
        }
    }

    static func shouldRefreshRegistrationBeforeRegister(status: SMAppService.Status) -> Bool {
        switch status {
        case .enabled:
            return true
        case .notRegistered, .requiresApproval, .notFound:
            return false
        @unknown default:
            return false
        }
    }

    private static func registrationDriver(for service: SMAppService) -> RegistrationDriver {
        RegistrationDriver(
            currentStatus: { service.status },
            register: { try service.register() },
            unregister: { try service.unregister() }
        )
    }

    @discardableResult
    static func unregisterForUserQuit() throws -> SMAppService.Status {
        let service = appService
        return try unregisterForUserQuit(
            isRunningAsLaunchAgentService: CLIInstaller.isRunningAsLaunchAgentService,
            driver: userQuitDriver(for: service)
        )
    }

    @discardableResult
    static func unregisterForUserQuit(
        isRunningAsLaunchAgentService: Bool,
        driver: UserQuitDriver
    ) throws -> SMAppService.Status {
        let statusBeforeQuit = driver.currentStatus()
        if shouldUnregisterBeforeUserQuit(status: statusBeforeQuit) {
            try driver.unregister()
        }

        if shouldCheckLaunchctlBeforeUserQuit(
            statusBeforeQuit: statusBeforeQuit,
            isRunningAsLaunchAgentService: isRunningAsLaunchAgentService
        ), driver.isLaunchAgentLoaded(launchAgentDomain) {
            try driver.bootoutLaunchAgent(launchAgentDomain)
        }

        return driver.currentStatus()
    }

    static func userQuitFailureMessage(_ error: Error) -> String {
        "Quit failed: \(error.localizedDescription). Bastion is still registered as a background service and may relaunch until macOS disables the service. Run launchctl bootout \(launchAgentDomain) or disable Bastion in System Settings > General > Login Items & Extensions, then quit again."
    }

    static func registerAndExitIfRequested() {
        guard ProcessInfo.processInfo.arguments.contains("--register-service") else {
            return
        }

        guard CLIInstaller.isStableInstalledBundleLocation else {
            let message = """
            Refusing to register Bastion background service from an unstable bundle path.
            Install or copy Bastion.app to /Applications or ~/Applications first.
            """
            FileHandle.standardError.write(Data("\(message)\n".utf8))
            fflush(stderr)
            exit(EXIT_FAILURE)
        }

        do {
            _ = try register(forceRefresh: true)
            clearUserRequestedShutdown()
            fflush(stdout)
            exit(EXIT_SUCCESS)
        } catch {
            let message = "Failed to register Bastion background service: \(error.localizedDescription)\n"
            FileHandle.standardError.write(Data(message.utf8))
            fflush(stderr)
            exit(EXIT_FAILURE)
        }
    }

    static func statusDescription() -> String {
        statusDescription(for: appService.status)
    }

    static func statusDescription(for status: SMAppService.Status) -> String {
        switch status {
        case .notRegistered:
            return "not_registered"
        case .enabled:
            return "enabled"
        case .requiresApproval:
            return "requires_approval"
        case .notFound:
            return "not_found"
        @unknown default:
            return "unknown"
        }
    }

    private static func userQuitDriver(for service: SMAppService) -> UserQuitDriver {
        UserQuitDriver(
            currentStatus: { service.status },
            unregister: { try service.unregister() },
            isLaunchAgentLoaded: { domain in
                (try? runLaunchctl(["print", domain])) != nil
            },
            bootoutLaunchAgent: { domain in
                _ = try runLaunchctl(["bootout", domain])
            }
        )
    }

    @discardableResult
    private static func runLaunchctl(_ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        process.arguments = arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        try process.run()
        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOutput = errorPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let outputText = String(data: output + errorOutput, encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw LaunchctlFailure(
                arguments: arguments,
                terminationStatus: process.terminationStatus,
                output: outputText
            )
        }
        return outputText
    }
}

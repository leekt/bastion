import Foundation
import ServiceManagement

enum ServiceRegistration {
    static let launchAgentPlistName = "com.bastion.xpc.plist"

    private static var appService: SMAppService {
        SMAppService.agent(plistName: launchAgentPlistName)
    }

    static func registerIfNeeded() {
        guard !CLIInstaller.isRunningAsLaunchAgentService else {
            return
        }
        guard CLIInstaller.isStableInstalledBundleLocation else {
            return
        }

        Task(priority: .utility) { @MainActor in
            try? register()
        }
    }

    @discardableResult
    static func register(forceRefresh: Bool = false) throws -> SMAppService.Status {
        let service = appService

        if forceRefresh, service.status == .enabled {
            try? service.unregister()
        }

        switch service.status {
        case .enabled:
            return .enabled
        case .requiresApproval, .notFound, .notRegistered:
            try service.register()
            return service.status
        @unknown default:
            try service.register()
            return service.status
        }
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
        switch appService.status {
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
}

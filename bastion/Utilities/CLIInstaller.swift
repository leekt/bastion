import Foundation

final class CLIInstaller {
    nonisolated static let launchAgentLabel = "com.bastion.xpc"
    private nonisolated static let userApplicationsPrefix = "\(NSHomeDirectory())/Applications/"

    nonisolated enum SymlinkInstallOutcome: Equatable {
        case installed
        case alreadyInstalled
        case skippedMissingBundledCLI
        case failed(String)
    }

    nonisolated static var isRunningAsLaunchAgentService: Bool {
        ProcessInfo.processInfo.environment["XPC_SERVICE_NAME"] == launchAgentLabel
    }

    nonisolated static var isStableInstalledBundleLocation: Bool {
        let bundlePath = Bundle.main.bundleURL.path
        return bundlePath.hasPrefix("/Applications/") || bundlePath.hasPrefix(userApplicationsPrefix)
    }

    static func installIfNeeded() {
        guard isRunningAsLaunchAgentService || isStableInstalledBundleLocation else {
            return
        }
        guard ProcessInfo.processInfo.environment["BASTION_ENABLE_CLI_SYMLINK"] == "1" else {
            return
        }

        let outcome = installCLISymlink()
        if case .failed(let reason) = outcome {
            DiagnosticLog.shared.record(
                level: .warning,
                category: .lifecycle,
                event: "cli_symlink_install_failed",
                message: "CLI symlink installation failed",
                context: ["reason": reason]
            )
        }
    }

    @discardableResult
    static func installCLISymlink(
        symlinkPath: String = "/usr/local/bin/bastion",
        bundleURL: URL = Bundle.main.bundleURL,
        fileManager: FileManager = .default
    ) -> SymlinkInstallOutcome {
        guard let bundlePath = bundledCLIExecutableURL(for: bundleURL)?.path,
              fileManager.fileExists(atPath: bundlePath) else {
            return .skippedMissingBundledCLI
        }

        if let existingTarget = try? fileManager.destinationOfSymbolicLink(atPath: symlinkPath),
           existingTarget == bundlePath {
            return .alreadyInstalled
        }

        let parentPath = URL(fileURLWithPath: symlinkPath).deletingLastPathComponent().path
        do {
            if !fileManager.fileExists(atPath: parentPath) {
                try fileManager.createDirectory(atPath: parentPath, withIntermediateDirectories: true)
            }
        } catch {
            return .failed("Could not create CLI symlink directory \(parentPath): \(error.localizedDescription)")
        }

        let tmpPath = symlinkPath + ".tmp.\(ProcessInfo.processInfo.processIdentifier)"
        do {
            try? fileManager.removeItem(atPath: tmpPath)
            try fileManager.createSymbolicLink(atPath: tmpPath, withDestinationPath: bundlePath)
            guard rename(tmpPath, symlinkPath) == 0 else {
                let reason = String(cString: strerror(errno))
                try? fileManager.removeItem(atPath: tmpPath)
                return .failed("Could not atomically install CLI symlink at \(symlinkPath): \(reason)")
            }
            return .installed
        } catch {
            try? fileManager.removeItem(atPath: tmpPath)
            return .failed("Could not install CLI symlink at \(symlinkPath): \(error.localizedDescription)")
        }
    }

    nonisolated static func bundledCLIExecutableURL(for bundleURL: URL) -> URL? {
        if isHelperBundle(bundleURL) {
            return hostAppBundleURL(forHelperBundle: bundleURL)?
                .appendingPathComponent("Contents/MacOS/bastion-cli")
        }

        return bundleURL.appendingPathComponent("Contents/MacOS/bastion-cli")
    }

    nonisolated static func hostAppBundleURL(forHelperBundle bundleURL: URL) -> URL? {
        guard isHelperBundle(bundleURL) else {
            return nil
        }

        return bundleURL
            .deletingLastPathComponent() // Helpers
            .deletingLastPathComponent() // Contents
            .deletingLastPathComponent() // Bastion Dev.app
    }

    private nonisolated static func isHelperBundle(_ bundleURL: URL) -> Bool {
        let path = bundleURL.path
        return path.hasSuffix("/Contents/Helpers/bastion-helper.app")
    }
}

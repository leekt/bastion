import Foundation

final class CLIInstaller {
    nonisolated static let launchAgentLabel = "com.bastion.xpc"
    private nonisolated static let userApplicationsPrefix = "\(NSHomeDirectory())/Applications/"

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

        installCLISymlink()
    }

    private static func installCLISymlink() {
        let symlinkPath = "/usr/local/bin/bastion"
        let fileManager = FileManager.default

        guard let bundlePath = bundledCLIExecutableURL(for: Bundle.main.bundleURL)?.path else {
            return
        }

        guard fileManager.fileExists(atPath: bundlePath) else {
            return
        }

        if let existingTarget = try? fileManager.destinationOfSymbolicLink(atPath: symlinkPath),
           existingTarget == bundlePath {
            return
        }

        if !fileManager.fileExists(atPath: "/usr/local/bin") {
            try? fileManager.createDirectory(atPath: "/usr/local/bin", withIntermediateDirectories: true)
        }

        try? fileManager.removeItem(atPath: symlinkPath)

        do {
            try fileManager.createSymbolicLink(atPath: symlinkPath, withDestinationPath: bundlePath)
        } catch {
            // User can install the symlink manually if /usr/local/bin is not writable.
        }
    }

    static func bundledCLIExecutableURL(for bundleURL: URL) -> URL? {
        if isHelperBundle(bundleURL) {
            return hostAppBundleURL(forHelperBundle: bundleURL)?
                .appendingPathComponent("Contents/MacOS/bastion-cli")
        }

        return bundleURL.appendingPathComponent("Contents/MacOS/bastion-cli")
    }

    static func hostAppBundleURL(forHelperBundle bundleURL: URL) -> URL? {
        guard isHelperBundle(bundleURL) else {
            return nil
        }

        return bundleURL
            .deletingLastPathComponent() // Helpers
            .deletingLastPathComponent() // Contents
            .deletingLastPathComponent() // Bastion Dev.app
    }

    private static func isHelperBundle(_ bundleURL: URL) -> Bool {
        let path = bundleURL.path
        return path.hasSuffix("/Contents/Helpers/bastion-helper.app")
    }
}

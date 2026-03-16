import Foundation

final class CLIInstaller {
    static func installIfNeeded() {
        installCLISymlink()
        installLaunchAgent()
    }

    // MARK: - CLI Symlink

    private static func installCLISymlink() {
        let symlinkPath = "/usr/local/bin/bastion"
        let fileManager = FileManager.default

        // Find bastion-cli in the app bundle
        guard let bundlePath = Bundle.main.executableURL?.deletingLastPathComponent()
            .appendingPathComponent("bastion-cli").path else {
            return
        }

        // Check if bastion-cli binary exists in bundle
        guard fileManager.fileExists(atPath: bundlePath) else {
            // CLI build sidecar missing from app bundle
            return
        }

        // Check if symlink already exists and points to correct location
        if let existingTarget = try? fileManager.destinationOfSymbolicLink(atPath: symlinkPath),
           existingTarget == bundlePath {
            return
        }

        // Create /usr/local/bin if needed
        if !fileManager.fileExists(atPath: "/usr/local/bin") {
            try? fileManager.createDirectory(atPath: "/usr/local/bin", withIntermediateDirectories: true)
        }

        // Remove existing symlink
        try? fileManager.removeItem(atPath: symlinkPath)

        do {
            try fileManager.createSymbolicLink(atPath: symlinkPath, withDestinationPath: bundlePath)
        } catch {
            // Symlink creation requires write permission to /usr/local/bin
            // User may need to run: ln -sf <bundlePath> /usr/local/bin/bastion
        }
    }

    // MARK: - LaunchAgent

    private static func installLaunchAgent() {
        let launchAgentsDir = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents")
        let plistPath = launchAgentsDir.appendingPathComponent("com.bastion.xpc.plist")

        guard let appPath = Bundle.main.executableURL?.path else { return }

        // Check if already installed with correct path
        if FileManager.default.fileExists(atPath: plistPath.path) {
            if let data = try? Data(contentsOf: plistPath),
               let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
               let args = plist["ProgramArguments"] as? [String],
               args.first == appPath {
                return
            }
        }

        let plistContent: [String: Any] = [
            "Label": "com.bastion.xpc",
            "ProgramArguments": [appPath],
            "MachServices": ["com.bastion.xpc": true],
            "KeepAlive": true,
            "RunAtLoad": true,
        ]

        if !FileManager.default.fileExists(atPath: launchAgentsDir.path) {
            try? FileManager.default.createDirectory(at: launchAgentsDir, withIntermediateDirectories: true)
        }

        if let data = try? PropertyListSerialization.data(
            fromPropertyList: plistContent,
            format: .xml,
            options: 0
        ) {
            try? data.write(to: plistPath, options: .atomic)
        }
    }
}

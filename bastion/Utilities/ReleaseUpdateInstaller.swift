import Darwin
import Foundation

nonisolated struct ReleaseUpdateInstallResult: Codable, Sendable, Equatable {
    let installedAppPath: String
    let backupAppPath: String?
    let version: String
    let build: String
    let serviceRecovered: Bool
    let relaunched: Bool
    let cliSymlinkInstalled: Bool
    let rollbackPerformed: Bool
}

nonisolated enum ReleaseUpdateInstallError: Error, LocalizedError, Sendable {
    case commandFailed(String)
    case extractedAppNotFound(String)
    case appIdentityMismatch(String)
    case appBundleInvalid(String)
    case appVerificationFailed(String)
    case serviceRecoveryFailed(String)
    case cliSymlinkInstallFailed(String)
    case installFailed(String)
    case installFailedAndRolledBack(String)
    case installFailedRollbackFailed(String)

    var errorDescription: String? {
        switch self {
        case .commandFailed(let reason):
            return "Update install command failed: \(reason)"
        case .extractedAppNotFound(let reason):
            return "Update archive did not contain an app bundle: \(reason)"
        case .appIdentityMismatch(let reason):
            return "Update app identity mismatch: \(reason)"
        case .appBundleInvalid(let reason):
            return "Update app bundle is invalid: \(reason)"
        case .appVerificationFailed(let reason):
            return "Update app verification failed: \(reason)"
        case .serviceRecoveryFailed(let reason):
            return "Update service recovery failed: \(reason)"
        case .cliSymlinkInstallFailed(let reason):
            return "Update CLI symlink install failed: \(reason)"
        case .installFailed(let reason):
            return "Update install failed: \(reason)"
        case .installFailedAndRolledBack(let reason):
            return "Update install failed and rollback completed: \(reason)"
        case .installFailedRollbackFailed(let reason):
            return "Update install failed and rollback failed: \(reason)"
        }
    }
}

nonisolated protocol ReleaseUpdateCommandRunning: Sendable {
    func run(_ executable: String, _ arguments: [String]) throws -> String
}

nonisolated struct DefaultReleaseUpdateCommandRunner: ReleaseUpdateCommandRunning {
    func run(_ executable: String, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments

        let outputPipe = Pipe()
        let errorPipe = Pipe()
        process.standardOutput = outputPipe
        process.standardError = errorPipe

        do {
            try process.run()
        } catch {
            throw ReleaseUpdateInstallError.commandFailed(
                "\(executable) \(arguments.joined(separator: " ")): \(error.localizedDescription)"
            )
        }

        let output = outputPipe.fileHandleForReading.readDataToEndOfFile()
        let errorOutput = errorPipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()

        let outputText = String(data: output + errorOutput, encoding: .utf8) ?? ""
        guard process.terminationStatus == 0 else {
            throw ReleaseUpdateInstallError.commandFailed(
                "\(executable) \(arguments.joined(separator: " ")) exited \(process.terminationStatus): \(outputText)"
            )
        }

        return outputText
    }
}

nonisolated struct ReleaseUpdateInstallEnvironment: Sendable {
    let commandRunner: any ReleaseUpdateCommandRunning
    let extractArchive: @Sendable (URL, URL) throws -> Void
    let copyAppBundle: @Sendable (URL, URL) throws -> Void
    let verifyAppBundle: @Sendable (URL) throws -> Void
    let verifyRecoveredService: @Sendable (URL) throws -> Void

    static func production() -> ReleaseUpdateInstallEnvironment {
        let runner = DefaultReleaseUpdateCommandRunner()
        return ReleaseUpdateInstallEnvironment(
            commandRunner: runner,
            extractArchive: { archiveURL, destinationURL in
                try FileManager.default.createDirectory(at: destinationURL, withIntermediateDirectories: true)
                _ = try runner.run("/usr/bin/ditto", ["-x", "-k", archiveURL.path, destinationURL.path])
            },
            copyAppBundle: { sourceURL, destinationURL in
                try? FileManager.default.removeItem(at: destinationURL)
                _ = try runner.run("/usr/bin/ditto", [sourceURL.path, destinationURL.path])
            },
            verifyAppBundle: { appURL in
                try Self.verifySignedAppBundle(appURL, runner: runner)
            },
            verifyRecoveredService: { appURL in
                try Self.verifyServiceRecovery(appURL, runner: runner)
            }
        )
    }

    private static func verifySignedAppBundle(
        _ appURL: URL,
        runner: any ReleaseUpdateCommandRunning
    ) throws {
        _ = try runner.run("/usr/bin/codesign", ["--verify", "--deep", "--strict", "--verbose=2", appURL.path])
        let signatureOutput = try runner.run("/usr/bin/codesign", ["-dv", appURL.path])
        let expectedTeamID = ProcessInfo.processInfo.environment["BASTION_EXPECTED_TEAM_ID"] ?? "926A27BQ7W"
        guard signatureOutput
            .split(separator: "\n")
            .contains(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("TeamIdentifier=\(expectedTeamID)") }) else {
            throw ReleaseUpdateInstallError.appVerificationFailed(
                "TeamIdentifier did not match \(expectedTeamID)"
            )
        }
        _ = try runner.run("/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose", appURL.path])
        _ = try runner.run("/usr/bin/xcrun", ["stapler", "validate", appURL.path])
    }

    private static func verifyServiceRecovery(
        _ appURL: URL,
        runner: any ReleaseUpdateCommandRunning
    ) throws {
        let cliURL = appURL.appendingPathComponent("Contents/MacOS/bastion-cli")
        let expectedExecutable = appURL.appendingPathComponent("Contents/MacOS/bastion").path

        for _ in 0..<10 {
            if let output = try? runner.run(cliURL.path, ["status"]),
               let data = output.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
               let executablePath = json["executablePath"] as? String,
               executablePath == expectedExecutable {
                return
            }
            Thread.sleep(forTimeInterval: 1.0)
        }

        throw ReleaseUpdateInstallError.serviceRecoveryFailed(
            "XPC service did not respond from \(expectedExecutable)"
        )
    }
}

nonisolated enum ReleaseUpdateInstaller {
    private static let launchAgentLabel = "com.bastion.xpc"

    @discardableResult
    static func installStagedArtifact(
        manifest: ReleaseUpdateManifest,
        artifact: ReleaseUpdateArtifact,
        installURL: URL,
        backupDirectory: URL? = nil,
        relaunch: Bool = true,
        recoverService: Bool = true,
        installCLISymlink: Bool = true,
        verifyAppBundle: Bool = true,
        environment: ReleaseUpdateInstallEnvironment = .production()
    ) throws -> ReleaseUpdateInstallResult {
        let fileManager = FileManager.default
        let artifactURL = URL(fileURLWithPath: artifact.localPath)
        _ = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)

        let tempRoot = fileManager.temporaryDirectory
            .appendingPathComponent("BastionUpdateInstall-\(UUID().uuidString)", isDirectory: true)
        let extractedRoot = tempRoot.appendingPathComponent("extracted", isDirectory: true)
        try fileManager.createDirectory(at: extractedRoot, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: tempRoot) }

        try environment.extractArchive(artifactURL, extractedRoot)
        let extractedAppURL = try findExtractedApp(in: extractedRoot)
        try validateAppBundle(extractedAppURL, manifest: manifest)
        if verifyAppBundle {
            try environment.verifyAppBundle(extractedAppURL)
        }

        let installParent = installURL.deletingLastPathComponent()
        try fileManager.createDirectory(at: installParent, withIntermediateDirectories: true)

        let backupRoot = backupDirectory
            ?? installParent.appendingPathComponent(".BastionUpdateBackups", isDirectory: true)
        let backupURL = existingDirectory(at: installURL)
            ? backupRoot.appendingPathComponent(backupName(for: installURL), isDirectory: true)
            : nil

        do {
            if recoverService {
                stopExistingService(environment.commandRunner)
            }

            if let backupURL {
                try fileManager.createDirectory(at: backupRoot, withIntermediateDirectories: true)
                try? fileManager.removeItem(at: backupURL)
                try fileManager.moveItem(at: installURL, to: backupURL)
            }

            try environment.copyAppBundle(extractedAppURL, installURL)
            try validateAppBundle(installURL, manifest: manifest)
            if verifyAppBundle {
                try environment.verifyAppBundle(installURL)
            }

            registerAppBundle(installURL, runner: environment.commandRunner)
            if recoverService {
                try registerAndRecoverService(installURL, environment: environment)
            }
            if installCLISymlink {
                try installBundledCLISymlink(installURL, runner: environment.commandRunner)
            }
            if relaunch {
                try relaunchApp(installURL, runner: environment.commandRunner)
            }

            return ReleaseUpdateInstallResult(
                installedAppPath: installURL.path,
                backupAppPath: backupURL?.path,
                version: manifest.version,
                build: manifest.build,
                serviceRecovered: recoverService,
                relaunched: relaunch,
                cliSymlinkInstalled: installCLISymlink,
                rollbackPerformed: false
            )
        } catch {
            let rolledBack = rollbackInstall(
                installURL: installURL,
                backupURL: backupURL,
                recoverService: recoverService,
                environment: environment
            )
            if rolledBack {
                throw ReleaseUpdateInstallError.installFailedAndRolledBack(error.localizedDescription)
            }
            if backupURL != nil {
                throw ReleaseUpdateInstallError.installFailedRollbackFailed(error.localizedDescription)
            }
            throw ReleaseUpdateInstallError.installFailed(error.localizedDescription)
        }
    }

    private static func findExtractedApp(in directory: URL) throws -> URL {
        let expected = directory.appendingPathComponent("Bastion.app", isDirectory: true)
        if existingDirectory(at: expected) {
            return expected
        }

        guard let enumerator = FileManager.default.enumerator(
            at: directory,
            includingPropertiesForKeys: [.isDirectoryKey],
            options: [.skipsHiddenFiles]
        ) else {
            throw ReleaseUpdateInstallError.extractedAppNotFound(directory.path)
        }

        for item in enumerator {
            guard let url = item as? URL, url.pathExtension == "app" else {
                continue
            }
            if existingDirectory(at: url) {
                return url
            }
        }

        throw ReleaseUpdateInstallError.extractedAppNotFound(directory.path)
    }

    private static func validateAppBundle(
        _ appURL: URL,
        manifest: ReleaseUpdateManifest
    ) throws {
        let identity = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: appURL)
        guard identity.bundleIdentifier == manifest.bundleIdentifier else {
            throw ReleaseUpdateInstallError.appIdentityMismatch(
                "bundle \(identity.bundleIdentifier) does not match \(manifest.bundleIdentifier)"
            )
        }
        guard identity.version == manifest.version, identity.build == manifest.build else {
            throw ReleaseUpdateInstallError.appIdentityMismatch(
                "version \(identity.version) (\(identity.build)) does not match \(manifest.version) (\(manifest.build))"
            )
        }

        let appBinary = appURL.appendingPathComponent("Contents/MacOS/bastion")
        let cliBinary = appURL.appendingPathComponent("Contents/MacOS/bastion-cli")
        guard FileManager.default.isExecutableFile(atPath: appBinary.path) else {
            throw ReleaseUpdateInstallError.appBundleInvalid("main executable missing at \(appBinary.path)")
        }
        guard FileManager.default.isExecutableFile(atPath: cliBinary.path) else {
            throw ReleaseUpdateInstallError.appBundleInvalid("CLI executable missing at \(cliBinary.path)")
        }
    }

    private static func stopExistingService(_ runner: any ReleaseUpdateCommandRunning) {
        let domain = serviceDomain()
        if (try? runner.run("/bin/launchctl", ["print", domain])) != nil {
            _ = try? runner.run("/bin/launchctl", ["bootout", domain])
        }
        _ = try? runner.run(
            "/usr/bin/pkill",
            ["-f", "/bastion-helper.app/Contents/MacOS/bastion-helper($| )"]
        )
        _ = try? runner.run(
            "/usr/bin/pkill",
            ["-f", "/Bastion([^/]*)\\.app/Contents/MacOS/bastion($| )"]
        )
    }

    private static func registerAppBundle(
        _ installURL: URL,
        runner: any ReleaseUpdateCommandRunning
    ) {
        _ = try? runner.run(
            "/System/Library/Frameworks/CoreServices.framework/Versions/Current/Frameworks/LaunchServices.framework/Versions/Current/Support/lsregister",
            ["-f", "-R", "-trusted", installURL.path]
        )
    }

    private static func registerAndRecoverService(
        _ installURL: URL,
        environment: ReleaseUpdateInstallEnvironment
    ) throws {
        let appBinary = installURL.appendingPathComponent("Contents/MacOS/bastion")
        do {
            _ = try environment.commandRunner.run(appBinary.path, ["--register-service"])
        } catch {
            throw ReleaseUpdateInstallError.serviceRecoveryFailed(
                "service registration failed for \(appBinary.path): \(error.localizedDescription)"
            )
        }

        let domain = serviceDomain()
        do {
            _ = try environment.commandRunner.run("/bin/launchctl", ["kickstart", "-k", domain])
        } catch {
            throw ReleaseUpdateInstallError.serviceRecoveryFailed(
                "launchctl kickstart \(domain) failed: \(error.localizedDescription)"
            )
        }

        do {
            try environment.verifyRecoveredService(installURL)
        } catch {
            throw ReleaseUpdateInstallError.serviceRecoveryFailed(
                "XPC verification failed for \(installURL.path): \(error.localizedDescription)"
            )
        }
    }

    private static func installBundledCLISymlink(
        _ installURL: URL,
        runner: any ReleaseUpdateCommandRunning
    ) throws {
        let cliBinary = installURL.appendingPathComponent("Contents/MacOS/bastion-cli")
        do {
            _ = try runner.run("/bin/mkdir", ["-p", "/usr/local/bin"])
            _ = try runner.run("/bin/ln", ["-sf", cliBinary.path, "/usr/local/bin/bastion"])
        } catch {
            throw ReleaseUpdateInstallError.cliSymlinkInstallFailed(error.localizedDescription)
        }
    }

    private static func relaunchApp(
        _ installURL: URL,
        runner: any ReleaseUpdateCommandRunning
    ) throws {
        _ = try runner.run("/usr/bin/open", [installURL.path])
    }

    private static func rollbackInstall(
        installURL: URL,
        backupURL: URL?,
        recoverService: Bool,
        environment: ReleaseUpdateInstallEnvironment
    ) -> Bool {
        let fileManager = FileManager.default
        try? fileManager.removeItem(at: installURL)
        guard let backupURL, existingDirectory(at: backupURL) else {
            return false
        }
        do {
            try fileManager.moveItem(at: backupURL, to: installURL)
            if recoverService {
                try registerAndRecoverService(installURL, environment: environment)
            }
            return true
        } catch {
            return false
        }
    }

    private static func existingDirectory(at url: URL) -> Bool {
        var isDirectory = ObjCBool(false)
        return FileManager.default.fileExists(atPath: url.path, isDirectory: &isDirectory)
            && isDirectory.boolValue
    }

    private static func backupName(for installURL: URL) -> String {
        let identity = try? ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        let version = sanitize(identity?.version ?? "unknown")
        let build = sanitize(identity?.build ?? "unknown")
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return "Bastion-\(version)-\(build)-\(formatter.string(from: Date()))-\(UUID().uuidString.prefix(8)).app"
    }

    private static func sanitize(_ value: String) -> String {
        value.replacingOccurrences(
            of: #"[^A-Za-z0-9._-]+"#,
            with: "-",
            options: .regularExpression
        )
    }

    private static func serviceDomain() -> String {
        "gui/\(getuid())/\(launchAgentLabel)"
    }
}

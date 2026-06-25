import CryptoKit
import Foundation

nonisolated struct UpdateScenarioCommandSnapshot: Codable, Equatable, Sendable {
    let executable: String
    let arguments: [String]
}

nonisolated struct UpdateScenarioSnapshot: Codable, Equatable, Sendable {
    let currentVersion: String
    let manifestVersion: String
    let checkState: String
    let downloadVerified: Bool
    let downloadedSizeBytes: Int
    let installedVersion: String
    let installedBuild: String
    let backupCreated: Bool
    let serviceRecovered: Bool
    let relaunched: Bool
    let cliSymlinkInstalled: Bool
    let rollbackPerformed: Bool
    let appVerificationCalls: Int
    let serviceVerificationCalls: Int
    let commandExecutables: [String]
    let commandSnapshots: [UpdateScenarioCommandSnapshot]
}

nonisolated struct UpdateScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let update: UpdateScenarioSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct UpdateScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

private nonisolated final class UpdateScenarioRecordingRunner: ReleaseUpdateCommandRunning, @unchecked Sendable {
    private let lock = NSLock()
    private var recordedCommands: [UpdateScenarioCommandSnapshot] = []

    func run(_ executable: String, _ arguments: [String]) throws -> String {
        lock.lock()
        recordedCommands.append(UpdateScenarioCommandSnapshot(executable: executable, arguments: arguments))
        lock.unlock()
        return ""
    }

    func commands() -> [UpdateScenarioCommandSnapshot] {
        lock.lock()
        defer { lock.unlock() }
        return recordedCommands
    }
}

private nonisolated final class UpdateScenarioCounters: @unchecked Sendable {
    private let lock = NSLock()
    private var appVerificationCount = 0
    private var serviceVerificationCount = 0

    func recordAppVerification() {
        lock.lock()
        appVerificationCount += 1
        lock.unlock()
    }

    func recordServiceVerification() {
        lock.lock()
        serviceVerificationCount += 1
        lock.unlock()
    }

    func snapshot() -> (appVerificationCount: Int, serviceVerificationCount: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (appVerificationCount, serviceVerificationCount)
    }
}

nonisolated enum UpdateScenarioProbe {
    static let overviewScenario = "overview"

    static func run(scenario: String) async throws -> UpdateScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = try await overview()
            return UpdateScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "checkState": response.update.checkState,
                    "installedVersion": response.update.installedVersion,
                    "backupCreated": String(response.update.backupCreated),
                    "commands": response.update.commandExecutables.joined(separator: ","),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.update-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown update scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    static func overview() async throws -> UpdateScenarioProbeResponse {
        let fileManager = FileManager.default
        let root = fileManager.temporaryDirectory
            .appendingPathComponent("BastionUpdateScenario-\(UUID().uuidString)", isDirectory: true)
        defer { try? fileManager.removeItem(at: root) }

        let sourceDir = root.appendingPathComponent("source", isDirectory: true)
        let installDir = root.appendingPathComponent("install", isDirectory: true)
        let backupDir = root.appendingPathComponent("backups", isDirectory: true)
        let downloadDir = root.appendingPathComponent("downloads", isDirectory: true)
        try fileManager.createDirectory(at: sourceDir, withIntermediateDirectories: true)
        try fileManager.createDirectory(at: installDir, withIntermediateDirectories: true)

        let installURL = installDir.appendingPathComponent("Bastion.app", isDirectory: true)
        let replacementURL = sourceDir.appendingPathComponent("Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: replacementURL, version: "1.1", build: "2")

        let artifactSource = sourceDir.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        let artifactData = Data("Bastion update scenario archive fixture".utf8)
        try artifactData.write(to: artifactSource)
        let manifest = ReleaseUpdateManifest(
            app: "Bastion",
            bundleIdentifier: ReleaseUpdateVerifier.expectedBundleIdentifier,
            version: "1.1",
            build: "2",
            platform: ReleaseUpdateVerifier.expectedPlatform,
            minimumOSVersion: "13.0",
            publishedAt: "2026-06-24T00:00:00Z",
            downloadURL: artifactSource.absoluteString,
            releaseNotesURL: "https://updates.example.invalid/bastion/1.1",
            sha256: sha256Hex(artifactData),
            sizeBytes: artifactData.count,
            notarized: true,
            stapled: true
        )
        let manifestURL = sourceDir.appendingPathComponent("latest.json")
        try JSONEncoder().encode(manifest).write(to: manifestURL)

        let loadedManifest = try await ReleaseUpdateVerifier.loadManifest(from: manifestURL)
        let current = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        let check = ReleaseUpdateVerifier.evaluate(manifest: loadedManifest, current: current)
        let downloaded = try await ReleaseUpdateVerifier.downloadAndVerify(
            manifest: loadedManifest,
            outputDirectory: downloadDir
        )

        let runner = UpdateScenarioRecordingRunner()
        let counters = UpdateScenarioCounters()
        let environment = ReleaseUpdateInstallEnvironment(
            commandRunner: runner,
            extractArchive: { _, destinationURL in
                let destination = destinationURL.appendingPathComponent("Bastion.app", isDirectory: true)
                try? FileManager.default.removeItem(at: destination)
                try FileManager.default.copyItem(at: replacementURL, to: destination)
            },
            copyAppBundle: { sourceURL, destinationURL in
                try? FileManager.default.removeItem(at: destinationURL)
                try FileManager.default.copyItem(at: sourceURL, to: destinationURL)
            },
            verifyAppBundle: { _ in
                counters.recordAppVerification()
            },
            verifyRecoveredService: { _ in
                counters.recordServiceVerification()
            }
        )

        let installResult = try ReleaseUpdateInstaller.installStagedArtifact(
            manifest: loadedManifest,
            artifact: downloaded,
            installURL: installURL,
            backupDirectory: backupDir,
            relaunch: true,
            recoverService: true,
            installCLISymlink: true,
            verifyAppBundle: true,
            environment: environment
        )
        let installedIdentity = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        let counts = counters.snapshot()
        let commands = runner.commands()
        let commandExecutables = commands.map(\.executable)
        let backupCreated = installResult.backupAppPath.map { fileManager.fileExists(atPath: $0) } ?? false

        let snapshot = UpdateScenarioSnapshot(
            currentVersion: current.version,
            manifestVersion: loadedManifest.version,
            checkState: check.state.rawValue,
            downloadVerified: downloaded.sha256 == loadedManifest.sha256
                && downloaded.sizeBytes == loadedManifest.sizeBytes
                && fileManager.fileExists(atPath: downloaded.localPath),
            downloadedSizeBytes: downloaded.sizeBytes,
            installedVersion: installedIdentity.version,
            installedBuild: installedIdentity.build,
            backupCreated: backupCreated,
            serviceRecovered: installResult.serviceRecovered,
            relaunched: installResult.relaunched,
            cliSymlinkInstalled: installResult.cliSymlinkInstalled,
            rollbackPerformed: installResult.rollbackPerformed,
            appVerificationCalls: counts.appVerificationCount,
            serviceVerificationCalls: counts.serviceVerificationCount,
            commandExecutables: commandExecutables,
            commandSnapshots: commands
        )

        let checks = [
            SettingsScenarioProbeCheck(
                name: "manifest check finds newer notarized macOS update",
                passed: snapshot.currentVersion == "1.0"
                    && snapshot.manifestVersion == "1.1"
                    && snapshot.checkState == ReleaseUpdateState.updateAvailable.rawValue
            ),
            SettingsScenarioProbeCheck(
                name: "download verifies artifact hash and size",
                passed: snapshot.downloadVerified
                    && snapshot.downloadedSizeBytes == artifactData.count
            ),
            SettingsScenarioProbeCheck(
                name: "install replaces app and creates rollback backup",
                passed: snapshot.installedVersion == "1.1"
                    && snapshot.installedBuild == "2"
                    && snapshot.backupCreated
                    && !snapshot.rollbackPerformed
            ),
            SettingsScenarioProbeCheck(
                name: "install invokes app verification before and after replacement",
                passed: snapshot.appVerificationCalls == 2
            ),
            SettingsScenarioProbeCheck(
                name: "install runs service recovery, CLI symlink, and relaunch paths",
                passed: snapshot.serviceRecovered
                    && snapshot.relaunched
                    && snapshot.cliSymlinkInstalled
                    && snapshot.serviceVerificationCalls == 1
                    && commandExecutables.contains("/bin/launchctl")
                    && commandExecutables.contains("/bin/mkdir")
                    && commandExecutables.contains("/bin/ln")
                    && commandExecutables.contains("/usr/bin/open")
            ),
        ]

        return UpdateScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy(\.passed),
            update: snapshot,
            checks: checks
        )
    }

    private static func makeAppBundle(at url: URL, version: String, build: String) throws {
        let fileManager = FileManager.default
        let contents = url.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        try fileManager.createDirectory(at: macOS, withIntermediateDirectories: true)

        let info: [String: Any] = [
            "CFBundleIdentifier": ReleaseUpdateVerifier.expectedBundleIdentifier,
            "CFBundleShortVersionString": version,
            "CFBundleVersion": build,
            "CFBundleExecutable": "bastion",
        ]
        let infoData = try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
        try infoData.write(to: contents.appendingPathComponent("Info.plist"))

        try writeExecutable(macOS.appendingPathComponent("bastion"))
        try writeExecutable(macOS.appendingPathComponent("bastion-cli"))
    }

    private static func writeExecutable(_ url: URL) throws {
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    }

    private static func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}

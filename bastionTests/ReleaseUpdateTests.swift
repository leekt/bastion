import CryptoKit
import Darwin
import Foundation
import Testing
@testable import bastion

@Suite("Release update verifier")
struct ReleaseUpdateTests {

    @Test("newer notarized manifest is update available")
    func newerManifestIsAvailable() {
        let current = InstalledReleaseIdentity(
            bundleIdentifier: "com.bastion.app",
            version: "1.0",
            build: "1"
        )
        let manifest = makeManifest(version: "1.1", build: "2")

        let result = ReleaseUpdateVerifier.evaluate(
            manifest: manifest,
            current: current,
            currentOSVersion: OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)
        )

        #expect(result.state == .updateAvailable)
        #expect(result.reason.contains("1.1"))
    }

    @Test("same version and build is up to date")
    func sameVersionIsCurrent() {
        let current = InstalledReleaseIdentity(
            bundleIdentifier: "com.bastion.app",
            version: "1.0",
            build: "1"
        )
        let manifest = makeManifest(version: "1.0", build: "1")

        let result = ReleaseUpdateVerifier.evaluate(
            manifest: manifest,
            current: current,
            currentOSVersion: OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)
        )

        #expect(result.state == .upToDate)
    }

    @Test("currentIdentity reloads app bundle Info.plist after in-place replacement")
    func currentIdentityReloadsReplacedAppBundleInfo() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let appURL = directory.appendingPathComponent("Bastion.app", isDirectory: true)
        let replacementURL = directory.appendingPathComponent("Replacement.app", isDirectory: true)
        try makeAppBundle(at: appURL, version: "1.0", build: "1")
        try makeAppBundle(at: replacementURL, version: "1.1", build: "2")

        let before = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: appURL)
        try FileManager.default.removeItem(at: appURL)
        try FileManager.default.copyItem(at: replacementURL, to: appURL)
        let after = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: appURL)

        #expect(before.version == "1.0")
        #expect(before.build == "1")
        #expect(after.version == "1.1")
        #expect(after.build == "2")
    }

    @Test("manifest identity and stapling are fail-closed")
    func manifestIdentityFailsClosed() {
        let current = InstalledReleaseIdentity(
            bundleIdentifier: "com.bastion.app",
            version: "1.0",
            build: "1"
        )
        let wrongBundle = makeManifest(bundleIdentifier: "com.example.other", version: "1.1", build: "2")
        let unstapled = makeManifest(version: "1.1", build: "2", stapled: false)

        let wrongBundleResult = ReleaseUpdateVerifier.evaluate(
            manifest: wrongBundle,
            current: current,
            currentOSVersion: OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)
        )
        let unstapledResult = ReleaseUpdateVerifier.evaluate(
            manifest: unstapled,
            current: current,
            currentOSVersion: OperatingSystemVersion(majorVersion: 14, minorVersion: 0, patchVersion: 0)
        )

        #expect(wrongBundleResult.state == .rejected)
        #expect(unstapledResult.state == .rejected)
    }

    @Test("file URL download is copied and hash verified")
    func fileDownloadIsVerified() async throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let source = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        let bytes = Data("verified update zip".utf8)
        try bytes.write(to: source)

        let output = directory.appendingPathComponent("staged", isDirectory: true)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: source.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )

        let artifact = try await ReleaseUpdateVerifier.downloadAndVerify(
            manifest: manifest,
            outputDirectory: output
        )

        #expect(FileManager.default.fileExists(atPath: artifact.localPath))
        #expect(artifact.sha256 == sha256Hex(bytes))
        #expect(artifact.sizeBytes == bytes.count)
    }

    @Test("staged update install replaces app and keeps rollback backup")
    func stagedInstallReplacesAppAndKeepsBackup() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let installURL = directory.appendingPathComponent("Applications/Bastion.app", isDirectory: true)
        let extractedApp = directory.appendingPathComponent("Extracted/Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: extractedApp, version: "1.1", build: "2")

        let bytes = Data("verified staged update".utf8)
        let artifactURL = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        try bytes.write(to: artifactURL)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: artifactURL.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )
        let artifact = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)
        let runner = RecordingUpdateCommandRunner()

        let result = try ReleaseUpdateInstaller.installStagedArtifact(
            manifest: manifest,
            artifact: artifact,
            installURL: installURL,
            backupDirectory: directory.appendingPathComponent("Backups", isDirectory: true),
            relaunch: false,
            recoverService: true,
            installCLISymlink: false,
            verifyAppBundle: false,
            environment: testInstallEnvironment(extractedApp: extractedApp, runner: runner)
        )

        let installed = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        let backupPath = try #require(result.backupAppPath)
        let backup = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: URL(fileURLWithPath: backupPath))

        #expect(installed.version == "1.1")
        #expect(installed.build == "2")
        #expect(backup.version == "1.0")
        #expect(result.serviceRecovered == true)
        #expect(result.relaunched == false)
        #expect(runner.commands.contains { $0.contains("--register-service") })
        #expect(runner.commands.contains { $0.contains("launchctl kickstart") })
    }

    @Test("staged production install accepts bundled MCP without CLI")
    func stagedProductionInstallAcceptsBundledMCPWithoutCLI() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let installURL = directory.appendingPathComponent("Applications/Bastion.app", isDirectory: true)
        let extractedApp = directory.appendingPathComponent("Extracted/Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: extractedApp, version: "1.1", build: "2", includeCLI: false)

        let bytes = Data("verified staged production update without cli".utf8)
        let artifactURL = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        try bytes.write(to: artifactURL)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: artifactURL.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )
        let artifact = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)
        let runner = RecordingUpdateCommandRunner()

        let result = try ReleaseUpdateInstaller.installStagedArtifact(
            manifest: manifest,
            artifact: artifact,
            installURL: installURL,
            backupDirectory: directory.appendingPathComponent("Backups", isDirectory: true),
            relaunch: false,
            recoverService: false,
            installCLISymlink: true,
            verifyAppBundle: false,
            environment: testInstallEnvironment(extractedApp: extractedApp, runner: runner)
        )

        let installed = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        #expect(installed.version == "1.1")
        #expect(installed.build == "2")
        #expect(FileManager.default.isExecutableFile(
            atPath: installURL.appendingPathComponent("Contents/MacOS/bastion-mcp").path
        ) == true)
        #expect(FileManager.default.fileExists(
            atPath: installURL.appendingPathComponent("Contents/MacOS/bastion-cli").path
        ) == false)
        #expect(result.cliSymlinkInstalled == false)
        #expect(runner.commands.contains { $0.contains("/bin/ln -sf") } == false)
    }

    @Test("staged install rejects app bundle missing MCP")
    func stagedInstallRejectsAppBundleMissingMCP() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let installURL = directory.appendingPathComponent("Applications/Bastion.app", isDirectory: true)
        let extractedApp = directory.appendingPathComponent("Extracted/Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: extractedApp, version: "1.1", build: "2", includeMCP: false)

        let bytes = Data("verified staged update missing mcp".utf8)
        let artifactURL = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        try bytes.write(to: artifactURL)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: artifactURL.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )
        let artifact = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)
        let runner = RecordingUpdateCommandRunner()
        var sawMissingMCP = false

        do {
            _ = try ReleaseUpdateInstaller.installStagedArtifact(
                manifest: manifest,
                artifact: artifact,
                installURL: installURL,
                backupDirectory: directory.appendingPathComponent("Backups", isDirectory: true),
                relaunch: false,
                recoverService: false,
                installCLISymlink: false,
                verifyAppBundle: false,
                environment: testInstallEnvironment(extractedApp: extractedApp, runner: runner)
            )
            Issue.record("Expected missing bastion-mcp to reject the staged app")
        } catch let error as ReleaseUpdateInstallError {
            if case .appBundleInvalid(let reason) = error {
                sawMissingMCP = reason.contains("bastion-mcp executable missing")
            } else {
                Issue.record("Expected appBundleInvalid, got \(error)")
            }
        }

        let stillInstalled = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        #expect(sawMissingMCP == true)
        #expect(stillInstalled.version == "1.0")
        #expect(stillInstalled.build == "1")
    }

    @Test("failed service recovery rolls back to previous app")
    func failedServiceRecoveryRollsBack() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let installURL = directory.appendingPathComponent("Applications/Bastion.app", isDirectory: true)
        let extractedApp = directory.appendingPathComponent("Extracted/Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: extractedApp, version: "1.1", build: "2")

        let bytes = Data("verified staged update with rollback".utf8)
        let artifactURL = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        try bytes.write(to: artifactURL)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: artifactURL.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )
        let artifact = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)
        let runner = RecordingUpdateCommandRunner()
        var sawRollbackError = false

        do {
            _ = try ReleaseUpdateInstaller.installStagedArtifact(
                manifest: manifest,
                artifact: artifact,
                installURL: installURL,
                backupDirectory: directory.appendingPathComponent("Backups", isDirectory: true),
                relaunch: false,
                recoverService: true,
                installCLISymlink: false,
                verifyAppBundle: false,
                environment: testInstallEnvironment(
                    extractedApp: extractedApp,
                    runner: runner,
                    failServiceRecoveryForVersion: "1.1"
                )
            )
            Issue.record("Expected service recovery failure to throw")
        } catch let error as ReleaseUpdateInstallError {
            if case .installFailedAndRolledBack = error {
                sawRollbackError = true
            } else {
                Issue.record("Expected rollback error, got \(error)")
            }
        }

        let restored = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        #expect(sawRollbackError == true)
        #expect(restored.version == "1.0")
        #expect(restored.build == "1")
    }

    @Test("failed service kickstart rolls back to previous app")
    func failedServiceKickstartRollsBack() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let installURL = directory.appendingPathComponent("Applications/Bastion.app", isDirectory: true)
        let extractedApp = directory.appendingPathComponent("Extracted/Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: extractedApp, version: "1.1", build: "2")

        let bytes = Data("verified staged update with kickstart rollback".utf8)
        let artifactURL = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        try bytes.write(to: artifactURL)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: artifactURL.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )
        let artifact = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)
        let oneShotKickstartFailure = OneShotCommandFailure { executable, arguments in
            executable == "/bin/launchctl" && arguments.starts(with: ["kickstart", "-k"])
        }
        let runner = RecordingUpdateCommandRunner { executable, arguments in
            oneShotKickstartFailure.errorIfMatched(
                executable: executable,
                arguments: arguments,
                error: TestInstallError.commandFailed("kickstart denied")
            )
        }
        var rollbackReason: String?

        do {
            _ = try ReleaseUpdateInstaller.installStagedArtifact(
                manifest: manifest,
                artifact: artifact,
                installURL: installURL,
                backupDirectory: directory.appendingPathComponent("Backups", isDirectory: true),
                relaunch: false,
                recoverService: true,
                installCLISymlink: false,
                verifyAppBundle: false,
                environment: testInstallEnvironment(extractedApp: extractedApp, runner: runner)
            )
            Issue.record("Expected service kickstart failure to throw")
        } catch let error as ReleaseUpdateInstallError {
            if case .installFailedAndRolledBack(let reason) = error {
                rollbackReason = reason
            } else {
                Issue.record("Expected rollback error, got \(error)")
            }
        }

        let restored = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        #expect(restored.version == "1.0")
        #expect(restored.build == "1")
        #expect(rollbackReason?.contains("launchctl kickstart") == true)
        #expect(rollbackReason?.contains("kickstart denied") == true)
        #expect(runner.commands.filter { $0.contains("launchctl kickstart") }.count == 2)
    }

    @Test("failed CLI symlink install rolls back to previous app")
    func failedCLISymlinkInstallRollsBack() throws {
        let directory = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }

        let installURL = directory.appendingPathComponent("Applications/Bastion.app", isDirectory: true)
        let extractedApp = directory.appendingPathComponent("Extracted/Bastion.app", isDirectory: true)
        try makeAppBundle(at: installURL, version: "1.0", build: "1")
        try makeAppBundle(at: extractedApp, version: "1.1", build: "2")

        let bytes = Data("verified staged update with CLI symlink rollback".utf8)
        let artifactURL = directory.appendingPathComponent("Bastion-1.1-2-macOS.zip")
        try bytes.write(to: artifactURL)
        let manifest = makeManifest(
            version: "1.1",
            build: "2",
            downloadURL: artifactURL.absoluteString,
            sha256: sha256Hex(bytes),
            sizeBytes: bytes.count
        )
        let artifact = try ReleaseUpdateVerifier.verifyArtifact(at: artifactURL, manifest: manifest)
        let runner = RecordingUpdateCommandRunner { executable, _ in
            executable == "/bin/ln" ? TestInstallError.commandFailed("symlink denied") : nil
        }
        var sawRollbackError = false

        do {
            _ = try ReleaseUpdateInstaller.installStagedArtifact(
                manifest: manifest,
                artifact: artifact,
                installURL: installURL,
                backupDirectory: directory.appendingPathComponent("Backups", isDirectory: true),
                relaunch: false,
                recoverService: false,
                installCLISymlink: true,
                verifyAppBundle: false,
                environment: testInstallEnvironment(extractedApp: extractedApp, runner: runner)
            )
            Issue.record("Expected CLI symlink install failure to throw")
        } catch let error as ReleaseUpdateInstallError {
            if case .installFailedAndRolledBack(let reason) = error {
                sawRollbackError = true
                #expect(reason.contains("CLI symlink"))
            } else {
                Issue.record("Expected rollback error, got \(error)")
            }
        }

        let restored = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: installURL)
        #expect(sawRollbackError == true)
        #expect(restored.version == "1.0")
        #expect(restored.build == "1")
        #expect(runner.commands.contains { $0.contains("/bin/mkdir -p /usr/local/bin") })
        #expect(runner.commands.contains { $0.contains("/bin/ln -sf") })
    }

    @MainActor
    @Test("update monitor config uses env URL before defaults")
    func monitorConfigUsesEnvURLBeforeDefaults() throws {
        let defaults = temporaryDefaults()
        defaults.set("https://defaults.example/latest.json", forKey: ReleaseUpdateMonitor.manifestDefaultsKey)
        defaults.set(false, forKey: ReleaseUpdateMonitor.autoDownloadDefaultsKey)

        let config = try #require(ReleaseUpdateMonitor.resolvedConfiguration(
            environment: [
                ReleaseUpdateMonitor.manifestEnvironmentKey: " file:///tmp/latest.json ",
                ReleaseUpdateMonitor.autoDownloadEnvironmentKey: "true"
            ],
            defaults: defaults
        ))

        #expect(config.manifestURL.absoluteString == "file:///tmp/latest.json")
        #expect(config.shouldAutoDownload == true)
    }

    @MainActor
    @Test("update monitor config rejects missing or relative manifest URLs")
    func monitorConfigRejectsMissingOrRelativeURLs() throws {
        let defaults = temporaryDefaults()

        #expect(ReleaseUpdateMonitor.resolvedConfiguration(
            environment: [:],
            defaults: defaults
        ) == nil)
        #expect(ReleaseUpdateMonitor.configurationFailure(
            environment: [:],
            defaults: defaults
        ) == nil)

        defaults.set("relative/latest.json", forKey: ReleaseUpdateMonitor.manifestDefaultsKey)
        #expect(ReleaseUpdateMonitor.resolvedConfiguration(
            environment: [:],
            defaults: defaults
        ) == nil)
        let defaultsFailure = ReleaseUpdateMonitor.configurationFailure(
            environment: [:],
            defaults: defaults
        )
        #expect(defaultsFailure?.message == "Release update monitor not started: invalid manifest URL in \(ReleaseUpdateMonitor.manifestDefaultsKey)")
        #expect(defaultsFailure?.context["source"] == ReleaseUpdateMonitor.manifestDefaultsKey)
        #expect(defaultsFailure?.context["configuredValue"] == "relative/latest.json")
        #expect(defaultsFailure?.context["reason"] == "Manifest URL must be absolute and include a scheme")

        let envFailure = ReleaseUpdateMonitor.configurationFailure(
            environment: [ReleaseUpdateMonitor.manifestEnvironmentKey: "relative/latest.json?token=secret"],
            defaults: defaults
        )
        #expect(envFailure?.context["source"] == ReleaseUpdateMonitor.manifestEnvironmentKey)
        #expect(envFailure?.context["configuredValue"] == "<redacted-invalid-url>")

        let missingHostEnvironment = [ReleaseUpdateMonitor.manifestEnvironmentKey: "https:///latest.json?token=secret"]
        #expect(ReleaseUpdateMonitor.resolvedConfiguration(
            environment: missingHostEnvironment,
            defaults: defaults
        ) == nil)
        let missingHostFailure = ReleaseUpdateMonitor.configurationFailure(
            environment: missingHostEnvironment,
            defaults: defaults
        )
        #expect(missingHostFailure?.context["source"] == ReleaseUpdateMonitor.manifestEnvironmentKey)
        #expect(missingHostFailure?.context["reason"] == "HTTP(S) manifest URL must include a host")
        #expect(missingHostFailure?.context["configuredValue"]?.contains("secret") == false)

        let recorder = MonitorDiagnosticRecorder()
        ReleaseUpdateMonitor.shared.stop()
        ReleaseUpdateMonitor.shared.startIfConfigured(
            environment: [ReleaseUpdateMonitor.manifestEnvironmentKey: "relative/latest.json?token=secret"],
            defaults: defaults,
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )
        ReleaseUpdateMonitor.shared.stop()

        let entry = try #require(recorder.entries().first)
        #expect(entry.level == .warning)
        #expect(entry.category == .update)
        #expect(entry.event == "update_monitor_configuration_invalid")
        #expect(entry.message == envFailure?.message)
        #expect(entry.context["source"] == ReleaseUpdateMonitor.manifestEnvironmentKey)
        #expect(entry.context["configuredValue"] == "<redacted-invalid-url>")
    }

    @MainActor
    @Test("update monitor auto-download defaults to on and honors false env")
    func monitorConfigAutoDownloadDefaultsAndEnvOverride() throws {
        let defaults = temporaryDefaults()
        defaults.set("https://updates.example/latest.json", forKey: ReleaseUpdateMonitor.manifestDefaultsKey)

        let defaultOn = try #require(ReleaseUpdateMonitor.resolvedConfiguration(
            environment: [:],
            defaults: defaults
        ))
        #expect(defaultOn.shouldAutoDownload == true)

        let envFalse = try #require(ReleaseUpdateMonitor.resolvedConfiguration(
            environment: [ReleaseUpdateMonitor.autoDownloadEnvironmentKey: " false "],
            defaults: defaults
        ))
        #expect(envFalse.shouldAutoDownload == false)
    }

    @Test("update monitor schedule checks immediately then after daily interval")
    func monitorScheduleRunsImmediateAndDailyChecks() async {
        let recorder = MonitorScheduleRecorder(cancelOnSleepAttempt: 2)
        let config = ReleaseUpdateMonitor.Configuration(
            manifestURL: URL(string: "https://updates.example/latest.json")!,
            shouldAutoDownload: true
        )

        await ReleaseUpdateMonitor.runScheduledChecks(
            configuration: config,
            interval: ReleaseUpdateMonitor.checkInterval,
            sleep: { interval in
                try await recorder.sleep(interval)
            },
            check: { url, shouldAutoDownload in
                await recorder.check(url: url, shouldAutoDownload: shouldAutoDownload)
            }
        )

        let checks = await recorder.checks
        let intervals = await recorder.intervals
        #expect(checks.map(\.url) == [config.manifestURL, config.manifestURL])
        #expect(checks.map(\.shouldAutoDownload) == [true, true])
        #expect(intervals == [ReleaseUpdateMonitor.checkInterval, ReleaseUpdateMonitor.checkInterval])
    }

    @Test("update monitor schedule does not check again when sleep is cancelled")
    func monitorScheduleStopsWhenSleepIsCancelled() async {
        let recorder = MonitorScheduleRecorder(cancelOnSleepAttempt: 1)
        let config = ReleaseUpdateMonitor.Configuration(
            manifestURL: URL(string: "https://updates.example/latest.json")!,
            shouldAutoDownload: false
        )

        await ReleaseUpdateMonitor.runScheduledChecks(
            configuration: config,
            interval: ReleaseUpdateMonitor.checkInterval,
            sleep: { interval in
                try await recorder.sleep(interval)
            },
            check: { url, shouldAutoDownload in
                await recorder.check(url: url, shouldAutoDownload: shouldAutoDownload)
            }
        )

        let checks = await recorder.checks
        let intervals = await recorder.intervals
        #expect(checks.map(\.url) == [config.manifestURL])
        #expect(checks.map(\.shouldAutoDownload) == [false])
        #expect(intervals == [ReleaseUpdateMonitor.checkInterval])
    }

    @Test("update monitor single check records update and staged artifact")
    func monitorSingleCheckRecordsUpdateAndStagedArtifact() async {
        let manifestURL = URL(fileURLWithPath: "/tmp/bastion-latest.json")
        let current = InstalledReleaseIdentity(
            bundleIdentifier: "com.bastion.app",
            version: "1.0",
            build: "1"
        )
        let manifest = makeManifest(version: "1.1", build: "2")
        let artifact = ReleaseUpdateArtifact(
            localPath: "/tmp/Bastion-1.1-2.zip",
            sha256: manifest.sha256,
            sizeBytes: manifest.sizeBytes
        )
        let recorder = MonitorDiagnosticRecorder()
        let loadedURL = MonitorBox<URL>()
        let downloadedManifest = MonitorBox<ReleaseUpdateManifest>()

        await ReleaseUpdateMonitor.checkOnce(
            manifestURL: manifestURL,
            shouldAutoDownload: true,
            currentIdentity: { current },
            loadManifest: { url in
                loadedURL.set(url)
                return manifest
            },
            downloadAndVerify: { manifest in
                downloadedManifest.set(manifest)
                return artifact
            },
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )

        let entries = recorder.entries()
        #expect(loadedURL.value() == manifestURL)
        #expect(downloadedManifest.value() == manifest)
        #expect(entries.map(\.event) == ["update_check", "update_staged"])
        #expect(entries.first?.level == .info)
        #expect(entries.first?.context["state"] == ReleaseUpdateState.updateAvailable.rawValue)
        #expect(entries.first?.context["version"] == "1.1")
        #expect(entries.first?.context["manifestURL"] == "file:///tmp/bastion-latest.json")
        #expect(entries.first?.context["autoDownload"] == "true")
        #expect(entries.first?.context["stage"] == "evaluate_manifest")
        #expect(entries.last?.context["version"] == "1.1")
        #expect(entries.last?.context["build"] == "2")
        #expect(entries.last?.context["manifestURL"] == "file:///tmp/bastion-latest.json")
        #expect(entries.last?.context["autoDownload"] == "true")
        #expect(entries.last?.context["stage"] == "download_and_verify")
        #expect(entries.last?.context["path"] == artifact.localPath)
        #expect(entries.last?.context["sha256"] == artifact.sha256)
    }

    @Test("update monitor single check skips staging when auto-download is off")
    func monitorSingleCheckHonorsAutoDownloadOff() async {
        let current = InstalledReleaseIdentity(
            bundleIdentifier: "com.bastion.app",
            version: "1.0",
            build: "1"
        )
        let manifest = makeManifest(version: "1.1", build: "2")
        let recorder = MonitorDiagnosticRecorder()
        let downloadAttempted = MonitorBox<Bool>()

        await ReleaseUpdateMonitor.checkOnce(
            manifestURL: URL(fileURLWithPath: "/tmp/bastion-latest.json"),
            shouldAutoDownload: false,
            currentIdentity: { current },
            loadManifest: { _ in manifest },
            downloadAndVerify: { manifest in
                downloadAttempted.set(true)
                return ReleaseUpdateArtifact(
                    localPath: "/tmp/\(manifest.version).zip",
                    sha256: manifest.sha256,
                    sizeBytes: manifest.sizeBytes
                )
            },
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )

        let entries = recorder.entries()
        #expect(downloadAttempted.value() == nil)
        #expect(entries.map(\.event) == ["update_check"])
        #expect(entries.first?.context["state"] == ReleaseUpdateState.updateAvailable.rawValue)
    }

    @Test("update monitor single check records load failures")
    func monitorSingleCheckRecordsFailures() async throws {
        let recorder = MonitorDiagnosticRecorder()
        let manifestURL = URL(string: "https://user:secret@updates.example/latest.json?token=secret#fragment")!

        await ReleaseUpdateMonitor.checkOnce(
            manifestURL: manifestURL,
            shouldAutoDownload: true,
            currentIdentity: {
                InstalledReleaseIdentity(
                    bundleIdentifier: "com.bastion.app",
                    version: "1.0",
                    build: "1"
                )
            },
            loadManifest: { _ in throw ReleaseUpdateError.invalidManifest("fixture failure") },
            downloadAndVerify: { _ in
                Issue.record("download should not run after manifest load failure")
                return ReleaseUpdateArtifact(localPath: "", sha256: "", sizeBytes: 0)
            },
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )

        let entry = try #require(recorder.entries().first)
        #expect(entry.level == .warning)
        #expect(entry.category == .update)
        #expect(entry.event == "update_check_failed")
        #expect(entry.message.contains("fixture failure"))
        #expect(entry.context["manifestURL"] == "https://updates.example/latest.json")
        #expect(entry.context["autoDownload"] == "true")
        #expect(entry.context["stage"] == "load_manifest")
        #expect(entry.context["error"]?.contains("fixture failure") == true)
    }

    @Test("update monitor download failures record failed stage")
    func monitorDownloadFailuresRecordFailedStage() async throws {
        let current = InstalledReleaseIdentity(
            bundleIdentifier: "com.bastion.app",
            version: "1.0",
            build: "1"
        )
        let manifest = makeManifest(version: "1.1", build: "2")
        let recorder = MonitorDiagnosticRecorder()

        await ReleaseUpdateMonitor.checkOnce(
            manifestURL: URL(string: "https://updates.example/latest.json?download_token=secret")!,
            shouldAutoDownload: true,
            currentIdentity: { current },
            loadManifest: { _ in manifest },
            downloadAndVerify: { _ in throw ReleaseUpdateError.downloadFailed("fixture download failure") },
            recordDiagnostic: { level, category, event, message, context in
                recorder.record(
                    level: level,
                    category: category,
                    event: event,
                    message: message,
                    context: context
                )
            }
        )

        let entries = recorder.entries()
        #expect(entries.map(\.event) == ["update_check", "update_check_failed"])
        let failure = try #require(entries.last)
        #expect(failure.level == .warning)
        #expect(failure.category == .update)
        #expect(failure.message.contains("fixture download failure"))
        #expect(failure.context["manifestURL"] == "https://updates.example/latest.json")
        #expect(failure.context["autoDownload"] == "true")
        #expect(failure.context["stage"] == "download_and_verify")
        #expect(failure.context["error"]?.contains("fixture download failure") == true)
    }

    private func makeManifest(
        bundleIdentifier: String = "com.bastion.app",
        version: String,
        build: String,
        downloadURL: String = "https://example.com/Bastion.zip",
        sha256: String = String(repeating: "a", count: 64),
        sizeBytes: Int = 123,
        stapled: Bool = true
    ) -> ReleaseUpdateManifest {
        ReleaseUpdateManifest(
            app: "Bastion",
            bundleIdentifier: bundleIdentifier,
            version: version,
            build: build,
            platform: "macOS",
            minimumOSVersion: "11.0",
            publishedAt: "2026-06-03T00:00:00Z",
            downloadURL: downloadURL,
            releaseNotesURL: "",
            sha256: sha256,
            sizeBytes: sizeBytes,
            notarized: true,
            stapled: stapled
        )
    }

    private func sha256Hex(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private func makeAppBundle(
        at url: URL,
        version: String,
        build: String,
        includeCLI: Bool = true,
        includeMCP: Bool = true
    ) throws {
        let contents = url.appendingPathComponent("Contents", isDirectory: true)
        let macOS = contents.appendingPathComponent("MacOS", isDirectory: true)
        try FileManager.default.createDirectory(at: macOS, withIntermediateDirectories: true)

        let info: [String: Any] = [
            "CFBundleIdentifier": "com.bastion.app",
            "CFBundleName": "Bastion",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": build,
            "CFBundlePackageType": "APPL",
        ]
        let plistData = try PropertyListSerialization.data(
            fromPropertyList: info,
            format: .xml,
            options: 0
        )
        try plistData.write(to: contents.appendingPathComponent("Info.plist"))

        let appBinary = macOS.appendingPathComponent("bastion")
        try Data("#!/bin/sh\n".utf8).write(to: appBinary)
        chmod(appBinary.path, 0o755)
        if includeCLI {
            let cliBinary = macOS.appendingPathComponent("bastion-cli")
            try Data("#!/bin/sh\n".utf8).write(to: cliBinary)
            chmod(cliBinary.path, 0o755)
        }
        if includeMCP {
            let mcpBinary = macOS.appendingPathComponent("bastion-mcp")
            try Data("#!/bin/sh\n".utf8).write(to: mcpBinary)
            chmod(mcpBinary.path, 0o755)
        }
    }

    private func temporaryDefaults() -> UserDefaults {
        let suiteName = "bastion.release-update-tests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suiteName)!
        defaults.removePersistentDomain(forName: suiteName)
        return defaults
    }

    private func testInstallEnvironment(
        extractedApp: URL,
        runner: RecordingUpdateCommandRunner,
        failServiceRecoveryForVersion: String? = nil
    ) -> ReleaseUpdateInstallEnvironment {
        ReleaseUpdateInstallEnvironment(
            commandRunner: runner,
            extractArchive: { _, destination in
                let outputApp = destination.appendingPathComponent("Bastion.app", isDirectory: true)
                try FileManager.default.copyItem(at: extractedApp, to: outputApp)
            },
            copyAppBundle: { source, destination in
                try FileManager.default.copyItem(at: source, to: destination)
            },
            verifyAppBundle: { _ in },
            verifyRecoveredService: { appURL in
                let identity = try ReleaseUpdateVerifier.currentIdentity(appBundleURL: appURL)
                if identity.version == failServiceRecoveryForVersion {
                    throw TestInstallError.serviceRecoveryFailed
                }
            }
        )
    }

    private enum TestInstallError: Error, LocalizedError {
        case serviceRecoveryFailed
        case commandFailed(String)

        var errorDescription: String? {
            switch self {
            case .serviceRecoveryFailed:
                return "fixture service recovery failed"
            case .commandFailed(let message):
                return message
            }
        }
    }
}

private final class RecordingUpdateCommandRunner: ReleaseUpdateCommandRunning, @unchecked Sendable {
    private let lock = NSLock()
    private let failure: @Sendable (String, [String]) -> Error?
    private var storedCommands: [String] = []

    init(failure: @escaping @Sendable (String, [String]) -> Error? = { _, _ in nil }) {
        self.failure = failure
    }

    var commands: [String] {
        lock.withLock { storedCommands }
    }

    func run(_ executable: String, _ arguments: [String]) throws -> String {
        lock.withLock {
            storedCommands.append(([executable] + arguments).joined(separator: " "))
        }
        if let error = failure(executable, arguments) {
            throw error
        }
        return ""
    }
}

private final class OneShotCommandFailure: @unchecked Sendable {
    private let lock = NSLock()
    private let shouldFail: @Sendable (String, [String]) -> Bool
    private var hasFailed = false

    init(shouldFail: @escaping @Sendable (String, [String]) -> Bool) {
        self.shouldFail = shouldFail
    }

    func errorIfMatched(
        executable: String,
        arguments: [String],
        error: Error
    ) -> Error? {
        lock.withLock {
            guard !hasFailed, shouldFail(executable, arguments) else { return nil }
            hasFailed = true
            return error
        }
    }
}

private final class MonitorDiagnosticRecorder: @unchecked Sendable {
    private let lock = NSLock()
    private var recorded: [DiagnosticLogEntry] = []

    func record(
        level: DiagnosticLevel,
        category: DiagnosticCategory,
        event: String,
        message: String,
        context: [String: String]
    ) {
        lock.withLock {
            recorded.append(DiagnosticLogEntry(
                timestamp: "test",
                level: level,
                category: category,
                event: event,
                message: message,
                context: context
            ))
        }
    }

    func entries() -> [DiagnosticLogEntry] {
        lock.withLock { recorded }
    }
}

private final class MonitorBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Value?

    func set(_ value: Value) {
        lock.withLock {
            stored = value
        }
    }

    func value() -> Value? {
        lock.withLock { stored }
    }
}

private actor MonitorScheduleRecorder {
    struct Check: Equatable, Sendable {
        let url: URL
        let shouldAutoDownload: Bool
    }

    private let cancelOnSleepAttempt: Int
    private(set) var checks: [Check] = []
    private(set) var intervals: [Duration] = []

    init(cancelOnSleepAttempt: Int) {
        self.cancelOnSleepAttempt = cancelOnSleepAttempt
    }

    func check(url: URL, shouldAutoDownload: Bool) {
        checks.append(Check(url: url, shouldAutoDownload: shouldAutoDownload))
    }

    func sleep(_ interval: Duration) throws {
        intervals.append(interval)
        if intervals.count >= cancelOnSleepAttempt {
            throw CancellationError()
        }
    }
}

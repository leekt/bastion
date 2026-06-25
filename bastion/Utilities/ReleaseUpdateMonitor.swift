import Foundation

@MainActor
final class ReleaseUpdateMonitor {
    static let shared = ReleaseUpdateMonitor()

    private var task: Task<Void, Never>?
    static let manifestEnvironmentKey = "BASTION_UPDATE_MANIFEST_URL"
    static let autoDownloadEnvironmentKey = "BASTION_AUTO_DOWNLOAD_UPDATES"
    static let manifestDefaultsKey = "BastionUpdateManifestURL"
    static let autoDownloadDefaultsKey = "BastionAutoDownloadUpdates"
    nonisolated static let checkInterval: Duration = .seconds(24 * 60 * 60)
    typealias DiagnosticRecorder = @Sendable (
        DiagnosticLevel,
        DiagnosticCategory,
        String,
        String,
        [String: String]
    ) -> Void

    struct Configuration: Equatable {
        let manifestURL: URL
        let shouldAutoDownload: Bool
    }

    struct ConfigurationFailure: Equatable {
        let source: String
        let configuredValue: String
        let reason: String

        var message: String {
            "Release update monitor not started: invalid manifest URL in \(source)"
        }

        var context: [String: String] {
            [
                "source": source,
                "configuredValue": configuredValue,
                "reason": reason,
            ]
        }
    }

    private init() {}

    func startIfConfigured(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        defaults: UserDefaults = .standard,
        recordDiagnostic: @escaping DiagnosticRecorder = { level, category, event, message, context in
            DiagnosticLog.shared.record(
                level: level,
                category: category,
                event: event,
                message: message,
                context: context
            )
        }
    ) {
        guard task == nil else {
            return
        }

        guard let configuration = Self.resolvedConfiguration(environment: environment, defaults: defaults) else {
            if let failure = Self.configurationFailure(environment: environment, defaults: defaults) {
                recordDiagnostic(
                    .warning,
                    .update,
                    "update_monitor_configuration_invalid",
                    failure.message,
                    failure.context
                )
            }
            return
        }

        task = Task.detached(priority: .background) {
            await Self.runScheduledChecks(configuration: configuration)
        }
    }

    func stop() {
        task?.cancel()
        task = nil
    }

    static func resolvedConfiguration(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        defaults: UserDefaults = .standard
    ) -> Configuration? {
        guard let manifestURL = configuredManifestURL(environment: environment, defaults: defaults) else {
            return nil
        }
        return Configuration(
            manifestURL: manifestURL,
            shouldAutoDownload: configuredAutoDownload(environment: environment, defaults: defaults)
        )
    }

    private static func configuredManifestURL(
        environment: [String: String],
        defaults: UserDefaults
    ) -> URL? {
        guard let configured = configuredManifestURLValue(environment: environment, defaults: defaults),
              Self.configurationFailure(for: configured) == nil,
              let url = URL(string: configured.value) else {
            return nil
        }
        return url
    }

    static func configurationFailure(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        defaults: UserDefaults = .standard
    ) -> ConfigurationFailure? {
        guard let configured = configuredManifestURLValue(environment: environment, defaults: defaults) else { return nil }
        return configurationFailure(for: configured)
    }

    private static func configurationFailure(for configured: (source: String, value: String)) -> ConfigurationFailure? {
        let reason: String?
        if let url = URL(string: configured.value),
           let scheme = url.scheme?.lowercased(),
           !scheme.isEmpty {
            switch scheme {
            case "file":
                reason = url.path.isEmpty ? "File manifest URL must include a path" : nil
            case "http", "https":
                reason = (url.host?.isEmpty ?? true) ? "HTTP(S) manifest URL must include a host" : nil
            default:
                reason = "Manifest URL must use file, http, or https"
            }
        } else {
            reason = "Manifest URL must be absolute and include a scheme"
        }

        guard let reason else { return nil }
        return ConfigurationFailure(
            source: configured.source,
            configuredValue: redactedConfiguredManifestValue(configured.value),
            reason: reason
        )
    }

    private static func configuredManifestURLValue(
        environment: [String: String],
        defaults: UserDefaults
    ) -> (source: String, value: String)? {
        if let env = trimmedNonEmpty(environment[manifestEnvironmentKey]) {
            return (manifestEnvironmentKey, env)
        }
        if let configuredDefault = trimmedNonEmpty(defaults.string(forKey: manifestDefaultsKey)) {
            return (manifestDefaultsKey, configuredDefault)
        }
        return nil
    }

    nonisolated static func redactedConfiguredManifestValue(_ value: String) -> String {
        guard let url = URL(string: value),
              url.scheme?.isEmpty == false else {
            if value.contains("@") || value.contains("?") || value.contains("#") {
                return "<redacted-invalid-url>"
            }
            return value
        }
        return redactedManifestURL(url)
    }

    private static func configuredAutoDownload(
        environment: [String: String],
        defaults: UserDefaults
    ) -> Bool {
        if let env = trimmedNonEmpty(environment[autoDownloadEnvironmentKey]) {
            let normalized = env.lowercased()
            return normalized != "0" && normalized != "false"
        }
        if defaults.object(forKey: autoDownloadDefaultsKey) == nil {
            return true
        }
        return defaults.bool(forKey: autoDownloadDefaultsKey)
    }

    private static func trimmedNonEmpty(_ value: String?) -> String? {
        let trimmed = value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed?.isEmpty == false ? trimmed : nil
    }

    nonisolated static func redactedManifestURL(_ url: URL) -> String {
        guard var components = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return url.absoluteString
        }
        components.user = nil
        components.password = nil
        components.query = nil
        components.fragment = nil
        return components.string ?? url.absoluteString
    }

    nonisolated static func diagnosticContext(
        manifestURL: URL,
        shouldAutoDownload: Bool,
        stage: String
    ) -> [String: String] {
        [
            "manifestURL": redactedManifestURL(manifestURL),
            "autoDownload": String(shouldAutoDownload),
            "stage": stage,
        ]
    }

    nonisolated static func runScheduledChecks(configuration: Configuration) async {
        await runScheduledChecks(
            configuration: configuration,
            interval: checkInterval,
            sleep: { interval in
                try await Task.sleep(for: interval)
            },
            check: { manifestURL, shouldAutoDownload in
                await ReleaseUpdateMonitor.checkOnce(
                    manifestURL: manifestURL,
                    shouldAutoDownload: shouldAutoDownload
                )
            }
        )
    }

    nonisolated static func runScheduledChecks(
        configuration: Configuration,
        interval: Duration,
        sleep: @Sendable (Duration) async throws -> Void,
        check: @Sendable (URL, Bool) async -> Void
    ) async {
        await check(configuration.manifestURL, configuration.shouldAutoDownload)
        while !Task.isCancelled {
            do {
                try await sleep(interval)
            } catch {
                break
            }
            guard !Task.isCancelled else {
                break
            }
            await check(configuration.manifestURL, configuration.shouldAutoDownload)
        }
    }

    nonisolated static func checkOnce(
        manifestURL: URL,
        shouldAutoDownload: Bool,
        currentIdentity: @Sendable () throws -> InstalledReleaseIdentity = {
            try ReleaseUpdateVerifier.currentIdentity()
        },
        loadManifest: @Sendable (URL) async throws -> ReleaseUpdateManifest = {
            try await ReleaseUpdateVerifier.loadManifest(from: $0)
        },
        downloadAndVerify: @Sendable (ReleaseUpdateManifest) async throws -> ReleaseUpdateArtifact = {
            try await ReleaseUpdateVerifier.downloadAndVerify(manifest: $0)
        },
        recordDiagnostic: @Sendable (
            DiagnosticLevel,
            DiagnosticCategory,
            String,
            String,
            [String: String]
        ) -> Void = { level, category, event, message, context in
            DiagnosticLog.shared.record(
                level: level,
                category: category,
                event: event,
                message: message,
                context: context
            )
        }
    ) async {
        var stage = "current_identity"
        do {
            let current = try currentIdentity()
            stage = "load_manifest"
            let manifest = try await loadManifest(manifestURL)
            stage = "evaluate_manifest"
            let result = ReleaseUpdateVerifier.evaluate(manifest: manifest, current: current)
            var checkContext = diagnosticContext(
                manifestURL: manifestURL,
                shouldAutoDownload: shouldAutoDownload,
                stage: stage
            )
            checkContext["state"] = result.state.rawValue
            checkContext["version"] = manifest.version
            checkContext["build"] = manifest.build

            recordDiagnostic(
                result.state == .rejected ? .warning : .info,
                .update,
                "update_check",
                result.reason,
                checkContext
            )

            guard shouldAutoDownload, result.state == .updateAvailable else {
                return
            }

            stage = "download_and_verify"
            let artifact = try await downloadAndVerify(manifest)
            var stagedContext = diagnosticContext(
                manifestURL: manifestURL,
                shouldAutoDownload: shouldAutoDownload,
                stage: stage
            )
            stagedContext["version"] = manifest.version
            stagedContext["build"] = manifest.build
            stagedContext["path"] = artifact.localPath
            stagedContext["sha256"] = artifact.sha256
            stagedContext["sizeBytes"] = String(artifact.sizeBytes)
            recordDiagnostic(
                .info,
                .update,
                "update_staged",
                "Verified update artifact staged",
                stagedContext
            )
        } catch {
            var failureContext = diagnosticContext(
                manifestURL: manifestURL,
                shouldAutoDownload: shouldAutoDownload,
                stage: stage
            )
            failureContext["error"] = error.localizedDescription
            recordDiagnostic(.warning, .update, "update_check_failed", error.localizedDescription, failureContext)
        }
    }
}

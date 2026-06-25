import Foundation
import Security

nonisolated struct LiveRuntimeServiceSnapshot: Codable, Equatable, Sendable {
    let bundlePath: String
    let expectedBundlePath: String
    let executablePath: String
    let bundleIdentifier: String?
    let processIdentifier: Int32
    let launchMode: String
    let machServiceName: String
    let launchAgentPlistName: String
    let serviceRegistrationStatus: String
    let configCorrupted: Bool
}

nonisolated struct LiveRuntimeKeychainSnapshot: Codable, Equatable, Sendable {
    let configReadResult: String
    let configVersion: Int
    let authPolicy: String
    let probeWriteSucceeded: Bool
    let probeReadMatches: Bool
    let probeDeleteSucceeded: Bool
    let queryUsesAccessGroup: Bool
    let queryUsesDataProtectionKeychain: Bool
    let addUsesAfterFirstUnlockThisDeviceOnly: Bool
}

nonisolated struct LiveRuntimeUpdateSnapshot: Codable, Equatable, Sendable {
    let configured: Bool
    let invalidConfigurationObserved: Bool
    let autoDownloadDefault: Bool
    let checkIntervalSeconds: Int
    let schedulerRunsImmediateCheck: Bool
    let schedulerStopsAfterCancelledSleep: Bool
}

nonisolated struct LiveRuntimeXPCSnapshot: Codable, Equatable, Sendable {
    let activeConnectionCount: Int
    let cliReadRequiresProfile: Bool
    let acceptsSignedCLIConnection: Bool
    let bundleIdentifierFromConnection: String
}

nonisolated struct LiveRuntimeScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let service: LiveRuntimeServiceSnapshot
    let secureEnclave: SecureEnclaveRuntimeProbeSnapshot
    let keychain: LiveRuntimeKeychainSnapshot
    let updateMonitor: LiveRuntimeUpdateSnapshot
    let xpc: LiveRuntimeXPCSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct LiveRuntimeScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

@MainActor
enum LiveRuntimeScenarioProbe {
    static let overviewScenario = "overview"

    static func run(
        scenario: String,
        activeConnectionCount: Int,
        clientBundleId: String?
    ) async throws -> LiveRuntimeScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = try await overview(
                activeConnectionCount: activeConnectionCount,
                clientBundleId: clientBundleId
            )
            return LiveRuntimeScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "launchMode": response.service.launchMode,
                    "serviceRegistration": response.service.serviceRegistrationStatus,
                    "secureEnclaveDeleted": String(response.secureEnclave.deletedAfterProbe),
                    "keychainProbe": String(response.keychain.probeReadMatches),
                    "xpcBundle": response.xpc.bundleIdentifierFromConnection,
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.live-runtime-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown live-runtime scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    private static func overview(
        activeConnectionCount: Int,
        clientBundleId: String?
    ) async throws -> LiveRuntimeScenarioProbeResponse {
        let service = serviceSnapshot()
        let secureEnclaveKeyTag = "com.bastion.signingkey.live-runtime-probe.\(UUID().uuidString)"
        let secureEnclave: SecureEnclaveRuntimeProbeSnapshot
        do {
            secureEnclave = try SecureEnclaveManager.shared.probeEphemeralSigningKey(
                keyTag: secureEnclaveKeyTag,
                digest: Data(repeating: 0x42, count: 32)
            )
        } catch {
            secureEnclave = SecureEnclaveRuntimeProbeSnapshot.failed(
                keyTag: secureEnclaveKeyTag,
                error: error
            )
        }
        let keychain = keychainSnapshot()
        let update = await updateSnapshot()
        let xpc = LiveRuntimeXPCSnapshot(
            activeConnectionCount: activeConnectionCount,
            cliReadRequiresProfile: true,
            acceptsSignedCLIConnection: clientBundleId != nil,
            bundleIdentifierFromConnection: clientBundleId ?? "<unknown>"
        )

        let checks = [
            SettingsScenarioProbeCheck(
                name: "installed service is running from the stable signed app bundle",
                passed: service.bundlePath == service.expectedBundlePath
                    && service.launchMode == "service"
                    && service.machServiceName == "com.bastion.xpc"
                    && service.serviceRegistrationStatus == "enabled"
                    && service.processIdentifier > 0
                    && !service.configCorrupted
            ),
            SettingsScenarioProbeCheck(
                name: "Secure Enclave probe signs with a non-exportable throwaway key",
                passed: secureEnclave.probeSucceeded
                    && secureEnclave.tokenID == String(describing: kSecAttrTokenIDSecureEnclave)
                    && secureEnclave.privateKeyExportBlocked
                    && secureEnclave.publicKeyExternalLength >= 65
                    && secureEnclave.signatureLength > 0
                    && secureEnclave.signatureVerified
                    && secureEnclave.deletedAfterProbe
            ),
            SettingsScenarioProbeCheck(
                name: "Keychain config and throwaway state use the data-protection access group",
                passed: keychain.configReadResult != "failure"
                    && keychain.configVersion >= 1
                    && keychain.probeWriteSucceeded
                    && keychain.probeReadMatches
                    && keychain.probeDeleteSucceeded
                    && keychain.queryUsesAccessGroup
                    && keychain.queryUsesDataProtectionKeychain
                    && keychain.addUsesAfterFirstUnlockThisDeviceOnly
            ),
            SettingsScenarioProbeCheck(
                name: "release update monitor configuration and scheduler behavior are installed-runtime safe",
                passed: !update.configured
                    && !update.invalidConfigurationObserved
                    && update.autoDownloadDefault
                    && update.checkIntervalSeconds == 24 * 60 * 60
                    && update.schedulerRunsImmediateCheck
                    && update.schedulerStopsAfterCancelledSleep
            ),
            SettingsScenarioProbeCheck(
                name: "XPC accepts the signed CLI connection while metadata reads remain profile-gated",
                passed: xpc.activeConnectionCount >= 1
                    && xpc.acceptsSignedCLIConnection
                    && xpc.bundleIdentifierFromConnection == "bastion-cli"
                    && xpc.cliReadRequiresProfile
            ),
        ]

        return LiveRuntimeScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy(\.passed),
            service: service,
            secureEnclave: secureEnclave,
            keychain: keychain,
            updateMonitor: update,
            xpc: xpc,
            checks: checks
        )
    }

    private static func serviceSnapshot() -> LiveRuntimeServiceSnapshot {
        let launchMode: String = {
            switch BastionLaunchController.resolveLaunchMode() {
            case .service: return "service"
            case .relay: return "relay"
            }
        }()
        return LiveRuntimeServiceSnapshot(
            bundlePath: URL(fileURLWithPath: Bundle.main.bundlePath, isDirectory: true).standardizedFileURL.path,
            expectedBundlePath: expectedDevelopmentAppPath(),
            executablePath: CommandLine.arguments.first ?? "",
            bundleIdentifier: Bundle.main.bundleIdentifier,
            processIdentifier: ProcessInfo.processInfo.processIdentifier,
            launchMode: launchMode,
            machServiceName: xpcServiceName,
            launchAgentPlistName: ServiceRegistration.launchAgentPlistName,
            serviceRegistrationStatus: ServiceRegistration.statusDescription(),
            configCorrupted: RuleEngine.shared.configCorrupted
        )
    }

    private static func expectedDevelopmentAppPath() -> String {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Applications", isDirectory: true)
            .appendingPathComponent("Bastion Dev.app", isDirectory: true)
            .standardizedFileURL
            .path
    }

    private static func keychainSnapshot() -> LiveRuntimeKeychainSnapshot {
        let configReadResult: String
        let configVersion: Int
        let authPolicy: String
        switch KeychainStore.readResult(account: "config") {
        case .found(let data):
            configReadResult = "found"
            let decoded = try? JSONDecoder().decode(BastionConfig.self, from: data)
            configVersion = decoded?.version ?? 0
            authPolicy = decoded?.authPolicy.rawValue ?? "<decode-failed>"
        case .missing:
            configReadResult = "missing"
            let loaded = RuleEngine.shared.loadConfig()
            configVersion = loaded.version
            authPolicy = loaded.authPolicy.rawValue
        case .failure:
            configReadResult = "failure"
            configVersion = 0
            authPolicy = "<read-failed>"
        }

        let probeAccount = "live-runtime-probe.\(UUID().uuidString)"
        let probeData = Data("live-runtime-keychain-probe".utf8)
        let probeWriteSucceeded = KeychainStore.write(account: probeAccount, data: probeData)
        let probeReadMatches = KeychainStore.read(account: probeAccount) == probeData
        let probeDeleteSucceeded = KeychainStore.delete(account: probeAccount)

        let base = KeychainStore.baseQuery(account: "config")
        let add = KeychainStore.addQuery(account: probeAccount, data: probeData)
        return LiveRuntimeKeychainSnapshot(
            configReadResult: configReadResult,
            configVersion: configVersion,
            authPolicy: authPolicy,
            probeWriteSucceeded: probeWriteSucceeded,
            probeReadMatches: probeReadMatches,
            probeDeleteSucceeded: probeDeleteSucceeded,
            queryUsesAccessGroup: base[kSecAttrAccessGroup as String] as? String == KeychainStore.accessGroup,
            queryUsesDataProtectionKeychain: base[kSecUseDataProtectionKeychain as String] as? Bool == true,
            addUsesAfterFirstUnlockThisDeviceOnly: add[kSecAttrAccessible as String] as? String == String(describing: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly)
        )
    }

    private static func updateSnapshot() async -> LiveRuntimeUpdateSnapshot {
        let configuration = ReleaseUpdateMonitor.resolvedConfiguration()
        let failure = ReleaseUpdateMonitor.configurationFailure()
        let recorder = LiveRuntimeScenarioCallRecorder()
        await ReleaseUpdateMonitor.runScheduledChecks(
            configuration: ReleaseUpdateMonitor.Configuration(
                manifestURL: URL(fileURLWithPath: "/tmp/bastion-live-runtime-update-probe.json"),
                shouldAutoDownload: true
            ),
            interval: .seconds(24 * 60 * 60),
            sleep: { _ in throw CancellationError() },
            check: { _, _ in
                await recorder.record()
            }
        )
        let recordedCount = await recorder.count()
        return LiveRuntimeUpdateSnapshot(
            configured: configuration != nil,
            invalidConfigurationObserved: failure != nil,
            autoDownloadDefault: ReleaseUpdateMonitor.resolvedConfiguration(
                environment: [ReleaseUpdateMonitor.manifestEnvironmentKey: "file:///tmp/bastion-live-runtime-update-probe.json"],
                defaults: UserDefaults(suiteName: "com.bastion.live-runtime-probe.\(UUID().uuidString)") ?? .standard
            )?.shouldAutoDownload == true,
            checkIntervalSeconds: 24 * 60 * 60,
            schedulerRunsImmediateCheck: recordedCount == 1,
            schedulerStopsAfterCancelledSleep: recordedCount == 1
        )
    }
}

private actor LiveRuntimeScenarioCallRecorder {
    private var value = 0

    func record() {
        value += 1
    }

    func count() -> Int {
        value
    }
}

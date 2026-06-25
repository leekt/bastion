import AppKit
import Foundation

nonisolated struct RuntimeStateSilentBannerSnapshot: Codable, Equatable, Sendable {
    let minimumWidth: Double
    let widenedWidth: Double
    let styleContainsBorderless: Bool
    let styleContainsNonactivatingPanel: Bool
    let styleContainsFullSizeContentView: Bool
    let levelRawValue: Int
    let collectionMovesToActiveSpace: Bool
    let collectionFullScreenAuxiliary: Bool
    let syntheticOriginX: Double
    let syntheticOriginY: Double
    let autoDismissDelay: Double?
    let autoDismissesAfterDelay: Bool
    let cancelPreventsDismiss: Bool
    let runtimePanelCountAfterFirstShow: Int
    let runtimePanelCountAfterReplacement: Int
    let runtimePanelCountAfterDismiss: Int
    let auditHistoryOpened: Bool
    let auditHistoryMatchedTitle: String?
}

nonisolated struct RuntimeStateSpendingSnapshot: Codable, Equatable, Sendable {
    let token: String
    let allowance: String
    let spent: String
    let remaining: String
    let windowSeconds: Int?
    let windowResetsAt: String?
    let expectedWindowResetsAt: String
    let lifetimeSpent: String
    let lifetimeRemaining: String
    let lifetimeWindowResetsAt: String?
}

nonisolated struct RuntimeStateBundlerSnapshot: Codable, Equatable, Sendable {
    let configuredOverrideProjectId: String
    let configuredOverrideSource: String
    let matchedProjectId: String
    let matchedSource: String
    let requestFallbackProjectId: String
    let requestFallbackSource: String
    let missingProjectThrows: Bool
}

nonisolated struct RuntimeStatePendingSubmissionSnapshot: Codable, Equatable, Sendable {
    let activeOrder: [String]
    let activeOrderAfterFinish: [String]
    let sectionTitle: String
    let auditButtonTitle: String
    let firstClientDisplayName: String
    let firstProvider: String
    let firstChainId: Int
    let firstStatusLabel: String
    let firstUserOpHashShort: String
    let firstRowHelp: String
    let pollDelayNanoseconds: UInt64?
    let pollContinuesAfterDelay: Bool
    let pollCancelStops: Bool
}

nonisolated struct RuntimeStateScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let silentBanner: RuntimeStateSilentBannerSnapshot
    let spending: RuntimeStateSpendingSnapshot
    let bundler: RuntimeStateBundlerSnapshot
    let pendingSubmission: RuntimeStatePendingSubmissionSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct RuntimeStateScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

private final class RuntimeStateScenarioMemoryKeychain: KeychainBackend, @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.bastion.runtime-state-scenario-memory-keychain")
    private var storage: [String: Data] = [:]

    func read(account: String) -> Data? {
        queue.sync { storage[account] }
    }

    func readResult(account: String) -> KeychainReadResult {
        queue.sync {
            if let data = storage[account] {
                return .found(data)
            }
            return .missing
        }
    }

    @discardableResult
    func write(account: String, data: Data) -> Bool {
        queue.sync {
            storage[account] = data
            return true
        }
    }

    @discardableResult
    func delete(account: String) -> Bool {
        queue.sync {
            storage.removeValue(forKey: account) != nil
        }
    }
}

private actor RuntimeStateScenarioDelayRecorder<Value: Sendable> {
    private var values: [Value] = []

    func record(_ value: Value) {
        values.append(value)
    }

    func snapshot() -> [Value] {
        values
    }
}

@MainActor
enum RuntimeStateScenarioProbe {
    static let overviewScenario = "overview"

    static func run(scenario: String) async throws -> RuntimeStateScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = await overview()
            return RuntimeStateScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "silentPanelReplacementCount": String(response.silentBanner.runtimePanelCountAfterReplacement),
                    "windowResetsAt": response.spending.windowResetsAt ?? "<nil>",
                    "bundlerOverrideSource": response.bundler.configuredOverrideSource,
                    "pendingActiveCount": String(response.pendingSubmission.activeOrder.count),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.runtime-state-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown runtime-state scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    static func overview() async -> RuntimeStateScenarioProbeResponse {
        let silent = await silentBanner()
        let spending = spendingLimit()
        let bundler = bundlerTrust()
        let pending = await pendingSubmission()

        let checks = [
            SettingsScenarioProbeCheck(
                name: "silent receipt presentation uses nonactivating top-right status panel",
                passed: silent.minimumWidth == 320
                    && silent.widenedWidth == 360
                    && silent.styleContainsBorderless
                    && silent.styleContainsNonactivatingPanel
                    && silent.styleContainsFullSizeContentView
                    && silent.levelRawValue == NSWindow.Level.statusBar.rawValue
                    && silent.collectionMovesToActiveSpace
                    && silent.collectionFullScreenAuxiliary
                    && silent.syntheticOriginX == 964
                    && silent.syntheticOriginY == 766
            ),
            SettingsScenarioProbeCheck(
                name: "silent receipt runtime show replaces existing panel and dismisses cleanly",
                passed: silent.runtimePanelCountAfterFirstShow == 1
                    && silent.runtimePanelCountAfterReplacement == 1
                    && silent.runtimePanelCountAfterDismiss == 0
            ),
            SettingsScenarioProbeCheck(
                name: "silent receipt auto-dismiss waits and cancellation prevents dismissal",
                passed: silent.autoDismissesAfterDelay
                    && silent.cancelPreventsDismiss
                    && silent.autoDismissDelay == 4
            ),
            SettingsScenarioProbeCheck(
                name: "silent receipt audit route opens Audit History in signed service",
                passed: silent.auditHistoryOpened
                    && silent.auditHistoryMatchedTitle == "Audit History"
            ),
            SettingsScenarioProbeCheck(
                name: "windowed spending status reports reset timestamp from oldest active spend",
                passed: spending.token == "USDC"
                    && spending.allowance == "1000000"
                    && spending.spent == "400000"
                    && spending.remaining == "600000"
                    && spending.windowSeconds == 3600
                    && spending.windowResetsAt == spending.expectedWindowResetsAt
            ),
            SettingsScenarioProbeCheck(
                name: "lifetime spending status has no reset timestamp",
                passed: spending.lifetimeSpent == "400000000000000000"
                    && spending.lifetimeRemaining == "600000000000000000"
                    && spending.lifetimeWindowResetsAt == nil
            ),
            SettingsScenarioProbeCheck(
                name: "bundler project id trust precedence is auditable",
                passed: bundler.configuredOverrideProjectId == "configured-project"
                    && bundler.configuredOverrideSource == ResolvedBundler.Source.configOverrodeRequest.rawValue
                    && bundler.matchedProjectId == "configured-project"
                    && bundler.matchedSource == ResolvedBundler.Source.configMatchedRequest.rawValue
                    && bundler.requestFallbackProjectId == "wire-project"
                    && bundler.requestFallbackSource == ResolvedBundler.Source.requestFallback.rawValue
                    && bundler.missingProjectThrows
            ),
            SettingsScenarioProbeCheck(
                name: "pending user operations sort newest first, clear by request, and feed menu presentation",
                passed: pending.activeOrder == ["newer", "older"]
                    && pending.activeOrderAfterFinish == ["older"]
                    && pending.sectionTitle == "Pending confirmations"
                    && pending.auditButtonTitle == "Audit"
                    && pending.firstClientDisplayName == "Bundler Agent"
                    && pending.firstProvider == "ZeroDev"
                    && pending.firstChainId == 8453
                    && pending.firstStatusLabel == "Awaiting receipt"
                    && pending.firstUserOpHashShort == "0x12345678…abcdef"
                    && pending.firstRowHelp.contains("Client: Bundler Agent")
                    && pending.firstRowHelp.contains("Provider: ZeroDev")
                    && pending.firstRowHelp.contains("Chain: 8453")
            ),
            SettingsScenarioProbeCheck(
                name: "receipt polling delay continues after sleep and stops on cancellation",
                passed: pending.pollDelayNanoseconds == 123
                    && pending.pollContinuesAfterDelay
                    && pending.pollCancelStops
            ),
        ]

        return RuntimeStateScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy(\.passed),
            silentBanner: silent,
            spending: spending,
            bundler: bundler,
            pendingSubmission: pending,
            checks: checks
        )
    }

    private static func silentBanner() async -> RuntimeStateSilentBannerSnapshot {
        let successRecorder = RuntimeStateScenarioDelayRecorder<TimeInterval>()
        let autoDismisses = await SilentBannerPresentation.shouldAutoDismissAfterDelay(
            duration: 4,
            sleep: { duration in
                await successRecorder.record(duration)
            }
        )
        let cancelRecorder = RuntimeStateScenarioDelayRecorder<TimeInterval>()
        let cancelDismiss = await SilentBannerPresentation.shouldAutoDismissAfterDelay(
            duration: 2,
            sleep: { duration in
                await cancelRecorder.record(duration)
                throw CancellationError()
            }
        )
        let successDurations = await successRecorder.snapshot()
        let cancelDurations = await cancelRecorder.snapshot()

        let before = silentPanelCount()
        SilentBannerManager.shared.show(
            title: "Signed",
            subtitle: "Runtime probe receipt",
            duration: 60
        )
        let afterFirst = max(0, silentPanelCount() - before)
        SilentBannerManager.shared.show(
            title: "Signed again",
            subtitle: "Runtime probe replacement",
            duration: 60
        )
        let afterReplacement = max(0, silentPanelCount() - before)
        SilentBannerManager.shared.dismiss()
        let afterDismiss = max(0, silentPanelCount() - before)

        let auditProbe = await ServiceUIBridge.probeInCurrentProcess(.auditHistory)

        let origin = SilentBannerPresentation.panelOrigin(
            visibleFrame: NSRect(x: 100, y: 50, width: 1_200, height: 800),
            panelSize: NSSize(width: 320, height: 72)
        )

        return RuntimeStateSilentBannerSnapshot(
            minimumWidth: Double(SilentBannerPresentation.panelWidth(fittingWidth: 280)),
            widenedWidth: Double(SilentBannerPresentation.panelWidth(fittingWidth: 360)),
            styleContainsBorderless: SilentBannerPresentation.styleMask.contains(.borderless),
            styleContainsNonactivatingPanel: SilentBannerPresentation.styleMask.contains(.nonactivatingPanel),
            styleContainsFullSizeContentView: SilentBannerPresentation.styleMask.contains(.fullSizeContentView),
            levelRawValue: SilentBannerPresentation.level.rawValue,
            collectionMovesToActiveSpace: SilentBannerPresentation.collectionBehavior.contains(.moveToActiveSpace),
            collectionFullScreenAuxiliary: SilentBannerPresentation.collectionBehavior.contains(.fullScreenAuxiliary),
            syntheticOriginX: origin.x,
            syntheticOriginY: origin.y,
            autoDismissDelay: successDurations.first,
            autoDismissesAfterDelay: autoDismisses,
            cancelPreventsDismiss: !cancelDismiss && cancelDurations == [2],
            runtimePanelCountAfterFirstShow: afterFirst,
            runtimePanelCountAfterReplacement: afterReplacement,
            runtimePanelCountAfterDismiss: afterDismiss,
            auditHistoryOpened: auditProbe.opened,
            auditHistoryMatchedTitle: auditProbe.matchedWindowTitle
        )
    }

    private static func silentPanelCount() -> Int {
        NSApplication.shared.windows.filter { window in
            window is NSPanel
                && window.isVisible
                && window.styleMask.contains(.borderless)
                && window.styleMask.contains(.nonactivatingPanel)
                && window.styleMask.contains(.fullSizeContentView)
                && window.level == .statusBar
                && !window.isOpaque
                && window.backgroundColor?.alphaComponent == 0
                && window.collectionBehavior.contains(.moveToActiveSpace)
                && window.collectionBehavior.contains(.fullScreenAuxiliary)
        }.count
    }

    private static func spendingLimit() -> RuntimeStateSpendingSnapshot {
        let keychain = RuntimeStateScenarioMemoryKeychain()
        let store = StateStore(keychain: keychain)
        let now = Date().timeIntervalSince1970
        let oldestActive = now - 1_200
        let newestActive = now - 60
        let expired = now - 7_200
        let rule = SpendingLimitRule(
            id: "runtime-window-usdc",
            token: .usdc,
            allowance: "1000000",
            windowSeconds: 3_600
        )
        let state = SpendingWindowState(entries: [
            SpendEntry(timestamp: oldestActive, amount: "250000"),
            SpendEntry(timestamp: newestActive, amount: "150000"),
            SpendEntry(timestamp: expired, amount: "999999"),
        ])
        let data = (try? JSONEncoder().encode(state)) ?? Data()
        keychain.write(account: "state.spending.\(rule.id)", data: data)

        let status = store.spendingLimitStatus(rule: rule)
        let expectedReset = StateStore.iso8601String(Date(timeIntervalSince1970: oldestActive + 3_600))

        let lifetimeRule = SpendingLimitRule(
            id: "runtime-lifetime-eth",
            token: .eth,
            allowance: "1000000000000000000",
            windowSeconds: nil
        )
        store.recordSpend(
            ruleId: lifetimeRule.id,
            amount: "400000000000000000",
            windowSeconds: nil
        )
        let lifetimeStatus = store.spendingLimitStatus(rule: lifetimeRule)

        return RuntimeStateSpendingSnapshot(
            token: status.token,
            allowance: status.allowance,
            spent: status.spent,
            remaining: status.remaining,
            windowSeconds: status.windowSeconds,
            windowResetsAt: status.windowResetsAt,
            expectedWindowResetsAt: expectedReset,
            lifetimeSpent: lifetimeStatus.spent,
            lifetimeRemaining: lifetimeStatus.remaining,
            lifetimeWindowResetsAt: lifetimeStatus.windowResetsAt
        )
    }

    private static func bundlerTrust() -> RuntimeStateBundlerSnapshot {
        var configured = BastionConfig.default
        configured.bundlerPreferences.zeroDevProjectId = "configured-project"
        let overridden = try? BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "wire-project",
            config: configured
        )
        let matched = try? BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "configured-project",
            config: configured
        )

        var fallbackConfig = BastionConfig.default
        fallbackConfig.bundlerPreferences.zeroDevProjectId = "  "
        let fallback = try? BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: " wire-project ",
            config: fallbackConfig
        )

        let missingThrows: Bool
        do {
            _ = try BundlerTrustResolver.resolveZeroDevProjectId(
                wireSupplied: " ",
                config: fallbackConfig
            )
            missingThrows = false
        } catch {
            missingThrows = true
        }

        return RuntimeStateBundlerSnapshot(
            configuredOverrideProjectId: overridden?.projectId ?? "",
            configuredOverrideSource: overridden?.source.rawValue ?? "",
            matchedProjectId: matched?.projectId ?? "",
            matchedSource: matched?.source.rawValue ?? "",
            requestFallbackProjectId: fallback?.projectId ?? "",
            requestFallbackSource: fallback?.source.rawValue ?? "",
            missingProjectThrows: missingThrows
        )
    }

    private static func pendingSubmission() async -> RuntimeStatePendingSubmissionSnapshot {
        let store = SubmissionStatusStore()
        let olderDate = Date(timeIntervalSince1970: 100)
        let newerDate = Date(timeIntervalSince1970: 200)
        store.markSubmitted(
            requestID: "older",
            clientDisplayName: "Legacy Agent",
            provider: "ZeroDev",
            chainId: 11155111,
            userOpHash: "0xolder",
            submittedAt: olderDate
        )
        store.markSubmitted(
            requestID: "newer",
            clientDisplayName: "Bundler Agent",
            provider: "ZeroDev",
            chainId: 8453,
            userOpHash: "0x1234567890abcdef1234567890abcdef",
            submittedAt: newerDate
        )
        let active = store.active()
        let presentation = MenuBarPendingSubmissionsPresentation.make(active)
        store.markFinished(requestID: "newer")
        let afterFinish = store.active()

        let pollSuccessRecorder = RuntimeStateScenarioDelayRecorder<UInt64>()
        let pollContinues = await SigningManager.shouldContinueUserOpReceiptPollingAfterDelay(
            intervalNanoseconds: 123,
            sleep: { nanoseconds in
                await pollSuccessRecorder.record(nanoseconds)
            }
        )
        let pollCancelRecorder = RuntimeStateScenarioDelayRecorder<UInt64>()
        let pollCancelStops = await SigningManager.shouldContinueUserOpReceiptPollingAfterDelay(
            intervalNanoseconds: 456,
            sleep: { nanoseconds in
                await pollCancelRecorder.record(nanoseconds)
                throw CancellationError()
            }
        )
        let pollSuccessDurations = await pollSuccessRecorder.snapshot()
        let pollCancelDurations = await pollCancelRecorder.snapshot()

        let row = presentation.rows.first
        return RuntimeStatePendingSubmissionSnapshot(
            activeOrder: active.map(\.requestID),
            activeOrderAfterFinish: afterFinish.map(\.requestID),
            sectionTitle: presentation.sectionTitle,
            auditButtonTitle: presentation.auditButtonTitle,
            firstClientDisplayName: row?.clientDisplayName ?? "",
            firstProvider: row?.provider ?? "",
            firstChainId: row?.chainId ?? 0,
            firstStatusLabel: row?.statusLabel ?? "",
            firstUserOpHashShort: row?.userOpHashShort ?? "",
            firstRowHelp: row?.rowHelp ?? "",
            pollDelayNanoseconds: pollSuccessDurations.first,
            pollContinuesAfterDelay: pollContinues,
            pollCancelStops: !pollCancelStops && pollCancelDurations == [456]
        )
    }
}

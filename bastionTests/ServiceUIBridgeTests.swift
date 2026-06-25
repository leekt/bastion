import Foundation
import Testing
@testable import bastion

@Suite("Service UI routing and reconnect")
struct ServiceUIBridgeTests {
    @Test("Notification click opens Audit History locally when handled by the service")
    func notificationClickOpensAuditHistoryInServiceProcess() {
        #expect(
            ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: true)
                == .openInCurrentProcess(.auditHistory)
        )
    }

    @Test("Notification click relays Audit History open when handled outside the service")
    func notificationClickRelaysAuditHistoryOutsideServiceProcess() {
        #expect(
            ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: false)
                == .requestServiceOpen(.auditHistory)
        )
    }

    @Test("Relay launches always request the registered service")
    func relayLaunchRequestsRegisteredService() {
        #expect(ServiceUIRoutePlanner.relayLaunchRoute(target: .settings) == .requestServiceOpen(.settings))
        #expect(ServiceUIRoutePlanner.relayLaunchRoute(target: .auditHistory) == .requestServiceOpen(.auditHistory))
        #expect(ServiceUIRoutePlanner.relayLaunchRoute(target: .diagnostics) == .requestServiceOpen(.diagnostics))
    }

    @Test("UI probe matching and response encoding are stable")
    func uiProbeMatchingAndEncoding() throws {
        let auditWindow = ServiceUIWindowSnapshot(
            title: "Audit History",
            className: "NSWindow",
            isVisible: true,
            isKeyWindow: true,
            isMainWindow: true,
            isPanel: false,
            isFloatingPanel: false,
            isTitled: true,
            isClosable: true,
            isFullSizeContentView: false,
            isBorderless: false,
            isNonactivatingPanel: false,
            isOpaque: true,
            hasShadow: true,
            backgroundAlpha: 1,
            hasContentView: true,
            contentViewClassName: "NSHostingView<AuditHistoryView>",
            frame: ServiceUIWindowFrame(x: 10, y: 20, width: 1180, height: 760)
        )
        let settingsWindow = ServiceUIWindowSnapshot(
            title: "Settings",
            className: "NSWindow",
            isVisible: true,
            isKeyWindow: false,
            isMainWindow: false,
            isPanel: false,
            isFloatingPanel: false,
            isTitled: true,
            isClosable: true,
            isFullSizeContentView: false,
            isBorderless: false,
            isNonactivatingPanel: false,
            isOpaque: true,
            hasShadow: true,
            backgroundAlpha: 1,
            hasContentView: true,
            contentViewClassName: "NSHostingView<RulesSettingsView>",
            frame: ServiceUIWindowFrame(x: 10, y: 20, width: 1180, height: 760)
        )
        let hiddenDiagnostics = ServiceUIWindowSnapshot(
            title: "Diagnostics",
            className: "NSWindow",
            isVisible: false,
            isKeyWindow: false,
            isMainWindow: false,
            isPanel: false,
            isFloatingPanel: false,
            isTitled: true,
            isClosable: true,
            isFullSizeContentView: false,
            isBorderless: false,
            isNonactivatingPanel: false,
            isOpaque: true,
            hasShadow: true,
            backgroundAlpha: 1,
            hasContentView: true,
            contentViewClassName: "NSHostingView<DiagnosticsSupportView>",
            frame: ServiceUIWindowFrame(x: 0, y: 0, width: 980, height: 680)
        )
        let approvalPanel = ServiceUIWindowSnapshot(
            title: "Bastion Approval",
            className: "NSPanel",
            isVisible: true,
            isKeyWindow: true,
            isMainWindow: true,
            isPanel: true,
            isFloatingPanel: true,
            isTitled: false,
            isClosable: false,
            isFullSizeContentView: false,
            isBorderless: true,
            isNonactivatingPanel: true,
            isOpaque: false,
            hasShadow: false,
            backgroundAlpha: 0,
            hasContentView: true,
            contentViewClassName: "NSHostingView<SigningRequestView>",
            frame: ServiceUIWindowFrame(x: 10, y: 20, width: 420, height: 640)
        )
        let nestedNativeApproval = ServiceUIWindowSnapshot(
            title: "Bastion Approval",
            className: "NSPanel",
            isVisible: true,
            isKeyWindow: true,
            isMainWindow: true,
            isPanel: true,
            isFloatingPanel: true,
            isTitled: true,
            isClosable: true,
            isFullSizeContentView: true,
            isBorderless: false,
            isNonactivatingPanel: false,
            isOpaque: true,
            hasShadow: true,
            backgroundAlpha: 1,
            hasContentView: true,
            contentViewClassName: "NSHostingView<SigningRequestView>",
            frame: ServiceUIWindowFrame(x: 10, y: 20, width: 520, height: 740)
        )

        #expect(ServiceUIProbeMatcher.matches(target: .auditHistory, snapshot: auditWindow))
        #expect(ServiceUIProbeMatcher.matches(target: .settings, snapshot: settingsWindow))
        #expect(!ServiceUIProbeMatcher.matches(target: .diagnostics, snapshot: hiddenDiagnostics))
        #expect(ServiceUIProbeMatcher.isBorderlessChrome(styleMask: [.borderless, .nonactivatingPanel]))
        #expect(!ServiceUIProbeMatcher.isBorderlessChrome(styleMask: [.titled, .closable]))
        #expect(ServiceUIProbeMatcher.matches(target: .approvalPolicy, snapshot: approvalPanel))
        #expect(ServiceUIProbeMatcher.matches(target: .approvalViolation, snapshot: approvalPanel))
        #expect(!ServiceUIProbeMatcher.matches(target: .approvalPolicy, snapshot: nestedNativeApproval))

        let response = ServiceUIProbeResponse(
            target: ServiceUITarget.auditHistory.rawValue,
            opened: true,
            matchedWindowTitle: auditWindow.title,
            visibleNonTargetWindowTitles: [],
            windows: [auditWindow, hiddenDiagnostics]
        )
        let data = try JSONEncoder().encode(response)
        let decoded = try JSONDecoder().decode(ServiceUIProbeResponse.self, from: data)
        #expect(decoded == response)
    }

    @Test("Service UI bridge retries until a restarted service accepts the request")
    func requestOpenRetriesUntilAccepted() async {
        let recorder = OpenRequestRecorder(results: [false, false, true])

        let opened = await ServiceUIBridge.requestOpen(
            .auditHistory,
            maxAttempts: 5,
            retryDelay: .seconds(0),
            sender: { target in
                await recorder.send(target)
            }
        )

        #expect(opened == true)
        #expect(await recorder.targets == [.auditHistory, .auditHistory, .auditHistory])
    }

    @Test("Service UI bridge stops after the configured reconnect budget")
    func requestOpenStopsAfterReconnectBudget() async {
        let recorder = OpenRequestRecorder(results: [false, false, false, true])

        let opened = await ServiceUIBridge.requestOpen(
            .diagnostics,
            maxAttempts: 3,
            retryDelay: .seconds(0),
            sender: { target in
                await recorder.send(target)
            }
        )

        #expect(opened == false)
        #expect(await recorder.targets == [.diagnostics, .diagnostics, .diagnostics])
    }

    @Test("Service UI bridge stops retrying when retry sleep is cancelled")
    func requestOpenStopsWhenRetrySleepIsCancelled() async {
        let recorder = OpenRequestRecorder(results: [false, true])

        let opened = await ServiceUIBridge.requestOpen(
            .settings,
            maxAttempts: 5,
            retryDelay: .seconds(1),
            sleep: { delay in
                try await recorder.sleepAndCancel(delay)
            },
            sender: { target in
                await recorder.send(target)
            }
        )

        #expect(opened == false)
        #expect(await recorder.targets == [.settings])
        #expect(await recorder.retryDelays == [.seconds(1)])
    }
}

private actor OpenRequestRecorder {
    private var results: [Bool]
    private(set) var targets: [ServiceUITarget] = []
    private(set) var retryDelays: [Duration] = []

    init(results: [Bool]) {
        self.results = results
    }

    func send(_ target: ServiceUITarget) -> Bool {
        targets.append(target)
        guard !results.isEmpty else {
            return false
        }
        return results.removeFirst()
    }

    func sleepAndCancel(_ delay: Duration) throws {
        retryDelays.append(delay)
        throw CancellationError()
    }
}

import AppKit
import Foundation

enum ServiceUITarget: String, Equatable, Sendable {
    case settings
    case auditHistory
    case diagnostics
    case approvalPolicy
    case approvalViolation

    var isOpenRequestAllowed: Bool {
        switch self {
        case .settings, .auditHistory, .diagnostics:
            return true
        case .approvalPolicy, .approvalViolation:
            return false
        }
    }

    var isApprovalPreview: Bool {
        switch self {
        case .approvalPolicy, .approvalViolation:
            return true
        case .settings, .auditHistory, .diagnostics:
            return false
        }
    }
}

enum ServiceUIRouteDecision: Equatable, Sendable {
    case openInCurrentProcess(ServiceUITarget)
    case requestServiceOpen(ServiceUITarget)
}

nonisolated struct ServiceUIWindowFrame: Codable, Equatable, Sendable {
    let x: Double
    let y: Double
    let width: Double
    let height: Double
}

nonisolated struct ServiceUIWindowSnapshot: Codable, Equatable, Sendable {
    let title: String
    let className: String
    let isVisible: Bool
    let isKeyWindow: Bool
    let isMainWindow: Bool
    let isPanel: Bool
    let isFloatingPanel: Bool
    let isTitled: Bool
    let isClosable: Bool
    let isFullSizeContentView: Bool
    let isBorderless: Bool
    let isNonactivatingPanel: Bool
    let isOpaque: Bool
    let hasShadow: Bool
    let backgroundAlpha: Double?
    let hasContentView: Bool
    let contentViewClassName: String?
    let frame: ServiceUIWindowFrame
}

nonisolated struct ServiceUIProbeResponse: Codable, Equatable, Sendable {
    let target: String
    let opened: Bool
    let matchedWindowTitle: String?
    let visibleNonTargetWindowTitles: [String]
    let windows: [ServiceUIWindowSnapshot]
}

nonisolated enum ServiceUIProbeMatcher {
    static let approvalPanelTitle = "Bastion Approval"
    private static let nativeChromeStyleBits: NSWindow.StyleMask = [
        .titled,
        .closable,
        .miniaturizable,
        .resizable,
        .fullSizeContentView
    ]

    static func isBorderlessChrome(styleMask: NSWindow.StyleMask) -> Bool {
        styleMask.intersection(nativeChromeStyleBits).isEmpty
    }

    static func matches(target: ServiceUITarget, snapshot: ServiceUIWindowSnapshot) -> Bool {
        guard snapshot.isVisible else {
            return false
        }

        switch target {
        case .settings:
            return snapshot.title.localizedCaseInsensitiveContains("Settings")
        case .auditHistory:
            return snapshot.title == "Audit History"
        case .diagnostics:
            return snapshot.title == "Diagnostics"
        case .approvalPolicy, .approvalViolation:
            return snapshot.title == approvalPanelTitle
                && snapshot.contentViewClassName == "NSHostingView<SigningRequestView>"
                && snapshot.isPanel
                && snapshot.isBorderless
                && snapshot.isNonactivatingPanel
                && !snapshot.isTitled
                && !snapshot.isClosable
                && !snapshot.isFullSizeContentView
                && !snapshot.isOpaque
                && snapshot.backgroundAlpha == 0
        }
    }
}

enum ServiceUIRoutePlanner {
    static func notificationClickRoute(
        isServiceProcess: Bool,
        target: ServiceUITarget = .auditHistory
    ) -> ServiceUIRouteDecision {
        isServiceProcess ? .openInCurrentProcess(target) : .requestServiceOpen(target)
    }

    static func relayLaunchRoute(target: ServiceUITarget) -> ServiceUIRouteDecision {
        .requestServiceOpen(target)
    }
}

enum ServiceUIBridge {
    private static let openRequestAttempts = 30
    private static let openRequestRetryDelay: Duration = .milliseconds(150)

    @MainActor
    static func openInCurrentProcess(_ target: ServiceUITarget) {
        NSApplication.shared.activate(ignoringOtherApps: true)

        switch target {
        case .settings:
            SettingsWindowManager.shared.showWindow()
        case .auditHistory:
            AuditHistoryWindowManager.shared.showWindow()
        case .diagnostics:
            DiagnosticsWindowManager.shared.showWindow()
        case .approvalPolicy:
            showApprovalPreview(SigningRequestPreviewFactory.policyReview())
        case .approvalViolation:
            showApprovalPreview(SigningRequestPreviewFactory.ruleOverride())
        }
    }

    @MainActor
    static func probeInCurrentProcess(_ target: ServiceUITarget) async -> ServiceUIProbeResponse {
        if target.isApprovalPreview {
            SettingsWindowManager.shared.showWindow()
            try? await Task.sleep(for: .milliseconds(100))
        }
        openInCurrentProcess(target)
        try? await Task.sleep(for: .milliseconds(250))

        let snapshots: [ServiceUIWindowSnapshot] = NSApplication.shared.windows.map { window in
            let panel = window as? NSPanel
            let styleMask = window.styleMask
            let backgroundAlpha = window.backgroundColor?.usingColorSpace(.deviceRGB)?.alphaComponent
                ?? window.backgroundColor?.alphaComponent
            return ServiceUIWindowSnapshot(
                title: window.title,
                className: String(describing: type(of: window)),
                isVisible: window.isVisible,
                isKeyWindow: window.isKeyWindow,
                isMainWindow: window.isMainWindow,
                isPanel: panel != nil,
                isFloatingPanel: panel?.isFloatingPanel ?? false,
                isTitled: styleMask.contains(.titled),
                isClosable: styleMask.contains(.closable),
                isFullSizeContentView: styleMask.contains(.fullSizeContentView),
                isBorderless: ServiceUIProbeMatcher.isBorderlessChrome(styleMask: styleMask),
                isNonactivatingPanel: styleMask.contains(.nonactivatingPanel),
                isOpaque: window.isOpaque,
                hasShadow: window.hasShadow,
                backgroundAlpha: backgroundAlpha.map { Double($0) },
                hasContentView: window.contentView != nil,
                contentViewClassName: window.contentView.map { String(describing: type(of: $0)) },
                frame: ServiceUIWindowFrame(
                    x: window.frame.origin.x,
                    y: window.frame.origin.y,
                    width: window.frame.size.width,
                    height: window.frame.size.height
                )
            )
        }
        let matchedWindow = snapshots.first { ServiceUIProbeMatcher.matches(target: target, snapshot: $0) }
        let visibleNonTargetWindowTitles = snapshots
            .filter { $0.isVisible && !ServiceUIProbeMatcher.matches(target: target, snapshot: $0) }
            .map(\.title)
        let response = ServiceUIProbeResponse(
            target: target.rawValue,
            opened: matchedWindow != nil,
            matchedWindowTitle: matchedWindow?.title,
            visibleNonTargetWindowTitles: visibleNonTargetWindowTitles,
            windows: snapshots
        )
        if target.isApprovalPreview {
            SigningRequestPanelManager.shared.closePanel()
        }
        return response
    }

    @MainActor
    private static func showApprovalPreview(_ approval: ApprovalRequest) {
        let primaryWindow = NSApplication.shared.keyWindow
            ?? NSApplication.shared.windows.first { $0.isVisible }
        ApprovalPreviewWindowHider.hideHostWindowsBeforePreview(primary: primaryWindow)
        SigningRequestPanelManager.shared.showRequest(
            approval,
            onApprove: {},
            onDeny: {}
        )
    }

    static func requestOpen(_ target: ServiceUITarget) async -> Bool {
        await requestOpen(
            target,
            maxAttempts: openRequestAttempts,
            retryDelay: openRequestRetryDelay,
            sender: { target in
                await sendOpenRequest(target)
            }
        )
    }

    static func requestOpen(
        _ target: ServiceUITarget,
        maxAttempts: Int,
        retryDelay: Duration,
        sleep: @Sendable (Duration) async throws -> Void = { delay in
            try await Task.sleep(for: delay)
        },
        sender: @escaping @Sendable (ServiceUITarget) async -> Bool
    ) async -> Bool {
        guard maxAttempts > 0 else {
            return false
        }

        for attempt in 0..<maxAttempts {
            guard !Task.isCancelled else {
                return false
            }
            if await sender(target) {
                return true
            }
            if attempt < maxAttempts - 1 {
                do {
                    try await sleep(retryDelay)
                } catch {
                    return false
                }
            }
        }
        return false
    }

    private static func sendOpenRequest(_ target: ServiceUITarget) async -> Bool {
        await withCheckedContinuation { continuation in
            let connection = NSXPCConnection(machServiceName: xpcServiceName, options: [])
            connection.remoteObjectInterface = NSXPCInterface(with: BastionXPCProtocol.self)

            let lock = NSLock()
            var didFinish = false

            func finish(_ result: Bool) {
                lock.lock()
                defer { lock.unlock() }

                guard !didFinish else {
                    return
                }

                didFinish = true
                connection.invalidationHandler = nil
                connection.interruptionHandler = nil
                connection.invalidate()
                continuation.resume(returning: result)
            }

            connection.invalidationHandler = {
                finish(false)
            }
            connection.interruptionHandler = {
                finish(false)
            }

            connection.resume()

            guard let proxy = connection.remoteObjectProxyWithErrorHandler({ _ in
                finish(false)
            }) as? BastionXPCProtocol else {
                finish(false)
                return
            }

            proxy.openUI(target: target.rawValue) { success, error in
                finish(success && error == nil)
            }

            DispatchQueue.global(qos: .utility).asyncAfter(deadline: .now() + 1.0) {
                finish(false)
            }
        }
    }
}

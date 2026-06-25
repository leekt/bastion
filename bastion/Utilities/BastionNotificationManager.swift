import AppKit
import Foundation
import UserNotifications

final class BastionNotificationManager: @unchecked Sendable {
    static let shared = BastionNotificationManager()

    private let authorizationLock = NSLock()
    private var hasRequestedAuthorization = false
    private let notificationDelegate = NotificationDelegate()

    private init() {}

    func configureIfNeeded() {
        Task {
            let center = UNUserNotificationCenter.current()
            center.delegate = notificationDelegate

            let shouldRequestAuthorization = authorizationLock.withLock {
                guard !hasRequestedAuthorization else {
                    return false
                }
                hasRequestedAuthorization = true
                return true
            }

            guard shouldRequestAuthorization else {
                return
            }

            let settings = await center.notificationSettings()
            let authorizationStatus = settings.authorizationStatus
            guard authorizationStatus == .notDetermined else {
                let authorizationUnavailable = authorizationStatus != .authorized
                    && authorizationStatus != .provisional
                DiagnosticLog.shared.record(
                    level: authorizationUnavailable ? .warning : .info,
                    category: .notification,
                    event: "notification_authorization_status",
                    message: authorizationUnavailable
                        ? "Notification authorization is unavailable"
                        : "Notification authorization already resolved",
                    context: notificationAuthorizationRemediationContext(
                        statusRawValue: "\(authorizationStatus.rawValue)"
                    )
                )
                return
            }

            do {
                let granted = try await center.requestAuthorization(options: [.alert, .sound, .badge])
                DiagnosticLog.shared.record(
                    category: .notification,
                    event: "notification_authorization_requested",
                    message: "Requested notification authorization",
                    context: notificationAuthorizationRequestContext(granted: granted)
                )
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .notification,
                    event: "notification_authorization_request_failed",
                    message: error.localizedDescription,
                    context: notificationAuthorizationRequestContext(
                        granted: false,
                        errorDescription: error.localizedDescription
                    )
                )
            }
        }
    }

    nonisolated func notify(
        title: String,
        subtitle: String? = nil,
        body: String,
        identifier: String = UUID().uuidString,
        userInfo: [String: String] = [:]
    ) {
        Task {
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
                DiagnosticLog.shared.record(
                    level: .warning,
                    category: .notification,
                    event: "notification_skipped_unauthorized",
                    message: "Notification skipped because authorization is unavailable",
                    context: notificationContext(
                        title: title,
                        identifier: identifier,
                        userInfo: userInfo,
                        extra: notificationAuthorizationRemediationContext(
                            statusRawValue: "\(settings.authorizationStatus.rawValue)"
                        )
                    )
                )
                return
            }

            let content = UNMutableNotificationContent()
            content.title = title
            if let subtitle, !subtitle.isEmpty {
                content.subtitle = subtitle
            }
            content.body = body
            content.sound = .default
            content.userInfo = notificationUserInfo(userInfo)

            let request = UNNotificationRequest(
                identifier: identifier,
                content: content,
                trigger: nil
            )

            do {
                try await center.add(request)
                DiagnosticLog.shared.record(
                    category: .notification,
                    event: "notification_delivered",
                    message: "Notification delivered",
                    context: notificationContext(
                        title: title,
                        identifier: identifier,
                        userInfo: userInfo
                    )
                )
            } catch {
                DiagnosticLog.shared.record(
                    level: .error,
                    category: .notification,
                    event: "notification_delivery_failed",
                    message: error.localizedDescription,
                    context: notificationContext(
                        title: title,
                        identifier: identifier,
                        userInfo: userInfo
                    )
                )
            }
        }
    }
}

nonisolated func notificationContext(
    title: String,
    identifier: String,
    userInfo: [String: String],
    extra: [String: String] = [:]
) -> [String: String] {
    var context = userInfo
    context["title"] = title
    context["notificationIdentifier"] = identifier
    for (key, value) in extra {
        context[key] = value
    }
    return context
}

nonisolated func notificationUserInfo(_ userInfo: [String: String]) -> [AnyHashable: Any] {
    userInfo.reduce(into: [AnyHashable: Any]()) { result, item in
        result[item.key] = item.value
    }
}

nonisolated func notificationAuthorizationRemediationContext(
    statusRawValue: String
) -> [String: String] {
    [
        "status": statusRawValue,
        "settingsPath": "System Settings > Notifications",
        "suggestedAction": "Enable notifications for Bastion, then rerun the notification-click live-runtime check.",
        "rerunCommand": "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click",
    ]
}

nonisolated func notificationAuthorizationRequestContext(
    granted: Bool,
    errorDescription: String? = nil
) -> [String: String] {
    var context = [
        "granted": String(granted),
        "requestFailed": String(errorDescription != nil),
    ]
    if let errorDescription, !errorDescription.isEmpty {
        context["error"] = errorDescription
        context["settingsPath"] = "System Settings > Notifications"
        context["suggestedAction"] = "Check notification prompt state, enable notifications for Bastion if present, then rerun the notification-click live-runtime check."
        context["rerunCommand"] = "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click"
    }
    return context
}

nonisolated func stringNotificationUserInfo(_ userInfo: [AnyHashable: Any]) -> [String: String] {
    userInfo.reduce(into: [String: String]()) { result, item in
        guard let key = item.key as? String,
              let value = item.value as? String else {
            return
        }
        result[key] = value
    }
}

enum NotificationClickHandler {
    static let defaultActionIdentifier = "com.apple.UNNotificationDefaultActionIdentifier"

    static func handle(
        title: String,
        identifier: String,
        userInfo: [String: String],
        actionIdentifier: String,
        isServiceProcess: Bool = CLIInstaller.isRunningAsLaunchAgentService,
        openInCurrentProcess: @escaping @MainActor (ServiceUITarget) -> Void = { target in
            ServiceUIBridge.openInCurrentProcess(target)
        },
        requestServiceOpen: @escaping @Sendable (ServiceUITarget) async -> Bool = { target in
            await ServiceUIBridge.requestOpen(target)
        },
        terminateRelay: @escaping @MainActor () -> Void = {
            NSApplication.shared.terminate(nil)
        }
    ) async -> Bool {
        let clickContext = notificationContext(
            title: title,
            identifier: identifier,
            userInfo: userInfo,
            extra: ["actionIdentifier": actionIdentifier]
        )

        switch ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: isServiceProcess) {
        case .openInCurrentProcess(let target):
            var context = clickContext
            context["target"] = target.rawValue
            DiagnosticLog.shared.record(
                category: .notification,
                event: "notification_click_local_open",
                message: "Notification click opened UI in current process",
                context: context
            )
            await MainActor.run {
                openInCurrentProcess(target)
            }
            return true
        case .requestServiceOpen(let target):
            var context = clickContext
            context["target"] = target.rawValue
            DiagnosticLog.shared.record(
                category: .notification,
                event: "notification_click_relay",
                message: "Notification click relayed UI request to service",
                context: context
            )
            let opened = await requestServiceOpen(target)
            context["opened"] = String(opened)
            DiagnosticLog.shared.record(
                level: opened ? .info : .error,
                category: .notification,
                event: "notification_click_relay_result",
                message: opened ? "Notification click relay opened UI in service" : "Notification click relay could not open UI in service",
                context: context
            )
            await MainActor.run {
                terminateRelay()
            }
            return opened
        }
    }
}

private final class NotificationDelegate: NSObject, UNUserNotificationCenterDelegate, @unchecked Sendable {
    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .list, .sound])
    }

    nonisolated func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        didReceive response: UNNotificationResponse,
        withCompletionHandler completionHandler: @escaping () -> Void
    ) {
        Task {
            _ = await NotificationClickHandler.handle(
                title: response.notification.request.content.title,
                identifier: response.notification.request.identifier,
                userInfo: stringNotificationUserInfo(response.notification.request.content.userInfo),
                actionIdentifier: response.actionIdentifier
            )
            completionHandler()
        }
    }
}

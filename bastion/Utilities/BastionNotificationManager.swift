import AppKit
import Foundation
import UserNotifications

final class BastionNotificationManager: @unchecked Sendable {
    static let shared = BastionNotificationManager()

    private var hasRequestedAuthorization = false
    private let notificationDelegate = NotificationDelegate()

    private init() {}

    func configureIfNeeded() {
        Task {
            let center = UNUserNotificationCenter.current()
            center.delegate = notificationDelegate

            guard !hasRequestedAuthorization else {
                return
            }
            hasRequestedAuthorization = true

            let settings = await center.notificationSettings()
            guard settings.authorizationStatus == .notDetermined else {
                return
            }

            _ = try? await center.requestAuthorization(options: [.alert, .sound, .badge])
        }
    }

    nonisolated func notify(title: String, subtitle: String? = nil, body: String) {
        Task {
            let center = UNUserNotificationCenter.current()
            let settings = await center.notificationSettings()
            guard settings.authorizationStatus == .authorized || settings.authorizationStatus == .provisional else {
                return
            }

            let content = UNMutableNotificationContent()
            content.title = title
            if let subtitle, !subtitle.isEmpty {
                content.subtitle = subtitle
            }
            content.body = body
            content.sound = .default

            let request = UNNotificationRequest(
                identifier: UUID().uuidString,
                content: content,
                trigger: nil
            )

            try? await center.add(request)
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
            if CLIInstaller.isRunningAsLaunchAgentService {
                await MainActor.run {
                    ServiceUIBridge.openInCurrentProcess(.auditHistory)
                }
            } else {
                _ = await ServiceUIBridge.requestOpen(.auditHistory)
                await MainActor.run {
                    NSApplication.shared.terminate(nil)
                }
            }
            completionHandler()
        }
    }
}

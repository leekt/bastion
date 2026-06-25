import AppKit
import SwiftUI

// Quiet receipt toast — surfaced briefly when a silent sign succeeds.
// Mirrors the SilentBanner component in approval-edge.jsx.
//
// SigningManager shows this after successful silent UserOperation signs so
// owners get a quiet receipt without interrupting the agent flow.

struct SilentBannerView: View {
    let title: String
    let subtitle: String
    let onAuditTapped: () -> Void

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 7).fill(Color.bastionOkSoft)
                CheckGlyph(size: 14, color: .bastionOk)
            }
            .frame(width: 30, height: 30)

            VStack(alignment: .leading, spacing: 1) {
                Text(title)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundStyle(Color.ink900)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Text(subtitle)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.ink500)
                    .lineLimit(1)
            }

            Spacer(minLength: 0)

            Button("Audit", action: onAuditTapped)
                .bastionButton(.ghost, size: .small)
        }
        .padding(EdgeInsets(top: 12, leading: 14, bottom: 12, trailing: 12))
        .frame(width: 320)
        .background(
            RoundedRectangle(cornerRadius: 12)
                .fill(Color.paper)
                .overlay(RoundedRectangle(cornerRadius: 12).strokeBorder(Color.ink150, lineWidth: 1))
                .shadow(color: Color.black.opacity(0.16), radius: 16, y: 12)
        )
    }
}

nonisolated enum SilentBannerPresentation {
    static let minimumWidth: CGFloat = 320
    static let trailingInset: CGFloat = 16
    static let topInset: CGFloat = 12
    static let styleMask: NSWindow.StyleMask = [.borderless, .nonactivatingPanel, .fullSizeContentView]
    static let level: NSWindow.Level = .statusBar
    static let collectionBehavior: NSWindow.CollectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]

    static func panelWidth(fittingWidth: CGFloat) -> CGFloat {
        max(fittingWidth, minimumWidth)
    }

    static func panelOrigin(visibleFrame: NSRect, panelSize: NSSize) -> NSPoint {
        NSPoint(
            x: visibleFrame.maxX - panelSize.width - trailingInset,
            y: visibleFrame.maxY - panelSize.height - topInset
        )
    }

    static func shouldAutoDismissAfterDelay(
        duration: TimeInterval,
        sleep: @Sendable (TimeInterval) async throws -> Void
    ) async -> Bool {
        do {
            try await sleep(duration)
            return !Task.isCancelled
        } catch {
            return false
        }
    }
}

@MainActor
final class SilentBannerManager {
    static let shared = SilentBannerManager()
    private var panel: NSPanel?
    private var dismissTask: Task<Void, Never>?

    private init() {}

    /// Show a quiet receipt toast at the top-right of the active screen.
    /// Auto-dismisses after `duration` seconds.
    func show(title: String, subtitle: String, duration: TimeInterval = 4) {
        dismiss()

        let view = SilentBannerView(title: title, subtitle: subtitle) { [weak self] in
            AuditHistoryWindowManager.shared.showWindow()
            self?.dismiss()
        }
        let host = NSHostingView(rootView: view)
        let size = host.fittingSize

        let newPanel = NSPanel(
            contentRect: NSRect(x: 0, y: 0, width: SilentBannerPresentation.panelWidth(fittingWidth: size.width), height: size.height),
            styleMask: SilentBannerPresentation.styleMask,
            backing: .buffered,
            defer: false
        )
        newPanel.contentView = host
        newPanel.level = SilentBannerPresentation.level
        newPanel.backgroundColor = .clear
        newPanel.isOpaque = false
        newPanel.hasShadow = false
        newPanel.collectionBehavior = SilentBannerPresentation.collectionBehavior

        if let screen = NSScreen.main {
            newPanel.setFrameOrigin(
                SilentBannerPresentation.panelOrigin(
                    visibleFrame: screen.visibleFrame,
                    panelSize: newPanel.frame.size
                )
            )
        }

        newPanel.orderFrontRegardless()
        panel = newPanel

        dismissTask = Task { @MainActor [weak self] in
            let shouldDismiss = await SilentBannerPresentation.shouldAutoDismissAfterDelay(
                duration: duration,
                sleep: { try await Task.sleep(for: .seconds($0)) }
            )
            guard shouldDismiss else { return }
            self?.dismiss()
        }
    }

    func dismiss() {
        dismissTask?.cancel()
        dismissTask = nil
        panel?.close()
        panel = nil
    }
}

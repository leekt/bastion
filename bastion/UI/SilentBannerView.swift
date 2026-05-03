import AppKit
import SwiftUI

// Quiet receipt toast — surfaced briefly when a silent sign succeeds.
// Mirrors the SilentBanner component in approval-edge.jsx.
//
// Backend wire-up (see task #19): SigningManager should call
//     SilentBannerManager.shared.show(for: approval, signed: signResponse)
// after a successful silent sign. Currently unused; left as a ready-to-call
// presentation primitive so the visual layer is complete.

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
            contentRect: NSRect(x: 0, y: 0, width: max(size.width, 320), height: size.height),
            styleMask: [.borderless, .nonactivatingPanel, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        newPanel.contentView = host
        newPanel.level = .statusBar
        newPanel.backgroundColor = .clear
        newPanel.isOpaque = false
        newPanel.hasShadow = false
        newPanel.collectionBehavior = [.moveToActiveSpace, .fullScreenAuxiliary]

        if let screen = NSScreen.main {
            let frame = screen.visibleFrame
            let panelSize = newPanel.frame.size
            let origin = NSPoint(
                x: frame.maxX - panelSize.width - 16,
                y: frame.maxY - panelSize.height - 12
            )
            newPanel.setFrameOrigin(origin)
        }

        newPanel.orderFrontRegardless()
        panel = newPanel

        dismissTask = Task { @MainActor [weak self] in
            try? await Task.sleep(for: .seconds(duration))
            guard !Task.isCancelled else { return }
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

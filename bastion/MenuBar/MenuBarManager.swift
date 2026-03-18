import AppKit
import SwiftUI

@Observable
@MainActor
final class MenuBarManager {
    private var showingRequestID: String?

    private let signingManager = SigningManager.shared

    var iconName: String = "lock.fill"

    func startObserving() {
        Task { @MainActor in
            await observeSigningState()
        }
    }

    private func flashIcon(_ name: String, duration: TimeInterval = 3.0) {
        iconName = name
        Task {
            try? await Task.sleep(for: .seconds(duration))
            iconName = "lock.fill"
        }
    }

    private func observeSigningState() async {
        while !Task.isCancelled {
            let currentState = signingManager.state
            switch currentState {
            case .idle:
                showingRequestID = nil
                SigningRequestPanelManager.shared.closePanel()
            case .pendingApproval(let approval):
                if showingRequestID != approval.request.requestID {
                    showingRequestID = approval.request.requestID
                    iconName = "lock.open.fill"
                    SigningRequestPanelManager.shared.showRequest(
                        approval,
                        onApprove: { [weak self] in
                            self?.signingManager.approveCurrentRequest()
                            self?.showingRequestID = nil
                            self?.flashIcon("checkmark.shield.fill")
                        },
                        onDeny: { [weak self] in
                            self?.signingManager.denyCurrentRequest()
                            self?.showingRequestID = nil
                            self?.flashIcon("xmark.shield.fill")
                        }
                    )
                }
            case .signing:
                break
            }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }
}

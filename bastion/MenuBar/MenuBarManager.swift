import AppKit
import SwiftUI

@Observable
@MainActor
final class MenuBarManager {
    private var showingRequestID: String?
    private var observationTask: Task<Void, Never>?
    private var flashResetTask: Task<Void, Never>?
    private var flashGeneration = 0

    private let signingManager = SigningManager.shared

    var iconName: String = "lock.fill"

    func startObserving() {
        guard observationTask == nil else { return }
        observationTask = Task { @MainActor [weak self] in
            guard let self else { return }
            await observeSigningState()
            observationTask = nil
        }
    }

    private func flashIcon(_ name: String, duration: Duration = MenuBarIconTiming.flashDuration) {
        flashResetTask?.cancel()
        flashGeneration += 1
        let generation = flashGeneration
        iconName = name
        flashResetTask = Task { @MainActor [weak self] in
            guard await MenuBarIconTiming.shouldResetFlashAfterDelay(duration: duration) else { return }
            guard let self else { return }
            guard flashGeneration == generation else { return }
            iconName = MenuBarIconTiming.defaultIconName
            flashResetTask = nil
        }
    }

    private func observeSigningState() async {
        while !Task.isCancelled {
            let currentState = signingManager.state
            switch currentState {
            case .idle:
                // Only close the panel when transitioning out of a request
                // we owned. The Test Approval / Test Violation buttons (and
                // any other surface that pushes a panel directly) leave
                // signingManager.state at .idle the entire time, so an
                // unconditional closePanel() here used to make those
                // panels disappear within the 100ms poll tick.
                if showingRequestID != nil {
                    showingRequestID = nil
                    SigningRequestPanelManager.shared.closePanel()
                }
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
            guard await MenuBarIconTiming.shouldContinueObservationAfterDelay() else { return }
        }
    }
}

nonisolated enum MenuBarIconTiming {
    static let defaultIconName = "lock.fill"
    static let flashDuration: Duration = .seconds(3)
    static let observationInterval: Duration = .milliseconds(100)

    static func shouldResetFlashAfterDelay(
        duration: Duration = flashDuration,
        sleep: @Sendable (Duration) async throws -> Void = { delay in
            try await Task.sleep(for: delay)
        }
    ) async -> Bool {
        do {
            try await sleep(duration)
        } catch {
            return false
        }
        return !Task.isCancelled
    }

    static func shouldContinueObservationAfterDelay(
        interval: Duration = observationInterval,
        sleep: @Sendable (Duration) async throws -> Void = { delay in
            try await Task.sleep(for: delay)
        }
    ) async -> Bool {
        do {
            try await sleep(interval)
        } catch {
            return false
        }
        return !Task.isCancelled
    }
}

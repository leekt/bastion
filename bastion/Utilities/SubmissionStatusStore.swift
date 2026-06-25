import Foundation

nonisolated struct PendingUserOperationStatus: Identifiable, Sendable, Equatable {
    let id: String
    let requestID: String
    let clientDisplayName: String
    let provider: String
    let chainId: Int
    let userOpHash: String
    let submittedAt: Date

    init(
        requestID: String,
        clientDisplayName: String,
        provider: String,
        chainId: Int,
        userOpHash: String,
        submittedAt: Date = Date()
    ) {
        self.id = requestID
        self.requestID = requestID
        self.clientDisplayName = clientDisplayName
        self.provider = provider
        self.chainId = chainId
        self.userOpHash = userOpHash
        self.submittedAt = submittedAt
    }
}

nonisolated final class SubmissionStatusStore: @unchecked Sendable {
    static let shared = SubmissionStatusStore()

    private let lock = NSLock()
    private var pendingByRequestID: [String: PendingUserOperationStatus] = [:]

    init() {}

    nonisolated func markSubmitted(
        requestID: String,
        clientDisplayName: String,
        provider: String,
        chainId: Int,
        userOpHash: String,
        submittedAt: Date = Date()
    ) {
        let status = PendingUserOperationStatus(
            requestID: requestID,
            clientDisplayName: clientDisplayName,
            provider: provider,
            chainId: chainId,
            userOpHash: userOpHash,
            submittedAt: submittedAt
        )
        lock.withLock {
            pendingByRequestID[requestID] = status
        }
    }

    nonisolated func markFinished(requestID: String) {
        _ = lock.withLock {
            pendingByRequestID.removeValue(forKey: requestID)
        }
    }

    nonisolated func active() -> [PendingUserOperationStatus] {
        lock.withLock {
            pendingByRequestID.values.sorted { lhs, rhs in
                lhs.submittedAt > rhs.submittedAt
            }
        }
    }
}

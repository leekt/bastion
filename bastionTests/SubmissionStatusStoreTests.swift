import Foundation
import Testing
@testable import bastion

@Suite("Submission status store")
struct SubmissionStatusStoreTests {

    @Test("Pending submissions sort newest first and clear by request")
    func pendingSubmissionsSortAndClear() {
        let store = SubmissionStatusStore()
        let older = Date(timeIntervalSince1970: 100)
        let newer = Date(timeIntervalSince1970: 200)

        store.markSubmitted(
            requestID: "older",
            clientDisplayName: "Agent A",
            provider: "ZeroDev",
            chainId: 11155111,
            userOpHash: "0xolder",
            submittedAt: older
        )
        store.markSubmitted(
            requestID: "newer",
            clientDisplayName: "Agent B",
            provider: "ZeroDev",
            chainId: 8453,
            userOpHash: "0xnewer",
            submittedAt: newer
        )

        #expect(store.active().map(\.requestID) == ["newer", "older"])

        store.markFinished(requestID: "newer")

        #expect(store.active().map(\.requestID) == ["older"])
    }
}

import Foundation
import LocalAuthentication

#if DEBUG
private nonisolated final class AuthBypassState: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func get() -> Bool {
        lock.withLock { value }
    }

    func set(_ newValue: Bool) {
        lock.withLock { value = newValue }
    }
}
#endif

final class AuthManager {
    static let shared = AuthManager()

    #if DEBUG
    /// Test-only bypass for biometric auth. Set from XCTest/swift-testing
    /// harnesses that cannot satisfy LocalAuthentication. Production builds
    /// compile this flag out entirely.
    private nonisolated static let bypassForTests = AuthBypassState()

    nonisolated static var _bypassForTests: Bool {
        get { bypassForTests.get() }
        set { bypassForTests.set(newValue) }
    }
    #endif

    private init() {}

    func authenticate(policy: AuthPolicy, reason: String) async throws {
        #if DEBUG
        if Self._bypassForTests {
            return
        }
        if RuntimeQAConfigOverride.isEnabled() {
            return
        }
        #endif
        guard let laPolicy = policy.laPolicy else {
            // .open policy = no authentication required
            return
        }

        let context = LAContext()
        var error: NSError?

        guard context.canEvaluatePolicy(laPolicy, error: &error) else {
            throw BastionError.authFailed
        }

        let success = try await context.evaluatePolicy(laPolicy, localizedReason: reason)
        guard success else {
            throw BastionError.authFailed
        }
    }
}

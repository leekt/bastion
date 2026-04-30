import Foundation
import LocalAuthentication

final class AuthManager {
    static let shared = AuthManager()

    #if DEBUG
    /// Test-only bypass for biometric auth. Set from XCTest/swift-testing
    /// harnesses that cannot satisfy LocalAuthentication. Production builds
    /// compile this flag out entirely.
    nonisolated(unsafe) static var _bypassForTests: Bool = false
    #endif

    private init() {}

    func authenticate(policy: AuthPolicy, reason: String) async throws {
        #if DEBUG
        if Self._bypassForTests {
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

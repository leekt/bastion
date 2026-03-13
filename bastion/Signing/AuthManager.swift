import Foundation
import LocalAuthentication

final class AuthManager {
    static let shared = AuthManager()

    private init() {}

    func authenticate(policy: AuthPolicy, reason: String) async throws {
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

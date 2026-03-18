import Testing
@testable import bastion

@Suite("Signing Manager Auth Policy")
struct SigningManagerAuthPolicyTests {

    @Test("Silent rule-matched requests do not require owner auth")
    func silentRuleMatchedRequestSkipsOwnerAuth() {
        #expect(
            SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: false,
                authPolicy: .biometricOrPasscode
            ) == false
        )
        #expect(
            SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: false,
                authPolicy: .passcode
            ) == false
        )
    }

    @Test("Manual approval respects auth policy")
    func manualApprovalRespectsAuthPolicy() {
        #expect(
            SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: true,
                authPolicy: .open
            ) == false
        )
        #expect(
            SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: true,
                authPolicy: .biometric
            ) == true
        )
        #expect(
            SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: true,
                authPolicy: .biometricOrPasscode
            ) == true
        )
    }
}

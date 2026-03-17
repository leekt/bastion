import Foundation
import Testing
@testable import bastion

@Suite("Signing Request Presentation")
struct SigningRequestPresentationTests {

    private func makeContext(bundleId: String?) -> ClientSigningContext {
        ClientSigningContext(
            bundleId: bundleId,
            profileId: bundleId,
            profileLabel: nil,
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.test",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
    }

    @Test("Policy review message request uses within-policy copy")
    func policyReviewMessageRequest() {
        let request = SignRequest(
            operation: .message("hello from bastion"),
            requestID: "req-1",
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.agent"
        )
        let presentation = SigningRequestPresentation(
            approval: ApprovalRequest(request: request, mode: .policyReview, clientContext: makeContext(bundleId: request.clientBundleId))
        )

        #expect(presentation.approvalModeLabel == "Within Policy")
        #expect(presentation.approveLabel == "Approve")
        #expect(presentation.requestKindLabel == "Raw Message")
        #expect(presentation.operationTitle == "Raw Message Review")
        #expect(presentation.headerIcon == "checkmark.shield.fill")
        #expect(presentation.shortClientLabel == "agent")
    }

    @Test("Rule override request uses override copy")
    func ruleOverrideRequest() {
        let request = SignRequest(
            operation: .message("override me"),
            requestID: "req-2",
            timestamp: Date(timeIntervalSince1970: 1_710_000_100),
            clientBundleId: nil
        )
        let presentation = SigningRequestPresentation(
            approval: ApprovalRequest(
                request: request,
                mode: .ruleOverride(["Outside allowed hours", "Target 0x1234... not in allowlist"]),
                clientContext: makeContext(bundleId: request.clientBundleId)
            )
        )

        #expect(presentation.approvalModeLabel == "Override")
        #expect(presentation.approveLabel == "Override & Approve")
        #expect(presentation.headerIcon == "exclamationmark.shield.fill")
        #expect(presentation.shortClientLabel == "Unknown")
        #expect(presentation.heroSubtitle.contains("exceeded the current rules"))
    }

    @Test("Typed data preview is sorted and limited")
    func typedDataPreviewSortsAndLimits() {
        let typedData = EIP712TypedData(
            types: [
                "EIP712Domain": [EIP712Field(name: "name", type: "string")],
                "Permit": [EIP712Field(name: "owner", type: "address")],
            ],
            primaryType: "Permit",
            domain: EIP712Domain(
                name: "Permit2",
                version: "1",
                chainId: 11155111,
                verifyingContract: "0x0000000000000000000000000000000000000001",
                salt: nil
            ),
            message: [
                "zeta": AnyCodable("last"),
                "alpha": AnyCodable("first"),
                "delta": AnyCodable(4),
                "gamma": AnyCodable(true),
                "beta": AnyCodable(["nested": "value"]),
                "epsilon": AnyCodable([1, 2, 3, 4, 5]),
                "eta": AnyCodable("trimmed"),
            ]
        )

        let request = SignRequest(
            operation: .typedData(typedData),
            requestID: "req-3",
            timestamp: Date(timeIntervalSince1970: 1_710_000_200),
            clientBundleId: "com.bastion.cli"
        )
        let presentation = SigningRequestPresentation(
            approval: ApprovalRequest(request: request, mode: .policyReview, clientContext: makeContext(bundleId: request.clientBundleId))
        )

        let preview = presentation.typedDataMessagePreview
        #expect(preview.count == 6)
        #expect(preview.map(\.label) == ["alpha", "beta", "delta", "epsilon", "eta", "gamma"])
        #expect(preview.first?.value == "first")
        #expect(preview[1].value == #"{"nested":"value"}"#)
        #expect(preview[3].value == "[1, 2, 3, 4, ...]")
    }

    @Test("UserOperation presentation uses user-op copy")
    func userOperationPresentation() {
        let op = UserOperation(
            sender: "0x1234567890abcdef1234567890abcdef12345678",
            nonce: "0x1",
            callData: Data(),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0f4240",
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x5208",
            maxPriorityFeePerGas: "0x3b9aca00",
            maxFeePerGas: "0x77359400",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: 11155111,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
        let request = SignRequest(
            operation: .userOperation(op),
            requestID: "req-4",
            timestamp: Date(timeIntervalSince1970: 1_710_000_300),
            clientBundleId: "com.example.worker"
        )
        let presentation = SigningRequestPresentation(
            approval: ApprovalRequest(request: request, mode: .policyReview, clientContext: makeContext(bundleId: request.clientBundleId))
        )

        #expect(presentation.requestKindLabel == "UserOp")
        #expect(presentation.operationTitle == "UserOp Review")
        #expect(presentation.operationSubtitle.contains("decoded execution details"))
        #expect(presentation.shortClientLabel == "worker")
    }

    @Test("Submitting UserOperation updates approval copy")
    func submittingUserOperationPresentation() {
        let op = UserOperation(
            sender: "0x1234567890abcdef1234567890abcdef12345678",
            nonce: "0x1",
            callData: Data(),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0f4240",
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x5208",
            maxPriorityFeePerGas: "0x3b9aca00",
            maxFeePerGas: "0x77359400",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: 11155111,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
        let request = SignRequest(
            operation: .userOperation(op),
            requestID: "req-5",
            timestamp: Date(timeIntervalSince1970: 1_710_000_400),
            clientBundleId: "com.example.worker",
            userOperationSubmission: UserOperationSubmissionRequest(projectId: "project-123")
        )
        let presentation = SigningRequestPresentation(
            approval: ApprovalRequest(request: request, mode: .policyReview, clientContext: makeContext(bundleId: request.clientBundleId))
        )

        #expect(presentation.approveLabel == "Approve & Send")
        #expect(presentation.heroSubtitle.contains("submit"))
        #expect(presentation.operationSubtitle.contains("ZeroDev"))
    }
}

import Foundation
import Testing
@testable import bastion

@Suite("Request execution mode")
struct RequestExecutionModeTests {

    @Test("SignRequest resolves sign-only without provider submission")
    func requestWithoutSubmissionIsSignOnly() {
        let request = SignRequest(
            operation: .message("hello"),
            requestID: "req",
            timestamp: Date(),
            clientBundleId: "com.example.agent"
        )

        #expect(request.executionMode == .signOnly)
        #expect(request.executionMode.label == "Sign only")
        #expect(request.executionMode.compactDetail == "Signature returned to client")
        #expect(request.operationKindLabel == "Message")
    }

    @Test("SignRequest resolves approve-and-send with provider submission")
    func requestWithSubmissionIsApproveAndSend() {
        let request = SignRequest(
            operation: .userOperation(userOperation()),
            requestID: "req",
            timestamp: Date(),
            clientBundleId: "com.example.agent",
            userOperationSubmission: UserOperationSubmissionRequest(
                provider: .zeroDev,
                projectId: "project"
            )
        )

        #expect(request.executionMode == .approveAndSend)
        #expect(request.executionMode.actionLabel == "Approve + send")
        #expect(request.executionMode.compactDetail == "Sign, then submit via provider")
        #expect(request.operationKindLabel == "UserOp")
    }

    @Test("Audit records infer approve-and-send from provider events")
    func auditRecordWithSubmissionIsApproveAndSend() {
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .userOpSubmitted,
                dataPrefix: "req",
                submission: AuditSubmissionSnapshot(
                    provider: "ZeroDev",
                    status: "submitted",
                    userOpHash: "0xabc",
                    transactionHash: nil,
                    detail: "Submission accepted"
                )
            )
        ])

        #expect(record.executionMode == .approveAndSend)
    }

    @Test("Audit records expose compact operation kind labels")
    func auditRecordOperationKindLabel() {
        let request = SignRequest(
            operation: .userOperation(userOperation()),
            requestID: "req",
            timestamp: Date(),
            clientBundleId: "com.example.agent"
        )
        let record = AuditRequestRecord(events: [
            AuditEvent(
                type: .signPending,
                dataPrefix: "req",
                request: request
            )
        ])

        #expect(record.operationKindLabel == "UserOp")
    }

    private func userOperation() -> UserOperation {
        UserOperation(
            sender: "0x1234567890abcdef1234567890abcdef12345678",
            nonce: "0x0",
            callData: KernelEncoding.executeCalldata(
                single: .init(to: "0x0000000000000000000000000000000000000001", value: 0, data: Data())
            ),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0f4240",
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x0f4240",
            maxPriorityFeePerGas: "0x59682f00",
            maxFeePerGas: "0x06fc23ac00",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: 1,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
    }
}

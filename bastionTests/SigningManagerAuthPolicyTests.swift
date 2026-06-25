import LocalAuthentication
import Security
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

    @Test("Auth policies map to expected LA policies and Secure Enclave access flags")
    func authPoliciesMapToLocalAuthenticationAndAccessControl() {
        #expect(AuthPolicy.open.laPolicy == nil)
        #expect(AuthPolicy.passcode.laPolicy == .deviceOwnerAuthentication)
        #expect(AuthPolicy.biometric.laPolicy == .deviceOwnerAuthenticationWithBiometrics)
        #expect(AuthPolicy.biometricOrPasscode.laPolicy == .deviceOwnerAuthentication)

        #expect(AuthPolicy.open.accessControlFlags == .privateKeyUsage)
        #expect(AuthPolicy.passcode.accessControlFlags == [.privateKeyUsage, .devicePasscode])
        #expect(AuthPolicy.biometric.accessControlFlags == [.privateKeyUsage, .biometryCurrentSet])
        #expect(AuthPolicy.biometricOrPasscode.accessControlFlags == [.privateKeyUsage, .userPresence])
    }

    @Test("Settings auth picker presentation keeps option order, labels, hints, and warning")
    func settingsAuthPickerPresentation() {
        let options = AuthPolicyPickerPresentation.options(selected: .biometric)

        #expect(options.map(\.policy) == [.open, .biometric, .biometricOrPasscode])
        #expect(options.map(\.label) == ["Silent", "Biometric", "Always confirm"])
        #expect(options.map(\.hint) == [
            "Complete matching requests",
            "Touch ID required after rules pass",
            "Owner approves every request",
        ])
        #expect(options.map(\.isSelected) == [false, true, false])
        #expect(AuthPolicyPickerPresentation.violationWarning == "Rule violations always require owner authentication, regardless of this setting.")
    }

    @Test("UserOperation notification identifiers are stable per request and stage")
    func userOperationNotificationIdentifiersAreStable() {
        #expect(
            SigningManager.notificationIdentifier(
                requestID: "request-123",
                stage: "confirmed"
            ) == "bastion.signing.request-123.confirmed"
        )
        #expect(
            SigningManager.notificationIdentifier(
                requestID: "request-123",
                stage: "receipt-timeout"
            ) == "bastion.signing.request-123.receipt-timeout"
        )
    }

    @Test("UserOperation receipt polling stops when delay sleep is cancelled")
    func userOperationReceiptPollingStopsWhenDelaySleepIsCancelled() async {
        let recorder = ReceiptPollDelayRecorder()

        let shouldContinue = await SigningManager.shouldContinueUserOpReceiptPollingAfterDelay(
            sleep: { interval in
                await recorder.record(interval)
                throw CancellationError()
            }
        )

        #expect(shouldContinue == false)
        #expect(await recorder.snapshot() == [SigningManager.userOpReceiptPollIntervalNanoseconds])
    }

    @Test("Approval timeout stops when delay sleep is cancelled")
    func approvalTimeoutStopsWhenDelaySleepIsCancelled() async {
        let recorder = ReceiptPollDelayRecorder()

        let shouldTimeout = await SigningManager.shouldTimeoutApprovalAfterDelay(
            sleep: { timeout in
                await recorder.record(timeout)
                throw CancellationError()
            }
        )

        #expect(shouldTimeout == false)
        #expect(await recorder.snapshot() == [SigningManager.approvalTimeoutNanoseconds])
    }

    @Test("UserOperation notification userInfo carries audit routing metadata")
    func userOperationNotificationUserInfoCarriesAuditRoutingMetadata() {
        let request = makeUserOperationRequest(
            submission: UserOperationSubmissionRequest(provider: .zeroDev, projectId: "project-1")
        )
        let context = ClientSigningContext(
            bundleId: "com.example.agent",
            profileId: "profile-agent",
            profileLabel: "Example Agent",
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.client.example",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )

        let userInfo = SigningManager.notificationUserInfo(
            request: request,
            clientContext: context,
            stage: "confirmed",
            provider: "ZeroDev",
            userOpHash: "0xuserop",
            transactionHash: "0xtx"
        )

        #expect(userInfo["requestID"] == "request-userop")
        #expect(userInfo["clientDisplayName"] == "Example Agent")
        #expect(userInfo["executionMode"] == RequestExecutionMode.approveAndSend.rawValue)
        #expect(userInfo["operationKind"] == "UserOp")
        #expect(userInfo["stage"] == "confirmed")
        #expect(userInfo["provider"] == "ZeroDev")
        #expect(userInfo["userOpHash"] == "0xuserop")
        #expect(userInfo["transactionHash"] == "0xtx")
    }

    @Test("Sign-only notification userInfo omits submission-only metadata")
    func signOnlyNotificationUserInfoOmitsSubmissionMetadata() {
        let request = SignRequest(
            operation: .message("hello"),
            requestID: "request-message",
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.agent"
        )
        let context = ClientSigningContext(
            bundleId: "com.example.agent",
            profileId: nil,
            profileLabel: nil,
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.client.example",
            accountAddress: nil,
            rules: .default
        )

        let userInfo = SigningManager.notificationUserInfo(
            request: request,
            clientContext: context,
            stage: "signed"
        )

        #expect(userInfo["requestID"] == "request-message")
        #expect(userInfo["clientDisplayName"] == "com.example.agent")
        #expect(userInfo["executionMode"] == RequestExecutionMode.signOnly.rawValue)
        #expect(userInfo["operationKind"] == "Message")
        #expect(userInfo["stage"] == "signed")
        #expect(userInfo["provider"] == nil)
        #expect(userInfo["userOpHash"] == nil)
        #expect(userInfo["transactionHash"] == nil)
    }

    @Test("Notification manager contexts preserve string userInfo and click routing metadata")
    func notificationManagerContextsPreserveStringUserInfoAndClickRoutingMetadata() {
        let userInfo = [
            "requestID": "request-userop",
            "clientDisplayName": "Example Agent",
            "executionMode": RequestExecutionMode.approveAndSend.rawValue,
            "stage": "confirmed",
            "provider": "ZeroDev",
            "userOpHash": "0xuserop",
            "transactionHash": "0xtx",
        ]
        let context = notificationContext(
            title: "UserOperation confirmed",
            identifier: "bastion.signing.request-userop.confirmed",
            userInfo: userInfo,
            extra: ["status": "0", "actionIdentifier": "com.apple.UNNotificationDefaultActionIdentifier"]
        )

        #expect(context["title"] == "UserOperation confirmed")
        #expect(context["notificationIdentifier"] == "bastion.signing.request-userop.confirmed")
        #expect(context["requestID"] == "request-userop")
        #expect(context["clientDisplayName"] == "Example Agent")
        #expect(context["executionMode"] == RequestExecutionMode.approveAndSend.rawValue)
        #expect(context["stage"] == "confirmed")
        #expect(context["provider"] == "ZeroDev")
        #expect(context["userOpHash"] == "0xuserop")
        #expect(context["transactionHash"] == "0xtx")
        #expect(context["status"] == "0")
        #expect(context["actionIdentifier"] == "com.apple.UNNotificationDefaultActionIdentifier")

        let bridged = notificationUserInfo(userInfo)
        #expect(bridged["requestID"] as? String == "request-userop")
        #expect(bridged["userOpHash"] as? String == "0xuserop")

        let mixed: [AnyHashable: Any] = [
            "requestID": "request-userop",
            "ignoredInt": 7,
            1: "ignoredKey",
            "stage": "confirmed",
        ]
        #expect(stringNotificationUserInfo(mixed) == [
            "requestID": "request-userop",
            "stage": "confirmed",
        ])

        #expect(ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: true) == .openInCurrentProcess(.auditHistory))
        #expect(ServiceUIRoutePlanner.notificationClickRoute(isServiceProcess: false) == .requestServiceOpen(.auditHistory))
    }

    @Test("Notification authorization remediation context is actionable")
    func notificationAuthorizationRemediationContextIsActionable() {
        let context = notificationAuthorizationRemediationContext(statusRawValue: "1")

        #expect(context["status"] == "1")
        #expect(context["settingsPath"] == "System Settings > Notifications")
        #expect(context["suggestedAction"]?.contains("Enable notifications for Bastion") == true)
        #expect(context["rerunCommand"] == "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click")
    }

    @Test("Notification authorization request failure context is actionable")
    func notificationAuthorizationRequestFailureContextIsActionable() {
        let granted = notificationAuthorizationRequestContext(granted: true)
        #expect(granted["granted"] == "true")
        #expect(granted["requestFailed"] == "false")
        #expect(granted["error"] == nil)

        let failed = notificationAuthorizationRequestContext(
            granted: false,
            errorDescription: "notifications unavailable"
        )
        #expect(failed["granted"] == "false")
        #expect(failed["requestFailed"] == "true")
        #expect(failed["error"] == "notifications unavailable")
        #expect(failed["settingsPath"] == "System Settings > Notifications")
        #expect(failed["suggestedAction"]?.contains("rerun the notification-click live-runtime check") == true)
        #expect(failed["rerunCommand"] == "qa/run_live_runtime_checks.sh --run-phase notification-click --require-notification-click")
    }

    private func makeUserOperationRequest(
        submission: UserOperationSubmissionRequest?
    ) -> SignRequest {
        SignRequest(
            operation: .userOperation(UserOperation(
                sender: "0x1234567890abcdef1234567890abcdef12345678",
                nonce: "0x0",
                callData: KernelEncoding.executeCalldata(
                    single: .init(
                        to: "0x0000000000000000000000000000000000000001",
                        value: 0,
                        data: Data()
                    )
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
                chainId: 11155111,
                entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
                entryPointVersion: .v0_7
            )),
            requestID: "request-userop",
            timestamp: Date(timeIntervalSince1970: 1_710_000_100),
            clientBundleId: "com.example.agent",
            userOperationSubmission: submission
        )
    }
}

private actor ReceiptPollDelayRecorder {
    private var intervals: [UInt64] = []

    func record(_ interval: UInt64) {
        intervals.append(interval)
    }

    func snapshot() -> [UInt64] {
        intervals
    }
}

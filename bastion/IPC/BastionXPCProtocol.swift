import Foundation

@objc protocol BastionXPCProtocol {
    func sign(
        data: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getPublicKey(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func ping(
        withReply reply: @escaping (Bool) -> Void
    )

    func openUI(
        target: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    )

    func probeUI(
        target: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeSettingsScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeMenuScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeWalletGroupScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeAuditHistoryScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeRuntimeStateScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeUpdateScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeKeyLifecycleScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func probeLiveRuntimeScenario(
        scenario: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func deliverNotificationProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    )

    func triggerNotificationClickProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    )

    func deliverUserOperationNotificationProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    )

    func triggerUserOperationNotificationClickProbe(
        probeID: String,
        withReply reply: @escaping (Bool, Error?) -> Void
    )

    func getRules(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getState(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getServiceInfo(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// requestData = `SupportBundleRequest` JSON -> returns a redacted support
    /// bundle JSON document.
    func exportSupportBundle(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func resetSigningKeys(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// requestData = `RotateClientKeyRequest` JSON -> returns
    /// `ClientKeyRotationResult`. Private-client profiles only; wallet-group
    /// members require on-chain validator rotation.
    func rotateClientKey(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Structured signing: accepts a JSON-encoded signing operation.
    /// operationType: "message" | "typedData" | "userOperation"
    /// operationData: JSON payload specific to the operation type
    func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    // MARK: - Trusted Agent Bridge

    /// Starts a pairing handshake for an agent behind Bastion's signed MCP/REST
    /// bridge. The bridge executable is authenticated by code signature; the
    /// agent identity is the Bastion-managed profile created after owner
    /// approval.
    func bridgeStartPairing(
        agentIdentifier: String,
        processName: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Returns `PairingPollResponse` JSON for a bridge pairing request.
    func bridgePollPairing(
        requestId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Same as `getPublicKey`, but scoped to a paired agent profile id carried
    /// by the trusted `bastion-mcp` bridge.
    func bridgeGetPublicKey(
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func bridgeGetRules(
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func bridgeGetState(
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func bridgeGetServiceInfo(
        agentProfileId: String?,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func bridgeSign(
        data: Data,
        requestID: String,
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func bridgeSignStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    // MARK: - Wallet Groups

    /// requestData = `CreateWalletGroupRequest` JSON → returns `WalletGroupInfo`.
    /// Requires owner biometric/passcode auth.
    func createWalletGroup(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Returns `WalletGroupListResponse` JSON with all groups and members.
    func listWalletGroups(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Returns `WalletGroupInfo` JSON for a single group.
    func getWalletGroup(
        groupId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// requestData = `AddAgentRequest` JSON → returns `AgentMembershipInfo`.
    /// Requires owner biometric/passcode auth.
    func addAgentToGroup(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Revokes an agent; deletes its SE key and unbinds its ClientProfile.
    /// Requires owner biometric/passcode auth.
    func removeAgentFromGroup(
        groupId: String,
        memberId: String,
        txHash: String?,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// requestData = `UpdateAgentScopeRequest` JSON.
    /// Requires owner biometric/passcode auth.
    func updateAgentScope(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// requestData = `MarkInstalledRequest` JSON → returns updated
    /// `AgentMembershipInfo`. Phase 1: owner calls this after manually
    /// submitting the on-chain install UserOp.
    func markAgentInstalled(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    // MARK: - Phase 2: On-Chain Validator Install

    /// requestData = `InstallAgentOnChainRequest` JSON → returns
    /// `WalletGroupChainResultInfo`. Owner-signed UserOp that installs the
    /// agent's validator module on the group's smart account; optionally
    /// submitted via ZeroDev.
    func installAgentOnChain(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// requestData = `UninstallAgentOnChainRequest` JSON → returns
    /// `WalletGroupChainResultInfo`. Inverse of `installAgentOnChain`.
    func uninstallAgentOnChain(
        requestData: Data,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    // MARK: - Pairing

    /// First-run pairing handshake. CLI calls this with its own bundleId +
    /// process name; Bastion mints a 6-character pairing code, surfaces a
    /// pending request to the menu bar / settings flow, and returns the
    /// code for the CLI to print to the operator's terminal.
    ///
    /// Reply payload: JSON-encoded `PairingHandshakeResponse`.
    /// On success the operator confirms the matching code in the app and
    /// `pollPairing` resolves with the materialised profile. On reject /
    /// timeout the CLI sees `pollPairing` return `.rejected` or `.expired`.
    func startPairing(
        bundleId: String,
        processName: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Polls for the outcome of a pairing handshake. Returns immediately
    /// with the current state — `.pending`, `.accepted(profileInfo)`,
    /// `.rejected`, or `.expired`. Callers should poll on a slow interval
    /// (e.g. 1 second) and stop on any terminal state.
    ///
    /// Reply payload: JSON-encoded `PairingPollResponse`.
    func pollPairing(
        requestId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )
}

let xpcServiceName = "com.bastion.xpc"

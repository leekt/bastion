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

    func getRules(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getState(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getServiceInfo(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func resetSigningKeys(
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

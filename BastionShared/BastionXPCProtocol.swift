import Foundation

// Shared XPC surface for app/CLI integration.
// Runtime models currently live in the app target and CLI target until this file is wired into both.
@objc protocol BastionXPCProtocol {
    func sign(data: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
    func openUI(target: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func deliverNotificationProbe(probeID: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func getRules(withReply reply: @escaping (Data?, Error?) -> Void)
    func getState(withReply reply: @escaping (Data?, Error?) -> Void)
    func getServiceInfo(withReply reply: @escaping (Data?, Error?) -> Void)
    func resetSigningKeys(withReply reply: @escaping (Data?, Error?) -> Void)
    func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    // Trusted agent bridge — production bastion-mcp only.
    func bridgeStartPairing(agentIdentifier: String, processName: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgePollPairing(requestId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetPublicKey(agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetRules(agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetState(agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetServiceInfo(agentProfileId: String?, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeSign(data: Data, requestID: String, agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeSignStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        agentProfileId: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    // Wallet groups — see app target's BastionXPCProtocol.swift for docs.
    func createWalletGroup(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func listWalletGroups(withReply reply: @escaping (Data?, Error?) -> Void)
    func getWalletGroup(groupId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func addAgentToGroup(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func removeAgentFromGroup(
        groupId: String,
        memberId: String,
        txHash: String?,
        withReply reply: @escaping (Data?, Error?) -> Void
    )
    func updateAgentScope(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func markAgentInstalled(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func installAgentOnChain(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func uninstallAgentOnChain(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
}

let xpcServiceName = "com.bastion.xpc"

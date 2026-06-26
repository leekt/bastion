import Darwin
import Foundation

private let maxReceiptWaitSeconds = 120
private let maxBodyBytes = 1 * 1024 * 1024
// DO-01 (audit 2026-06-taek): bound the header section so an endless header
// stream (no `\r\n\r\n`) cannot grow the buffer to OOM before the body cap
// can apply. Also bounds the cost of the marker scan.
private let maxHeaderBytes = 64 * 1024
// Per-connection read/idle timeout (seconds) — defeats slowloris.
private let socketReadTimeoutSeconds = 15
// Ceiling on concurrently-handled REST connections; excess connections wait
// for a slot instead of each pinning a libdispatch worker indefinitely.
private let maxConcurrentRESTConnections = 64
private let maxMessageBytes = 64 * 1024
private let maxJSONBytes = 512 * 1024
private let maxDataChars = 256 * 1024
private let maxLabelChars = 128
private let maxProjectIDChars = 128
private let maxUserOpActions = 16
private let defaultChainID = 11155111
private let xpcServiceName = "com.bastion.xpc"

@objc protocol BastionXPCProtocol {
    func ping(withReply reply: @escaping (Bool) -> Void)
    func bridgeStartPairing(agentIdentifier: String, processName: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgePollPairing(requestId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetPublicKey(agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetRules(agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetState(agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeGetServiceInfo(agentProfileId: String?, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeSign(data: Data, requestID: String, agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func bridgeSignStructured(operationType: String, operationData: Data, requestID: String, agentProfileId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func createWalletGroup(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func listWalletGroups(withReply reply: @escaping (Data?, Error?) -> Void)
    func getWalletGroup(groupId: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func addAgentToGroup(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func removeAgentFromGroup(groupId: String, memberId: String, txHash: String?, withReply reply: @escaping (Data?, Error?) -> Void)
    func updateAgentScope(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func markAgentInstalled(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func installAgentOnChain(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func uninstallAgentOnChain(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
}

private enum BridgeError: Error, LocalizedError {
    case input(String)
    case xpc(String)
    case auth(String)
    case payloadTooLarge(String)
    case notFound

    var errorDescription: String? {
        switch self {
        case .input(let message), .xpc(let message), .auth(let message), .payloadTooLarge(let message):
            return message
        case .notFound:
            return "not found"
        }
    }

    var httpStatus: Int {
        switch self {
        case .input, .auth:
            return 400
        case .payloadTooLarge:
            return 413
        case .notFound:
            return 404
        case .xpc:
            return 502
        }
    }
}

private final class XPCClient {
    private func connection() -> NSXPCConnection {
        let connection = NSXPCConnection(machServiceName: xpcServiceName, options: [])
        connection.remoteObjectInterface = NSXPCInterface(with: BastionXPCProtocol.self)
        return connection
    }

    private func proxy(_ connection: NSXPCConnection, finish: @escaping (Data?, Error?) -> Void) throws -> BastionXPCProtocol {
        guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            finish(nil, error)
        }) as? BastionXPCProtocol else {
            throw BridgeError.xpc("Failed to get XPC proxy. Is Bastion.app running?")
        }
        return proxy
    }

    private func perform(timeoutSeconds: Int = 120, _ invoke: (BastionXPCProtocol, @escaping (Data?, Error?) -> Void) -> Void) throws -> Data {
        let connection = connection()
        let semaphore = DispatchSemaphore(value: 0)
        let lock = NSLock()
        var completed = false
        var responseData: Data?
        var responseError: Error?

        func finish(_ data: Data?, _ error: Error?) {
            lock.lock()
            defer { lock.unlock() }
            guard !completed else { return }
            completed = true
            responseData = data
            responseError = error
            semaphore.signal()
        }

        connection.interruptionHandler = {
            finish(nil, BridgeError.xpc("XPC connection interrupted - ensure the signed Bastion app and service are running"))
        }
        connection.invalidationHandler = {
            finish(nil, BridgeError.xpc("XPC connection invalidated - ensure the signed Bastion app and service are running"))
        }

        connection.resume()
        let p = try proxy(connection, finish: finish)
        invoke(p, finish)

        if semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
            connection.invalidate()
            throw BridgeError.xpc("Request timed out")
        }
        connection.invalidate()
        if let responseError {
            throw BridgeError.xpc(responseError.localizedDescription)
        }
        guard let responseData else {
            throw BridgeError.xpc("No response data")
        }
        return responseData
    }

    func status(agentProfileId: String?) throws -> Data {
        try perform(timeoutSeconds: 10) { proxy, reply in
            proxy.bridgeGetServiceInfo(agentProfileId: agentProfileId, withReply: reply)
        }
    }

    func account(agentProfileId: String) throws -> Data {
        try perform(timeoutSeconds: 10) { proxy, reply in
            proxy.bridgeGetPublicKey(agentProfileId: agentProfileId, withReply: reply)
        }
    }

    func rules(agentProfileId: String) throws -> Data {
        try perform(timeoutSeconds: 10) { proxy, reply in
            proxy.bridgeGetRules(agentProfileId: agentProfileId, withReply: reply)
        }
    }

    func state(agentProfileId: String) throws -> Data {
        try perform(timeoutSeconds: 10) { proxy, reply in
            proxy.bridgeGetState(agentProfileId: agentProfileId, withReply: reply)
        }
    }

    func pair(agentIdentifier: String, processName: String) throws -> Data {
        try perform(timeoutSeconds: 5) { proxy, reply in
            proxy.bridgeStartPairing(agentIdentifier: agentIdentifier, processName: processName, withReply: reply)
        }
    }

    func pollPairing(requestId: String) throws -> Data {
        try perform(timeoutSeconds: 5) { proxy, reply in
            proxy.bridgePollPairing(requestId: requestId, withReply: reply)
        }
    }

    func signRaw(hex: String, agentProfileId: String) throws -> Data {
        guard let raw = Data(hexString: hex), raw.count == 32 else {
            throw BridgeError.input("data must be 32 bytes of hex")
        }
        return try perform(timeoutSeconds: 65) { proxy, reply in
            proxy.bridgeSign(data: raw, requestID: UUID().uuidString, agentProfileId: agentProfileId, withReply: reply)
        }
    }

    func signStructured(operationType: String, data: Data, agentProfileId: String, timeoutSeconds: Int = 120) throws -> Data {
        try perform(timeoutSeconds: timeoutSeconds) { proxy, reply in
            proxy.bridgeSignStructured(
                operationType: operationType,
                operationData: data,
                requestID: UUID().uuidString,
                agentProfileId: agentProfileId,
                withReply: reply
            )
        }
    }

    func createWalletGroup(_ data: Data) throws -> Data {
        try perform(timeoutSeconds: 60) { proxy, reply in proxy.createWalletGroup(requestData: data, withReply: reply) }
    }

    func listWalletGroups() throws -> Data {
        try perform(timeoutSeconds: 10) { proxy, reply in proxy.listWalletGroups(withReply: reply) }
    }

    func getWalletGroup(groupId: String) throws -> Data {
        try perform(timeoutSeconds: 10) { proxy, reply in proxy.getWalletGroup(groupId: groupId, withReply: reply) }
    }

    func addAgent(_ data: Data) throws -> Data {
        try perform(timeoutSeconds: 60) { proxy, reply in proxy.addAgentToGroup(requestData: data, withReply: reply) }
    }

    func removeAgent(groupId: String, memberId: String, txHash: String?) throws -> Data {
        try perform(timeoutSeconds: 60) { proxy, reply in
            proxy.removeAgentFromGroup(groupId: groupId, memberId: memberId, txHash: txHash, withReply: reply)
        }
    }

    func updateAgentScope(_ data: Data) throws -> Data {
        try perform(timeoutSeconds: 60) { proxy, reply in proxy.updateAgentScope(requestData: data, withReply: reply) }
    }

    func markAgentInstalled(_ data: Data) throws -> Data {
        try perform(timeoutSeconds: 60) { proxy, reply in proxy.markAgentInstalled(requestData: data, withReply: reply) }
    }

    func installAgentOnChain(_ data: Data, waitSeconds: Int?) throws -> Data {
        let timeout = max(120, (waitSeconds ?? 30) + 60)
        return try perform(timeoutSeconds: timeout) { proxy, reply in
            proxy.installAgentOnChain(requestData: data, withReply: reply)
        }
    }

    func uninstallAgentOnChain(_ data: Data, waitSeconds: Int?) throws -> Data {
        let timeout = max(120, (waitSeconds ?? 30) + 60)
        return try perform(timeoutSeconds: timeout) { proxy, reply in
            proxy.uninstallAgentOnChain(requestData: data, withReply: reply)
        }
    }
}

private let xpc = XPCClient()

private extension Data {
    init?(hexString: String) {
        var hex = hexString.trimmingCharacters(in: .whitespacesAndNewlines)
        if hex.hasPrefix("0x") || hex.hasPrefix("0X") {
            hex.removeFirst(2)
        }
        guard hex.count % 2 == 0 else { return nil }
        var data = Data(capacity: hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            data.append(byte)
            index = next
        }
        self = data
    }
}

private func jsonData(_ object: Any) throws -> Data {
    try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
}

private func jsonObject(_ data: Data) throws -> Any {
    try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
}

private func jsonDictionary(_ data: Data) throws -> [String: Any] {
    guard let object = try jsonObject(data) as? [String: Any] else {
        throw BridgeError.input("request body must be a JSON object")
    }
    return object
}

private func jsonText(_ object: Any) -> String {
    guard let data = try? JSONSerialization.data(withJSONObject: object, options: [.sortedKeys]),
          let text = String(data: data, encoding: .utf8) else {
        return "{}"
    }
    return text
}

private func textFromJSONData(_ data: Data) -> String {
    guard let object = try? jsonObject(data),
          let pretty = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
          let text = String(data: pretty, encoding: .utf8) else {
        return String(data: data, encoding: .utf8) ?? ""
    }
    return text
}

private func rawJSONStringData(_ text: String) throws -> Data {
    let data = Data(text.utf8)
    _ = try jsonObject(data)
    return data
}

private func requiredString(_ value: Any?, _ label: String, max: Int = 128) throws -> String {
    guard let string = value as? String else {
        throw BridgeError.input("\(label) must be a string")
    }
    guard !string.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
        throw BridgeError.input("\(label) is required")
    }
    guard string.utf8.count <= max else {
        throw BridgeError.input("\(label) exceeds maximum size")
    }
    return string
}

private func optionalString(_ value: Any?, _ label: String, max: Int = 128) throws -> String? {
    guard let value else { return nil }
    guard let string = value as? String else {
        throw BridgeError.input("\(label) must be a string")
    }
    guard string.utf8.count <= max else {
        throw BridgeError.input("\(label) exceeds maximum size")
    }
    return string
}

private func optionalBool(_ value: Any?, _ label: String) throws -> Bool? {
    guard let value else { return nil }
    guard let bool = value as? Bool else {
        throw BridgeError.input("\(label) must be a boolean")
    }
    return bool
}

private func optionalInt(_ value: Any?, _ label: String, min: Int = 1, max: Int = Int(Int32.max)) throws -> Int? {
    guard let value else { return nil }
    let number: Int?
    if let int = value as? Int {
        number = int
    } else if let ns = value as? NSNumber {
        number = ns.intValue
    } else {
        number = nil
    }
    guard let number, number >= min, number <= max else {
        throw BridgeError.input("\(label) must be an integer from \(min) to \(max)")
    }
    return number
}

private func validAddress(_ value: String) -> Bool {
    value.range(of: #"^0x[0-9a-fA-F]{40}$"#, options: .regularExpression) != nil
}

private func validHexBytes(_ value: String) -> Bool {
    value.range(of: #"^0x([0-9a-fA-F]{2})*$"#, options: .regularExpression) != nil
}

private func validTxHash(_ value: String) -> Bool {
    value.range(of: #"^0x[0-9a-fA-F]{64}$"#, options: .regularExpression) != nil
}

private func validUUID(_ value: String) -> Bool {
    value.range(of: #"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"#, options: .regularExpression) != nil
}

private func validUIntString(_ value: String) -> Bool {
    value.range(of: #"^([0-9]+|0x[0-9a-fA-F]+)$"#, options: .regularExpression) != nil
}

// AC-01 / RE-01 / RP-01 (audit 2026-06-taek): a single normalization +
// authorization choke point for every profile-scoped op on BOTH transports.
//
// Background: the XPC service authorizes a bridge-supplied `agentProfileId`
// only by its existence in the machine-global config, so a bridge that can
// name any paired UUID can read/sign for any tenant. The bridge therefore
// must scope itself: each bridge process declares the profile id(s) it is
// authorized for via BASTION_AGENT_PROFILE_ID (comma-separated for a
// multi-profile bridge) and refuses to proxy anything outside that set. This
// also normalizes the id identically on REST and MCP (RP-01 parity drift),
// rejecting whitespace-only / overlong / control-char header values before
// they cross XPC.

/// Trim + shape-check a profile id. Returns nil for empty/overlong/odd-charset
/// input. UUIDs (the app's profile-id format) satisfy `[A-Za-z0-9-]{1,64}`.
private func normalizedProfileId(_ raw: String?) -> String? {
    guard let raw else { return nil }
    let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    guard trimmed.range(of: #"^[A-Za-z0-9-]{1,64}$"#, options: .regularExpression) != nil else {
        return nil
    }
    return trimmed
}

/// The set of profile ids this bridge process is authorized to proxy, parsed
/// from BASTION_AGENT_PROFILE_ID (comma-separated). Empty when unset.
private func allowedAgentProfileIds() -> Set<String> {
    guard let env = ProcessInfo.processInfo.environment["BASTION_AGENT_PROFILE_ID"] else {
        return []
    }
    return Set(env.split(separator: ",").compactMap { normalizedProfileId(String($0)) })
}

/// Resolve + authorize the target profile for a profile-scoped op.
/// - An explicitly requested id must normalize AND be in the bridge's
///   authorized set.
/// - With no explicit id, fall back to the configured profile only when the
///   set is unambiguous (exactly one).
private func authorizeProfileId(requested: String?) throws -> String {
    let allowed = allowedAgentProfileIds()
    let requestedTrimmed = requested?.trimmingCharacters(in: .whitespacesAndNewlines)

    if let requestedTrimmed, !requestedTrimmed.isEmpty {
        guard let id = normalizedProfileId(requestedTrimmed) else {
            throw BridgeError.input("agentProfileId must be 1-64 characters of [A-Za-z0-9-].")
        }
        guard !allowed.isEmpty else {
            throw BridgeError.auth("This bridge has no BASTION_AGENT_PROFILE_ID configured, so it may not proxy agent profiles. Set BASTION_AGENT_PROFILE_ID to the paired profile id(s) this bridge is authorized for.")
        }
        guard allowed.contains(id) else {
            throw BridgeError.auth("agentProfileId is not in this bridge's authorized set (BASTION_AGENT_PROFILE_ID).")
        }
        return id
    }

    if allowed.count == 1 {
        return allowed.first!
    }
    if allowed.isEmpty {
        throw BridgeError.input("agentProfileId is required. Pair the agent first, then set BASTION_AGENT_PROFILE_ID or pass agentProfileId.")
    }
    throw BridgeError.input("agentProfileId is required: this bridge is configured for multiple profiles; specify which one.")
}

/// Status may run unscoped (general service health). If a profile is named it
/// must still be authorized; an unambiguous single-profile bridge scopes to it.
private func authorizeOptionalProfileId(requested: String?) throws -> String? {
    let requestedTrimmed = requested?.trimmingCharacters(in: .whitespacesAndNewlines)
    if requestedTrimmed == nil || requestedTrimmed!.isEmpty {
        let allowed = allowedAgentProfileIds()
        return allowed.count == 1 ? allowed.first : nil
    }
    return try authorizeProfileId(requested: requested)
}

private func validateAgentProfileId(_ args: [String: Any]) throws -> String {
    try authorizeProfileId(requested: args["agentProfileId"] as? String)
}

private func validatedActions(_ value: Any?) throws -> [[String: String]] {
    guard let actions = value as? [[String: Any]], !actions.isEmpty else {
        throw BridgeError.input("actions must include at least one action")
    }
    guard actions.count <= maxUserOpActions else {
        throw BridgeError.input("actions exceeds maximum count of \(maxUserOpActions)")
    }
    return try actions.enumerated().map { index, action in
        let target = try requiredString(action["target"], "actions[\(index)].target", max: 42)
        let value = try optionalString(action["value"], "actions[\(index)].value", max: 78) ?? "0"
        let data = try optionalString(action["data"], "actions[\(index)].data", max: maxDataChars) ?? "0x"
        guard validAddress(target) else {
            throw BridgeError.input("actions[\(index)].target must be a 0x-prefixed 20-byte address")
        }
        guard validUIntString(value) else {
            throw BridgeError.input("actions[\(index)].value must be a decimal or 0x-hex non-negative integer")
        }
        guard validHexBytes(data), !data.contains(",") else {
            throw BridgeError.input("actions[\(index)].data must be 0x-prefixed hex bytes")
        }
        return ["target": target, "value": value, "data": data]
    }
}

private func userOpIntentData(args: [String: Any]) throws -> Data {
    let actions = try validatedActions(args["actions"])
    let send = try optionalBool(args["send"], "send") ?? false
    let chainId = try optionalInt(args["chainId"], "chainId") ?? defaultChainID
    let projectId = try optionalString(args["projectId"], "projectId", max: maxProjectIDChars)
    var envelope: [String: Any] = [
        "chainId": chainId,
        "executions": actions,
        "submit": send
    ]
    if let projectId, !projectId.isEmpty {
        envelope["projectId"] = projectId
    }
    return try jsonData(envelope)
}

private func userOpJSONData(userOpJson: Any, send: Bool, projectId: String?) throws -> Data {
    let raw: Data
    if let text = userOpJson as? String {
        guard text.utf8.count <= maxJSONBytes else {
            throw BridgeError.input("userOpJson exceeds maximum size")
        }
        raw = try rawJSONStringData(text)
    } else {
        raw = try jsonData(userOpJson)
    }
    let object = try jsonObject(raw)
    guard var userOp = object as? [String: Any] else {
        throw BridgeError.input("userOpJson must be a JSON object")
    }
    if !send {
        return try jsonData(userOp)
    }
    var submission: [String: Any] = ["provider": "zeroDev"]
    if let projectId, !projectId.isEmpty {
        submission["projectId"] = projectId
    }
    userOp.removeValue(forKey: "signature")
    return try jsonData(["userOperation": userOp, "submission": submission])
}

private func makeCreateWalletGroupData(_ args: [String: Any]) throws -> Data {
    let label = try requiredString(args["label"], "label", max: maxLabelChars)
    var body: [String: Any] = ["label": label]
    if let chainIds = args["chainIds"] as? [Any] {
        body["chainIds"] = try chainIds.map { try optionalInt($0, "chainIds[]") ?? 0 }
    }
    if let sharedRules = args["sharedRulesJson"] {
        if let text = sharedRules as? String {
            body["sharedRules"] = try jsonObject(Data(text.utf8))
        } else {
            body["sharedRules"] = sharedRules
        }
    } else if let sharedRules = args["sharedRules"] {
        body["sharedRules"] = sharedRules
    }
    return try jsonData(body)
}

private func makeAddAgentData(_ args: [String: Any], groupId explicitGroupId: String? = nil) throws -> Data {
    let groupId: String
    if let explicitGroupId {
        groupId = explicitGroupId
    } else {
        groupId = try requiredString(args["groupId"], "groupId", max: 64)
    }
    guard validUUID(groupId) else { throw BridgeError.input("groupId must be a UUID") }
    var body: [String: Any] = ["groupId": groupId]
    if let label = try optionalString(args["label"], "label", max: maxLabelChars), !label.isEmpty {
        body["label"] = label
    }
    if let clientProfileId = try optionalString(args["clientProfileId"], "clientProfileId", max: 64), !clientProfileId.isEmpty {
        guard validUUID(clientProfileId) else { throw BridgeError.input("clientProfileId must be a UUID") }
        body["clientProfileId"] = clientProfileId
    }
    if let scopedRules = args["scopedRulesJson"] {
        if let text = scopedRules as? String {
            body["scopedRules"] = try jsonObject(Data(text.utf8))
        } else {
            body["scopedRules"] = scopedRules
        }
    } else if let scopedRules = args["scopedRules"] {
        body["scopedRules"] = scopedRules
    }
    return try jsonData(body)
}

private func makeScopeData(groupId: String, memberId: String, scopedRules: Any?) throws -> Data {
    guard validUUID(groupId), validUUID(memberId) else {
        throw BridgeError.input("groupId and memberId must be UUIDs")
    }
    guard let scopedRules else { throw BridgeError.input("scopedRules is required") }
    let rules: Any
    if let text = scopedRules as? String {
        rules = try jsonObject(Data(text.utf8))
    } else {
        rules = scopedRules
    }
    return try jsonData(["groupId": groupId, "memberId": memberId, "scopedRules": rules])
}

private func makeInstallData(groupId: String, memberId: String, args: [String: Any]) throws -> (Data, Int?) {
    guard validUUID(groupId), validUUID(memberId) else {
        throw BridgeError.input("groupId and memberId must be UUIDs")
    }
    guard let chainId = try optionalInt(args["chainId"], "chainId") else {
        throw BridgeError.input("chainId is required")
    }
    let submit = try optionalBool(args["submit"], "submit") ?? false
    let wait = try optionalInt(args["waitForReceiptSeconds"], "waitForReceiptSeconds", min: 0, max: maxReceiptWaitSeconds)
    let projectId = try optionalString(args["projectId"], "projectId", max: maxProjectIDChars)
    var body: [String: Any] = [
        "groupId": groupId,
        "memberId": memberId,
        "chainId": chainId,
        "submit": submit
    ]
    if let projectId, !projectId.isEmpty {
        body["projectId"] = projectId
    }
    if let wait {
        body["waitForReceiptSeconds"] = wait
    }
    return (try jsonData(body), wait)
}

private func makeMarkInstalledData(groupId: String, memberId: String, args: [String: Any]) throws -> Data {
    guard validUUID(groupId), validUUID(memberId) else {
        throw BridgeError.input("groupId and memberId must be UUIDs")
    }
    let txHash = try requiredString(args["txHash"], "txHash", max: 66)
    guard validTxHash(txHash) else { throw BridgeError.input("txHash must be a 0x-prefixed 32-byte hash") }
    var body: [String: Any] = ["groupId": groupId, "memberId": memberId, "txHash": txHash]
    if let validatorAddress = try optionalString(args["validatorAddress"], "validatorAddress", max: 42), !validatorAddress.isEmpty {
        guard validAddress(validatorAddress) else {
            throw BridgeError.input("validatorAddress must be a 0x-prefixed 20-byte address")
        }
        body["validatorAddress"] = validatorAddress
    }
    return try jsonData(body)
}

private func toolResult(_ data: Data) -> [String: Any] {
    ["content": [["type": "text", "text": textFromJSONData(data)]]]
}

private func toolText(_ text: String) -> [String: Any] {
    ["content": [["type": "text", "text": text]]]
}

private func toolError(_ error: Error) -> [String: Any] {
    ["content": [["type": "text", "text": "Error: \(error.localizedDescription)"]], "isError": true]
}

private func callTool(name: String, args: [String: Any]) -> [String: Any] {
    do {
        switch name {
        case "bastion_pair_agent":
            let identifier = try requiredString(args["agentIdentifier"], "agentIdentifier", max: 256)
            let label = try optionalString(args["label"], "label", max: 256) ?? identifier
            return toolResult(try xpc.pair(agentIdentifier: identifier, processName: label))
        case "bastion_poll_pairing":
            return toolResult(try xpc.pollPairing(requestId: requiredString(args["requestId"], "requestId", max: 64)))
        case "bastion_status":
            let profile = try authorizeOptionalProfileId(requested: args["agentProfileId"] as? String)
            return toolResult(try xpc.status(agentProfileId: profile))
        case "bastion_get_account":
            return toolResult(try xpc.account(agentProfileId: validateAgentProfileId(args)))
        case "bastion_get_rules":
            return toolResult(try xpc.rules(agentProfileId: validateAgentProfileId(args)))
        case "bastion_get_state":
            return toolResult(try xpc.state(agentProfileId: validateAgentProfileId(args)))
        case "bastion_sign_message":
            let message = try requiredString(args["message"], "message", max: maxMessageBytes)
            let profile = try validateAgentProfileId(args)
            // chainId present → Kernel v3.3 ERC-1271 path (smart-account signature
            // a dApp can verify on-chain). Absent → plain EIP-191 digest.
            if let chainId = try optionalInt(args["chainId"], "chainId") {
                let env = try jsonData(["message": message, "chainId": chainId])
                return toolResult(try xpc.signStructured(operationType: "message1271", data: env, agentProfileId: profile, timeoutSeconds: 65))
            }
            return toolResult(try xpc.signStructured(operationType: "message", data: Data(message.utf8), agentProfileId: profile, timeoutSeconds: 65))
        case "bastion_sign_typed_data":
            let typed = args["typedData"]
            let typedObj: Any
            if let text = typed as? String {
                typedObj = try jsonObject(Data(text.utf8))
            } else if let typed {
                typedObj = typed
            } else {
                throw BridgeError.input("typedData is required")
            }
            let profile = try validateAgentProfileId(args)
            if let chainId = try optionalInt(args["chainId"], "chainId") {
                let env = try jsonData(["typedData": typedObj, "chainId": chainId])
                return toolResult(try xpc.signStructured(operationType: "typedData1271", data: env, agentProfileId: profile))
            }
            return toolResult(try xpc.signStructured(operationType: "typedData", data: try jsonData(typedObj), agentProfileId: profile))
        case "bastion_sign_raw":
            return toolResult(try xpc.signRaw(hex: requiredString(args["data"], "data", max: 66), agentProfileId: validateAgentProfileId(args)))
        case "bastion_send_user_op":
            return toolResult(try xpc.signStructured(operationType: "userOperation", data: userOpIntentData(args: args), agentProfileId: validateAgentProfileId(args)))
        case "bastion_sign_user_op_json":
            let data = try userOpJSONData(
                userOpJson: args["userOpJson"] as Any,
                send: try optionalBool(args["send"], "send") ?? false,
                projectId: try optionalString(args["projectId"], "projectId", max: maxProjectIDChars)
            )
            return toolResult(try xpc.signStructured(operationType: "userOperation", data: data, agentProfileId: validateAgentProfileId(args)))
        case "bastion_create_wallet_group":
            return toolResult(try xpc.createWalletGroup(makeCreateWalletGroupData(args)))
        case "bastion_list_wallet_groups":
            return toolResult(try xpc.listWalletGroups())
        case "bastion_get_wallet_group":
            return toolResult(try xpc.getWalletGroup(groupId: requiredString(args["groupId"], "groupId", max: 64)))
        case "bastion_add_agent_to_group":
            return toolResult(try xpc.addAgent(makeAddAgentData(args)))
        case "bastion_remove_agent_from_group":
            let groupId = try requiredString(args["groupId"], "groupId", max: 64)
            let memberId = try requiredString(args["memberId"], "memberId", max: 64)
            let txHash = try optionalString(args["txHash"], "txHash", max: 66)
            _ = try xpc.removeAgent(groupId: groupId, memberId: memberId, txHash: txHash)
            return toolText("Agent \(memberId) revoked from group \(groupId).")
        case "bastion_update_agent_scope":
            let groupId = try requiredString(args["groupId"], "groupId", max: 64)
            let memberId = try requiredString(args["memberId"], "memberId", max: 64)
            _ = try xpc.updateAgentScope(makeScopeData(groupId: groupId, memberId: memberId, scopedRules: args["scopedRulesJson"] ?? args["scopedRules"]))
            return toolText("Scope updated for agent \(memberId) in group \(groupId).")
        case "bastion_mark_agent_installed":
            let groupId = try requiredString(args["groupId"], "groupId", max: 64)
            let memberId = try requiredString(args["memberId"], "memberId", max: 64)
            return toolResult(try xpc.markAgentInstalled(makeMarkInstalledData(groupId: groupId, memberId: memberId, args: args)))
        case "bastion_install_agent_on_chain":
            let groupId = try requiredString(args["groupId"], "groupId", max: 64)
            let memberId = try requiredString(args["memberId"], "memberId", max: 64)
            let request = try makeInstallData(groupId: groupId, memberId: memberId, args: args)
            return toolResult(try xpc.installAgentOnChain(request.0, waitSeconds: request.1))
        case "bastion_uninstall_agent_on_chain":
            let groupId = try requiredString(args["groupId"], "groupId", max: 64)
            let memberId = try requiredString(args["memberId"], "memberId", max: 64)
            let request = try makeInstallData(groupId: groupId, memberId: memberId, args: args)
            return toolResult(try xpc.uninstallAgentOnChain(request.0, waitSeconds: request.1))
        default:
            throw BridgeError.input("Unknown tool: \(name)")
        }
    } catch {
        return toolError(error)
    }
}

private func schema(_ properties: [String: Any], required: [String] = []) -> [String: Any] {
    var result: [String: Any] = ["type": "object", "properties": properties]
    if !required.isEmpty {
        result["required"] = required
    }
    return result
}

private func toolDefinitions() -> [[String: Any]] {
    let profile: [String: Any] = ["type": "string", "description": "Paired Bastion agent profile id. Defaults to BASTION_AGENT_PROFILE_ID."]
    let chainId: [String: Any] = ["type": "integer", "minimum": 1, "maximum": Int(Int32.max)]
    let receiptWait: [String: Any] = ["type": "integer", "minimum": 0, "maximum": maxReceiptWaitSeconds]
    let bool: [String: Any] = ["type": "boolean"]
    let string: [String: Any] = ["type": "string"]
    let actionSchema: [String: Any] = [
        "type": "object",
        "properties": [
            "target": ["type": "string"],
            "value": ["type": "string", "default": "0"],
            "data": ["type": "string", "default": "0x"]
        ],
        "required": ["target"]
    ]
    return [
        ["name": "bastion_pair_agent", "description": "Start Bastion owner-approved pairing for an agent behind the signed MCP bridge.", "inputSchema": schema(["agentIdentifier": string, "label": string], required: ["agentIdentifier"])],
        ["name": "bastion_poll_pairing", "description": "Poll a Bastion agent pairing request.", "inputSchema": schema(["requestId": string], required: ["requestId"])],
        ["name": "bastion_status", "description": "Check Bastion service status.", "inputSchema": schema(["agentProfileId": profile])],
        ["name": "bastion_get_account", "description": "Get the paired agent P-256 public key and smart account address.", "inputSchema": schema(["agentProfileId": profile])],
        ["name": "bastion_get_rules", "description": "Get current effective signing rules for the paired agent.", "inputSchema": schema(["agentProfileId": profile])],
        ["name": "bastion_get_state", "description": "Get rate limit and spending counters for the paired agent.", "inputSchema": schema(["agentProfileId": profile])],
        ["name": "bastion_sign_message", "description": "Sign an EIP-191 personal message.", "inputSchema": schema(["message": string, "agentProfileId": profile], required: ["message"])],
        ["name": "bastion_sign_typed_data", "description": "Sign EIP-712 typed data.", "inputSchema": schema(["typedData": ["type": ["object", "string"]], "agentProfileId": profile], required: ["typedData"])],
        ["name": "bastion_sign_raw", "description": "Sign a raw 32-byte hash.", "inputSchema": schema(["data": string, "agentProfileId": profile], required: ["data"])],
        ["name": "bastion_send_user_op", "description": "Build, sign, and optionally send an ERC-4337 UserOperation.", "inputSchema": schema(["actions": ["type": "array", "items": actionSchema], "send": bool, "chainId": chainId, "projectId": string, "agentProfileId": profile], required: ["actions"])],
        ["name": "bastion_sign_user_op_json", "description": "Sign an explicit ERC-4337 UserOperation JSON.", "inputSchema": schema(["userOpJson": ["type": ["object", "string"]], "send": bool, "projectId": string, "agentProfileId": profile], required: ["userOpJson"])],
        ["name": "bastion_create_wallet_group", "description": "Create a shared wallet group.", "inputSchema": schema(["label": string, "chainIds": ["type": "array", "items": chainId], "sharedRulesJson": string], required: ["label"])],
        ["name": "bastion_list_wallet_groups", "description": "List wallet groups.", "inputSchema": schema([:])],
        ["name": "bastion_get_wallet_group", "description": "Get a wallet group by id.", "inputSchema": schema(["groupId": string], required: ["groupId"])],
        ["name": "bastion_add_agent_to_group", "description": "Add an agent to a wallet group.", "inputSchema": schema(["groupId": string, "label": string, "clientProfileId": string, "scopedRulesJson": string], required: ["groupId"])],
        ["name": "bastion_remove_agent_from_group", "description": "Revoke an agent membership.", "inputSchema": schema(["groupId": string, "memberId": string, "txHash": string], required: ["groupId", "memberId"])],
        ["name": "bastion_update_agent_scope", "description": "Update agent scoped rules.", "inputSchema": schema(["groupId": string, "memberId": string, "scopedRulesJson": string], required: ["groupId", "memberId", "scopedRulesJson"])],
        ["name": "bastion_mark_agent_installed", "description": "Mark an agent validator installed.", "inputSchema": schema(["groupId": string, "memberId": string, "txHash": string, "validatorAddress": string], required: ["groupId", "memberId", "txHash"])],
        ["name": "bastion_install_agent_on_chain", "description": "Build and optionally submit installModule UserOp for an agent validator.", "inputSchema": schema(["groupId": string, "memberId": string, "chainId": chainId, "submit": bool, "projectId": string, "waitForReceiptSeconds": receiptWait], required: ["groupId", "memberId", "chainId"])],
        ["name": "bastion_uninstall_agent_on_chain", "description": "Build and optionally submit uninstallModule UserOp for an agent validator.", "inputSchema": schema(["groupId": string, "memberId": string, "chainId": chainId, "submit": bool, "projectId": string, "waitForReceiptSeconds": receiptWait], required: ["groupId", "memberId", "chainId"])]
    ]
}

private func sendMCPResponse(_ object: [String: Any]) {
    FileHandle.standardOutput.write(Data((jsonText(object) + "\n").utf8))
}

private func runMCP() {
    fputs("Bastion Swift MCP bridge running on stdio\n", stderr)
    while let line = readLine() {
        guard let data = line.data(using: .utf8),
              let request = try? jsonObject(data) as? [String: Any],
              let method = request["method"] as? String else {
            continue
        }
        let id = request["id"]
        if method.hasPrefix("notifications/") || id == nil {
            continue
        }

        let result: [String: Any]
        switch method {
        case "initialize":
            result = [
                "protocolVersion": "2024-11-05",
                "capabilities": ["tools": [:]],
                "serverInfo": ["name": "bastion", "version": "0.1.0"]
            ]
        case "ping":
            result = [:]
        case "tools/list":
            result = ["tools": toolDefinitions()]
        case "tools/call":
            let params = request["params"] as? [String: Any] ?? [:]
            let name = params["name"] as? String ?? ""
            let args = params["arguments"] as? [String: Any] ?? [:]
            result = callTool(name: name, args: args)
        default:
            sendMCPResponse(["jsonrpc": "2.0", "id": id as Any, "error": ["code": -32601, "message": "Method not found"]])
            continue
        }
        sendMCPResponse(["jsonrpc": "2.0", "id": id as Any, "result": result])
    }
}

private struct HTTPRequest {
    let method: String
    let path: String
    let query: [String: String]
    let headers: [String: String]
    let body: Data
}

private func estimatedShannonBits(_ value: String) -> Double {
    var counts: [Character: Double] = [:]
    for ch in value { counts[ch, default: 0] += 1 }
    return counts.values.reduce(0) { total, count in
        let p = count / Double(value.count)
        return total - p * log2(p) * Double(value.count)
    }
}

private func hasRepeatedPattern(_ value: String) -> Bool {
    let normalized = value.lowercased()
    let maxPatternLength = min(16, normalized.count / 2)
    guard maxPatternLength > 0 else { return false }
    for size in 1...maxPatternLength {
        guard normalized.count % size == 0 else { continue }
        let end = normalized.index(normalized.startIndex, offsetBy: size)
        let pattern = String(normalized[..<end])
        if String(repeating: pattern, count: normalized.count / size) == normalized {
            return true
        }
    }
    return false
}

private func hasLongSequence(_ value: String) -> Bool {
    let normalized = value.lowercased()
    let sequences = [
        "abcdefghijklmnopqrstuvwxyz",
        "0123456789",
        "qwertyuiopasdfghjklzxcvbnm"
    ]
    for sequence in sequences {
        for source in [sequence, String(sequence.reversed())] {
            for size in 8...source.count {
                var offset = 0
                while offset + size <= source.count {
                    let start = source.index(source.startIndex, offsetBy: offset)
                    let end = source.index(start, offsetBy: size)
                    if normalized.contains(source[start..<end]) {
                        return true
                    }
                    offset += 1
                }
            }
        }
    }
    return false
}

private func tokenLooksHighEntropy(_ value: String?) -> Bool {
    guard let value, value.count >= 32 else { return false }
    guard Set(value).count >= 8 else { return false }
    if value.range(of: #"(.)\1{12,}"#, options: .regularExpression) != nil {
        return false
    }
    if hasRepeatedPattern(value) || hasLongSequence(value) {
        return false
    }
    return estimatedShannonBits(value) >= 128
}

private func parseQuery(_ text: String) -> [String: String] {
    var result: [String: String] = [:]
    for pair in text.split(separator: "&") {
        let parts = pair.split(separator: "=", maxSplits: 1).map(String.init)
        let key = parts.first?.removingPercentEncoding ?? ""
        guard !key.isEmpty else { continue }
        result[key] = (parts.count > 1 ? parts[1] : "").removingPercentEncoding
    }
    return result
}

private func parseHTTPRequest(_ data: Data) throws -> HTTPRequest {
    guard let marker = "\r\n\r\n".data(using: .utf8),
          let range = data.range(of: marker),
          let head = String(data: data[..<range.lowerBound], encoding: .utf8) else {
        throw BridgeError.input("malformed HTTP request")
    }
    let lines = head.components(separatedBy: "\r\n")
    let requestLine = lines.first?.split(separator: " ").map(String.init) ?? []
    guard requestLine.count >= 2 else { throw BridgeError.input("malformed HTTP request") }
    var headers: [String: String] = [:]
    for line in lines.dropFirst() {
        guard let colon = line.firstIndex(of: ":") else { continue }
        let key = line[..<colon].trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespacesAndNewlines)
        headers[key] = value
    }
    let rawTarget = requestLine[1]
    let parts = rawTarget.split(separator: "?", maxSplits: 1).map(String.init)
    let body = data[range.upperBound...]
    return HTTPRequest(
        method: requestLine[0],
        path: parts[0],
        query: parts.count > 1 ? parseQuery(parts[1]) : [:],
        headers: headers,
        body: Data(body)
    )
}

private func readHTTPRequest(fd: Int32) throws -> Data {
    let marker = Data("\r\n\r\n".utf8)
    var buffer = Data()
    var temp = [UInt8](repeating: 0, count: 8192)
    var contentLength: Int?
    var headerEnd: Int?          // index just past the `\r\n\r\n` once seen
    var scanFrom = 0             // incremental scan cursor (avoids O(n^2) rescans)

    while true {
        let count = recv(fd, &temp, temp.count, 0)
        // count == 0 → peer closed; count < 0 → error or SO_RCVTIMEO expiry.
        if count <= 0 { break }
        buffer.append(temp, count: count)

        if headerEnd == nil {
            // DO-01: cap the header section before the terminator arrives.
            if buffer.count > maxHeaderBytes {
                throw BridgeError.payloadTooLarge("request headers too large")
            }
            // Only scan the new tail (with a 3-byte overlap so a marker split
            // across two recv chunks is still found).
            let searchStart = max(0, scanFrom - (marker.count - 1))
            if let range = buffer.range(of: marker, in: searchStart..<buffer.count) {
                headerEnd = range.upperBound
                if let head = String(data: buffer[..<range.lowerBound], encoding: .utf8) {
                    for line in head.components(separatedBy: "\r\n").dropFirst() {
                        if line.lowercased().hasPrefix("content-length:") {
                            contentLength = Int(line.split(separator: ":", maxSplits: 1).last?.trimmingCharacters(in: .whitespaces) ?? "0")
                        }
                    }
                }
                if let contentLength, contentLength > maxBodyBytes {
                    throw BridgeError.payloadTooLarge("request body too large")
                }
            } else {
                scanFrom = buffer.count
            }
        }

        if let headerEnd {
            let expected = headerEnd + (contentLength ?? 0)
            if buffer.count >= expected { break }
        }
    }
    return buffer
}

private func responseJSON(_ status: Int, _ object: Any) -> Data {
    let body = (try? jsonData(object)) ?? Data("{}".utf8)
    let reason = status == 200 ? "OK" : status == 400 ? "Bad Request" : status == 401 ? "Unauthorized" : status == 403 ? "Forbidden" : status == 404 ? "Not Found" : status == 413 ? "Payload Too Large" : "Bad Gateway"
    var head = "HTTP/1.1 \(status) \(reason)\r\n"
    head += "Content-Type: application/json\r\n"
    head += "Content-Length: \(body.count)\r\n"
    head += "Connection: close\r\n\r\n"
    return Data(head.utf8) + body
}

private func responseRawJSON(_ status: Int, _ body: Data) -> Data {
    var head = "HTTP/1.1 \(status) OK\r\n"
    head += "Content-Type: application/json\r\n"
    head += "Content-Length: \(body.count)\r\n"
    head += "Connection: close\r\n\r\n"
    return Data(head.utf8) + body
}

private func authorizedAgentProfileId(_ req: HTTPRequest, args: [String: Any] = [:]) throws -> String {
    // RP-01: normalize + authorize the header through the SAME path as MCP,
    // instead of forwarding the raw header verbatim across XPC.
    let requested = req.headers["x-bastion-agent-profile"] ?? (args["agentProfileId"] as? String)
    return try authorizeProfileId(requested: requested)
}

private func routeREST(_ req: HTTPRequest) throws -> Data {
    if req.headers["origin"] != nil {
        return responseJSON(403, ["error": "Cross-origin requests are not allowed"])
    }
    let expectedToken = ProcessInfo.processInfo.environment["BASTION_API_TOKEN"]
    guard tokenLooksHighEntropy(expectedToken) else {
        throw BridgeError.auth("BASTION_API_TOKEN must be set to a high-entropy value of at least 128 estimated bits.")
    }
    guard req.headers["authorization"] == "Bearer \(expectedToken!)" else {
        return responseJSON(401, ["error": "Unauthorized"])
    }
    if req.body.count > maxBodyBytes {
        return responseJSON(413, ["error": "request body too large"])
    }

    let body = req.body.isEmpty ? [:] : try jsonDictionary(req.body)
    let path = req.path.split(separator: "/").map(String.init)

    switch (req.method, path) {
    case ("GET", ["health"]):
        return responseJSON(200, ["status": "ok"])
    case ("GET", ["status"]):
        return responseRawJSON(200, try xpc.status(agentProfileId: authorizeOptionalProfileId(requested: req.headers["x-bastion-agent-profile"])))
    case ("GET", ["account"]):
        return responseRawJSON(200, try xpc.account(agentProfileId: authorizedAgentProfileId(req)))
    case ("GET", ["rules"]):
        return responseRawJSON(200, try xpc.rules(agentProfileId: authorizedAgentProfileId(req)))
    case ("GET", ["state"]):
        return responseRawJSON(200, try xpc.state(agentProfileId: authorizedAgentProfileId(req)))
    case ("POST", ["pair"]):
        let identifier = try requiredString(body["agentIdentifier"], "agentIdentifier", max: 256)
        let label = try optionalString(body["label"], "label", max: 256) ?? identifier
        return responseRawJSON(200, try xpc.pair(agentIdentifier: identifier, processName: label))
    case ("POST", ["sign", "message"]):
        let message = try requiredString(body["message"], "message", max: maxMessageBytes)
        return responseRawJSON(200, try xpc.signStructured(operationType: "message", data: Data(message.utf8), agentProfileId: authorizedAgentProfileId(req, args: body), timeoutSeconds: 65))
    case ("POST", ["sign", "typed-data"]):
        guard let typedData = body["typedData"] else { throw BridgeError.input("typedData is required") }
        let data = try (typedData as? String).map { try rawJSONStringData($0) } ?? jsonData(typedData)
        return responseRawJSON(200, try xpc.signStructured(operationType: "typedData", data: data, agentProfileId: authorizedAgentProfileId(req, args: body)))
    case ("POST", ["sign", "raw"]):
        let hex = try requiredString(body["data"], "data", max: 66)
        return responseRawJSON(200, try xpc.signRaw(hex: hex, agentProfileId: authorizedAgentProfileId(req, args: body)))
    case ("POST", ["sign", "user-op"]):
        if let userOpJson = body["userOpJson"] {
            let data = try userOpJSONData(
                userOpJson: userOpJson,
                send: try optionalBool(body["send"], "send") ?? false,
                projectId: try optionalString(body["projectId"], "projectId", max: maxProjectIDChars)
            )
            return responseRawJSON(200, try xpc.signStructured(operationType: "userOperation", data: data, agentProfileId: authorizedAgentProfileId(req, args: body)))
        }
        return responseRawJSON(200, try xpc.signStructured(operationType: "userOperation", data: userOpIntentData(args: body), agentProfileId: authorizedAgentProfileId(req, args: body)))
    case ("GET", ["groups"]):
        return responseRawJSON(200, try xpc.listWalletGroups())
    case ("POST", ["groups"]):
        return responseRawJSON(200, try xpc.createWalletGroup(makeCreateWalletGroupData(body)))
    default:
        break
    }

    if req.method == "GET", path.count == 2, path[0] == "pair" {
        return responseRawJSON(200, try xpc.pollPairing(requestId: path[1]))
    }

    if req.method == "GET", path.count == 2, path[0] == "groups" {
        let groupId = path[1]
        guard validUUID(groupId) else { throw BridgeError.input("group id must be a UUID") }
        return responseRawJSON(200, try xpc.getWalletGroup(groupId: groupId))
    }

    if req.method == "POST", path.count == 3, path[0] == "groups", path[2] == "agents" {
        let groupId = path[1]
        return responseRawJSON(200, try xpc.addAgent(makeAddAgentData(body, groupId: groupId)))
    }

    if req.method == "DELETE", path.count == 4, path[0] == "groups", path[2] == "agents" {
        let groupId = path[1]
        let memberId = path[3]
        let tx = req.query["tx"]
        if let tx, !validTxHash(tx) { throw BridgeError.input("tx must be a 0x-prefixed 32-byte hash") }
        _ = try xpc.removeAgent(groupId: groupId, memberId: memberId, txHash: tx)
        return responseJSON(200, ["revoked": true, "groupId": groupId, "memberId": memberId])
    }

    if req.method == "PATCH", path.count == 5, path[0] == "groups", path[2] == "agents", path[4] == "scope" {
        let groupId = path[1]
        let memberId = path[3]
        _ = try xpc.updateAgentScope(makeScopeData(groupId: groupId, memberId: memberId, scopedRules: body["scopedRules"]))
        return responseJSON(200, ["updated": true, "groupId": groupId, "memberId": memberId])
    }

    if req.method == "POST", path.count == 5, path[0] == "groups", path[2] == "agents", path[4] == "install-on-chain" {
        let groupId = path[1]
        let memberId = path[3]
        let request = try makeInstallData(groupId: groupId, memberId: memberId, args: body)
        return responseRawJSON(200, try xpc.installAgentOnChain(request.0, waitSeconds: request.1))
    }

    if req.method == "POST", path.count == 5, path[0] == "groups", path[2] == "agents", path[4] == "uninstall-on-chain" {
        let groupId = path[1]
        let memberId = path[3]
        let request = try makeInstallData(groupId: groupId, memberId: memberId, args: body)
        return responseRawJSON(200, try xpc.uninstallAgentOnChain(request.0, waitSeconds: request.1))
    }

    if req.method == "POST", path.count == 5, path[0] == "groups", path[2] == "agents", path[4] == "installed" {
        let groupId = path[1]
        let memberId = path[3]
        return responseRawJSON(200, try xpc.markAgentInstalled(makeMarkInstalledData(groupId: groupId, memberId: memberId, args: body)))
    }

    throw BridgeError.notFound
}

private func setSocketReadWriteTimeout(_ fd: Int32, seconds: Int) {
    var tv = timeval(tv_sec: seconds, tv_usec: 0)
    let len = socklen_t(MemoryLayout<timeval>.size)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, len)
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, len)
}

private func handleClient(fd: Int32) {
    defer { close(fd) }
    // DO-01: a slow/silent client can no longer pin this worker forever —
    // recv/send return after the timeout, ending the handler.
    setSocketReadWriteTimeout(fd, seconds: socketReadTimeoutSeconds)
    do {
        let data = try readHTTPRequest(fd: fd)
        let request = try parseHTTPRequest(data)
        let response = try routeREST(request)
        _ = response.withUnsafeBytes { send(fd, $0.baseAddress, response.count, 0) }
    } catch let error as BridgeError {
        let response = responseJSON(error.httpStatus, ["error": error.localizedDescription])
        _ = response.withUnsafeBytes { send(fd, $0.baseAddress, response.count, 0) }
    } catch {
        let response = responseJSON(500, ["error": error.localizedDescription])
        _ = response.withUnsafeBytes { send(fd, $0.baseAddress, response.count, 0) }
    }
}

private func runREST() throws -> Never {
    let port = UInt16(ProcessInfo.processInfo.environment["BASTION_API_PORT"] ?? "9587") ?? 9587
    guard tokenLooksHighEntropy(ProcessInfo.processInfo.environment["BASTION_API_TOKEN"]) else {
        fputs("BASTION_API_TOKEN must be set to a high-entropy value of at least 128 estimated bits.\n", stderr)
        exit(1)
    }

    let fd = socket(AF_INET, SOCK_STREAM, 0)
    guard fd >= 0 else { throw BridgeError.xpc("socket failed") }
    var yes: Int32 = 1
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = port.bigEndian
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bindResult = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    guard bindResult == 0 else { throw BridgeError.xpc("bind failed on 127.0.0.1:\(port)") }
    guard listen(fd, 64) == 0 else { throw BridgeError.xpc("listen failed") }
    fputs("Bastion REST API starting on http://127.0.0.1:\(port)\n", stderr)
    // DO-01: bound concurrent handlers so a flood of (even timed-out)
    // connections cannot exhaust the libdispatch worker pool. Combined with the
    // per-connection read timeout this caps worst-case occupancy.
    let admission = DispatchSemaphore(value: maxConcurrentRESTConnections)
    let workQueue = DispatchQueue(label: "com.bastion.mcp.rest", attributes: .concurrent)
    while true {
        let client = accept(fd, nil, nil)
        if client >= 0 {
            admission.wait()
            workQueue.async {
                defer { admission.signal() }
                handleClient(fd: client)
            }
        }
    }
}

let args = CommandLine.arguments.dropFirst()
do {
    if args.first == "rest" || args.first == "--rest" {
        try runREST()
    } else {
        runMCP()
    }
} catch {
    fputs("Fatal: \(error.localizedDescription)\n", stderr)
    exit(1)
}

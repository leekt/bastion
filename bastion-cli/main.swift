import Foundation

// MARK: - XPC Protocol (duplicated for CLI target since BastionShared must be added to both targets)

@objc protocol BastionXPCProtocol {
    func sign(data: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
    func openUI(target: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func getRules(withReply reply: @escaping (Data?, Error?) -> Void)
    func getState(withReply reply: @escaping (Data?, Error?) -> Void)
    func getServiceInfo(withReply reply: @escaping (Data?, Error?) -> Void)
    func resetSigningKeys(withReply reply: @escaping (Data?, Error?) -> Void)
    func signStructured(operationType: String, operationData: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
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

private let userOpFieldHelp = """
Required JSON fields:
  sender, nonce, callData, verificationGasLimit, callGasLimit,
  preVerificationGas, maxPriorityFeePerGas, maxFeePerGas,
  chainId, entryPoint, entryPointVersion ("v0.7"|"v0.8"|"v0.9")

Optional: factory, factoryData, paymaster, paymasterVerificationGasLimit,
          paymasterPostOpGasLimit, paymasterData
"""

private let cliUsage = """
Usage:
  bastion sign --data <32byte hex>              # Legacy: sign raw hash
  bastion eth message <text>                    # EIP-191 personal sign
  bastion eth typedData --json '{...}'          # EIP-712 typed data
  bastion eth typedData --json-file <path>      # EIP-712 typed data from file
  bastion eth userOp --op <target,value,data>   # Build/sign Kernel UserOp from one action
  bastion eth userOp --op <...> --op <...>      # Build/sign Kernel batch UserOp
  bastion eth userOp --send --op <target,value,data>
                                               # Build, sign, and submit via configured ZeroDev project
  bastion eth userOp --json '{...}'             # Advanced: sign explicit ERC-4337 UserOperation
  bastion eth userOp --json-file <path>         # Advanced: UserOperation from file
  bastion eth userOp --send --json-file <path>
                                               # Sign and submit explicit UserOperation via ZeroDev
  bastion pubkey                                # Get public key
  bastion status                                # Check app status
  bastion rules                                 # Get current rules
  bastion state                                 # Get signing state
  bastion reset-keys                            # Delete Bastion signing keys

Wallet groups (owner sudo + scoped agent validators):
  bastion groups create --label <name> [--chain <id>] [--chain <id>]
                                                # Create a shared wallet (requires biometric auth)
  bastion groups list                           # List all wallet groups
  bastion groups show <groupId>                 # Show a group and its members
  bastion groups add-agent <groupId> [--label <name>] [--profile-id <id>]
                                                [--scope-json-file <path>]
                                                # Add an agent with scoped signing power
  bastion groups remove-agent <groupId> <memberId> [--tx <hash>]
                                                # Revoke an agent (deletes its SE key)
  bastion groups mark-installed <groupId> <memberId> --tx <hash> [--validator <addr>]
                                                # Record on-chain validator install (Phase 1 manual)
  bastion groups install-agent <groupId> <memberId> --chain <id> [--submit] [--project-id <id>]
                                                [--wait-seconds <n>]
                                                # Phase 2: build (and optionally submit) the owner-
                                                # signed UserOp that installs the agent's validator.
  bastion groups uninstall-agent <groupId> <memberId> --chain <id> [--submit] [--project-id <id>]
                                                # Phase 2: inverse of install-agent.
  bastion groups update-scope <groupId> <memberId> --scope-json-file <path>
                                                # Tighten/relax an agent's scope

UserOp JSON fields (all byte fields hex-encoded with 0x prefix):
  sender, nonce, callData, verificationGasLimit, callGasLimit,
  preVerificationGas, maxPriorityFeePerGas, maxFeePerGas,
  chainId (int), entryPoint, entryPointVersion ("v0.7"|"v0.8"|"v0.9")
"""

private let userOpIntentHelp = """
High-level UserOp builder:
  --op <target,value,data>
    target = 20-byte hex address
    value  = uint256 in decimal or 0x hex
    data   = hex calldata (use 0x for empty)

Repeat `--op` to build a batch execute() call. `--ops` is accepted as an alias.
High-level builds use Bastion's configured ZeroDev project ID by default.
`--project-id` remains available as an optional override for debugging.
"""

// MARK: - Helpers

func exitWithError(_ message: String) -> Never {
    FileHandle.standardError.write(Data("Error: \(message)\n".utf8))
    exit(1)
}

func exitWithUsage(_ usage: String = cliUsage) -> Never {
    FileHandle.standardError.write(Data((usage + "\n").utf8))
    exit(1)
}

func printJSON<T: Encodable>(_ value: T) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    guard let data = try? encoder.encode(value),
          let json = String(data: data, encoding: .utf8) else {
        exitWithError("Failed to encode response")
    }
    print(json)
}

// MARK: - XPC Connection

func createConnection() -> NSXPCConnection {
    let connection = NSXPCConnection(machServiceName: "com.bastion.xpc", options: [])
    connection.remoteObjectInterface = NSXPCInterface(with: BastionXPCProtocol.self)
    return connection
}

func getProxy(
    _ connection: NSXPCConnection,
    errorHandler: @escaping (Error) -> Void
) -> BastionXPCProtocol {
    guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
        errorHandler(error)
    }) as? BastionXPCProtocol else {
        exitWithError("Failed to get XPC proxy. Is Bastion.app running?")
    }
    return proxy
}

// MARK: - Structured Signing Helper

func readAllStdin() -> Data {
    do {
        return try FileHandle.standardInput.readToEnd() ?? Data()
    } catch {
        exitWithError("Failed to read stdin: \(error.localizedDescription)")
    }
}

func structuredJSONUsage(for commandName: String) -> String {
    var usage = "Usage: bastion eth \(commandName) --json '{...}' or --json-file /path/to/request.json"
    if commandName == "userOp" {
        usage += """

        \(userOpIntentHelp)

        Optional submission flags:
          --send
          --submit      # legacy alias
          --project-id <zerodev-project-id>
          --chain-id <chain-id>   # default: 11155111 for high-level --op path

        If `--submit` is set, Bastion will sign the UserOperation and ask the app
        to immediately send it to the configured bundler after approval. If
        `--project-id` is omitted, Bastion uses the app's configured ZeroDev
        project ID, then falls back to BASTION_ZERODEV_PROJECT_ID when present.

        \(userOpFieldHelp)
        """
    }
    return usage
}

func decodeJSON<T: Decodable>(_ type: T.Type, from data: Data) -> T {
    guard let decoded = try? JSONDecoder().decode(type, from: data) else {
        exitWithError("Invalid response format")
    }
    return decoded
}

func decodeJSONString(_ data: Data) -> String {
    guard let json = String(data: data, encoding: .utf8) else {
        exitWithError("No response data")
    }
    return json
}

func prettyPrintJSONData(_ data: Data) {
    do {
        let object = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        let pretty = try JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys])
        guard let json = String(data: pretty, encoding: .utf8) else {
            exitWithError("Failed to render JSON")
        }
        print(json)
    } catch {
        print(decodeJSONString(data))
    }
}

func performDataRequest(
    timeoutSeconds: Int,
    timeoutMessage: String = "Request timed out",
    _ invoke: (BastionXPCProtocol, @escaping (Data?, Error?) -> Void) -> Void
) -> Data {
    let connection = createConnection()
    let semaphore = DispatchSemaphore(value: 0)
    let completionLock = NSLock()
    var responseData: Data?
    var responseError: Error?
    var completed = false

    func finish(data: Data?, error: Error?) {
        completionLock.lock()
        defer { completionLock.unlock() }
        guard !completed else { return }
        completed = true
        responseData = data
        responseError = error
        semaphore.signal()
    }

    connection.interruptionHandler = {
        finish(
            data: nil,
            error: NSError(
                domain: "com.bastion.cli",
                code: 1,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection interrupted"]
            )
        )
    }
    connection.invalidationHandler = {
        finish(
            data: nil,
            error: NSError(
                domain: "com.bastion.cli",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection invalidated"]
            )
        )
    }
    connection.resume()
    let proxy = getProxy(connection) { error in
        finish(data: nil, error: error)
    }

    invoke(proxy) { data, error in
        finish(data: data, error: error)
    }

    if semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
        connection.invalidate()
        exitWithError(timeoutMessage)
    }

    connection.invalidate()

    if let responseError {
        exitWithError(responseError.localizedDescription)
    }

    guard let responseData else {
        exitWithError("No response data")
    }

    return responseData
}

func performBoolRequest(
    timeoutSeconds: Int,
    timeoutMessage: String,
    _ invoke: (BastionXPCProtocol, @escaping (Bool) -> Void) -> Void
) -> Bool {
    let connection = createConnection()
    let semaphore = DispatchSemaphore(value: 0)
    let completionLock = NSLock()
    var value = false
    var responseError: Error?
    var completed = false

    func finish(result: Bool? = nil, error: Error? = nil) {
        completionLock.lock()
        defer { completionLock.unlock() }
        guard !completed else { return }
        completed = true
        if let result {
            value = result
        }
        responseError = error
        semaphore.signal()
    }

    connection.interruptionHandler = {
        finish(
            error: NSError(
                domain: "com.bastion.cli",
                code: 3,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection interrupted"]
            )
        )
    }
    connection.invalidationHandler = {
        finish(
            error: NSError(
                domain: "com.bastion.cli",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection invalidated"]
            )
        )
    }
    connection.resume()
    let proxy = getProxy(connection) { error in
        finish(error: error)
    }

    invoke(proxy) { result in
        finish(result: result)
    }

    if semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
        connection.invalidate()
        exitWithError(timeoutMessage)
    }

    connection.invalidate()
    if let responseError {
        exitWithError(responseError.localizedDescription)
    }
    return value
}

func resolveStructuredJSONInput(
    _ args: ArraySlice<String>,
    commandName: String
) -> Data {
    var jsonString: String?
    var jsonFilePath: String?

    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--json":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--json requires a value")
            }
            jsonString = args[next]
            i = args.index(after: next)
        case "--json-file":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--json-file requires a path")
            }
            jsonFilePath = args[next]
            i = args.index(after: next)
        default:
            i = args.index(after: i)
        }
    }

    if let json = jsonString {
        guard let data = json.data(using: .utf8) else {
            exitWithError("Invalid JSON string")
        }
        return data
    }

    if let path = jsonFilePath {
        do {
            return try Data(contentsOf: URL(fileURLWithPath: path))
        } catch {
            exitWithError("Failed to read JSON file: \(error.localizedDescription)")
        }
    }

    let stdinData = readAllStdin()
    if !stdinData.isEmpty {
        return stdinData
    }

    exitWithError(structuredJSONUsage(for: commandName))
}

struct UserOperationCommandOptions {
    let requestPayload: Data
}

struct RequestedExecution: Encodable {
    let target: String
    let value: String
    let data: String
}

struct UserOperationIntentRequestEnvelope: Encodable {
    let projectId: String?
    let chainId: Int
    let executions: [RequestedExecution]
    let submit: Bool
}

private func normalizeHexString(_ value: String) -> String {
    value.hasPrefix("0x") || value.hasPrefix("0X") ? value : "0x" + value
}

private func isValidUInt256String(_ value: String) -> Bool {
    if value.hasPrefix("0x") || value.hasPrefix("0X") {
        guard let bytes = Data(hexString: value) else {
            return false
        }
        return bytes.count <= 32
    }

    guard !value.isEmpty else {
        return false
    }

    var bytes = [UInt8](repeating: 0, count: 32)
    for character in value {
        guard let digit = character.wholeNumberValue else {
            return false
        }

        var carry = digit
        for index in stride(from: bytes.count - 1, through: 0, by: -1) {
            let next = Int(bytes[index]) * 10 + carry
            bytes[index] = UInt8(next & 0xff)
            carry = next >> 8
        }

        if carry != 0 {
            return false
        }
    }

    return true
}

private func parseRequestedExecution(_ rawValue: String) -> RequestedExecution {
    let components = rawValue.split(separator: ",", maxSplits: 2, omittingEmptySubsequences: false)
    guard components.count == 3 else {
        exitWithError("--op requires target,value,data")
    }

    let target = components[0].trimmingCharacters(in: .whitespacesAndNewlines)
    let value = components[1].trimmingCharacters(in: .whitespacesAndNewlines)
    let dataValue = components[2].trimmingCharacters(in: .whitespacesAndNewlines)
    let dataHex = dataValue.isEmpty ? "0x" : normalizeHexString(dataValue)

    guard let targetBytes = Data(hexString: target), targetBytes.count == 20 else {
        exitWithError("Invalid --op target address: \(target)")
    }

    guard isValidUInt256String(value) else {
        exitWithError("Invalid --op value (expected uint256 decimal or 0x hex): \(value)")
    }

    guard Data(hexString: dataHex) != nil else {
        exitWithError("Invalid --op calldata hex: \(dataValue)")
    }

    return RequestedExecution(
        target: normalizeHexString(target),
        value: value,
        data: dataHex
    )
}

func resolveUserOperationOptions(_ args: ArraySlice<String>) -> UserOperationCommandOptions {
    var shouldSubmit = false
    var explicitProjectId: String?
    var chainId = 11155111
    var executionInputs = [String]()
    var sawJSONInput = false

    var index = args.startIndex
    while index < args.endIndex {
        switch args[index] {
        case "--submit", "--send":
            shouldSubmit = true
            index = args.index(after: index)
        case "--project-id":
            let next = args.index(after: index)
            guard next < args.endIndex else {
                exitWithError("--project-id requires a value")
            }
            explicitProjectId = args[next]
            index = args.index(after: next)
        case "--chain-id":
            let next = args.index(after: index)
            guard next < args.endIndex else {
                exitWithError("--chain-id requires a value")
            }
            guard let parsed = Int(args[next]) else {
                exitWithError("--chain-id must be an integer")
            }
            chainId = parsed
            index = args.index(after: next)
        case "--op", "--ops":
            let next = args.index(after: index)
            guard next < args.endIndex else {
                exitWithError("\(args[index]) requires a value")
            }
            executionInputs.append(args[next])
            index = args.index(after: next)
        case "--json", "--json-file":
            sawJSONInput = true
            let next = args.index(after: index)
            guard next < args.endIndex else {
                exitWithError("\(args[index]) requires a value")
            }
            index = args.index(after: next)
        default:
            index = args.index(after: index)
        }
    }

    let envProjectId = ProcessInfo.processInfo.environment["BASTION_ZERODEV_PROJECT_ID"]
    let projectId = explicitProjectId ?? envProjectId

    if !executionInputs.isEmpty {
        if sawJSONInput {
            exitWithError("Use either --op/--ops or --json/--json-file, not both")
        }

        let envelope = UserOperationIntentRequestEnvelope(
            projectId: projectId,
            chainId: chainId,
            executions: executionInputs.map(parseRequestedExecution),
            submit: shouldSubmit
        )

        do {
            return UserOperationCommandOptions(
                requestPayload: try JSONEncoder().encode(envelope)
            )
        } catch {
            exitWithError("Failed to encode UserOperation intent request: \(error.localizedDescription)")
        }
    }

    let requestData = resolveStructuredJSONInput(args, commandName: "userOp")

    return UserOperationCommandOptions(
        requestPayload: shouldSubmit ? wrapUserOperationForSubmission(requestData, projectId: projectId) : requestData
    )
}

func wrapUserOperationForSubmission(_ userOpJSON: Data, projectId: String?) -> Data {
    do {
        let object = try JSONSerialization.jsonObject(with: userOpJSON, options: [.fragmentsAllowed])
        guard let userOp = object as? [String: Any] else {
            exitWithError("UserOperation JSON must decode to an object")
        }
        var submission: [String: Any] = [
            "provider": "zerodev",
        ]
        if let projectId, !projectId.isEmpty {
            submission["projectId"] = projectId
        }
        let envelope: [String: Any] = [
            "userOperation": userOp,
            "submission": submission,
        ]
        return try JSONSerialization.data(withJSONObject: envelope, options: [])
    } catch {
        exitWithError("Failed to wrap UserOperation submission request: \(error.localizedDescription)")
    }
}

func callSignStructured(type: String, data: Data) {
    let requestID = UUID().uuidString
    let responseData = performDataRequest(timeoutSeconds: 65, timeoutMessage: "Request timed out (65s)") { proxy, reply in
        proxy.signStructured(operationType: type, operationData: data, requestID: requestID, withReply: reply)
    }
    printJSON(decodeJSON(SignResponse.self, from: responseData))
}

// MARK: - Commands

func cmdSign(dataHex: String) {
    guard dataHex.count == 64,
          let data = Data(hexString: dataHex) else {
        exitWithError("--data must be exactly 32 bytes (64 hex characters)")
    }

    let requestID = UUID().uuidString
    let responseData = performDataRequest(timeoutSeconds: 65, timeoutMessage: "Request timed out (65s)") { proxy, reply in
        proxy.sign(data: data, requestID: requestID, withReply: reply)
    }
    printJSON(decodeJSON(SignResponse.self, from: responseData))
}

func cmdEthMessage(_ args: ArraySlice<String>) {
    guard !args.isEmpty else {
        exitWithError("Usage: bastion eth message <text>")
    }
    let text = args.joined(separator: " ")
    callSignStructured(type: "message", data: Data(text.utf8))
}

func cmdEthTypedData(_ args: ArraySlice<String>) {
    let data = resolveStructuredJSONInput(args, commandName: "typedData")
    callSignStructured(type: "typedData", data: data)
}

func cmdEthUserOp(_ args: ArraySlice<String>) {
    let options = resolveUserOperationOptions(args)
    callSignStructured(type: "userOperation", data: options.requestPayload)
}

func cmdPubkey() {
    let responseData = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.getPublicKey(withReply: reply)
    }
    printJSON(decodeJSON(PublicKeyResponse.self, from: responseData))
}

func cmdStatus() {
    let responseData = performDataRequest(timeoutSeconds: 5, timeoutMessage: "Bastion app is not running") { proxy, reply in
        proxy.getServiceInfo(withReply: reply)
    }
    let info = decodeJSON(ServiceInfoResponse.self, from: responseData)
    printJSON(info)
}

func cmdRules() {
    let responseData = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.getRules(withReply: reply)
    }
    print(decodeJSONString(responseData))
}

func cmdState() {
    let responseData = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.getState(withReply: reply)
    }
    print(decodeJSONString(responseData))
}

func cmdResetKeys() {
    let responseData = performDataRequest(timeoutSeconds: 15, timeoutMessage: "Reset keys request timed out") { proxy, reply in
        proxy.resetSigningKeys(withReply: reply)
    }
    printJSON(decodeJSON(ResetSigningKeysResponse.self, from: responseData))
}

// MARK: - Wallet Group Commands

/// Server-pretty JSON is sufficient — the CLI does not need to decode into
/// typed structs because the rule-config payloads are deeply nested.
private func printRawServerJSON(_ data: Data) {
    if data.isEmpty {
        print("{}")
        return
    }
    if let obj = try? JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed]),
       let pretty = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]),
       let text = String(data: pretty, encoding: .utf8) {
        print(text)
        return
    }
    print(String(data: data, encoding: .utf8) ?? "")
}

private func readScopeJSON(from args: ArraySlice<String>) -> Data? {
    var i = args.startIndex
    while i < args.endIndex {
        let arg = args[i]
        if arg == "--scope-json-file" {
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--scope-json-file requires a path argument")
            }
            let path = args[next]
            guard let data = try? Data(contentsOf: URL(fileURLWithPath: path)) else {
                exitWithError("Failed to read scope JSON from \(path)")
            }
            // Validate it's valid JSON before forwarding.
            guard (try? JSONSerialization.jsonObject(with: data)) != nil else {
                exitWithError("Scope file at \(path) is not valid JSON")
            }
            return data
        }
        if arg == "--scope-json" {
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--scope-json requires a JSON string argument")
            }
            let inline = args[next].data(using: .utf8) ?? Data()
            guard (try? JSONSerialization.jsonObject(with: inline)) != nil else {
                exitWithError("--scope-json value is not valid JSON")
            }
            return inline
        }
        i = args.index(after: i)
    }
    return nil
}

private func optionValue(_ args: ArraySlice<String>, flag: String) -> String? {
    var i = args.startIndex
    while i < args.endIndex {
        if args[i] == flag {
            let next = args.index(after: i)
            if next < args.endIndex {
                return args[next]
            }
            exitWithError("\(flag) requires a value")
        }
        i = args.index(after: i)
    }
    return nil
}

private func optionValues(_ args: ArraySlice<String>, flag: String) -> [String] {
    var out: [String] = []
    var i = args.startIndex
    while i < args.endIndex {
        if args[i] == flag {
            let next = args.index(after: i)
            if next < args.endIndex {
                out.append(args[next])
            }
        }
        i = args.index(after: i)
    }
    return out
}

func cmdGroupsCreate(_ args: ArraySlice<String>) {
    guard let label = optionValue(args, flag: "--label") else {
        exitWithError("Usage: bastion groups create --label <name> [--chain <id>]")
    }
    let chains = optionValues(args, flag: "--chain").compactMap { Int($0) }

    var body: [String: Any] = ["label": label, "chainIds": chains]
    if let scopeData = readScopeJSON(from: args),
       let scope = try? JSONSerialization.jsonObject(with: scopeData) {
        body["sharedRules"] = scope
    }

    guard let requestData = try? JSONSerialization.data(withJSONObject: body) else {
        exitWithError("Failed to serialize create-group request")
    }

    let response = performDataRequest(timeoutSeconds: 30, timeoutMessage: "Create wallet group timed out") { proxy, reply in
        proxy.createWalletGroup(requestData: requestData, withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsList() {
    let response = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.listWalletGroups(withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsShow(_ args: ArraySlice<String>) {
    guard let groupId = args.first else {
        exitWithError("Usage: bastion groups show <groupId>")
    }
    let response = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.getWalletGroup(groupId: groupId, withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsAddAgent(_ args: ArraySlice<String>) {
    guard let groupId = args.first else {
        exitWithError("Usage: bastion groups add-agent <groupId> [--label <n>] [--profile-id <id>] [--scope-json-file <path>]")
    }
    let rest = args.dropFirst()
    let label = optionValue(rest, flag: "--label")
    let profileId = optionValue(rest, flag: "--profile-id")

    var body: [String: Any] = ["groupId": groupId]
    if let label { body["label"] = label }
    if let profileId { body["clientProfileId"] = profileId }
    if let scopeData = readScopeJSON(from: rest),
       let scope = try? JSONSerialization.jsonObject(with: scopeData) {
        body["scopedRules"] = scope
    }

    guard let requestData = try? JSONSerialization.data(withJSONObject: body) else {
        exitWithError("Failed to serialize add-agent request")
    }

    let response = performDataRequest(timeoutSeconds: 30, timeoutMessage: "Add agent timed out") { proxy, reply in
        proxy.addAgentToGroup(requestData: requestData, withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsRemoveAgent(_ args: ArraySlice<String>) {
    guard args.count >= 2 else {
        exitWithError("Usage: bastion groups remove-agent <groupId> <memberId> [--tx <hash>]")
    }
    let groupId = args[args.startIndex]
    let memberId = args[args.index(after: args.startIndex)]
    let rest = args.dropFirst(2)
    let txHash = optionValue(rest, flag: "--tx")

    let response = performDataRequest(timeoutSeconds: 30, timeoutMessage: "Remove agent timed out") { proxy, reply in
        proxy.removeAgentFromGroup(
            groupId: groupId,
            memberId: memberId,
            txHash: txHash,
            withReply: reply
        )
    }
    printRawServerJSON(response)
    print("Agent \(memberId) revoked from group \(groupId). SE key deleted.")
}

func cmdGroupsUpdateScope(_ args: ArraySlice<String>) {
    guard args.count >= 2 else {
        exitWithError("Usage: bastion groups update-scope <groupId> <memberId> --scope-json-file <path>")
    }
    let groupId = args[args.startIndex]
    let memberId = args[args.index(after: args.startIndex)]
    let rest = args.dropFirst(2)
    guard let scopeData = readScopeJSON(from: rest),
          let scope = try? JSONSerialization.jsonObject(with: scopeData) else {
        exitWithError("--scope-json-file or --scope-json is required")
    }

    let body: [String: Any] = [
        "groupId": groupId,
        "memberId": memberId,
        "scopedRules": scope
    ]
    guard let requestData = try? JSONSerialization.data(withJSONObject: body) else {
        exitWithError("Failed to serialize update-scope request")
    }

    _ = performDataRequest(timeoutSeconds: 30, timeoutMessage: "Update scope timed out") { proxy, reply in
        proxy.updateAgentScope(requestData: requestData, withReply: reply)
    }
    print("Scope updated for agent \(memberId) in group \(groupId).")
}

func cmdGroupsInstallAgentOnChain(_ args: ArraySlice<String>) {
    guard args.count >= 2 else {
        exitWithError("Usage: bastion groups install-agent <groupId> <memberId> --chain <id> [--submit] [--project-id <id>] [--wait-seconds <n>]")
    }
    let groupId = args[args.startIndex]
    let memberId = args[args.index(after: args.startIndex)]
    let rest = args.dropFirst(2)
    guard let chainIdStr = optionValue(rest, flag: "--chain"),
          let chainId = Int(chainIdStr) else {
        exitWithError("--chain <id> is required")
    }
    let projectId = optionValue(rest, flag: "--project-id")
    let submit = rest.contains("--submit")
    let wait = optionValue(rest, flag: "--wait-seconds").flatMap(Int.init)

    var body: [String: Any] = [
        "groupId": groupId,
        "memberId": memberId,
        "chainId": chainId,
        "submit": submit
    ]
    if let projectId { body["projectId"] = projectId }
    if let wait { body["waitForReceiptSeconds"] = wait }

    guard let requestData = try? JSONSerialization.data(withJSONObject: body) else {
        exitWithError("Failed to serialize install-agent request")
    }

    // Install flows can take a while (bundler + receipt polling). Generous timeout.
    let timeout = max(45, (wait ?? 30) + 15)
    let response = performDataRequest(timeoutSeconds: timeout, timeoutMessage: "On-chain install timed out") { proxy, reply in
        proxy.installAgentOnChain(requestData: requestData, withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsUninstallAgentOnChain(_ args: ArraySlice<String>) {
    guard args.count >= 2 else {
        exitWithError("Usage: bastion groups uninstall-agent <groupId> <memberId> --chain <id> [--submit] [--project-id <id>] [--wait-seconds <n>]")
    }
    let groupId = args[args.startIndex]
    let memberId = args[args.index(after: args.startIndex)]
    let rest = args.dropFirst(2)
    guard let chainIdStr = optionValue(rest, flag: "--chain"),
          let chainId = Int(chainIdStr) else {
        exitWithError("--chain <id> is required")
    }
    let projectId = optionValue(rest, flag: "--project-id")
    let submit = rest.contains("--submit")
    let wait = optionValue(rest, flag: "--wait-seconds").flatMap(Int.init)

    var body: [String: Any] = [
        "groupId": groupId,
        "memberId": memberId,
        "chainId": chainId,
        "submit": submit
    ]
    if let projectId { body["projectId"] = projectId }
    if let wait { body["waitForReceiptSeconds"] = wait }

    guard let requestData = try? JSONSerialization.data(withJSONObject: body) else {
        exitWithError("Failed to serialize uninstall-agent request")
    }

    let timeout = max(45, (wait ?? 30) + 15)
    let response = performDataRequest(timeoutSeconds: timeout, timeoutMessage: "On-chain uninstall timed out") { proxy, reply in
        proxy.uninstallAgentOnChain(requestData: requestData, withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsMarkInstalled(_ args: ArraySlice<String>) {
    guard args.count >= 2 else {
        exitWithError("Usage: bastion groups mark-installed <groupId> <memberId> --tx <hash> [--validator <addr>]")
    }
    let groupId = args[args.startIndex]
    let memberId = args[args.index(after: args.startIndex)]
    let rest = args.dropFirst(2)
    guard let txHash = optionValue(rest, flag: "--tx") else {
        exitWithError("--tx <hash> is required")
    }
    let validatorAddress = optionValue(rest, flag: "--validator")

    var body: [String: Any] = [
        "groupId": groupId,
        "memberId": memberId,
        "txHash": txHash
    ]
    if let validatorAddress { body["validatorAddress"] = validatorAddress }

    guard let requestData = try? JSONSerialization.data(withJSONObject: body) else {
        exitWithError("Failed to serialize mark-installed request")
    }

    let response = performDataRequest(timeoutSeconds: 30, timeoutMessage: "Mark installed timed out") { proxy, reply in
        proxy.markAgentInstalled(requestData: requestData, withReply: reply)
    }
    printRawServerJSON(response)
}

// MARK: - Response Types (duplicated for CLI target)

struct SignResponse: Codable {
    let pubkeyX: String
    let pubkeyY: String
    let r: String
    let s: String
    let accountAddress: String?
    let clientBundleId: String?
    let submission: UserOperationSubmissionResponse?
}

struct UserOperationSubmissionResponse: Codable {
    let provider: String
    let status: String
    let userOpHash: String?
    let transactionHash: String?
    let error: String?
}

struct PublicKeyResponse: Codable {
    let x: String
    let y: String
}

struct ServiceInfoResponse: Codable {
    let version: String
    let serviceRegistrationStatus: String
    let configCorrupted: Bool
}

struct ResetSigningKeysResponse: Codable {
    let deletedKeyTags: [String]
    let requestedKeyTags: [String]
}

// MARK: - Hex Helpers

extension Data {
    init?(hexString: String) {
        var hex = hexString.hasPrefix("0x") ? String(hexString.dropFirst(2)) : hexString
        if hex.count.isMultiple(of: 2) == false {
            hex = "0" + hex
        }
        let len = hex.count / 2
        var data = Data(capacity: len)
        var index = hex.startIndex
        for _ in 0..<len {
            let nextIndex = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}

// MARK: - Main

let args = CommandLine.arguments

guard args.count >= 2 else {
    exitWithUsage()
}

switch args[1] {
case "sign":
    guard args.count >= 4, args[2] == "--data" else {
        exitWithError("Usage: bastion sign --data <32byte hex>")
    }
    cmdSign(dataHex: args[3])

case "eth":
    guard args.count >= 3 else {
        exitWithError("Usage: bastion eth <message|typedData|userOp> ...")
    }
    switch args[2] {
    case "message":
        cmdEthMessage(args[3...])
    case "typedData":
        cmdEthTypedData(args[3...])
    case "userOp":
        cmdEthUserOp(args[3...])
    default:
        exitWithError("Unknown eth subcommand: \(args[2]). Use: message, typedData, userOp")
    }

case "pubkey":
    cmdPubkey()

case "status":
    cmdStatus()

case "rules":
    cmdRules()

case "state":
    cmdState()

case "reset-keys":
    cmdResetKeys()

case "groups":
    guard args.count >= 3 else {
        exitWithError("Usage: bastion groups <create|list|show|add-agent|remove-agent|update-scope|mark-installed> ...")
    }
    switch args[2] {
    case "create":
        cmdGroupsCreate(args[3...])
    case "list":
        cmdGroupsList()
    case "show":
        cmdGroupsShow(args[3...])
    case "add-agent":
        cmdGroupsAddAgent(args[3...])
    case "remove-agent":
        cmdGroupsRemoveAgent(args[3...])
    case "update-scope":
        cmdGroupsUpdateScope(args[3...])
    case "mark-installed":
        cmdGroupsMarkInstalled(args[3...])
    case "install-agent":
        cmdGroupsInstallAgentOnChain(args[3...])
    case "uninstall-agent":
        cmdGroupsUninstallAgentOnChain(args[3...])
    default:
        exitWithError("Unknown groups subcommand: \(args[2]). Use: create, list, show, add-agent, remove-agent, update-scope, mark-installed, install-agent, uninstall-agent")
    }

default:
    exitWithError("Unknown command: \(args[1])")
}

import Foundation
import Security

let maxReceiptWaitSeconds = 120

// MARK: - XPC Protocol (duplicated for CLI target since BastionShared must be added to both targets)

@objc protocol BastionXPCProtocol {
    func sign(data: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
    func openUI(target: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func probeUI(target: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeSettingsScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeMenuScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeWalletGroupScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeAuditHistoryScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeRuntimeStateScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeUpdateScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeKeyLifecycleScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func probeLiveRuntimeScenario(scenario: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func deliverNotificationProbe(probeID: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func triggerNotificationClickProbe(probeID: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func deliverUserOperationNotificationProbe(probeID: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func triggerUserOperationNotificationClickProbe(probeID: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func getRules(withReply reply: @escaping (Data?, Error?) -> Void)
    func getState(withReply reply: @escaping (Data?, Error?) -> Void)
    func getServiceInfo(withReply reply: @escaping (Data?, Error?) -> Void)
    func exportSupportBundle(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
    func resetSigningKeys(withReply reply: @escaping (Data?, Error?) -> Void)
    func rotateClientKey(requestData: Data, withReply reply: @escaping (Data?, Error?) -> Void)
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
    func startPairing(bundleId: String, processName: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func pollPairing(requestId: String, withReply reply: @escaping (Data?, Error?) -> Void)
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
  bastion open-ui <settings|auditHistory|diagnostics>
                                               # Ask the registered service to open a UI target
  bastion ui-probe <settings|auditHistory|diagnostics|approvalPolicy|approvalViolation>
                                               # Open a UI target and return in-process window metadata
  bastion settings-scenario-probe <saveDiff|postureControls|authPolicy|projectId|rpcChain|rpcProbe|ruleTemplates|targetAdd|targetRemove|globalCaps|addressBook|highValue|policyHistory|policySimulator>
                                               # Run a read-only Settings presentation scenario in the signed app
  bastion menu-scenario-probe <overview>        # Run a read-only menu-bar presentation scenario in the signed app
  bastion wallet-group-scenario-probe <overview>
                                               # Run a read-only wallet-group presentation scenario in the signed app
  bastion audit-history-scenario-probe <overview>
                                               # Run a read-only Audit History presentation scenario in the signed app
  bastion runtime-state-scenario-probe <overview>
                                               # Run a read-only runtime state/presentation scenario in the signed app
  bastion update-scenario-probe <overview>      # Run an update check/download/install scenario in the signed app
  bastion key-lifecycle-scenario-probe <overview>
                                               # Run a non-destructive key reset/rotation scenario in the signed app
  bastion live-runtime-scenario-probe <overview>
                                               # Run installed-service live runtime checks in the signed app
  bastion notification-probe [--id <probeId>]   # Deliver a clickable lifecycle probe notification
  bastion notification-click-probe [--id <probeId>]
                                               # Exercise notification click routing through XPC
  bastion userop-notification-probe [--id <probeId>]
                                               # Deliver a UserOperation result notification probe
  bastion userop-notification-click-probe [--id <probeId>]
                                               # Exercise UserOperation notification click routing
  bastion rules                                 # Get current rules
  bastion state                                 # Get signing state
  bastion support-bundle [--output <path>]      # Export redacted support JSON
  bastion update check --manifest-url <url>     # Check release manifest
  bastion update download --manifest-url <url>  # Download and verify update ZIP
  bastion update install --manifest-url <url>   # Install verified staged/downloaded ZIP
  bastion reset-keys                            # Delete Bastion signing keys
  bastion rotate-client-key <profileId>         # Rotate one private-client SE key

Pairing (first-run handshake):
  bastion pair [--label <name>] [--bundle-id <id>]
                                                # Print a pairing code and wait for owner approval

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

private final class AsyncResultBox<T>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Result<T, Error>?

    func set(_ newValue: Result<T, Error>) {
        lock.lock()
        value = newValue
        lock.unlock()
    }

    func get() -> Result<T, Error>? {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}

func runAsync<T>(_ operation: @escaping () async throws -> T) -> T {
    let semaphore = DispatchSemaphore(value: 0)
    let outcome = AsyncResultBox<T>()

    Task {
        do {
            let value = try await operation()
            outcome.set(.success(value))
        } catch {
            outcome.set(.failure(error))
        }
        semaphore.signal()
    }

    semaphore.wait()

    switch outcome.get() {
    case .success(let value):
        return value
    case .failure(let error):
        exitWithError(error.localizedDescription)
    case nil:
        exitWithError("Async operation did not complete")
    }
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
                userInfo: [NSLocalizedDescriptionKey: "XPC connection interrupted — ensure the signed Bastion app and service are running"]
            )
        )
    }
    connection.invalidationHandler = {
        finish(
            data: nil,
            error: NSError(
                domain: "com.bastion.cli",
                code: 2,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection invalidated — ensure the signed Bastion app and service are running"]
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
                userInfo: [NSLocalizedDescriptionKey: "XPC connection interrupted — ensure the signed Bastion app and service are running"]
            )
        )
    }
    connection.invalidationHandler = {
        finish(
            error: NSError(
                domain: "com.bastion.cli",
                code: 4,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection invalidated — ensure the signed Bastion app and service are running"]
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

func performBoolErrorRequest(
    timeoutSeconds: Int,
    timeoutMessage: String,
    _ invoke: (BastionXPCProtocol, @escaping (Bool, Error?) -> Void) -> Void
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
                code: 5,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection interrupted — ensure the signed Bastion app and service are running"]
            )
        )
    }
    connection.invalidationHandler = {
        finish(
            error: NSError(
                domain: "com.bastion.cli",
                code: 6,
                userInfo: [NSLocalizedDescriptionKey: "XPC connection invalidated — ensure the signed Bastion app and service are running"]
            )
        )
    }
    connection.resume()
    let proxy = getProxy(connection) { error in
        finish(error: error)
    }

    invoke(proxy) { result, error in
        finish(result: result, error: error)
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
    guard let data = Data(hexString: dataHex),
          data.count == 32 else {
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

func cmdOpenUI(_ args: ArraySlice<String>) {
    guard args.count == 1, let target = args.first else {
        exitWithError("Usage: bastion open-ui <settings|auditHistory|diagnostics>")
    }
    let allowedTargets = ["settings", "auditHistory", "diagnostics"]
    guard allowedTargets.contains(target) else {
        exitWithError("Unknown UI target: \(target). Use settings, auditHistory, or diagnostics.")
    }

    let opened = performBoolErrorRequest(
        timeoutSeconds: 5,
        timeoutMessage: "Timed out opening \(target)"
    ) { proxy, reply in
        proxy.openUI(target: target, withReply: reply)
    }

    guard opened else {
        exitWithError("Bastion service refused to open \(target)")
    }

    printJSON(OpenUIResponse(target: target, opened: opened))
}

func cmdUIProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let target = args.first else {
        exitWithError("Usage: bastion ui-probe <settings|auditHistory|diagnostics|approvalPolicy|approvalViolation>")
    }
    let allowedTargets = ["settings", "auditHistory", "diagnostics", "approvalPolicy", "approvalViolation"]
    guard allowedTargets.contains(target) else {
        exitWithError("Unknown UI target: \(target). Use settings, auditHistory, diagnostics, approvalPolicy, or approvalViolation.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing \(target)"
    ) { proxy, reply in
        proxy.probeUI(target: target, withReply: reply)
    }

    printJSON(decodeJSON(UIProbeResponse.self, from: responseData))
}

func cmdSettingsScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion settings-scenario-probe <saveDiff|postureControls|authPolicy|projectId|rpcChain|rpcProbe|ruleTemplates|targetAdd|targetRemove|globalCaps|addressBook|highValue|policyHistory|policySimulator>")
    }
    let allowedScenarios = ["saveDiff", "postureControls", "authPolicy", "projectId", "rpcChain", "rpcProbe", "ruleTemplates", "targetAdd", "targetRemove", "globalCaps", "addressBook", "highValue", "policyHistory", "policySimulator"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown Settings scenario: \(scenario). Use saveDiff, postureControls, authPolicy, projectId, rpcChain, rpcProbe, targetAdd, targetRemove, globalCaps, addressBook, highValue, policyHistory, or policySimulator.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing Settings scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeSettingsScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdMenuScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion menu-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown menu scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing menu scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeMenuScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdWalletGroupScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion wallet-group-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown wallet-group scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing wallet-group scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeWalletGroupScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdAuditHistoryScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion audit-history-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown audit-history scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing audit-history scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeAuditHistoryScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdRuntimeStateScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion runtime-state-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown runtime-state scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing runtime-state scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeRuntimeStateScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdUpdateScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion update-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown update scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 15,
        timeoutMessage: "Timed out probing update scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeUpdateScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdKeyLifecycleScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion key-lifecycle-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown key lifecycle scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 8,
        timeoutMessage: "Timed out probing key lifecycle scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeKeyLifecycleScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdLiveRuntimeScenarioProbe(_ args: ArraySlice<String>) {
    guard args.count == 1, let scenario = args.first else {
        exitWithError("Usage: bastion live-runtime-scenario-probe <overview>")
    }
    let allowedScenarios = ["overview"]
    guard allowedScenarios.contains(scenario) else {
        exitWithError("Unknown live-runtime scenario: \(scenario). Use overview.")
    }

    let responseData = performDataRequest(
        timeoutSeconds: 15,
        timeoutMessage: "Timed out probing live-runtime scenario \(scenario)"
    ) { proxy, reply in
        proxy.probeLiveRuntimeScenario(scenario: scenario, withReply: reply)
    }

    prettyPrintJSONData(responseData)
}

func cmdNotificationProbe(_ args: ArraySlice<String>) {
    var probeID = UUID().uuidString
    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--id":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--id requires a value")
            }
            probeID = args[next]
            i = args.index(after: next)
        default:
            exitWithError("Usage: bastion notification-probe [--id <probeId>]")
        }
    }

    let requested = performBoolErrorRequest(
        timeoutSeconds: 5,
        timeoutMessage: "Timed out requesting lifecycle notification probe"
    ) { proxy, reply in
        proxy.deliverNotificationProbe(probeID: probeID, withReply: reply)
    }

    guard requested else {
        exitWithError("Bastion service refused lifecycle notification probe")
    }

    printJSON(NotificationProbeResponse(probeID: probeID, requested: requested))
}

func cmdNotificationClickProbe(_ args: ArraySlice<String>) {
    var probeID = UUID().uuidString
    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--id":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--id requires a value")
            }
            probeID = args[next]
            i = args.index(after: next)
        default:
            exitWithError("Usage: bastion notification-click-probe [--id <probeId>]")
        }
    }

    let opened = performBoolErrorRequest(
        timeoutSeconds: 5,
        timeoutMessage: "Timed out triggering lifecycle notification click probe"
    ) { proxy, reply in
        proxy.triggerNotificationClickProbe(probeID: probeID, withReply: reply)
    }

    guard opened else {
        exitWithError("Bastion service refused lifecycle notification click probe")
    }

    printJSON(NotificationClickProbeResponse(probeID: probeID, opened: opened))
}

func cmdUserOperationNotificationProbe(_ args: ArraySlice<String>) {
    var probeID = UUID().uuidString
    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--id":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--id requires a value")
            }
            probeID = args[next]
            i = args.index(after: next)
        default:
            exitWithError("Usage: bastion userop-notification-probe [--id <probeId>]")
        }
    }

    let requested = performBoolErrorRequest(
        timeoutSeconds: 5,
        timeoutMessage: "Timed out requesting UserOperation notification probe"
    ) { proxy, reply in
        proxy.deliverUserOperationNotificationProbe(probeID: probeID, withReply: reply)
    }

    guard requested else {
        exitWithError("Bastion service refused UserOperation notification probe")
    }

    printJSON(UserOperationNotificationProbeResponse(probeID: probeID, requested: requested))
}

func cmdUserOperationNotificationClickProbe(_ args: ArraySlice<String>) {
    var probeID = UUID().uuidString
    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--id":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--id requires a value")
            }
            probeID = args[next]
            i = args.index(after: next)
        default:
            exitWithError("Usage: bastion userop-notification-click-probe [--id <probeId>]")
        }
    }

    let opened = performBoolErrorRequest(
        timeoutSeconds: 5,
        timeoutMessage: "Timed out triggering UserOperation notification click probe"
    ) { proxy, reply in
        proxy.triggerUserOperationNotificationClickProbe(probeID: probeID, withReply: reply)
    }

    guard opened else {
        exitWithError("Bastion service refused UserOperation notification click probe")
    }

    printJSON(UserOperationNotificationClickProbeResponse(probeID: probeID, opened: opened))
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

func cmdSupportBundle(_ args: ArraySlice<String>) {
    var outputPath: String?
    var maxAuditRecords: Int?
    var maxDiagnosticEntries: Int?
    var maxCrashReports: Int?

    func parseLimit(_ rawValue: String, flag: String, maximum: Int) -> Int {
        guard let value = Int(rawValue) else {
            exitWithError("\(flag) requires an integer")
        }
        guard value >= 1, value <= maximum else {
            exitWithError("\(flag) must be between 1 and \(maximum)")
        }
        return value
    }

    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--output", "-o":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--output requires a path")
            }
            outputPath = args[next]
            i = args.index(after: next)
        case "--audit-limit":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--audit-limit requires a value")
            }
            maxAuditRecords = parseLimit(args[next], flag: "--audit-limit", maximum: 200)
            i = args.index(after: next)
        case "--diagnostics-limit":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--diagnostics-limit requires a value")
            }
            maxDiagnosticEntries = parseLimit(args[next], flag: "--diagnostics-limit", maximum: 1000)
            i = args.index(after: next)
        case "--crash-limit":
            let next = args.index(after: i)
            guard next < args.endIndex else {
                exitWithError("--crash-limit requires a value")
            }
            maxCrashReports = parseLimit(args[next], flag: "--crash-limit", maximum: 50)
            i = args.index(after: next)
        default:
            exitWithError("Unknown support-bundle option: \(args[i])")
        }
    }

    let request = SupportBundleRequest(
        maxAuditRecords: maxAuditRecords,
        maxDiagnosticEntries: maxDiagnosticEntries,
        maxCrashReports: maxCrashReports
    )
    guard let requestData = try? JSONEncoder().encode(request) else {
        exitWithError("Failed to serialize support bundle request")
    }
    let responseData = performDataRequest(timeoutSeconds: 20, timeoutMessage: "Support bundle export timed out") { proxy, reply in
        proxy.exportSupportBundle(requestData: requestData, withReply: reply)
    }

    if let outputPath {
        do {
            try responseData.write(to: URL(fileURLWithPath: outputPath), options: .atomic)
            print(outputPath)
        } catch {
            exitWithError("Failed to write support bundle: \(error.localizedDescription)")
        }
    } else {
        print(decodeJSONString(responseData))
    }
}

func cmdResetKeys() {
    let responseData = performDataRequest(timeoutSeconds: 15, timeoutMessage: "Reset keys request timed out") { proxy, reply in
        proxy.resetSigningKeys(withReply: reply)
    }
    printJSON(decodeJSON(ResetSigningKeysResponse.self, from: responseData))
}

func cmdRotateClientKey(_ args: ArraySlice<String>) {
    guard let profileId = args.first, args.count == 1 else {
        exitWithError("Usage: bastion rotate-client-key <profileId>")
    }
    let request = RotateClientKeyRequest(profileId: profileId)
    guard let requestData = try? JSONEncoder().encode(request) else {
        exitWithError("Failed to serialize key rotation request")
    }
    let responseData = performDataRequest(timeoutSeconds: 30, timeoutMessage: "Rotate client key request timed out") { proxy, reply in
        proxy.rotateClientKey(requestData: requestData, withReply: reply)
    }
    printJSON(decodeJSON(ClientKeyRotationResult.self, from: responseData))
}

// MARK: - Updates

private let updateUsage = """
Usage:
  bastion update check --manifest-url <url>
  bastion update download --manifest-url <url> [--output <directory>] [--force]
  bastion update install --manifest-url <url> [--artifact <zip>] [--install-path <path>] [--force]

Options:
  --manifest-url <url>       latest.json URL. Defaults to BASTION_UPDATE_MANIFEST_URL.
  --output <directory>       Download directory for `download`; defaults to Application Support.
  --artifact <zip>           Use an already-staged ZIP for `install`; otherwise downloads first.
  --install-path <path>      App install target; defaults to inferred host app or /Applications/Bastion.app.
  --backup-directory <path>  Directory for rollback backups; defaults beside install target.
  --app-bundle <path>        Installed Bastion.app path. Usually inferred from bundled CLI.
  --current-version <value>  Override current version for dry-run/testing.
  --current-build <value>    Override current build for dry-run/testing.
  --bundle-id <value>        Override current bundle id with version/build overrides.
  --force                    Download even when manifest is not newer.
  --no-relaunch              Install but do not relaunch Bastion.
  --skip-service-recovery    Install but do not register/kickstart/verify the XPC service.
  --skip-cli-symlink         Install but do not update /usr/local/bin/bastion.
  --skip-app-verification    Skip codesign, Gatekeeper, and stapler checks after hash/identity verification.
"""

func cmdUpdate(_ args: ArraySlice<String>) {
    guard let subcommand = args.first else {
        exitWithError(updateUsage)
    }
    let rest = args.dropFirst()
    switch subcommand {
    case "check":
        printJSON(updateCheck(rest, shouldDownload: false))
    case "download":
        printJSON(updateCheck(rest, shouldDownload: true))
    case "install":
        printJSON(updateInstall(rest))
    default:
        exitWithError("Unknown update subcommand: \(subcommand). Use: check, download, install")
    }
}

private func updateCheck(_ args: ArraySlice<String>, shouldDownload: Bool) -> ReleaseUpdateCheckResult {
    let manifestURLString = optionValue(args, flag: "--manifest-url")
        ?? ProcessInfo.processInfo.environment["BASTION_UPDATE_MANIFEST_URL"]
    guard let manifestURLString, let manifestURL = URL(string: manifestURLString) else {
        exitWithError("--manifest-url is required unless BASTION_UPDATE_MANIFEST_URL is set")
    }

    let current = resolveCurrentReleaseIdentity(args)
    let manifest = runAsync {
        try await ReleaseUpdateVerifier.loadManifest(from: manifestURL)
    }
    let result = ReleaseUpdateVerifier.evaluate(manifest: manifest, current: current)

    guard shouldDownload else {
        return result
    }

    let force = args.contains("--force")
    guard result.state == .updateAvailable || force else {
        return result
    }

    let outputDirectory = optionValue(args, flag: "--output")
        .map { URL(fileURLWithPath: $0, isDirectory: true) }
        ?? ReleaseUpdateVerifier.appSupportUpdateDirectory()

    let artifact = runAsync {
        try await ReleaseUpdateVerifier.downloadAndVerify(
            manifest: manifest,
            outputDirectory: outputDirectory
        )
    }

    return ReleaseUpdateCheckResult(
        state: result.state,
        reason: result.reason,
        current: result.current,
        manifest: result.manifest,
        artifact: artifact
    )
}

private func resolveCurrentReleaseIdentity(_ args: ArraySlice<String>) -> InstalledReleaseIdentity {
    let explicitVersion = optionValue(args, flag: "--current-version")
    let explicitBuild = optionValue(args, flag: "--current-build")
    if explicitVersion != nil || explicitBuild != nil {
        guard let explicitVersion, let explicitBuild else {
            exitWithError("--current-version and --current-build must be provided together")
        }
        return InstalledReleaseIdentity(
            bundleIdentifier: optionValue(args, flag: "--bundle-id") ?? ReleaseUpdateVerifier.expectedBundleIdentifier,
            version: explicitVersion,
            build: explicitBuild
        )
    }

    let appBundleURL = optionValue(args, flag: "--app-bundle")
        .map { URL(fileURLWithPath: $0, isDirectory: true) }
        ?? inferredHostAppBundleURL()

    do {
        return try ReleaseUpdateVerifier.currentIdentity(appBundleURL: appBundleURL)
    } catch {
        exitWithError("\(error.localizedDescription). Use --app-bundle or --current-version/--current-build.")
    }
}

private func updateInstall(_ args: ArraySlice<String>) -> ReleaseUpdateInstallResult {
    let manifestURLString = optionValue(args, flag: "--manifest-url")
        ?? ProcessInfo.processInfo.environment["BASTION_UPDATE_MANIFEST_URL"]
    guard let manifestURLString, let manifestURL = URL(string: manifestURLString) else {
        exitWithError("--manifest-url is required unless BASTION_UPDATE_MANIFEST_URL is set")
    }

    let current = resolveCurrentReleaseIdentity(args)
    let manifest = runAsync {
        try await ReleaseUpdateVerifier.loadManifest(from: manifestURL)
    }
    let result = ReleaseUpdateVerifier.evaluate(manifest: manifest, current: current)
    let force = args.contains("--force")
    guard result.state == .updateAvailable || force else {
        exitWithError("\(result.reason). Use --force to install anyway.")
    }

    let artifact: ReleaseUpdateArtifact
    if let artifactPath = optionValue(args, flag: "--artifact") {
        do {
            artifact = try ReleaseUpdateVerifier.verifyArtifact(
                at: URL(fileURLWithPath: artifactPath),
                manifest: manifest
            )
        } catch {
            exitWithError(error.localizedDescription)
        }
    } else {
        let outputDirectory = optionValue(args, flag: "--output")
            .map { URL(fileURLWithPath: $0, isDirectory: true) }
            ?? ReleaseUpdateVerifier.appSupportUpdateDirectory()
        artifact = runAsync {
            try await ReleaseUpdateVerifier.downloadAndVerify(
                manifest: manifest,
                outputDirectory: outputDirectory
            )
        }
    }

    let installURL = optionValue(args, flag: "--install-path")
        .map { URL(fileURLWithPath: $0, isDirectory: true) }
        ?? inferredHostAppBundleURL()
        ?? URL(fileURLWithPath: "/Applications/Bastion.app", isDirectory: true)
    let backupDirectory = optionValue(args, flag: "--backup-directory")
        .map { URL(fileURLWithPath: $0, isDirectory: true) }

    do {
        return try ReleaseUpdateInstaller.installStagedArtifact(
            manifest: manifest,
            artifact: artifact,
            installURL: installURL,
            backupDirectory: backupDirectory,
            relaunch: !args.contains("--no-relaunch"),
            recoverService: !args.contains("--skip-service-recovery"),
            installCLISymlink: !args.contains("--skip-cli-symlink"),
            verifyAppBundle: !args.contains("--skip-app-verification")
        )
    } catch {
        exitWithError(error.localizedDescription)
    }
}

private func inferredHostAppBundleURL() -> URL? {
    guard let executablePath = CommandLine.arguments.first else {
        return nil
    }
    let executableURL = URL(fileURLWithPath: executablePath)
    guard executableURL.lastPathComponent == "bastion-cli" else {
        return nil
    }
    let macOSURL = executableURL.deletingLastPathComponent()
    guard macOSURL.lastPathComponent == "MacOS" else {
        return nil
    }
    let contentsURL = macOSURL.deletingLastPathComponent()
    guard contentsURL.lastPathComponent == "Contents" else {
        return nil
    }
    let appURL = contentsURL.deletingLastPathComponent()
    return appURL.pathExtension == "app" ? appURL : nil
}

// MARK: - Pairing

private func selfCodeSigningIdentifier() -> String? {
    var code: SecCode?
    guard SecCodeCopySelf([], &code) == errSecSuccess,
          let secCode = code else {
        return nil
    }
    var staticCode: SecStaticCode?
    guard SecCodeCopyStaticCode(secCode, [], &staticCode) == errSecSuccess,
          let signedCode = staticCode else {
        return nil
    }
    var info: CFDictionary?
    guard SecCodeCopySigningInformation(
        signedCode,
        SecCSFlags(rawValue: kSecCSSigningInformation),
        &info
    ) == errSecSuccess,
          let signingInfo = info as? [String: Any],
          let identifier = signingInfo[kSecCodeInfoIdentifier as String] as? String else {
        return nil
    }
    let trimmed = identifier.trimmingCharacters(in: .whitespacesAndNewlines)
    return trimmed.isEmpty ? nil : trimmed
}

private func defaultPairingBundleIdentifier() -> String {
    selfCodeSigningIdentifier()
        ?? Bundle.main.bundleIdentifier
        ?? "com.bastion.cli"
}

private struct PairingHandshakeResponse: Codable {
    let requestId: String
    let pairingCode: String
    let expiresAt: Date
}

private struct PairingPollResponse: Codable {
    enum State: String, Codable { case pending, accepted, rejected, expired }
    let state: State
    let profile: ClientProfileInfo?
    let reason: String?
}

private struct ClientProfileInfo: Codable {
    let id: String
    let bundleId: String
    let label: String?
    let authPolicy: String?
    let keyTag: String?
    let accountAddress: String?
    let walletGroupId: String?
    let membershipId: String?
}

func cmdPair(_ args: ArraySlice<String>) {
    // Optional `--label "Display name"` pre-fills the menu bar label suggestion.
    // Optional `--bundle-id` lets the operator override the auto-detected bundle id
    // (mainly for tests). The trusted bundleId is whatever the XPC layer
    // verifies — wire-supplied values are display only.
    var label: String? = nil
    var bundleId = defaultPairingBundleIdentifier()

    var i = args.startIndex
    while i < args.endIndex {
        switch args[i] {
        case "--label":
            i = args.index(after: i)
            guard i < args.endIndex else {
                exitWithError("--label requires a value")
            }
            let trimmedLabel = args[i].trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedLabel.isEmpty else {
                exitWithError("--label cannot be empty")
            }
            label = trimmedLabel
        case "--bundle-id":
            i = args.index(after: i)
            guard i < args.endIndex else {
                exitWithError("--bundle-id requires a value")
            }
            bundleId = args[i]
        default:
            exitWithError("Unknown pair argument: \(args[i])")
        }
        i = args.index(after: i)
    }

    let processName = ProcessInfo.processInfo.processName
    let displayName = label ?? processName

    // Step 1 — start the handshake. App returns a pairing code.
    let startData = performDataRequest(
        timeoutSeconds: 5,
        timeoutMessage: "Bastion app is not responding"
    ) { proxy, reply in
        proxy.startPairing(bundleId: bundleId, processName: displayName, withReply: reply)
    }
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    guard let response = try? decoder.decode(PairingHandshakeResponse.self, from: startData) else {
        exitWithError("Could not parse pairing handshake response")
    }

    // Print the code prominently. The operator confirms it matches what the
    // menu bar prompt shows.
    print("")
    print("  Pairing code: \(response.pairingCode)")
    print("")
    print("  Open Bastion in the menu bar and confirm this pairing code.")
    print("  Waiting for owner approval (request \(response.requestId.prefix(8)))…")
    print("")

    // Step 2 — poll until terminal state.
    let pollIntervalSeconds: UInt32 = 1
    let maxAttempts = 300 // matches the broker's 5-minute window
    for _ in 0..<maxAttempts {
        let pollData = performDataRequest(
            timeoutSeconds: 5,
            timeoutMessage: "Bastion app stopped responding mid-pair"
        ) { proxy, reply in
            proxy.pollPairing(requestId: response.requestId, withReply: reply)
        }
        let outcome = decodeJSON(PairingPollResponse.self, from: pollData)
        switch outcome.state {
        case .pending:
            sleep(pollIntervalSeconds)
            continue
        case .accepted:
            if let profile = outcome.profile {
                print("Paired. Profile id: \(profile.id)")
                printJSON(profile)
            } else {
                print("Paired.")
            }
            return
        case .rejected:
            exitWithError("Pairing rejected: \(outcome.reason ?? "owner declined")")
        case .expired:
            exitWithError("Pairing expired: \(outcome.reason ?? "no response within window")")
        }
    }
    exitWithError("Pairing timed out — try again")
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
            guard next < args.endIndex else {
                exitWithError("\(flag) requires a value")
            }
            out.append(args[next])
            i = args.index(after: next)
            continue
        }
        i = args.index(after: i)
    }
    return out
}

private func integerOptionValue(_ args: ArraySlice<String>, flag: String) -> Int? {
    guard let value = optionValue(args, flag: flag) else {
        return nil
    }
    guard let parsed = Int(value) else {
        exitWithError("\(flag) must be an integer")
    }
    return parsed
}

private func integerOptionValues(_ args: ArraySlice<String>, flag: String) -> [Int] {
    optionValues(args, flag: flag).map { value in
        guard let parsed = Int(value) else {
            exitWithError("\(flag) must be an integer")
        }
        return parsed
    }
}

private func normalizedRequiredOptionValue(
    _ args: ArraySlice<String>,
    flag: String,
    usage: String,
    emptyMessage: String
) -> String {
    guard let value = optionValue(args, flag: flag) else {
        exitWithError(usage)
    }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        exitWithError(emptyMessage)
    }
    return trimmed
}

private func normalizedOptionalOptionValue(
    _ args: ArraySlice<String>,
    flag: String,
    emptyMessage: String
) -> String? {
    guard let value = optionValue(args, flag: flag) else {
        return nil
    }
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        exitWithError(emptyMessage)
    }
    return trimmed
}

private func normalizedRequiredArgument(
    _ value: String,
    name: String
) -> String {
    let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !trimmed.isEmpty else {
        exitWithError("\(name) cannot be empty")
    }
    return trimmed
}

func cmdGroupsCreate(_ args: ArraySlice<String>) {
    let label = normalizedRequiredOptionValue(
        args,
        flag: "--label",
        usage: "Usage: bastion groups create --label <name> [--chain <id>]",
        emptyMessage: "--label cannot be empty"
    )
    let chains = integerOptionValues(args, flag: "--chain")

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
    let response = performDataRequest(
        timeoutSeconds: 10,
        timeoutMessage: "List wallet groups timed out — ensure the signed Bastion service is running and update to a build where read-only group listing does not require owner authentication"
    ) { proxy, reply in
        proxy.listWalletGroups(withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsShow(_ args: ArraySlice<String>) {
    guard let groupId = args.first else {
        exitWithError("Usage: bastion groups show <groupId>")
    }
    let normalizedGroupId = normalizedRequiredArgument(groupId, name: "groupId")
    let response = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.getWalletGroup(groupId: normalizedGroupId, withReply: reply)
    }
    printRawServerJSON(response)
}

func cmdGroupsAddAgent(_ args: ArraySlice<String>) {
    guard let groupId = args.first else {
        exitWithError("Usage: bastion groups add-agent <groupId> [--label <n>] [--profile-id <id>] [--scope-json-file <path>]")
    }
    let normalizedGroupId = normalizedRequiredArgument(groupId, name: "groupId")
    let rest = args.dropFirst()
    let label = normalizedOptionalOptionValue(
        rest,
        flag: "--label",
        emptyMessage: "--label cannot be empty"
    )
    let profileId = normalizedOptionalOptionValue(
        rest,
        flag: "--profile-id",
        emptyMessage: "--profile-id cannot be empty"
    )

    var body: [String: Any] = ["groupId": normalizedGroupId]
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
    let groupId = normalizedRequiredArgument(args[args.startIndex], name: "groupId")
    let memberId = normalizedRequiredArgument(args[args.index(after: args.startIndex)], name: "memberId")
    let rest = args.dropFirst(2)
    let txHash = normalizedOptionalOptionValue(
        rest,
        flag: "--tx",
        emptyMessage: "--tx cannot be empty"
    )

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
    let groupId = normalizedRequiredArgument(args[args.startIndex], name: "groupId")
    let memberId = normalizedRequiredArgument(args[args.index(after: args.startIndex)], name: "memberId")
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
    let groupId = normalizedRequiredArgument(args[args.startIndex], name: "groupId")
    let memberId = normalizedRequiredArgument(args[args.index(after: args.startIndex)], name: "memberId")
    let rest = args.dropFirst(2)
    guard let chainIdStr = optionValue(rest, flag: "--chain"),
          let chainId = Int(chainIdStr) else {
        exitWithError("--chain <id> is required")
    }
    let projectId = normalizedOptionalOptionValue(
        rest,
        flag: "--project-id",
        emptyMessage: "--project-id cannot be empty"
    )
    let submit = rest.contains("--submit")
    let wait = integerOptionValue(rest, flag: "--wait-seconds")
    if let wait, wait < 0 || wait > maxReceiptWaitSeconds {
        exitWithError("--wait-seconds must be between 0 and \(maxReceiptWaitSeconds)")
    }

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
    let groupId = normalizedRequiredArgument(args[args.startIndex], name: "groupId")
    let memberId = normalizedRequiredArgument(args[args.index(after: args.startIndex)], name: "memberId")
    let rest = args.dropFirst(2)
    guard let chainIdStr = optionValue(rest, flag: "--chain"),
          let chainId = Int(chainIdStr) else {
        exitWithError("--chain <id> is required")
    }
    let projectId = normalizedOptionalOptionValue(
        rest,
        flag: "--project-id",
        emptyMessage: "--project-id cannot be empty"
    )
    let submit = rest.contains("--submit")
    let wait = integerOptionValue(rest, flag: "--wait-seconds")
    if let wait, wait < 0 || wait > maxReceiptWaitSeconds {
        exitWithError("--wait-seconds must be between 0 and \(maxReceiptWaitSeconds)")
    }

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
    let groupId = normalizedRequiredArgument(args[args.startIndex], name: "groupId")
    let memberId = normalizedRequiredArgument(args[args.index(after: args.startIndex)], name: "memberId")
    let rest = args.dropFirst(2)
    let txHash = normalizedRequiredOptionValue(
        rest,
        flag: "--tx",
        usage: "--tx <hash> is required",
        emptyMessage: "--tx cannot be empty"
    )
    let validatorAddress = normalizedOptionalOptionValue(
        rest,
        flag: "--validator",
        emptyMessage: "--validator cannot be empty"
    )

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
    let failureStage: String?
    let failureCategory: String?
    let retryable: Bool?
    let recoverySuggestion: String?
}

struct PublicKeyResponse: Codable {
    let x: String
    let y: String
}

struct ServiceInfoResponse: Codable {
    let version: String
    let serviceRegistrationStatus: String
    let configCorrupted: Bool
    let bundlePath: String
    let executablePath: String
    let bundleIdentifier: String?
    let processIdentifier: Int32?
    let launchMode: String?
    let machServiceName: String?
    let launchAgentPlistName: String?
}

struct OpenUIResponse: Codable {
    let target: String
    let opened: Bool
}

struct UIProbeWindowFrame: Codable {
    let x: Double
    let y: Double
    let width: Double
    let height: Double
}

struct UIProbeWindowSnapshot: Codable {
    let title: String
    let className: String
    let isVisible: Bool
    let isKeyWindow: Bool
    let isMainWindow: Bool
    let isPanel: Bool
    let isFloatingPanel: Bool
    let isTitled: Bool
    let isClosable: Bool
    let isFullSizeContentView: Bool
    let isBorderless: Bool
    let isNonactivatingPanel: Bool
    let isOpaque: Bool
    let hasShadow: Bool
    let backgroundAlpha: Double?
    let hasContentView: Bool
    let contentViewClassName: String?
    let frame: UIProbeWindowFrame
}

struct UIProbeResponse: Codable {
    let target: String
    let opened: Bool
    let matchedWindowTitle: String?
    let visibleNonTargetWindowTitles: [String]
    let windows: [UIProbeWindowSnapshot]
}

struct NotificationProbeResponse: Codable {
    let probeID: String
    let requested: Bool
}

struct NotificationClickProbeResponse: Codable {
    let probeID: String
    let opened: Bool
}

struct UserOperationNotificationProbeResponse: Codable {
    let probeID: String
    let requested: Bool
}

struct UserOperationNotificationClickProbeResponse: Codable {
    let probeID: String
    let opened: Bool
}

struct ResetSigningKeysResponse: Codable {
    let deletedKeyTags: [String]
    let requestedKeyTags: [String]
}

struct SupportBundleRequest: Codable {
    let maxAuditRecords: Int?
    let maxDiagnosticEntries: Int?
    let maxCrashReports: Int?
}

struct RotateClientKeyRequest: Codable {
    let profileId: String
}

struct ClientKeyRotationResult: Codable {
    let profileId: String
    let bundleId: String
    let oldKeyTag: String
    let newKeyTag: String
    let oldAccountAddress: String?
    let newAccountAddress: String?
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

case "open-ui":
    cmdOpenUI(args[2...])

case "ui-probe":
    cmdUIProbe(args[2...])

case "settings-scenario-probe":
    cmdSettingsScenarioProbe(args[2...])

case "menu-scenario-probe":
    cmdMenuScenarioProbe(args[2...])

case "wallet-group-scenario-probe":
    cmdWalletGroupScenarioProbe(args[2...])

case "audit-history-scenario-probe":
    cmdAuditHistoryScenarioProbe(args[2...])

case "runtime-state-scenario-probe":
    cmdRuntimeStateScenarioProbe(args[2...])

case "update-scenario-probe":
    cmdUpdateScenarioProbe(args[2...])

case "key-lifecycle-scenario-probe":
    cmdKeyLifecycleScenarioProbe(args[2...])

case "live-runtime-scenario-probe":
    cmdLiveRuntimeScenarioProbe(args[2...])

case "notification-probe":
    cmdNotificationProbe(args[2...])

case "notification-click-probe":
    cmdNotificationClickProbe(args[2...])

case "userop-notification-probe":
    cmdUserOperationNotificationProbe(args[2...])

case "userop-notification-click-probe":
    cmdUserOperationNotificationClickProbe(args[2...])

case "rules":
    cmdRules()

case "state":
    cmdState()

case "support-bundle":
    cmdSupportBundle(args[2...])

case "update":
    cmdUpdate(args[2...])

case "reset-keys":
    cmdResetKeys()

case "rotate-client-key":
    cmdRotateClientKey(args[2...])

case "pair":
    cmdPair(args[2...])

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

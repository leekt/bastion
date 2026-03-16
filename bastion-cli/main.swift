import Foundation

// MARK: - XPC Protocol (duplicated for CLI target since BastionShared must be added to both targets)

@objc protocol BastionXPCProtocol {
    func sign(data: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
    func getRules(withReply reply: @escaping (Data?, Error?) -> Void)
    func getState(withReply reply: @escaping (Data?, Error?) -> Void)
    func signStructured(operationType: String, operationData: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
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
  bastion eth userOp --json '{...}'             # ERC-4337 UserOperation (v0.7+)
  bastion eth userOp --json-file <path>         # ERC-4337 UserOperation from file
  bastion pubkey                                # Get public key
  bastion status                                # Check app status
  bastion rules                                 # Get current rules
  bastion state                                 # Get signing state

UserOp JSON fields (all byte fields hex-encoded with 0x prefix):
  sender, nonce, callData, verificationGasLimit, callGasLimit,
  preVerificationGas, maxPriorityFeePerGas, maxFeePerGas,
  chainId (int), entryPoint, entryPointVersion ("v0.7"|"v0.8"|"v0.9")
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
    connection.resume()
    return connection
}

func getProxy(_ connection: NSXPCConnection) -> BastionXPCProtocol {
    guard let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
        exitWithError("XPC connection failed: \(error.localizedDescription)")
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
        usage += "\n\n" + userOpFieldHelp
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

func performDataRequest(
    timeoutSeconds: Int,
    timeoutMessage: String = "Request timed out",
    _ invoke: (BastionXPCProtocol, @escaping (Data?, Error?) -> Void) -> Void
) -> Data {
    let connection = createConnection()
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)
    var responseData: Data?
    var responseError: Error?

    invoke(proxy) { data, error in
        responseData = data
        responseError = error
        semaphore.signal()
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
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)
    var value = false

    invoke(proxy) { result in
        value = result
        semaphore.signal()
    }

    if semaphore.wait(timeout: .now() + .seconds(timeoutSeconds)) == .timedOut {
        connection.invalidate()
        exitWithError(timeoutMessage)
    }

    connection.invalidate()
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
    let data = resolveStructuredJSONInput(args, commandName: "userOp")
    callSignStructured(type: "userOperation", data: data)
}

func cmdPubkey() {
    let responseData = performDataRequest(timeoutSeconds: 10) { proxy, reply in
        proxy.getPublicKey(withReply: reply)
    }
    printJSON(decodeJSON(PublicKeyResponse.self, from: responseData))
}

func cmdStatus() {
    let alive = performBoolRequest(timeoutSeconds: 5, timeoutMessage: "Bastion app is not running") { proxy, reply in
        proxy.ping(withReply: reply)
    }
    guard alive else {
        exitWithError("App not responding")
    }
    print("{\"status\": \"running\"}")
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

// MARK: - Response Types (duplicated for CLI target)

struct SignResponse: Codable {
    let pubkeyX: String
    let pubkeyY: String
    let r: String
    let s: String
}

struct PublicKeyResponse: Codable {
    let x: String
    let y: String
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

default:
    exitWithError("Unknown command: \(args[1])")
}

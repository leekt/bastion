import Foundation

// MARK: - XPC Protocol (duplicated for CLI target since BastionShared must be added to both targets)

@objc protocol BastionXPCProtocol {
    func sign(data: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
    func getRules(withReply reply: @escaping (Data?, Error?) -> Void)
    func getState(withReply reply: @escaping (Data?, Error?) -> Void)
}

// MARK: - Helpers

func exitWithError(_ message: String) -> Never {
    FileHandle.standardError.write(Data("Error: \(message)\n".utf8))
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

// MARK: - Commands

func cmdSign(dataHex: String) {
    guard dataHex.count == 64,
          let data = Data(hexString: dataHex) else {
        exitWithError("--data must be exactly 32 bytes (64 hex characters)")
    }

    let requestID = UUID().uuidString
    let connection = createConnection()
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)

    proxy.sign(data: data, requestID: requestID) { responseData, error in
        defer { semaphore.signal() }

        if let error = error {
            exitWithError(error.localizedDescription)
        }

        guard let responseData = responseData else {
            exitWithError("No response data")
        }

        guard let response = try? JSONDecoder().decode(SignResponse.self, from: responseData) else {
            exitWithError("Invalid response format")
        }

        printJSON(response)
    }

    if semaphore.wait(timeout: .now() + 65) == .timedOut {
        exitWithError("Request timed out (65s)")
    }

    connection.invalidate()
}

func cmdPubkey() {
    let connection = createConnection()
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)

    proxy.getPublicKey { responseData, error in
        defer { semaphore.signal() }

        if let error = error {
            exitWithError(error.localizedDescription)
        }

        guard let responseData = responseData else {
            exitWithError("No response data")
        }

        guard let response = try? JSONDecoder().decode(PublicKeyResponse.self, from: responseData) else {
            exitWithError("Invalid response format")
        }

        printJSON(response)
    }

    if semaphore.wait(timeout: .now() + 10) == .timedOut {
        exitWithError("Request timed out")
    }

    connection.invalidate()
}

func cmdStatus() {
    let connection = createConnection()
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)

    proxy.ping { alive in
        defer { semaphore.signal() }
        if alive {
            print("{\"status\": \"running\"}")
        } else {
            exitWithError("App not responding")
        }
    }

    if semaphore.wait(timeout: .now() + 5) == .timedOut {
        exitWithError("Bastion app is not running")
    }

    connection.invalidate()
}

func cmdRules() {
    let connection = createConnection()
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)

    proxy.getRules { responseData, error in
        defer { semaphore.signal() }

        if let error = error {
            exitWithError(error.localizedDescription)
        }

        guard let responseData = responseData,
              let json = String(data: responseData, encoding: .utf8) else {
            exitWithError("No response data")
        }

        print(json)
    }

    if semaphore.wait(timeout: .now() + 10) == .timedOut {
        exitWithError("Request timed out")
    }

    connection.invalidate()
}

func cmdState() {
    let connection = createConnection()
    let proxy = getProxy(connection)
    let semaphore = DispatchSemaphore(value: 0)

    proxy.getState { responseData, error in
        defer { semaphore.signal() }

        if let error = error {
            exitWithError(error.localizedDescription)
        }

        guard let responseData = responseData else {
            exitWithError("No response data")
        }

        guard let response = try? JSONDecoder().decode(StateResponse.self, from: responseData) else {
            exitWithError("Invalid response format")
        }

        printJSON(response)
    }

    if semaphore.wait(timeout: .now() + 10) == .timedOut {
        exitWithError("Request timed out")
    }

    connection.invalidate()
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

struct StateResponse: Codable {
    let todayCount: Int
    let dailyLimit: Int?
    let remaining: Int?
}

extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var index = hexString.startIndex
        for _ in 0..<len {
            let nextIndex = hexString.index(index, offsetBy: 2)
            guard let byte = UInt8(hexString[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        self = data
    }
}

// MARK: - Main

let args = CommandLine.arguments

guard args.count >= 2 else {
    FileHandle.standardError.write(Data("""
    Usage:
      bastion sign --data <32byte hex>   # Request signing
      bastion pubkey                      # Get public key
      bastion status                      # Check app status
      bastion rules                       # Get current rules
      bastion state                       # Get signing state (tx count, limits)

    """.utf8))
    exit(1)
}

switch args[1] {
case "sign":
    guard args.count >= 4, args[2] == "--data" else {
        exitWithError("Usage: bastion sign --data <32byte hex>")
    }
    cmdSign(dataHex: args[3])

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

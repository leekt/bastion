import Foundation

private let configFileName = "runtime-qa-config.json"
private let markerFileName = "runtime-qa-config.enabled"

enum SeederError: Error, CustomStringConvertible {
    case usage
    case invalidBackup
    case invalidConfig
    case configDirectoryUnavailable
    case fileRead(String)
    case fileWrite(String)
    case fileDelete(String)

    var description: String {
        switch self {
        case .usage:
            return "usage: runtime-profile-seeder backup <path> | seed <backup-path> [bundle-id] [label] | restore <backup-path>"
        case .invalidBackup:
            return "invalid backup file"
        case .invalidConfig:
            return "stored config is not a JSON object"
        case .configDirectoryUnavailable:
            return "QA config override directory could not be resolved"
        case .fileRead(let detail):
            return "QA config override read failed: \(detail)"
        case .fileWrite(let detail):
            return "QA config override write failed: \(detail)"
        case .fileDelete(let detail):
            return "QA config override delete failed: \(detail)"
        }
    }
}

struct ConfigBackup: Codable {
    let store: String
    let configPresent: Bool
    let markerPresent: Bool
    let dataBase64: String?
    let createdAt: String
}

func configDirectory() throws -> URL {
    if let override = ProcessInfo.processInfo.environment["BASTION_QA_CONFIG_DIR"]?
        .trimmingCharacters(in: .whitespacesAndNewlines),
       !override.isEmpty {
        return URL(fileURLWithPath: override, isDirectory: true)
    }
    guard let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
        throw SeederError.configDirectoryUnavailable
    }
    return support.appendingPathComponent("Bastion", isDirectory: true)
}

func configURL() throws -> URL {
    try configDirectory().appendingPathComponent(configFileName, isDirectory: false)
}

func markerURL() throws -> URL {
    try configDirectory().appendingPathComponent(markerFileName, isDirectory: false)
}

func fileExists(_ url: URL) -> Bool {
    FileManager.default.fileExists(atPath: url.path)
}

func readConfigData() throws -> Data? {
    let url = try configURL()
    guard fileExists(url) else { return nil }
    do {
        return try Data(contentsOf: url)
    } catch {
        throw SeederError.fileRead(error.localizedDescription)
    }
}

func writeConfigData(_ data: Data) throws {
    do {
        let directory = try configDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: try configURL(), options: [.atomic])
        try Data("enabled\n".utf8).write(to: try markerURL(), options: [.atomic])
    } catch let error as SeederError {
        throw error
    } catch {
        throw SeederError.fileWrite(error.localizedDescription)
    }
}

func removeConfigOverride() throws {
    for url in try [configURL(), markerURL()] {
        guard fileExists(url) else { continue }
        do {
            try FileManager.default.removeItem(at: url)
        } catch {
            throw SeederError.fileDelete(error.localizedDescription)
        }
    }
}

func isoNow() -> String {
    ISO8601DateFormatter().string(from: Date())
}

func defaultRules() -> [String: Any] {
    [
        "userOpPosture": "enforce_and_approve",
        "enabled": true,
        "requireExplicitApproval": true,
        "rateLimits": [],
        "spendingLimits": [],
        "rawMessagePolicy": [
            "posture": "enforce_and_approve",
            "enabled": true,
            "allowRawSigning": false,
        ],
        "typedDataPolicy": [
            "posture": "enforce_and_approve",
            "enabled": true,
            "requireExplicitApproval": true,
            "domainRules": [],
            "structRules": [],
        ],
    ]
}

func qaAutoSignRules() -> [String: Any] {
    [
        "userOpPosture": "enforce_and_auto",
        "enabled": true,
        "requireExplicitApproval": false,
        "rateLimits": [],
        "spendingLimits": [],
        "rawMessagePolicy": [
            "posture": "enforce_and_auto",
            "enabled": true,
            "allowRawSigning": true,
        ],
        "typedDataPolicy": [
            "posture": "enforce_and_auto",
            "enabled": true,
            "requireExplicitApproval": false,
            "domainRules": [],
            "structRules": [],
        ],
    ]
}

func defaultConfig() -> [String: Any] {
    [
        "version": 9,
        "authPolicy": "biometricOrPasscode",
        "rules": defaultRules(),
        "bundlerPreferences": [
            "chainRPCs": [],
        ],
        "clientProfiles": [],
        "walletGroups": [],
        "auditRedactionLevel": "none",
        "addressBook": [],
        "ruleTemplates": [],
        "highValue": [
            "enabled": false,
            "thresholdUsd": 10_000,
            "confirmationPhrase": "TRANSFER",
        ],
        "pauseState": [
            "paused": false,
            "lockedDown": false,
        ],
    ]
}

func decodedConfig(from data: Data?) throws -> [String: Any] {
    guard let data else {
        return defaultConfig()
    }
    let object = try JSONSerialization.jsonObject(with: data, options: [])
    guard var config = object as? [String: Any] else {
        throw SeederError.invalidConfig
    }
    if config["rules"] == nil {
        config["rules"] = defaultRules()
    }
    if config["clientProfiles"] == nil {
        config["clientProfiles"] = []
    }
    return config
}

func encodedConfig(_ config: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: config, options: [.prettyPrinted, .sortedKeys])
}

func backup(to path: URL) throws {
    let data = try readConfigData()
    let markerPresent = try fileExists(markerURL())
    let backup = ConfigBackup(
        store: "runtime-qa-config-override",
        configPresent: data != nil,
        markerPresent: markerPresent,
        dataBase64: data?.base64EncodedString(),
        createdAt: isoNow()
    )
    let encoded = try JSONEncoder().encode(backup)
    try encoded.write(to: path, options: .atomic)
    print("backup written: \(path.path); configPresent=\(backup.configPresent); markerPresent=\(backup.markerPresent)")
}

func seed(backupPath: URL, bundleId: String, label: String) throws {
    if !FileManager.default.fileExists(atPath: backupPath.path) {
        try backup(to: backupPath)
    }
    var config = try decodedConfig(from: try readConfigData())
    var profiles = config["clientProfiles"] as? [[String: Any]] ?? []
    profiles.removeAll {
        guard let existing = $0["bundleId"] as? String else { return false }
        return existing.caseInsensitiveCompare(bundleId) == .orderedSame
    }
    profiles.append([
        "id": "runtime-qa-\(UUID().uuidString.lowercased())",
        "bundleId": bundleId,
        "label": label,
        "authPolicy": "open",
        "keyTag": "com.bastion.signingkey.client.runtime-qa.\(bundleId.replacingOccurrences(of: ".", with: "-"))",
        "rules": qaAutoSignRules(),
    ])
    config["clientProfiles"] = profiles
    try writeConfigData(try encodedConfig(config))
    print("seeded runtime QA profile for \(bundleId)")
}

func restore(from path: URL) throws {
    let data = try Data(contentsOf: path)
    let backup = try JSONDecoder().decode(ConfigBackup.self, from: data)
    guard backup.store == "runtime-qa-config-override" else {
        throw SeederError.invalidBackup
    }
    if backup.configPresent {
        guard let base64 = backup.dataBase64, let original = Data(base64Encoded: base64) else {
            throw SeederError.invalidBackup
        }
        try writeConfigData(original)
        if !backup.markerPresent, fileExists(try markerURL()) {
            try FileManager.default.removeItem(at: try markerURL())
        }
        print("restored runtime QA config override from backup")
    } else {
        try removeConfigOverride()
        print("deleted seeded runtime QA config override; original was absent")
    }
}

do {
    let args = Array(CommandLine.arguments.dropFirst())
    guard let command = args.first else {
        throw SeederError.usage
    }
    switch command {
    case "backup":
        guard args.count == 2 else { throw SeederError.usage }
        try backup(to: URL(fileURLWithPath: args[1]))
    case "seed":
        guard args.count >= 2 && args.count <= 4 else { throw SeederError.usage }
        let bundleId = args.count >= 3 ? args[2] : "bastion-cli"
        let label = args.count >= 4 ? args[3] : "Runtime QA CLI"
        try seed(backupPath: URL(fileURLWithPath: args[1]), bundleId: bundleId, label: label)
    case "restore":
        guard args.count == 2 else { throw SeederError.usage }
        try restore(from: URL(fileURLWithPath: args[1]))
    default:
        throw SeederError.usage
    }
} catch {
    fputs("runtime-profile-seeder: \(error)\n", stderr)
    exit(1)
}

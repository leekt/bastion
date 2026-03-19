import Foundation

struct LiveTestConfig {
    let projectId: String
    let sepoliaRPCURL: String
    let baseSepoliaRPCURL: String?

    static var current: LiveTestConfig? {
        let env = resolvedEnvironment()
        guard env["BASTION_RUN_LIVE_AA_TESTS"] == "1" else {
            return nil
        }
        guard
            let projectId = env["BASTION_ZERODEV_PROJECT_ID"],
            !projectId.isEmpty,
            let sepoliaRPCURL = env["BASTION_SEPOLIA_RPC_URL"],
            !sepoliaRPCURL.isEmpty
        else {
            return nil
        }
        let baseSepoliaRPCURL = env["BASTION_BASE_SEPOLIA_RPC_URL"]
        return LiveTestConfig(
            projectId: projectId,
            sepoliaRPCURL: sepoliaRPCURL,
            baseSepoliaRPCURL: baseSepoliaRPCURL?.isEmpty == false ? baseSepoliaRPCURL : nil
        )
    }

    private static func resolvedEnvironment() -> [String: String] {
        var env = ProcessInfo.processInfo.environment
        if let fileEnv = loadDotEnv(named: ".env.test") {
            for (key, value) in fileEnv where env[key]?.isEmpty != false {
                env[key] = value
            }
        }
        return env
    }

    private static func loadDotEnv(named fileName: String) -> [String: String]? {
        for directory in candidateDirectories() {
            let fileURL = directory.appendingPathComponent(fileName)
            guard let contents = try? String(contentsOf: fileURL, encoding: .utf8) else {
                continue
            }
            return parseDotEnv(contents)
        }
        return nil
    }

    private static func candidateDirectories() -> [URL] {
        var directories: [URL] = []
        var seen = Set<String>()

        func addParents(startingAt start: URL) {
            var current = start.standardizedFileURL
            while seen.insert(current.path).inserted {
                directories.append(current)
                let parent = current.deletingLastPathComponent()
                if parent.path == current.path {
                    break
                }
                current = parent
            }
        }

        addParents(startingAt: URL(fileURLWithPath: FileManager.default.currentDirectoryPath, isDirectory: true))
        addParents(startingAt: URL(fileURLWithPath: #filePath).deletingLastPathComponent())
        return directories
    }

    private static func parseDotEnv(_ contents: String) -> [String: String] {
        var values: [String: String] = [:]

        for rawLine in contents.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !line.isEmpty, !line.hasPrefix("#"), let separator = line.firstIndex(of: "=") else {
                continue
            }

            let key = String(line[..<separator]).trimmingCharacters(in: .whitespaces)
            var value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            if value.hasPrefix("\""), value.hasSuffix("\""), value.count >= 2 {
                value.removeFirst()
                value.removeLast()
            }
            values[key] = value
        }

        return values
    }
}

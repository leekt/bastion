import Foundation

nonisolated enum DiagnosticCategory: String, Codable, Sendable, Equatable {
    case lifecycle
    case xpc
    case approval
    case submission
    case notification
    case support
    case update
    case policy
}

nonisolated enum DiagnosticLevel: String, Codable, Sendable, Equatable {
    case info
    case warning
    case error
}

nonisolated struct DiagnosticLogEntry: Codable, Sendable, Equatable {
    let timestamp: String
    let level: DiagnosticLevel
    let category: DiagnosticCategory
    let event: String
    let message: String
    let context: [String: String]
}

nonisolated final class DiagnosticLog: @unchecked Sendable {
    static let shared = DiagnosticLog()

    private let logURL: URL
    private let fileManager: FileManager
    private let queue = DispatchQueue(label: "com.bastion.diagnosticlog")
    private let encoder = JSONEncoder()

    private init() {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let bastionDir = appSupport.appendingPathComponent("Bastion", isDirectory: true)
        self.logURL = bastionDir.appendingPathComponent("diagnostics.jsonl")
        self.fileManager = .default
    }

    init(logURL: URL, fileManager: FileManager = .default) {
        self.logURL = logURL
        self.fileManager = fileManager
    }

    nonisolated func record(
        level: DiagnosticLevel = .info,
        category: DiagnosticCategory,
        event: String,
        message: String,
        context: [String: String] = [:]
    ) {
        let entry = DiagnosticLogEntry(
            timestamp: Self.timestamp(),
            level: level,
            category: category,
            event: event,
            message: message,
            context: context
        )
        append(entry)
    }

    nonisolated func recentEntries(limit: Int) -> [DiagnosticLogEntry] {
        queue.sync {
            guard limit > 0,
                  let data = try? Data(contentsOf: logURL),
                  let text = String(data: data, encoding: .utf8) else {
                return []
            }
            let decoder = JSONDecoder()
            let entries = text
                .split(separator: "\n")
                .compactMap { line -> DiagnosticLogEntry? in
                    guard let lineData = line.data(using: .utf8) else { return nil }
                    return try? decoder.decode(DiagnosticLogEntry.self, from: lineData)
                }
            return Array(entries.suffix(limit))
        }
    }

    private func append(_ entry: DiagnosticLogEntry) {
        queue.sync {
            do {
                try fileManager.createDirectory(
                    at: logURL.deletingLastPathComponent(),
                    withIntermediateDirectories: true
                )
                let data = try encoder.encode(entry) + Data([0x0a])
                if fileManager.fileExists(atPath: logURL.path),
                   let handle = try? FileHandle(forWritingTo: logURL) {
                    defer { try? handle.close() }
                    try handle.seekToEnd()
                    try handle.write(contentsOf: data)
                } else {
                    try data.write(to: logURL, options: .atomic)
                }
            } catch {
                NSLog("[DiagnosticLog] failed to append %@: %@", entry.event, error.localizedDescription)
            }
        }
    }

    private static func timestamp() -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: Date())
    }
}

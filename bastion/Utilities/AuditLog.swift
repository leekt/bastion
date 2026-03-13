import Foundation

nonisolated struct AuditEvent: Codable, Sendable {
    nonisolated enum EventType: String, Codable, Sendable {
        case signSuccess = "sign_success"
        case signDenied = "sign_denied"
        case ruleViolation = "rule_violation"
        case authFailed = "auth_failed"
    }

    let timestamp: String
    let type: EventType
    let dataPrefix: String
    let reason: String?

    init(type: EventType, dataPrefix: String, reason: String? = nil) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        self.timestamp = formatter.string(from: Date())
        self.type = type
        self.dataPrefix = dataPrefix
        self.reason = reason
    }
}

nonisolated final class AuditLog: @unchecked Sendable {
    static let shared = AuditLog()

    private let logURL: URL
    private let fileManager = FileManager.default
    private let queue = DispatchQueue(label: "com.bastion.auditlog")

    private init() {
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let bastionDir = appSupport.appendingPathComponent("Bastion")
        if !fileManager.fileExists(atPath: bastionDir.path) {
            try? fileManager.createDirectory(at: bastionDir, withIntermediateDirectories: true)
        }
        self.logURL = bastionDir.appendingPathComponent("audit.log")
    }

    nonisolated func record(_ event: AuditEvent) {
        queue.sync {
            let encoder = JSONEncoder()
            guard let jsonData = try? encoder.encode(event),
                  var line = String(data: jsonData, encoding: .utf8) else { return }
            line += "\n"
            if let data = line.data(using: .utf8) {
                if fileManager.fileExists(atPath: logURL.path) {
                    if let handle = try? FileHandle(forWritingTo: logURL) {
                        handle.seekToEndOfFile()
                        handle.write(data)
                        handle.closeFile()
                    }
                } else {
                    try? data.write(to: logURL, options: .atomic)
                }
            }
        }
    }

    nonisolated func recentEvents(limit: Int) -> [AuditEvent] {
        queue.sync {
            guard let data = try? Data(contentsOf: logURL),
                  let content = String(data: data, encoding: .utf8) else { return [] }
            let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }
            let recent = Array(lines.suffix(limit))
            let decoder = JSONDecoder()
            return recent.compactMap { line in
                guard let data = line.data(using: .utf8) else { return nil }
                return try? decoder.decode(AuditEvent.self, from: data)
            }
        }
    }

    nonisolated func totalCountToday(type: AuditEvent.EventType) -> Int {
        queue.sync {
            guard let data = try? Data(contentsOf: logURL),
                  let content = String(data: data, encoding: .utf8) else { return 0 }
            let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }
            let decoder = JSONDecoder()
            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let calendar = Calendar.current
            let today = calendar.startOfDay(for: Date())
            var count = 0
            for line in lines.reversed() {
                guard let lineData = line.data(using: .utf8),
                      let event = try? decoder.decode(AuditEvent.self, from: lineData),
                      let date = formatter.date(from: event.timestamp) else { continue }
                if date < today { break }
                if event.type == type { count += 1 }
            }
            return count
        }
    }
}

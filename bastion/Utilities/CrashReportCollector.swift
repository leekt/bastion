import Foundation

nonisolated struct CrashReportSummary: Codable, Sendable, Equatable, Identifiable {
    let id: String
    let filename: String
    let modifiedAt: String
    let reportType: String
    let process: String?
    let identifier: String?
    let incidentIdentifier: String?
    let dateTime: String?
    let exceptionType: String?
    let exceptionCodes: String?
    let terminationReason: String?
    let summary: [String]
}

nonisolated final class CrashReportCollector: @unchecked Sendable {
    static let shared = CrashReportCollector()

    private let directories: [URL]
    private let fileManager: FileManager

    private init() {
        self.directories = Self.defaultDirectories()
        self.fileManager = .default
    }

    init(directories: [URL], fileManager: FileManager = .default) {
        self.directories = directories
        self.fileManager = fileManager
    }

    nonisolated func recentReports(limit: Int) -> [CrashReportSummary] {
        guard limit > 0 else { return [] }
        let candidates = directories.flatMap { reports(in: $0) }
        return candidates
            .sorted { $0.modifiedAt > $1.modifiedAt }
            .prefix(limit)
            .compactMap { parse(url: $0.url, modifiedAt: $0.modifiedAt) }
    }

    private static func defaultDirectories() -> [URL] {
        let home = FileManager.default.homeDirectoryForCurrentUser
        return [
            home.appendingPathComponent("Library/Logs/DiagnosticReports", isDirectory: true),
            home.appendingPathComponent("Library/Logs/DiagnosticReports/Retired", isDirectory: true),
            URL(fileURLWithPath: "/Library/Logs/DiagnosticReports", isDirectory: true)
        ]
    }

    private func reports(in directory: URL) -> [(url: URL, modifiedAt: Date)] {
        guard let urls = try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.contentModificationDateKey, .isRegularFileKey],
            options: [.skipsHiddenFiles]
        ) else {
            return []
        }

        return urls.compactMap { url in
            guard isSupportedReport(url) else { return nil }
            let values = try? url.resourceValues(forKeys: [.contentModificationDateKey, .isRegularFileKey])
            guard values?.isRegularFile != false else { return nil }
            return (url, values?.contentModificationDate ?? .distantPast)
        }
    }

    private func isSupportedReport(_ url: URL) -> Bool {
        let filename = url.lastPathComponent.lowercased()
        let ext = url.pathExtension.lowercased()
        guard filename.contains("bastion") else { return false }
        return ["crash", "ips", "diag", "hang", "spin"].contains(ext)
    }

    private func parse(url: URL, modifiedAt: Date) -> CrashReportSummary? {
        guard let data = readPrefix(url, byteLimit: 256 * 1024),
              let text = String(data: data, encoding: .utf8) else {
            return nil
        }

        let parsed = parseJSONCrash(text) ?? parseTextCrash(text)
        let summary = [
            parsed.process.map { "Process: \($0)" },
            parsed.identifier.map { "Identifier: \($0)" },
            parsed.exceptionType.map { "Exception: \($0)" },
            parsed.terminationReason.map { "Termination: \($0)" }
        ].compactMap { $0 }

        return CrashReportSummary(
            id: "\(url.lastPathComponent)|\(Int(modifiedAt.timeIntervalSince1970))",
            filename: url.lastPathComponent,
            modifiedAt: Self.timestamp(modifiedAt),
            reportType: url.pathExtension.lowercased(),
            process: parsed.process,
            identifier: parsed.identifier,
            incidentIdentifier: parsed.incidentIdentifier,
            dateTime: parsed.dateTime,
            exceptionType: parsed.exceptionType,
            exceptionCodes: parsed.exceptionCodes,
            terminationReason: parsed.terminationReason,
            summary: summary
        )
    }

    private func readPrefix(_ url: URL, byteLimit: Int) -> Data? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        return try? handle.read(upToCount: byteLimit)
    }

    private struct ParsedCrash {
        var process: String?
        var identifier: String?
        var incidentIdentifier: String?
        var dateTime: String?
        var exceptionType: String?
        var exceptionCodes: String?
        var terminationReason: String?
    }

    private func parseTextCrash(_ text: String) -> ParsedCrash {
        let lines = text.split(whereSeparator: \.isNewline).map(String.init)
        return ParsedCrash(
            process: lineValue("Process:", in: lines) ?? jsonLineValue("procName", in: lines) ?? jsonLineValue("app_name", in: lines),
            identifier: lineValue("Identifier:", in: lines) ?? jsonLineValue("bundleID", in: lines),
            incidentIdentifier: lineValue("Incident Identifier:", in: lines) ?? jsonLineValue("incident", in: lines),
            dateTime: lineValue("Date/Time:", in: lines) ?? jsonLineValue("captureTime", in: lines) ?? jsonLineValue("timestamp", in: lines),
            exceptionType: lineValue("Exception Type:", in: lines) ?? jsonLineValue("exceptionType", in: lines),
            exceptionCodes: lineValue("Exception Codes:", in: lines) ?? jsonLineValue("exceptionCodes", in: lines),
            terminationReason: lineValue("Termination Reason:", in: lines) ?? jsonLineValue("terminationReason", in: lines)
        )
    }

    private func parseJSONCrash(_ text: String) -> ParsedCrash? {
        guard let data = text.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return nil
        }
        let exception = object["exception"] as? [String: Any]
        let termination = object["termination"] as? [String: Any]
        return ParsedCrash(
            process: stringValue(object["procName"] ?? object["app_name"]),
            identifier: stringValue(object["bundleID"]),
            incidentIdentifier: stringValue(object["incident"]),
            dateTime: stringValue(object["captureTime"] ?? object["timestamp"]),
            exceptionType: stringValue(exception?["type"] ?? object["exceptionType"]),
            exceptionCodes: stringValue(exception?["codes"] ?? object["exceptionCodes"]),
            terminationReason: terminationReason(termination)
        )
    }

    private func lineValue(_ label: String, in lines: [String]) -> String? {
        guard let line = lines.first(where: { $0.hasPrefix(label) }) else { return nil }
        let value = line.dropFirst(label.count).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }

    private func jsonLineValue(_ key: String, in lines: [String]) -> String? {
        guard let line = lines.first(where: { $0.contains("\"\(key)\"") }),
              let colon = line.firstIndex(of: ":") else {
            return nil
        }
        let raw = line[line.index(after: colon)...]
            .trimmingCharacters(in: CharacterSet(charactersIn: " \t\","))
        return raw.isEmpty ? nil : raw
    }

    private func stringValue(_ value: Any?) -> String? {
        switch value {
        case let value as String:
            return value.isEmpty ? nil : value
        case let value as NSNumber:
            return value.stringValue
        default:
            return nil
        }
    }

    private func terminationReason(_ termination: [String: Any]?) -> String? {
        guard let termination else { return nil }
        let namespace = stringValue(termination["namespace"])
        let code = stringValue(termination["code"])
        let indicator = stringValue(termination["indicator"])
        return [namespace, code, indicator]
            .compactMap { $0 }
            .joined(separator: " ")
            .nilIfEmpty
    }

    private static func timestamp(_ date: Date) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.string(from: date)
    }
}

private extension String {
    var nilIfEmpty: String? {
        isEmpty ? nil : self
    }
}

import CommonCrypto
import Foundation

// Signed audit-log exporter.
//
// Produces a JSON bundle (or CSV, plain JSON) of the requested records,
// optionally HMAC-signed using the same key the AuditLog uses for tamper
// evidence so external verifiers can validate authenticity.

nonisolated enum AuditExportFormat: String, Sendable {
    case signedJSON
    case plainJSON
    case csv
}

nonisolated struct AuditExportBundle: Codable, Sendable {
    let exportedAt: Date
    let installId: String
    let recordCount: Int
    let records: [AuditRequestRecord]
    /// HMAC-SHA256 over the JSON-encoded record array. Present on signedJSON
    /// exports; nil on plain JSON.
    let signature: String?
}

nonisolated final class AuditExporter: @unchecked Sendable {
    static let shared = AuditExporter()
    private init() {}

    /// Renders the export to bytes ready to drop into a file. Caller chooses
    /// the format. Returns suggested filename + content type metadata for UI.
    func render(records: [AuditRequestRecord], format: AuditExportFormat) throws -> (data: Data, suggestedFilename: String) {
        switch format {
        case .signedJSON:
            return try renderSignedJSON(records)
        case .plainJSON:
            return try renderPlainJSON(records)
        case .csv:
            return (renderCSV(records), suggestedFilename: "bastion-audit-\(timestampSuffix()).csv")
        }
    }

    private func renderSignedJSON(_ records: [AuditRequestRecord]) throws -> (Data, String) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let recordsData = try encoder.encode(records)
        let signature = AuditLog.shared.computeExportHMAC(over: recordsData)
        let bundle = AuditExportBundle(
            exportedAt: Date(),
            installId: AuditLog.shared.installIdentifier(),
            recordCount: records.count,
            records: records,
            signature: signature
        )
        let data = try encoder.encode(bundle)
        return (data, "bastion-audit-\(timestampSuffix()).signed.json")
    }

    private func renderPlainJSON(_ records: [AuditRequestRecord]) throws -> (Data, String) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        encoder.dateEncodingStrategy = .iso8601
        let data = try encoder.encode(records)
        return (data, "bastion-audit-\(timestampSuffix()).json")
    }

    private func renderCSV(_ records: [AuditRequestRecord]) -> Data {
        var lines: [String] = ["timestamp,client,operation,result,reason,request_id"]
        for record in records {
            let last = record.latestEvent
            let ts = last?.timestamp ?? ""
            let client = csvEscape(record.clientDisplayName)
            let op = csvEscape(record.operationTitle)
            let result = csvEscape(record.latestResultLabel)
            let reason = csvEscape(record.latestReason ?? "")
            let id = csvEscape(record.requestID)
            lines.append("\(ts),\(client),\(op),\(result),\(reason),\(id)")
        }
        return lines.joined(separator: "\n").data(using: .utf8) ?? Data()
    }

    private func csvEscape(_ s: String) -> String {
        if s.contains(",") || s.contains("\"") || s.contains("\n") {
            let escaped = s.replacingOccurrences(of: "\"", with: "\"\"")
            return "\"\(escaped)\""
        }
        return s
    }

    private func timestampSuffix() -> String {
        let f = DateFormatter()
        f.dateFormat = "yyyyMMdd-HHmmss"
        return f.string(from: Date())
    }
}

extension AuditLog {
    /// Stable identifier for this Bastion install. Derived from the HMAC key
    /// (first 16 bytes of SHA-256). Used as the installId in export bundles.
    nonisolated func installIdentifier() -> String {
        let key = ensureExportKey()
        var hash = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        hash.withUnsafeMutableBytes { hashPtr in
            key.withUnsafeBytes { keyPtr in
                _ = CC_SHA256(keyPtr.baseAddress, CC_LONG(key.count), hashPtr.baseAddress?.assumingMemoryBound(to: UInt8.self))
            }
        }
        return hash.prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    /// HMAC-SHA256 over the export payload.
    nonisolated func computeExportHMAC(over data: Data) -> String {
        let key = ensureExportKey()
        var mac = Data(count: Int(CC_SHA256_DIGEST_LENGTH))
        mac.withUnsafeMutableBytes { macPtr in
            key.withUnsafeBytes { keyPtr in
                data.withUnsafeBytes { dataPtr in
                    CCHmac(
                        CCHmacAlgorithm(kCCHmacAlgSHA256),
                        keyPtr.baseAddress, key.count,
                        dataPtr.baseAddress, data.count,
                        macPtr.baseAddress
                    )
                }
            }
        }
        return mac.map { String(format: "%02x", $0) }.joined()
    }

    /// Returns or lazily creates a 32-byte HMAC key dedicated to exports.
    /// Stored alongside the existing audit-log HMAC key. Distinct from the
    /// internal log MAC so leaking an export bundle's signature doesn't
    /// imply the log on disk was authenticated by the same key.
    nonisolated fileprivate func ensureExportKey() -> Data {
        let account = "auditlog.exportkey"
        let backend = SystemKeychainBackend()
        if let existing = backend.read(account: account), existing.count >= 32 {
            return existing
        }
        var key = Data(count: 32)
        _ = key.withUnsafeMutableBytes { ptr in
            SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        backend.write(account: account, data: key)
        return key
    }
}

import CommonCrypto
import Foundation

nonisolated struct AuditClientSnapshot: Codable, Sendable {
    let bundleId: String?
    let displayName: String
    let accountAddress: String?
}

nonisolated struct AuditPayloadSnapshot: Codable, Sendable, Identifiable {
    let id: String
    let title: String
    let value: String

    init(title: String, value: String) {
        self.id = title
        self.title = title
        self.value = value
    }
}

nonisolated struct AuditSubmissionSnapshot: Codable, Sendable {
    let provider: String
    let status: String
    let userOpHash: String?
    let transactionHash: String?
    let detail: String?
}

nonisolated struct AuditRequestSnapshot: Codable, Sendable {
    let requestID: String
    let operationKind: String
    let title: String
    let summary: String
    let details: [String]
    let digestHex: String
    let payloads: [AuditPayloadSnapshot]?
}

nonisolated struct AuditEvent: Codable, Sendable, Identifiable {
    nonisolated enum EventType: String, Codable, Sendable {
        /// Approval window was shown; awaiting user decision. Records the request
        /// before the blocking await so there is always an audit entry even if the
        /// process is killed while the window is open.
        case signPending = "sign_pending"
        case signSuccess = "sign_success"
        case signDenied = "sign_denied"
        case ruleViolation = "rule_violation"
        case authFailed = "auth_failed"
        /// Preflight simulation completed before the approval window opened.
        case preflightCompleted = "preflight_completed"
        case userOpSubmitted = "user_op_submitted"
        case userOpSendFailed = "user_op_send_failed"
        case userOpReceiptSuccess = "user_op_receipt_success"
        case userOpReceiptFailed = "user_op_receipt_failed"
        case userOpReceiptTimeout = "user_op_receipt_timeout"
    }

    nonisolated enum ApprovalMode: String, Codable, Sendable {
        /// Rules were enabled and passed — signed silently without showing the approval window.
        case auto = "auto"
        /// Rules were disabled — the approval window was shown for user review.
        case policyReview = "policy_review"
        /// A rule was violated — the approval window required explicit override + biometric.
        case ruleOverride = "rule_override"
    }

    let id: String
    let timestamp: String
    let type: EventType
    let dataPrefix: String
    let reason: String?
    let approvalMode: ApprovalMode?
    let client: AuditClientSnapshot?
    let request: AuditRequestSnapshot?
    let submission: AuditSubmissionSnapshot?

    init(
        type: EventType,
        dataPrefix: String,
        reason: String? = nil,
        approvalMode: ApprovalMode? = nil,
        request: SignRequest? = nil,
        clientContext: ClientSigningContext? = nil,
        submission: AuditSubmissionSnapshot? = nil,
        redactionLevel: AuditRedactionLevel = .none
    ) {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]

        self.id = UUID().uuidString
        self.timestamp = formatter.string(from: Date())
        self.type = type
        self.dataPrefix = dataPrefix
        self.reason = reason
        self.approvalMode = approvalMode
        self.client = clientContext.map {
            AuditClientSnapshot(
                bundleId: $0.bundleId,
                displayName: $0.displayName,
                accountAddress: $0.accountAddress
            )
        }
        self.request = request.map { Self.makeRequestSnapshot($0, redactionLevel: redactionLevel) }
        self.submission = submission
    }

    private enum CodingKeys: String, CodingKey {
        case id
        case timestamp
        case type
        case dataPrefix
        case reason
        case approvalMode
        case client
        case request
        case submission
    }

    init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        timestamp = try container.decode(String.self, forKey: .timestamp)
        type = try container.decode(EventType.self, forKey: .type)
        dataPrefix = try container.decodeIfPresent(String.self, forKey: .dataPrefix) ?? "unknown"
        reason = try container.decodeIfPresent(String.self, forKey: .reason)
        approvalMode = try container.decodeIfPresent(ApprovalMode.self, forKey: .approvalMode)
        client = try container.decodeIfPresent(AuditClientSnapshot.self, forKey: .client)
        request = try container.decodeIfPresent(AuditRequestSnapshot.self, forKey: .request)
        submission = try container.decodeIfPresent(AuditSubmissionSnapshot.self, forKey: .submission)
        id = try container.decodeIfPresent(String.self, forKey: .id) ?? "\(timestamp)|\(type.rawValue)|\(dataPrefix)"
    }

    var timestampDate: Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: timestamp)
    }

    var clientDisplayName: String {
        client?.displayName ?? "Unknown client"
    }

    var operationTitle: String {
        switch type {
        case .userOpSubmitted:
            return "UserOp Submitted"
        case .userOpSendFailed:
            return "UserOp Send Failed"
        case .userOpReceiptSuccess:
            return "UserOp Confirmed"
        case .userOpReceiptFailed:
            return "UserOp Receipt Failed"
        case .userOpReceiptTimeout:
            return "UserOp Receipt Pending"
        case .signPending, .signSuccess, .signDenied, .ruleViolation, .authFailed, .preflightCompleted:
            break
        }
        return request?.title ?? type.rawValue
    }

    var resultLabel: String {
        switch type {
        case .signPending:
            return "Pending Approval"
        case .signSuccess:
            switch approvalMode {
            case .auto: return "Signed (Auto)"
            case .policyReview: return "Signed (Approved)"
            case .ruleOverride: return "Signed (Override)"
            case nil: return "Signed"
            }
        case .signDenied:
            return "Denied"
        case .ruleViolation:
            return "Rule Violation"
        case .authFailed:
            return "Auth Failed"
        case .userOpSubmitted:
            return "Submitted"
        case .userOpSendFailed:
            return "Send Failed"
        case .userOpReceiptSuccess:
            return "Confirmed"
        case .userOpReceiptFailed:
            return "Receipt Failed"
        case .userOpReceiptTimeout:
            return "Receipt Pending"
        case .preflightCompleted:
            return "Preflight"
        }
    }

    private static func makeRequestSnapshot(
        _ request: SignRequest,
        redactionLevel: AuditRedactionLevel
    ) -> AuditRequestSnapshot {
        let rawSnapshot = makeRawRequestSnapshot(request)
        return applyRedaction(rawSnapshot, level: redactionLevel)
    }

    // MARK: - Redaction

    private static func applyRedaction(
        _ snapshot: AuditRequestSnapshot,
        level: AuditRedactionLevel
    ) -> AuditRequestSnapshot {
        switch level {
        case .none:
            return snapshot
        case .redactPayloads:
            let redactedDetails = snapshot.details.map { detail -> String in
                // Redact lines that contain Ethereum addresses (0x + 40 hex chars) or
                // numeric amounts (pure digit strings longer than 10 chars, e.g. wei).
                if containsSensitiveData(detail) {
                    return "[REDACTED]"
                }
                return detail
            }
            return AuditRequestSnapshot(
                requestID: snapshot.requestID,
                operationKind: snapshot.operationKind,
                title: snapshot.title,
                summary: snapshot.summary,
                details: redactedDetails,
                digestHex: snapshot.digestHex,
                payloads: nil
            )
        case .redactAll:
            return AuditRequestSnapshot(
                requestID: snapshot.requestID,
                operationKind: snapshot.operationKind,
                title: snapshot.title,
                summary: snapshot.summary,
                details: ["[REDACTED]"],
                digestHex: "[REDACTED]",
                payloads: nil
            )
        }
    }

    /// Returns true if the string appears to contain an Ethereum address or large numeric amount.
    private static func containsSensitiveData(_ string: String) -> Bool {
        // Ethereum address: 0x followed by exactly 40 hex characters
        if let range = string.range(of: "0x[0-9a-fA-F]{40}", options: .regularExpression) {
            _ = range
            return true
        }
        // Large numeric value (>10 digits, e.g. wei amounts)
        if let _ = string.range(of: "\\b[0-9]{11,}\\b", options: .regularExpression) {
            return true
        }
        return false
    }

    // MARK: - Raw snapshot construction (no redaction)

    private static func makeRawRequestSnapshot(_ request: SignRequest) -> AuditRequestSnapshot {
        let digestHex = "0x" + request.data.hex

        switch request.operation {
        case .message(let text):
            let isHexPayload = text.hasPrefix("0x")
            return AuditRequestSnapshot(
                requestID: request.requestID,
                operationKind: "raw_message",
                title: "Raw / Message Signing",
                summary: isHexPayload ? "Personal-sign hex payload" : "Personal-sign UTF-8 message",
                details: [
                    "Encoding: \(isHexPayload ? "Hex payload" : "UTF-8 text")",
                    "Length: \(text.count) characters",
                ],
                digestHex: digestHex,
                payloads: [
                    AuditPayloadSnapshot(title: "Message", value: text),
                ]
            )

        case .rawBytes(let data):
            return AuditRequestSnapshot(
                requestID: request.requestID,
                operationKind: "raw_bytes",
                title: "Raw Bytes Signing",
                summary: "Direct 32-byte signing — no Ethereum prefix applied",
                details: [
                    "Length: \(data.count) bytes",
                    "Warning: payload signed as-is without any EIP-191 or EIP-712 prefix",
                ],
                digestHex: digestHex,
                payloads: [
                    AuditPayloadSnapshot(title: "Payload", value: "0x" + data.hex),
                ]
            )

        case .typedData(let typed):
            var details: [String] = [
                "Primary Type: \(typed.primaryType)",
            ]

            if let name = typed.domain.name {
                details.append("Domain Name: \(name)")
            }
            if let version = typed.domain.version {
                details.append("Domain Version: \(version)")
            }
            if let chainId = typed.domain.chainId {
                details.append("Chain: \(ChainConfig.name(for: chainId)) (\(chainId))")
            }
            if let verifyingContract = typed.domain.verifyingContract {
                details.append("Verifying Contract: \(verifyingContract)")
            }
            if let messageJSON = prettyJSONString(typed.message.mapValues(\.value)) {
                details.append("Message JSON:\n\(messageJSON)")
            }

            return AuditRequestSnapshot(
                requestID: request.requestID,
                operationKind: "typed_data",
                title: "EIP-712 Typed Data",
                summary: typed.domain.name.map { "\(typed.primaryType) for \($0)" } ?? typed.primaryType,
                details: details,
                digestHex: digestHex,
                payloads: [
                    AuditPayloadSnapshot(
                        title: "Typed Data JSON",
                        value: prettyJSONString(fromEncodable: typed) ?? typed.primaryType
                    ),
                ]
            )

        case .userOperation(let op):
            let decoded = CalldataDecoder.decode(op)
            var details: [String] = [
                "Smart Account: \(op.sender)",
                "Chain: \(decoded.chainName) (\(op.chainId))",
                "EntryPoint: \(op.entryPointVersion.rawValue)",
            ]
            var payloads = [
                AuditPayloadSnapshot(
                    title: "UserOperation JSON",
                    value: prettyJSONString(fromEncodable: op) ?? "Unable to encode UserOperation"
                ),
            ]

            if let factory = op.factory {
                details.append("Factory: \(factory)")
            }
            if let submission = request.userOperationSubmission {
                details.append("Post-Approval Action: Submit to \(submission.provider.displayName)")
                payloads.append(
                    AuditPayloadSnapshot(
                        title: "Submission Request",
                        value: prettyJSONString(fromEncodable: submission) ?? submission.provider.displayName
                    )
                )
            }

            if decoded.executions.isEmpty {
                details.append("Actions: No decoded execution")
            } else {
                for (index, execution) in decoded.executions.enumerated().prefix(10) {
                    details.append("Action \(index + 1): \(execution.description)")
                }
                if decoded.executions.count > 10 {
                    details.append("Actions: +\(decoded.executions.count - 10) more")
                }
            }

            return AuditRequestSnapshot(
                requestID: request.requestID,
                operationKind: "user_operation",
                title: decoded.isDeployment ? "UserOperation Deployment" : "UserOperation",
                summary: decoded.executions.first?.description ?? "UserOperation on \(decoded.chainName)",
                details: details,
                digestHex: digestHex,
                payloads: payloads
            )
        }
    }

    private static func prettyJSONString(_ object: Any) -> String? {
        guard JSONSerialization.isValidJSONObject(object),
              let data = try? JSONSerialization.data(withJSONObject: object, options: [.prettyPrinted, .sortedKeys]),
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }
        return string
    }

    private static func prettyJSONString<T: Encodable>(fromEncodable value: T) -> String? {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(value),
              let string = String(data: data, encoding: .utf8) else {
            return nil
        }
        return string
    }
}

nonisolated struct AuditRequestRecord: Codable, Sendable, Identifiable {
    let id: String
    let client: AuditClientSnapshot?
    let request: AuditRequestSnapshot?
    let events: [AuditEvent]

    init(events: [AuditEvent]) {
        let sortedEvents = events.sorted { lhs, rhs in
            switch (lhs.timestampDate, rhs.timestampDate) {
            case let (left?, right?):
                return left < right
            default:
                return lhs.timestamp < rhs.timestamp
            }
        }

        self.events = sortedEvents
        self.request = sortedEvents.reversed().compactMap(\.request).first
        self.client = sortedEvents.reversed().compactMap(\.client).first
        self.id = self.request?.requestID ?? sortedEvents.last?.id ?? UUID().uuidString
    }

    func appending(_ event: AuditEvent) -> AuditRequestRecord {
        if events.contains(where: { $0.id == event.id }) {
            return self
        }
        return AuditRequestRecord(events: events + [event])
    }

    var latestEvent: AuditEvent? {
        events.last
    }

    var latestSubmission: AuditSubmissionSnapshot? {
        events.reversed().compactMap(\.submission).first
    }

    var latestTimestamp: Date? {
        latestEvent?.timestampDate
    }

    var latestResultLabel: String {
        latestEvent?.resultLabel ?? "Unknown"
    }

    var latestReason: String? {
        latestEvent?.reason
    }

    var clientDisplayName: String {
        client?.displayName ?? latestEvent?.clientDisplayName ?? "Unknown client"
    }

    var operationTitle: String {
        request?.title ?? latestEvent?.operationTitle ?? "Audit Request"
    }

    var summary: String {
        request?.summary ?? latestEvent?.reason ?? "No request summary available."
    }

    var requestID: String {
        request?.requestID ?? id
    }
}

// MARK: - HMAC helpers (CommonCrypto)

private nonisolated func hmacSHA256(key: Data, data: Data) -> Data {
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
    return mac
}

// MARK: - AuditLog

nonisolated final class AuditLog: @unchecked Sendable {
    static let shared = AuditLog()

    // L-05: Cap audit records to prevent unbounded growth / DoS via flooding.
    private nonisolated static let maxRecords = 1000
    // D-01: Drop records older than this to limit on-disk audit footprint.
    private nonisolated static let maxAgeSeconds: TimeInterval = 90 * 24 * 3600

    // Keychain accounts for HMAC tamper evidence.
    private nonisolated static let hmacKeyAccount = "auditlog.hmackey"
    private nonisolated static let hmacMacAccount = "auditlog.mac"

    private let logURL: URL
    private let fileManager = FileManager.default
    private let queue = DispatchQueue(label: "com.bastion.auditlog")

    /// The keychain backend used for HMAC key and MAC storage.
    /// Defaults to the system keychain; can be injected for testing.
    private let keychain: KeychainBackend

    /// Whether the last load detected a HMAC mismatch (file may have been tampered with).
    /// Written only from the serial queue; read from any thread.
    private var _logTampered: Bool = false
    var logTampered: Bool {
        queue.sync { _logTampered }
    }

    /// Redaction level applied when building `AuditRequestSnapshot` values.
    /// Set from config on startup and whenever config is updated.
    var redactionLevel: AuditRedactionLevel {
        get { queue.sync { _redactionLevel } }
        set { queue.sync { _redactionLevel = newValue } }
    }
    private var _redactionLevel: AuditRedactionLevel = .none

    private init() {
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let bastionDir = appSupport.appendingPathComponent("Bastion")
        if !fileManager.fileExists(atPath: bastionDir.path) {
            try? fileManager.createDirectory(at: bastionDir, withIntermediateDirectories: true)
        }
        self.logURL = bastionDir.appendingPathComponent("audit.log")
        self.keychain = SystemKeychainBackend()
    }

    init(logURL: URL, keychain: KeychainBackend = SystemKeychainBackend()) {
        self.logURL = logURL
        self.keychain = keychain
    }

    nonisolated func record(_ event: AuditEvent) {
        queue.sync {
            var records = loadRequestRecordsLocked()
            let key = event.request?.requestID ?? "legacy|\(event.id)"

            if let index = records.firstIndex(where: { $0.requestID == key }) {
                records[index] = records[index].appending(event)
            } else {
                records.append(AuditRequestRecord(events: [event]))
            }

            saveRequestRecordsLocked(records)
        }
    }

    nonisolated func record(
        type: AuditEvent.EventType,
        dataPrefix: String,
        reason: String? = nil,
        approvalMode: AuditEvent.ApprovalMode? = nil,
        request: SignRequest? = nil,
        clientContext: ClientSigningContext? = nil,
        submission: AuditSubmissionSnapshot? = nil
    ) {
        let level = queue.sync { _redactionLevel }
        let event = AuditEvent(
            type: type,
            dataPrefix: dataPrefix,
            reason: reason,
            approvalMode: approvalMode,
            request: request,
            clientContext: clientContext,
            submission: submission,
            redactionLevel: level
        )
        record(event)
    }

    nonisolated func recentEvents(limit: Int) -> [AuditEvent] {
        queue.sync {
            let allEvents = loadRequestRecordsLocked()
                .flatMap(\.events)
                .sorted { lhs, rhs in
                    switch (lhs.timestampDate, rhs.timestampDate) {
                    case let (left?, right?):
                        return left < right
                    default:
                        return lhs.timestamp < rhs.timestamp
                    }
                }
            return Array(allEvents.suffix(limit))
        }
    }

    nonisolated func recentRequestRecords(limit: Int) -> [AuditRequestRecord] {
        queue.sync {
            Array(loadRequestRecordsLocked()
                .sorted { lhs, rhs in
                switch (lhs.latestTimestamp, rhs.latestTimestamp) {
                case let (left?, right?):
                    return left > right
                case (.some, .none):
                    return true
                case (.none, .some):
                    return false
                case (.none, .none):
                    return lhs.id > rhs.id
                }
            }
                .prefix(limit))
        }
    }

    nonisolated func totalCountToday(type: AuditEvent.EventType) -> Int {
        queue.sync {
            let calendar = Calendar.current
            let today = calendar.startOfDay(for: Date())
            return loadRequestRecordsLocked()
                .flatMap(\.events)
                .filter { event in
                    guard event.type == type,
                          let date = event.timestampDate else { return false }
                    return date >= today
                }
                .count
        }
    }

    // MARK: - HMAC key management (called on queue)

    private nonisolated func hmacKeyLocked() -> Data {
        if let existing = keychain.read(account: Self.hmacKeyAccount) {
            return existing
        }
        var fresh = Data(count: 32)
        fresh.withUnsafeMutableBytes { ptr in
            _ = SecRandomCopyBytes(kSecRandomDefault, 32, ptr.baseAddress!)
        }
        keychain.write(account: Self.hmacKeyAccount, data: fresh)
        return fresh
    }

    // MARK: - Load / Save (called on queue)

    private nonisolated func loadRequestRecordsLocked() -> [AuditRequestRecord] {
        guard let data = try? Data(contentsOf: logURL), !data.isEmpty else {
            // Fresh start — clear any stale MAC.
            keychain.delete(account: Self.hmacMacAccount)
            _logTampered = false
            return []
        }

        // HMAC verification
        let key = hmacKeyLocked()
        let computedMAC = hmacSHA256(key: key, data: data)
        if let storedMAC = keychain.read(account: Self.hmacMacAccount) {
            if storedMAC != computedMAC {
                NSLog("[AuditLog] WARNING: HMAC mismatch — audit log may have been tampered with")
                _logTampered = true
            } else {
                _logTampered = false
            }
        }
        // If no stored MAC yet (e.g. migrating from older version), accept data and store MAC now.
        // _logTampered remains unchanged from its current value.

        let decoder = JSONDecoder()
        if let records = try? decoder.decode([AuditRequestRecord].self, from: data) {
            return records
        }

        guard let content = String(data: data, encoding: .utf8) else {
            return []
        }

        let lines = content.components(separatedBy: "\n").filter { !$0.isEmpty }
        if lines.isEmpty {
            return []
        }

        var parsedRecords: [AuditRequestRecord] = []
        var parsedEvents: [AuditEvent] = []

        for line in lines {
            guard let lineData = line.data(using: .utf8) else { continue }
            if let record = try? decoder.decode(AuditRequestRecord.self, from: lineData) {
                parsedRecords.append(record)
            } else if let event = try? decoder.decode(AuditEvent.self, from: lineData) {
                parsedEvents.append(event)
            }
        }

        if !parsedRecords.isEmpty {
            saveRequestRecordsLocked(parsedRecords)
            return parsedRecords
        }

        if parsedEvents.isEmpty {
            return []
        }

        var grouped: [String: [AuditEvent]] = [:]
        for event in parsedEvents {
            let key = event.request?.requestID ?? "legacy|\(event.id)"
            grouped[key, default: []].append(event)
        }
        let records = grouped.values.map(AuditRequestRecord.init)
        saveRequestRecordsLocked(records)
        return records
    }

    private nonisolated func saveRequestRecordsLocked(_ records: [AuditRequestRecord]) {
        let sortedRecords = records.sorted { lhs, rhs in
            switch (lhs.latestTimestamp, rhs.latestTimestamp) {
            case let (left?, right?):
                return left > right
            case (.some, .none):
                return true
            case (.none, .some):
                return false
            case (.none, .none):
                return lhs.id > rhs.id
            }
        }

        // D-01: Drop records older than maxAgeSeconds. Records with no parseable
        // timestamp are retained (conservative — better to keep than silently drop).
        let cutoff = Date().addingTimeInterval(-Self.maxAgeSeconds)
        let ageFilteredRecords = sortedRecords.filter { record in
            guard let latest = record.latestTimestamp else { return true }
            return latest >= cutoff
        }

        // L-05: Trim to max records to prevent unbounded growth.
        let trimmedRecords = Array(ageFilteredRecords.prefix(Self.maxRecords))

        let directory = logURL.deletingLastPathComponent()
        if !fileManager.fileExists(atPath: directory.path) {
            try? fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        guard let data = try? encoder.encode(trimmedRecords) else { return }
        try? data.write(to: logURL, options: .atomic)

        // H-04: Set restrictive file permissions (owner read/write only).
        // Prevents other user-level processes from tampering with the audit log.
        try? fileManager.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: logURL.path
        )

        // Store HMAC-SHA256(key, data) so tamper detection works on next load.
        let key = hmacKeyLocked()
        let mac = hmacSHA256(key: key, data: data)
        keychain.write(account: Self.hmacMacAccount, data: mac)
    }
}

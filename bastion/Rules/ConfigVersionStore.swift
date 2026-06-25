import Foundation

// Policy version history. Every successful BastionConfig save snapshots the
// resulting config to disk under ~/Library/Application Support/Bastion/policy-history/.
// Old snapshots are pruned beyond `maxVersions`. The Settings UI surfaces the
// list and lets the owner roll back.

nonisolated struct PolicyVersion: Codable, Sendable, Identifiable {
    let id: String
    let timestamp: Date
    let summary: String
    let config: BastionConfig
}

nonisolated final class ConfigVersionStore: @unchecked Sendable {
    typealias DiagnosticRecorder = @Sendable (
        DiagnosticLevel,
        DiagnosticCategory,
        String,
        String,
        [String: String]
    ) -> Void

    static let shared = ConfigVersionStore()
    private let lock = NSLock()
    private let directoryURL: URL?
    private let maxVersions: Int
    private let recordDiagnostic: DiagnosticRecorder

    init(
        directoryURL: URL? = nil,
        maxVersions: Int = 50,
        recordDiagnostic: @escaping DiagnosticRecorder = { level, category, event, message, context in
            DiagnosticLog.shared.record(
                level: level,
                category: category,
                event: event,
                message: message,
                context: context
            )
        }
    ) {
        self.directoryURL = directoryURL
        self.maxVersions = maxVersions
        self.recordDiagnostic = recordDiagnostic
    }

    /// Records a new version. Best-effort so the user-facing save flow can't be
    /// blocked by file-system errors, but failures are still written to diagnostics.
    func recordVersion(_ config: BastionConfig) {
        lock.lock(); defer { lock.unlock() }
        do {
            let dir = try ensureDir()
            let id = UUID().uuidString
            let summary = makeSummary(config)
            let version = PolicyVersion(id: id, timestamp: Date(), summary: summary, config: config)
            let url = dir.appendingPathComponent("\(version.timestamp.timeIntervalSince1970)-\(id).json")
            let data = try JSONEncoder().encode(version)
            try data.write(to: url, options: .atomic)
            lockDownFile(url)
            pruneOld(in: dir)
        } catch {
            let message = policyHistorySnapshotFailureMessage(error)
            recordDiagnostic(
                .warning,
                .policy,
                "policy_history_snapshot_failed",
                message,
                policyHistorySnapshotFailureContext(error: error)
            )
            NSLog("[ConfigVersionStore] %@", message)
        }
    }

    /// Returns versions newest-first.
    func versions() -> [PolicyVersion] {
        lock.lock(); defer { lock.unlock() }
        let dir: URL
        do {
            dir = try ensureDir()
        } catch {
            recordPolicyHistoryReadFailure(error)
            return []
        }

        let urls: [URL]
        do {
            urls = try FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)
        } catch {
            recordPolicyHistoryReadFailure(error)
            return []
        }

        let decoder = JSONDecoder()
        let versions: [PolicyVersion] = urls.compactMap { url in
            do {
                let data = try Data(contentsOf: url)
                return try decoder.decode(PolicyVersion.self, from: data)
            } catch {
                recordPolicyHistorySnapshotReadFailure(url: url, error: error)
                return nil
            }
        }
        return versions.sorted { $0.timestamp > $1.timestamp }
    }

    /// Restore a previous version. Caller must follow up with
    /// RuleEngine.updateConfig (which prompts biometric and persists).
    func resolve(versionId: String) -> BastionConfig? {
        versions().first { $0.id == versionId }?.config
    }

    private func makeSummary(_ config: BastionConfig) -> String {
        var parts: [String] = []
        parts.append("auth=\(config.authPolicy.rawValue)")
        parts.append("clients=\(config.clientProfiles.count)")
        parts.append("groups=\(config.walletGroups.count)")
        parts.append("templates=\(config.ruleTemplates.count)")
        if config.pauseState.paused { parts.append("paused") }
        if config.pauseState.lockedDown { parts.append("lockdown") }
        return parts.joined(separator: " · ")
    }

    func policyHistorySnapshotFailureMessage(_ error: Error) -> String {
        "Policy history snapshot failed: \(error.localizedDescription)"
    }

    func policyHistorySnapshotFailureContext(error: Error) -> [String: String] {
        [
            "historyDirectory": configuredHistoryDirectoryPath(),
            "maxVersions": String(maxVersions),
            "error": error.localizedDescription,
        ]
    }

    func policyHistoryReadFailureMessage(_ error: Error) -> String {
        "Policy history read failed: \(error.localizedDescription)"
    }

    func policyHistoryReadFailureContext(error: Error) -> [String: String] {
        [
            "historyDirectory": configuredHistoryDirectoryPath(),
            "error": error.localizedDescription,
        ]
    }

    func policyHistorySnapshotReadFailureMessage(url: URL, error: Error) -> String {
        "Policy history snapshot read failed for \(url.lastPathComponent): \(error.localizedDescription)"
    }

    func policyHistorySnapshotReadFailureContext(url: URL, error: Error) -> [String: String] {
        [
            "historyDirectory": configuredHistoryDirectoryPath(),
            "snapshotFile": url.lastPathComponent,
            "error": error.localizedDescription,
        ]
    }

    private func recordPolicyHistoryReadFailure(_ error: Error) {
        let message = policyHistoryReadFailureMessage(error)
        recordDiagnostic(
            .warning,
            .policy,
            "policy_history_read_failed",
            message,
            policyHistoryReadFailureContext(error: error)
        )
        NSLog("[ConfigVersionStore] %@", message)
    }

    private func recordPolicyHistorySnapshotReadFailure(url: URL, error: Error) {
        let message = policyHistorySnapshotReadFailureMessage(url: url, error: error)
        recordDiagnostic(
            .warning,
            .policy,
            "policy_history_snapshot_read_failed",
            message,
            policyHistorySnapshotReadFailureContext(url: url, error: error)
        )
        NSLog("[ConfigVersionStore] %@", message)
    }

    private func configuredHistoryDirectoryPath() -> String {
        if let directoryURL {
            return directoryURL.path
        }
        return "~/Library/Application Support/Bastion/policy-history"
    }

    private func ensureDir() throws -> URL {
        let support: URL
        if let directoryURL {
            support = directoryURL
        } else {
            support = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            ).appendingPathComponent("Bastion/policy-history", isDirectory: true)
        }
        // Lock the directory down so a malicious local user (different uid)
        // can't read snapshots of the policy. Snapshots include client
        // allowlists, key tags, and audit redaction settings — sensitive
        // metadata even if there are no raw keys.
        try FileManager.default.createDirectory(
            at: support,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
        // createDirectory only sets permissions on newly-created leaf dirs;
        // re-apply to be safe on older installs.
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o700],
            ofItemAtPath: support.path
        )
        return support
    }

    /// Apply 0600 to a freshly-written snapshot file.
    private func lockDownFile(_ url: URL) {
        try? FileManager.default.setAttributes(
            [.posixPermissions: 0o600],
            ofItemAtPath: url.path
        )
    }

    private func pruneOld(in dir: URL) {
        let urls = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: [.creationDateKey])) ?? []
        guard urls.count > maxVersions else { return }
        let decoder = JSONDecoder()
        let sorted = urls.sorted { lhs, rhs in
            let l = sortDate(for: lhs, decoder: decoder)
            let r = sortDate(for: rhs, decoder: decoder)
            if l != r {
                return l > r
            }
            return lhs.lastPathComponent > rhs.lastPathComponent
        }
        for url in sorted.dropFirst(maxVersions) {
            try? FileManager.default.removeItem(at: url)
        }
    }

    private func sortDate(for url: URL, decoder: JSONDecoder) -> Date {
        if let data = try? Data(contentsOf: url),
           let version = try? decoder.decode(PolicyVersion.self, from: data) {
            return version.timestamp
        }
        return (try? url.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
    }
}

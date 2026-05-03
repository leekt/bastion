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
    static let shared = ConfigVersionStore()
    private let lock = NSLock()
    private let maxVersions = 50

    /// Records a new version. Best-effort — failures are logged and dropped so
    /// the user-facing save flow can't be blocked by file system errors.
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
            NSLog("[ConfigVersionStore] failed to record version: %@", String(describing: error))
        }
    }

    /// Returns versions newest-first.
    func versions() -> [PolicyVersion] {
        lock.lock(); defer { lock.unlock() }
        guard let dir = try? ensureDir() else { return [] }
        let urls = (try? FileManager.default.contentsOfDirectory(at: dir, includingPropertiesForKeys: nil)) ?? []
        let decoder = JSONDecoder()
        let versions: [PolicyVersion] = urls.compactMap { url in
            guard let data = try? Data(contentsOf: url) else { return nil }
            return try? decoder.decode(PolicyVersion.self, from: data)
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

    private func ensureDir() throws -> URL {
        let support = try FileManager.default.url(
            for: .applicationSupportDirectory,
            in: .userDomainMask,
            appropriateFor: nil,
            create: true
        ).appendingPathComponent("Bastion/policy-history", isDirectory: true)
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
        let sorted = urls.sorted { lhs, rhs in
            let l = (try? lhs.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
            let r = (try? rhs.resourceValues(forKeys: [.creationDateKey]).creationDate) ?? .distantPast
            return l > r
        }
        for url in sorted.dropFirst(maxVersions) {
            try? FileManager.default.removeItem(at: url)
        }
    }
}

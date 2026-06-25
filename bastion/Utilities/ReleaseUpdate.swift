import CryptoKit
import Foundation

nonisolated struct InstalledReleaseIdentity: Codable, Sendable, Equatable {
    let bundleIdentifier: String
    let version: String
    let build: String
}

nonisolated struct ReleaseUpdateManifest: Codable, Sendable, Equatable {
    let app: String
    let bundleIdentifier: String
    let version: String
    let build: String
    let platform: String
    let minimumOSVersion: String
    let publishedAt: String
    let downloadURL: String
    let releaseNotesURL: String
    let sha256: String
    let sizeBytes: Int
    let notarized: Bool
    let stapled: Bool
}

nonisolated enum ReleaseUpdateState: String, Codable, Sendable, Equatable {
    case updateAvailable = "update_available"
    case upToDate = "up_to_date"
    case incompatible
    case rejected
}

nonisolated struct ReleaseUpdateArtifact: Codable, Sendable, Equatable {
    let localPath: String
    let sha256: String
    let sizeBytes: Int
}

nonisolated struct ReleaseUpdateCheckResult: Codable, Sendable, Equatable {
    let state: ReleaseUpdateState
    let reason: String
    let current: InstalledReleaseIdentity
    let manifest: ReleaseUpdateManifest
    let artifact: ReleaseUpdateArtifact?
}

nonisolated enum ReleaseUpdateError: Error, LocalizedError, Sendable {
    case invalidManifest(String)
    case downloadFailed(String)
    case artifactVerificationFailed(String)
    case currentIdentityUnavailable

    var errorDescription: String? {
        switch self {
        case .invalidManifest(let reason):
            return "Invalid update manifest: \(reason)"
        case .downloadFailed(let reason):
            return "Update download failed: \(reason)"
        case .artifactVerificationFailed(let reason):
            return "Update artifact verification failed: \(reason)"
        case .currentIdentityUnavailable:
            return "Could not determine the installed Bastion app identity"
        }
    }
}

nonisolated enum ReleaseUpdateVerifier {
    static let expectedBundleIdentifier = "com.bastion.app"
    static let expectedPlatform = "macOS"

    static func currentIdentity(appBundleURL: URL? = nil) throws -> InstalledReleaseIdentity {
        let info: [String: Any]?
        if let appBundleURL {
            let infoURL = appBundleURL
                .appendingPathComponent("Contents", isDirectory: true)
                .appendingPathComponent("Info.plist")
            let data = try? Data(contentsOf: infoURL)
            info = data.flatMap {
                try? PropertyListSerialization.propertyList(from: $0, options: [], format: nil) as? [String: Any]
            }
        } else {
            info = Bundle.main.infoDictionary
        }

        guard let info,
              let bundleIdentifier = info["CFBundleIdentifier"] as? String,
              let version = info["CFBundleShortVersionString"] as? String,
              let build = info["CFBundleVersion"] as? String else {
            throw ReleaseUpdateError.currentIdentityUnavailable
        }

        return InstalledReleaseIdentity(
            bundleIdentifier: bundleIdentifier,
            version: version,
            build: build
        )
    }

    static func appSupportUpdateDirectory() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return appSupport
            .appendingPathComponent("Bastion", isDirectory: true)
            .appendingPathComponent("Updates", isDirectory: true)
    }

    static func loadManifest(from url: URL) async throws -> ReleaseUpdateManifest {
        let data: Data
        if url.isFileURL {
            data = try Data(contentsOf: url)
        } else {
            let (downloaded, response) = try await URLSession.shared.data(from: url)
            if let http = response as? HTTPURLResponse,
               !(200..<300).contains(http.statusCode) {
                throw ReleaseUpdateError.downloadFailed("manifest HTTP \(http.statusCode)")
            }
            data = downloaded
        }

        do {
            return try JSONDecoder().decode(ReleaseUpdateManifest.self, from: data)
        } catch {
            throw ReleaseUpdateError.invalidManifest(error.localizedDescription)
        }
    }

    static func evaluate(
        manifest: ReleaseUpdateManifest,
        current: InstalledReleaseIdentity,
        currentOSVersion: OperatingSystemVersion = ProcessInfo.processInfo.operatingSystemVersion,
        expectedBundleIdentifier: String = Self.expectedBundleIdentifier
    ) -> ReleaseUpdateCheckResult {
        if manifest.bundleIdentifier != expectedBundleIdentifier {
            return result(
                .rejected,
                "Manifest bundle identifier \(manifest.bundleIdentifier) does not match \(expectedBundleIdentifier)",
                current: current,
                manifest: manifest
            )
        }

        if current.bundleIdentifier != expectedBundleIdentifier {
            return result(
                .rejected,
                "Installed bundle identifier \(current.bundleIdentifier) does not match \(expectedBundleIdentifier)",
                current: current,
                manifest: manifest
            )
        }

        if manifest.platform != Self.expectedPlatform {
            return result(.rejected, "Manifest platform \(manifest.platform) is not macOS", current: current, manifest: manifest)
        }

        if manifest.notarized == false || manifest.stapled == false {
            return result(.rejected, "Manifest is not marked notarized and stapled", current: current, manifest: manifest)
        }

        if URL(string: manifest.downloadURL) == nil || manifest.downloadURL.isEmpty {
            return result(.rejected, "Manifest downloadURL is empty or invalid", current: current, manifest: manifest)
        }

        if manifest.sha256.range(of: #"^[0-9a-fA-F]{64}$"#, options: .regularExpression) == nil {
            return result(.rejected, "Manifest SHA-256 is not a 64-character hex digest", current: current, manifest: manifest)
        }

        if manifest.sizeBytes <= 0 {
            return result(.rejected, "Manifest sizeBytes must be positive", current: current, manifest: manifest)
        }

        if !isOS(currentOSVersion, atLeast: manifest.minimumOSVersion) {
            return result(
                .incompatible,
                "Installed macOS is older than required \(manifest.minimumOSVersion)",
                current: current,
                manifest: manifest
            )
        }

        if isRemoteNewer(manifest: manifest, current: current) {
            return result(
                .updateAvailable,
                "Bastion \(manifest.version) (\(manifest.build)) is available",
                current: current,
                manifest: manifest
            )
        }

        return result(.upToDate, "Installed Bastion is current", current: current, manifest: manifest)
    }

    static func downloadAndVerify(
        manifest: ReleaseUpdateManifest,
        outputDirectory: URL = appSupportUpdateDirectory()
    ) async throws -> ReleaseUpdateArtifact {
        guard let sourceURL = URL(string: manifest.downloadURL) else {
            throw ReleaseUpdateError.invalidManifest("downloadURL is invalid")
        }

        try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)
        let filename = sourceURL.lastPathComponent.isEmpty
            ? "Bastion-\(manifest.version)-\(manifest.build)-macOS.zip"
            : sourceURL.lastPathComponent
        let destination = outputDirectory.appendingPathComponent(filename)
        try? FileManager.default.removeItem(at: destination)

        do {
            if sourceURL.isFileURL {
                try FileManager.default.copyItem(at: sourceURL, to: destination)
            } else {
                let (tempURL, response) = try await URLSession.shared.download(from: sourceURL)
                if let http = response as? HTTPURLResponse,
                   !(200..<300).contains(http.statusCode) {
                    throw ReleaseUpdateError.downloadFailed("artifact HTTP \(http.statusCode)")
                }
                try FileManager.default.moveItem(at: tempURL, to: destination)
            }
        } catch let error as ReleaseUpdateError {
            throw error
        } catch {
            throw ReleaseUpdateError.downloadFailed(error.localizedDescription)
        }

        return try verifyArtifact(at: destination, manifest: manifest)
    }

    static func verifyArtifact(at url: URL, manifest: ReleaseUpdateManifest) throws -> ReleaseUpdateArtifact {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attributes[.size] as? NSNumber)?.intValue ?? -1
        guard size == manifest.sizeBytes else {
            throw ReleaseUpdateError.artifactVerificationFailed(
                "size \(size) does not match manifest \(manifest.sizeBytes)"
            )
        }

        let digest = try sha256Hex(of: url)
        guard digest.caseInsensitiveCompare(manifest.sha256) == .orderedSame else {
            throw ReleaseUpdateError.artifactVerificationFailed(
                "SHA-256 \(digest) does not match manifest \(manifest.sha256)"
            )
        }

        return ReleaseUpdateArtifact(localPath: url.path, sha256: digest, sizeBytes: size)
    }

    private static func result(
        _ state: ReleaseUpdateState,
        _ reason: String,
        current: InstalledReleaseIdentity,
        manifest: ReleaseUpdateManifest,
        artifact: ReleaseUpdateArtifact? = nil
    ) -> ReleaseUpdateCheckResult {
        ReleaseUpdateCheckResult(
            state: state,
            reason: reason,
            current: current,
            manifest: manifest,
            artifact: artifact
        )
    }

    private static func sha256Hex(of url: URL) throws -> String {
        let data = try Data(contentsOf: url)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    private static func isRemoteNewer(
        manifest: ReleaseUpdateManifest,
        current: InstalledReleaseIdentity
    ) -> Bool {
        switch compareVersion(manifest.version, current.version) {
        case .orderedDescending:
            return true
        case .orderedAscending:
            return false
        case .orderedSame:
            return compareVersion(manifest.build, current.build) == .orderedDescending
        }
    }

    private static func compareVersion(_ lhs: String, _ rhs: String) -> ComparisonResult {
        let left = versionParts(lhs)
        let right = versionParts(rhs)
        let count = max(left.count, right.count)

        for index in 0..<count {
            let a = index < left.count ? left[index] : "0"
            let b = index < right.count ? right[index] : "0"
            if let ai = Int(a), let bi = Int(b) {
                if ai < bi { return .orderedAscending }
                if ai > bi { return .orderedDescending }
            } else {
                let cmp = a.localizedStandardCompare(b)
                if cmp != .orderedSame { return cmp }
            }
        }

        return .orderedSame
    }

    private static func versionParts(_ value: String) -> [String] {
        value
            .split { !$0.isLetter && !$0.isNumber }
            .map(String.init)
    }

    private static func isOS(_ current: OperatingSystemVersion, atLeast required: String) -> Bool {
        let parts = versionParts(required).compactMap(Int.init)
        guard !parts.isEmpty else {
            return true
        }
        let requiredVersion = OperatingSystemVersion(
            majorVersion: parts[safe: 0] ?? 0,
            minorVersion: parts[safe: 1] ?? 0,
            patchVersion: parts[safe: 2] ?? 0
        )
        if current.majorVersion != requiredVersion.majorVersion {
            return current.majorVersion > requiredVersion.majorVersion
        }
        if current.minorVersion != requiredVersion.minorVersion {
            return current.minorVersion > requiredVersion.minorVersion
        }
        return current.patchVersion >= requiredVersion.patchVersion
    }
}

private extension Array {
    subscript(safe index: Int) -> Element? {
        indices.contains(index) ? self[index] : nil
    }
}

#if DEBUG
import Foundation

nonisolated enum RuntimeQAConfigOverride {
    static let directoryEnvironmentKey = "BASTION_QA_CONFIG_DIR"
    static let configFileName = "runtime-qa-config.json"
    static let markerFileName = "runtime-qa-config.enabled"

    static func directoryURL(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        fileManager: FileManager = .default
    ) -> URL? {
        if let override = environment[directoryEnvironmentKey]?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        guard let support = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first else {
            return nil
        }
        return support.appendingPathComponent("Bastion", isDirectory: true)
    }

    static func configURL(directory: URL) -> URL {
        directory.appendingPathComponent(configFileName, isDirectory: false)
    }

    static func markerURL(directory: URL) -> URL {
        directory.appendingPathComponent(markerFileName, isDirectory: false)
    }

    static func isEnabled(directory: URL? = directoryURL(), fileManager: FileManager = .default) -> Bool {
        guard let directory else { return false }
        return fileManager.fileExists(atPath: markerURL(directory: directory).path)
    }

    static func readDataIfEnabled(
        directory: URL? = directoryURL(),
        fileManager: FileManager = .default
    ) -> Data? {
        guard let directory,
              isEnabled(directory: directory, fileManager: fileManager) else {
            return nil
        }
        return try? Data(contentsOf: configURL(directory: directory))
    }

    @discardableResult
    static func writeData(
        _ data: Data,
        directory: URL? = directoryURL(),
        fileManager: FileManager = .default
    ) -> Bool {
        guard let directory else { return false }
        do {
            try fileManager.createDirectory(at: directory, withIntermediateDirectories: true)
            try data.write(to: configURL(directory: directory), options: [.atomic])
            try Data("enabled\n".utf8).write(to: markerURL(directory: directory), options: [.atomic])
            return true
        } catch {
            return false
        }
    }

    @discardableResult
    static func clear(directory: URL? = directoryURL(), fileManager: FileManager = .default) -> Bool {
        guard let directory else { return true }
        var ok = true
        for url in [configURL(directory: directory), markerURL(directory: directory)] {
            guard fileManager.fileExists(atPath: url.path) else { continue }
            do {
                try fileManager.removeItem(at: url)
            } catch {
                ok = false
            }
        }
        return ok
    }
}

nonisolated struct RuntimeQAConfigOverrideProvider: Sendable {
    let readDataIfEnabled: @Sendable () -> Data?
    let isEnabled: @Sendable () -> Bool
    let writeData: @Sendable (Data) -> Bool

    static let live = RuntimeQAConfigOverrideProvider(
        readDataIfEnabled: {
            RuntimeQAConfigOverride.readDataIfEnabled()
        },
        isEnabled: {
            RuntimeQAConfigOverride.isEnabled()
        },
        writeData: { data in
            RuntimeQAConfigOverride.writeData(data)
        }
    )

    static let disabled = RuntimeQAConfigOverrideProvider(
        readDataIfEnabled: { nil },
        isEnabled: { false },
        writeData: { _ in false }
    )

    static func directory(_ directory: URL) -> RuntimeQAConfigOverrideProvider {
        RuntimeQAConfigOverrideProvider(
            readDataIfEnabled: {
                RuntimeQAConfigOverride.readDataIfEnabled(directory: directory)
            },
            isEnabled: {
                RuntimeQAConfigOverride.isEnabled(directory: directory)
            },
            writeData: { data in
                RuntimeQAConfigOverride.writeData(data, directory: directory)
            }
        )
    }
}
#endif

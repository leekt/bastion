import Foundation

// MARK: - State Signer Protocol

nonisolated protocol StateSigner: Sendable {
    func signState(_ data: Data) throws -> Data
    func verifyState(_ data: Data, signature: Data) throws -> Bool
}

extension SecureEnclaveManager: StateSigner {}

// MARK: - Rate Limit Store

/// Tamper-proof daily transaction counter.
/// Persisted to disk and signed by Secure Enclave Key C.
/// Only Bastion.app can increment — agents cannot forge the signature.
nonisolated final class RateLimitStore: @unchecked Sendable {
    static let shared = RateLimitStore(
        fileURL: {
            let appSupport = FileManager.default.urls(
                for: .applicationSupportDirectory,
                in: .userDomainMask
            ).first!
            let bastionDir = appSupport.appendingPathComponent("Bastion")
            if !FileManager.default.fileExists(atPath: bastionDir.path) {
                try? FileManager.default.createDirectory(at: bastionDir, withIntermediateDirectories: true)
            }
            return bastionDir.appendingPathComponent("ratelimit.signed")
        }(),
        signer: SecureEnclaveManager.shared
    )

    private let fileURL: URL
    private let signer: StateSigner
    private let queue = DispatchQueue(label: "com.bastion.ratelimit")

    // In-memory cache
    private var currentDate: String = ""
    private var currentCount: Int = 0

    init(fileURL: URL, signer: StateSigner) {
        self.fileURL = fileURL
        self.signer = signer
        loadFromDisk()
    }

    /// Returns today's successful sign count.
    nonisolated func todayCount() -> Int {
        queue.sync {
            let today = Self.todayString()
            if currentDate == today {
                return currentCount
            }
            return 0
        }
    }

    /// Increments today's counter and persists to disk with signature.
    nonisolated func increment() {
        queue.sync {
            let today = Self.todayString()
            if currentDate == today {
                currentCount += 1
            } else {
                currentDate = today
                currentCount = 1
            }
            saveToDisk()
        }
    }

    // MARK: - Persistence

    /// File format: [4-byte sig length][signature][json payload]
    private func loadFromDisk() {
        queue.sync {
            guard FileManager.default.fileExists(atPath: fileURL.path),
                  let fileData = try? Data(contentsOf: fileURL),
                  fileData.count > 4 else {
                currentDate = Self.todayString()
                currentCount = 0
                return
            }

            let sigLen = Int(fileData.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian })
            guard fileData.count > 4 + sigLen else {
                assumeTampered()
                return
            }

            let signature = fileData.subdata(in: 4..<4 + sigLen)
            let payload = fileData.subdata(in: 4 + sigLen..<fileData.count)

            guard let valid = try? signer.verifyState(payload, signature: signature), valid else {
                assumeTampered()
                return
            }

            guard let state = try? JSONDecoder().decode(RateLimitState.self, from: payload) else {
                assumeTampered()
                return
            }

            let today = Self.todayString()
            if state.date == today {
                currentDate = state.date
                currentCount = state.count
            } else {
                currentDate = today
                currentCount = 0
            }
        }
    }

    private func saveToDisk() {
        let state = RateLimitState(date: currentDate, count: currentCount)
        guard let payload = try? JSONEncoder().encode(state),
              let signature = try? signer.signState(payload) else {
            return
        }

        var sigLen = UInt32(signature.count).bigEndian
        var fileData = Data(bytes: &sigLen, count: 4)
        fileData.append(signature)
        fileData.append(payload)

        try? fileData.write(to: fileURL, options: .atomic)
    }

    private func assumeTampered() {
        currentDate = Self.todayString()
        currentCount = Int.max
    }

    static func todayString() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd"
        formatter.timeZone = .current
        return formatter.string(from: Date())
    }
}

struct RateLimitState: Codable {
    let date: String
    let count: Int
}

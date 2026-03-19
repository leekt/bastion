import Foundation

// MARK: - Trace Analysis Types

/// An ERC-20 Transfer event extracted from a `debug_traceCall` trace.
nonisolated struct TransferEvent: Codable, Sendable, Equatable {
    /// ERC-20 contract address that emitted the Transfer event.
    let token: String
    /// Sender address (decoded from topics[1]).
    let from: String
    /// Recipient address (decoded from topics[2]).
    let to: String
    /// Transfer amount as a decimal string (parsed from the log data field).
    let amount: String
}

/// Aggregated analysis of a `debug_traceCall` result.
nonisolated struct TraceAnalysis: Codable, Sendable {
    /// ERC-20 Transfer events found in the trace logs.
    let transfers: [TransferEvent]
    /// All addresses invoked during execution (collected from every call frame).
    let touchedAddresses: Set<String>
    /// Total native ETH value sent from the account across all call frames (decimal string in wei).
    let nativeSpend: String
}

// MARK: - Trace Analyzer

/// Parses a `debug_traceCall` result tree to extract spending data and touched addresses.
nonisolated enum TraceAnalyzer {
    /// keccak256("Transfer(address,address,uint256)")
    static let transferTopic = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

    /// Analyze a trace call result, extracting Transfer events, touched addresses,
    /// and native ETH spending from the given account.
    ///
    /// - Parameters:
    ///   - trace: The root call frame from `debug_traceCall`.
    ///   - accountAddress: The smart account address (used to track native ETH outflows).
    /// - Returns: A `TraceAnalysis` with all extracted data.
    static func analyze(_ trace: TraceCallResult, accountAddress: String) -> TraceAnalysis {
        var transfers: [TransferEvent] = []
        var touchedAddresses: Set<String> = []
        var nativeSpendTotal: UInt128 = 0

        walkTrace(
            trace,
            accountAddress: accountAddress.lowercased(),
            transfers: &transfers,
            touchedAddresses: &touchedAddresses,
            nativeSpendTotal: &nativeSpendTotal
        )

        return TraceAnalysis(
            transfers: transfers,
            touchedAddresses: touchedAddresses,
            nativeSpend: String(nativeSpendTotal)
        )
    }

    // MARK: - Recursive Tree Walk

    private static func walkTrace(
        _ frame: TraceCallResult,
        accountAddress: String,
        transfers: inout [TransferEvent],
        touchedAddresses: inout Set<String>,
        nativeSpendTotal: inout UInt128
    ) {
        // Collect the `to` address from this call frame.
        if let to = frame.to {
            touchedAddresses.insert(to.lowercased())
        }
        // Also collect the `from` address.
        touchedAddresses.insert(frame.from.lowercased())

        // Track native ETH value sent from the account.
        if frame.from.lowercased() == accountAddress,
           let valueHex = frame.value,
           let value = hexToUInt128(valueHex),
           value > 0 {
            let (newTotal, overflow) = nativeSpendTotal.addingReportingOverflow(value)
            if !overflow {
                nativeSpendTotal = newTotal
            }
            // On overflow, we've hit UInt128.max — spending is astronomical, leave capped.
        }

        // Parse logs for Transfer events.
        if let logs = frame.logs {
            for log in logs {
                if let transfer = parseTransferLog(log) {
                    transfers.append(transfer)
                }
            }
        }

        // Recurse into nested calls.
        if let calls = frame.calls {
            for child in calls {
                walkTrace(
                    child,
                    accountAddress: accountAddress,
                    transfers: &transfers,
                    touchedAddresses: &touchedAddresses,
                    nativeSpendTotal: &nativeSpendTotal
                )
            }
        }
    }

    // MARK: - Transfer Event Parsing

    /// Parse a single trace log entry. Returns a `TransferEvent` if it matches the
    /// ERC-20 Transfer(address,address,uint256) signature, otherwise nil.
    private static func parseTransferLog(_ log: TraceLog) -> TransferEvent? {
        // Transfer event: topics[0] = Transfer topic, topics[1] = from, topics[2] = to
        // data = uint256 amount
        guard log.topics.count >= 3 else { return nil }

        // Check topic[0] matches Transfer signature (case-insensitive).
        guard log.topics[0].lowercased() == transferTopic else { return nil }

        // topics[1] and topics[2] are 32-byte (64 hex char) padded addresses.
        // Strip to last 20 bytes (40 hex chars) to get the address.
        let fromAddress = extractAddress(from: log.topics[1])
        let toAddress = extractAddress(from: log.topics[2])

        // data field contains the uint256 amount as 32-byte hex.
        let amount = hexToDecimalString(log.data)

        return TransferEvent(
            token: log.address.lowercased(),
            from: fromAddress,
            to: toAddress,
            amount: amount
        )
    }

    /// Extract a 20-byte address from a 32-byte hex-encoded topic value.
    /// The address occupies the last 20 bytes (last 40 hex chars).
    private static func extractAddress(from topic: String) -> String {
        let hex = topic.hasPrefix("0x") ? String(topic.dropFirst(2)) : topic
        // Take last 40 hex characters (20 bytes)
        let addressHex: String
        if hex.count >= 40 {
            addressHex = String(hex.suffix(40))
        } else {
            addressHex = hex
        }
        return "0x" + addressHex.lowercased()
    }

    /// Convert a hex string (with or without 0x prefix) to a decimal string.
    private static func hexToDecimalString(_ hex: String) -> String {
        guard let data = Data(hexString: hex) else { return "0" }
        return decimalString(forUnsignedBigEndian: data)
    }

    /// Convert a hex string to UInt128, returning nil if the value overflows.
    private static func hexToUInt128(_ hex: String) -> UInt128? {
        guard let data = Data(hexString: hex) else { return nil }
        let bytes = [UInt8](data)
        let highByteCount = max(0, bytes.count - 16)
        guard !bytes.prefix(highByteCount).contains(where: { $0 != 0 }) else {
            return nil
        }
        var result: UInt128 = 0
        for byte in bytes.suffix(16) {
            result = (result << 8) | UInt128(byte)
        }
        return result
    }

    /// Convert big-endian unsigned bytes to a decimal string.
    private static func decimalString(forUnsignedBigEndian data: Data) -> String {
        let bytes = [UInt8](data)
        guard let firstNonZero = bytes.firstIndex(where: { $0 != 0 }) else {
            return "0"
        }

        var digits: [UInt8] = [0]
        for byte in bytes[firstNonZero...] {
            var carry = Int(byte)
            for index in 0..<digits.count {
                let value = Int(digits[index]) * 256 + carry
                digits[index] = UInt8(value % 10)
                carry = value / 10
            }
            while carry > 0 {
                digits.append(UInt8(carry % 10))
                carry /= 10
            }
        }

        return digits.reversed().map(String.init).joined()
    }
}

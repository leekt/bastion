import Foundation

// MARK: - Calldata Decoder

/// Decodes Kernel v3.3 and common ERC-20 calldata into human-readable descriptions.
/// Used by the signing approval popup to show the user what they're signing.
nonisolated enum CalldataDecoder {

    // MARK: - Decoded Types

    struct DecodedUserOp: Sendable {
        let sender: String
        let chainName: String
        let isDeployment: Bool
        let executions: [DecodedExecution]
    }

    struct DecodedExecution: Sendable {
        let to: String
        let value: String       // wei (decimal string)
        let selector: Data?     // 4-byte function selector, nil if no calldata
        let functionName: String?
        let description: String  // human-readable summary
        let tokenOperation: TokenOperation?
        let hasUnrecognizedCalldata: Bool  // H-03: true when selector is unknown
    }

    struct TokenOperation: Sendable {
        let kind: TokenOperationKind
        let amount: String
        let counterparty: String?
        let source: String?
    }

    enum TokenOperationKind: String, Sendable {
        case transfer
        case approve
        case transferFrom
    }

    enum InspectionResult: Sendable {
        case decoded([DecodedExecution])
        case opaque(String)
    }

    private struct ParsedAmount: Sendable {
        let decimalString: String
        let uint128Value: UInt128?
    }

    // MARK: - Known Selectors

    private static let kernelExecute = Data([0xe9, 0xae, 0x5c, 0x53])       // execute(bytes32,bytes)
    private static let erc20Transfer = Data([0xa9, 0x05, 0x9c, 0xbb])       // transfer(address,uint256)
    private static let erc20Approve  = Data([0x09, 0x5e, 0xa7, 0xb3])       // approve(address,uint256)
    private static let erc20TransferFrom = Data([0x23, 0xb8, 0x72, 0xdd])   // transferFrom(address,address,uint256)

    // MARK: - Decode UserOperation

    static func decode(_ op: UserOperation) -> DecodedUserOp {
        let chainName = ChainConfig.name(for: op.chainId)
        let isDeployment = op.factory != nil
        let executions: [DecodedExecution]
        switch inspect(op) {
        case .decoded(let decoded):
            executions = decoded
        case .opaque(let reason):
            executions = [
                DecodedExecution(
                    to: "unknown",
                    value: "0",
                    selector: nil,
                    functionName: nil,
                    description: reason,
                    tokenOperation: nil,
                    hasUnrecognizedCalldata: true
                )
            ]
        }

        return DecodedUserOp(
            sender: op.sender,
            chainName: chainName,
            isDeployment: isDeployment,
            executions: executions
        )
    }

    static func inspect(_ op: UserOperation) -> InspectionResult {
        inspectKernelCalldata(op.callData, chainId: op.chainId)
    }

    // MARK: - Kernel execute(bytes32, bytes)

    private static func inspectKernelCalldata(_ data: Data, chainId: Int) -> InspectionResult {
        guard data.count >= 4 else {
            return .opaque("Malformed UserOperation calldata")
        }
        guard data.prefix(4) == kernelExecute else {
            return .opaque("Unsupported UserOperation calldata: expected Kernel execute()")
        }

        let params = data.dropFirst(4)
        guard params.count >= 96 else {
            return .opaque("Malformed Kernel calldata")
        }

        // First 32 bytes = ExecMode, first byte = call type
        let callType = params[params.startIndex]

        // bytes offset at params[32..<64], then length at the offset, then data
        let offsetBytes = params[params.startIndex + 32 ..< params.startIndex + 64]
        guard let offset = readUInt64Checked(offsetBytes) else {
            return .opaque("Kernel bytes offset has non-zero upper bytes — potential ABI manipulation")
        }
        let dataStart = params.startIndex + Int(offset)
        guard dataStart + 32 <= params.endIndex else {
            return .opaque("Kernel bytes offset is out of bounds")
        }

        let lengthBytes = params[dataStart ..< dataStart + 32]
        guard let lengthU64 = readUInt64Checked(lengthBytes) else {
            return .opaque("Kernel payload length has non-zero upper bytes — potential ABI manipulation")
        }
        let length = Int(lengthU64)
        let execDataStart = dataStart + 32
        guard execDataStart + length <= params.endIndex else {
            return .opaque("Kernel execution payload is truncated")
        }
        let execData = Data(params[execDataStart ..< execDataStart + length])

        switch callType {
        case 0x00: // Single
            guard let execution = decodeSingleExecution(execData, chainId: chainId) else {
                return .opaque("Invalid single execution payload")
            }
            return .decoded([execution])
        case 0x01: // Batch
            guard let executions = decodeBatchExecution(execData, chainId: chainId) else {
                return .opaque("Invalid batch execution payload")
            }
            return .decoded(executions)
        case 0x02, 0xFF: // C-01: Delegatecall — always hard-blocked
            return .opaque("Delegatecall detected (call type 0x\(String(format: "%02x", callType))) — blocked for security")
        default:
            return .opaque("Unknown Kernel call type: 0x\(String(format: "%02x", callType)) — blocked for security")
        }
    }

    // MARK: - Single Execution (abi.encodePacked)

    /// Single execution: `abi.encodePacked(target[20], value[32], callData[...])`
    private static func decodeSingleExecution(_ data: Data, chainId: Int) -> DecodedExecution? {
        guard data.count >= 52 else { return nil }
        let target = "0x" + data.prefix(20).hex
        let value = parseUInt256(Data(data[data.startIndex + 20 ..< data.startIndex + 52]))
        let innerCalldata = data.count > 52 ? Data(data.dropFirst(52)) : Data()

        return decodeInnerCall(to: target, value: value, calldata: innerCalldata, chainId: chainId)
    }

    // MARK: - Batch Execution (abi.encode)

    private static func decodeBatchExecution(_ data: Data, chainId: Int) -> [DecodedExecution]? {
        // abi.encode of Execution[]:
        // offset(32) + length(32) + offsets[n](32 each) + tuple data
        guard data.count >= 64 else { return nil }

        guard let arrayOffset = readUInt64Checked(data.prefix(32)) else { return nil }
        let arrayStart = Int(arrayOffset)
        guard arrayStart + 32 <= data.count else { return nil }

        guard let countU64 = readUInt64Checked(Data(data[arrayStart ..< arrayStart + 32])) else { return nil }
        let count = Int(countU64)
        guard count > 0, count < 100 else { return nil } // sanity

        let offsetTableStart = arrayStart + 32
        var results: [DecodedExecution] = []

        for i in 0..<count {
            let offsetPos = offsetTableStart + i * 32
            guard offsetPos + 32 <= data.count else { return nil }
            guard let tupleOffsetU64 = readUInt64Checked(Data(data[offsetPos ..< offsetPos + 32])) else { return nil }
            let tupleOffset = Int(tupleOffsetU64)
            let tupleStart = arrayStart + 32 + tupleOffset  // relative to array elements area
            guard tupleStart + 96 <= data.count else { return nil }

            // Tuple: address(32) + value(32) + offset(32) + [length(32) + bytes]
            let target = "0x" + Data(data[tupleStart + 12 ..< tupleStart + 32]).hex // skip 12-byte padding
            let value = parseUInt256(Data(data[tupleStart + 32 ..< tupleStart + 64]))
            guard let bytesOffsetU64 = readUInt64Checked(Data(data[tupleStart + 64 ..< tupleStart + 96])) else { return nil }
            let bytesLenPos = tupleStart + Int(bytesOffsetU64)
            guard bytesLenPos + 32 <= data.count else { return nil }
            guard let bytesLenU64 = readUInt64Checked(Data(data[bytesLenPos ..< bytesLenPos + 32])) else { return nil }
            let bytesLen = Int(bytesLenU64)
            let bytesStart = bytesLenPos + 32
            guard bytesStart + bytesLen <= data.count else { return nil }
            let innerCalldata = Data(data[bytesStart ..< bytesStart + bytesLen])

            results.append(decodeInnerCall(to: target, value: value, calldata: innerCalldata, chainId: chainId))
        }

        return results
    }

    // MARK: - Inner Call Decoding

    private static func decodeInnerCall(
        to target: String,
        value: ParsedAmount,
        calldata: Data,
        chainId: Int
    ) -> DecodedExecution {
        let shortTarget = "\(target.prefix(8))...\(target.suffix(4))"

        // No calldata = plain ETH transfer or no-op call
        if calldata.isEmpty {
            if value.decimalString != "0" {
                return DecodedExecution(
                    to: target,
                    value: value.decimalString,
                    selector: nil,
                    functionName: nil,
                    description: "Send \(formatEth(value)) ETH to \(shortTarget)",
                    tokenOperation: nil,
                    hasUnrecognizedCalldata: false
                )
            }
            return DecodedExecution(
                to: target,
                value: value.decimalString,
                selector: nil,
                functionName: nil,
                description: "Call \(shortTarget) (no data)",
                tokenOperation: nil,
                hasUnrecognizedCalldata: false
            )
        }

        guard calldata.count >= 4 else {
            return DecodedExecution(
                to: target,
                value: value.decimalString,
                selector: nil,
                functionName: nil,
                description: "Call \(shortTarget) (\(calldata.count) bytes)",
                tokenOperation: nil,
                hasUnrecognizedCalldata: true
            )
        }

        let callSelector = calldata.prefix(4)

        // ERC-20 transfer(address, uint256)
        if callSelector == erc20Transfer, calldata.count >= 68 {
            let recipient = "0x" + Data(calldata[16..<36]).hex  // skip 12 bytes padding
            let amount = parseUInt256(Data(calldata[36..<68]))
            let shortRecipient = "\(recipient.prefix(8))...\(recipient.suffix(4))"
            let tokenName = resolveTokenName(address: target, chainId: chainId)
            return DecodedExecution(
                to: target,
                value: value.decimalString,
                selector: erc20Transfer,
                functionName: "transfer",
                description: "Transfer \(formatTokenAmount(amount, token: target, chainId: chainId)) \(tokenName) to \(shortRecipient)",
                tokenOperation: TokenOperation(
                    kind: .transfer,
                    amount: amount.decimalString,
                    counterparty: recipient,
                    source: nil
                ),
                hasUnrecognizedCalldata: false
            )
        }

        // ERC-20 approve(address, uint256)
        if callSelector == erc20Approve, calldata.count >= 68 {
            let spender = "0x" + Data(calldata[16..<36]).hex
            let amount = parseUInt256(Data(calldata[36..<68]))
            let shortSpender = "\(spender.prefix(8))...\(spender.suffix(4))"
            let tokenName = resolveTokenName(address: target, chainId: chainId)
            let isMaxApproval = Data(calldata[36..<68]) == Data(repeating: 0xff, count: 32)
            let amountStr = isMaxApproval ? "unlimited" : formatTokenAmount(amount, token: target, chainId: chainId)
            return DecodedExecution(
                to: target,
                value: value.decimalString,
                selector: erc20Approve,
                functionName: "approve",
                description: "Approve \(amountStr) \(tokenName) for \(shortSpender)",
                tokenOperation: TokenOperation(
                    kind: .approve,
                    amount: amount.decimalString,
                    counterparty: spender,
                    source: nil
                ),
                hasUnrecognizedCalldata: false
            )
        }

        // ERC-20 transferFrom(address, address, uint256)
        if callSelector == erc20TransferFrom, calldata.count >= 100 {
            let from = "0x" + Data(calldata[16..<36]).hex
            let to = "0x" + Data(calldata[48..<68]).hex
            let amount = parseUInt256(Data(calldata[68..<100]))
            let shortFrom = "\(from.prefix(8))...\(from.suffix(4))"
            let shortTo = "\(to.prefix(8))...\(to.suffix(4))"
            let tokenName = resolveTokenName(address: target, chainId: chainId)
            return DecodedExecution(
                to: target,
                value: value.decimalString,
                selector: erc20TransferFrom,
                functionName: "transferFrom",
                description: "TransferFrom \(formatTokenAmount(amount, token: target, chainId: chainId)) \(tokenName) from \(shortFrom) to \(shortTo)",
                tokenOperation: TokenOperation(
                    kind: .transferFrom,
                    amount: amount.decimalString,
                    counterparty: to,
                    source: from
                ),
                hasUnrecognizedCalldata: false
            )
        }

        // Unknown selector — H-03: flag for spending limit enforcement
        let selectorHex = "0x" + callSelector.hex
        let valueStr = value.decimalString != "0" ? " + \(formatEth(value)) ETH" : ""
        return DecodedExecution(
            to: target,
            value: value.decimalString,
            selector: Data(callSelector),
            functionName: selectorHex,
            description: "Call \(shortTarget) [\(selectorHex)]\(valueStr) (\(calldata.count) bytes)",
            tokenOperation: nil,
            hasUnrecognizedCalldata: true
        )
    }

    // MARK: - Token Resolution

    private static func resolveTokenName(address: String, chainId: Int) -> String {
        let lower = address.lowercased()
        // Check USDC
        if let usdcAddr = USDCAddresses.address(for: chainId), usdcAddr.lowercased() == lower {
            return "USDC"
        }
        return "\(address.prefix(8))...\(address.suffix(4))"
    }

    // MARK: - Formatting

    private static func formatEth(_ amount: ParsedAmount) -> String {
        if amount.decimalString == "0" { return "0" }
        guard let numericValue = amount.uint128Value,
              let asDouble = Double(String(numericValue)) else {
            return "\(amount.decimalString) wei"
        }
        let eth = asDouble / 1e18
        if eth >= 0.001 {
            return String(format: "%.4f", eth)
        }
        return "\(amount.decimalString) wei"
    }

    private static func formatTokenAmount(_ amount: ParsedAmount, token: String, chainId: Int) -> String {
        let lower = token.lowercased()
        guard let numericValue = amount.uint128Value,
              let asDouble = Double(String(numericValue)) else {
            return amount.decimalString
        }

        // USDC = 6 decimals
        if let usdcAddr = USDCAddresses.address(for: chainId), usdcAddr.lowercased() == lower {
            let formatted = asDouble / 1e6
            return String(format: "%.2f", formatted)
        }

        // Default 18 decimals
        let formatted = asDouble / 1e18
        if formatted >= 0.0001 {
            return String(format: "%.4f", formatted)
        }
        return amount.decimalString
    }

    // MARK: - Helpers

    /// Read the last 8 bytes of a 32-byte big-endian value as UInt64.
    /// M-07: Returns nil if upper bytes are non-zero (prevents truncation attacks).
    private static func readUInt64Checked(_ data: Data) -> UInt64? {
        let bytes = [UInt8](data)
        let start = max(0, bytes.count - 8)
        // Reject if any upper bytes are non-zero
        for i in 0..<start {
            if bytes[i] != 0 { return nil }
        }
        var result: UInt64 = 0
        for i in start..<bytes.count {
            result = result << 8 | UInt64(bytes[i])
        }
        return result
    }

    private static func parseUInt256(_ data: Data) -> ParsedAmount {
        ParsedAmount(
            decimalString: decimalString(forUnsignedBigEndian: data),
            uint128Value: readUInt128(data)
        )
    }

    private static func readUInt128(_ data: Data) -> UInt128? {
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

    private static func decimalString(forUnsignedBigEndian data: Data) -> String {
        let bytes = [UInt8](data)
        guard let firstNonZero = bytes.firstIndex(where: { $0 != 0 }) else {
            return "0"
        }

        var digits: [UInt8] = [0] // little-endian base-10 digits
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

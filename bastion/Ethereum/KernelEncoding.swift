import Foundation

// MARK: - ZeroDev Kernel v3.3 Calldata Encoding

/// Encodes calldata for ZeroDev Kernel v3.3 smart accounts.
/// Kernel follows ERC-7579 execution encoding.
nonisolated enum KernelEncoding {

    // MARK: - ERC-7579 Execution Types

    /// A single execution call.
    struct Execution {
        let to: String      // address (hex)
        let value: UInt64   // wei value
        let data: Data      // calldata
    }

    // MARK: - CallType Constants

    /// ERC-7579 call types (first byte of ExecMode)
    private static let CALLTYPE_SINGLE: UInt8    = 0x00
    private static let CALLTYPE_BATCH: UInt8     = 0x01

    /// ERC-7579 exec types (second byte of ExecMode)
    private static let EXECTYPE_DEFAULT: UInt8   = 0x00

    // MARK: - ExecMode

    /// Build the 32-byte ExecMode for a single call with default execution.
    static func execModeSingle() -> Data {
        var mode = Data(repeating: 0, count: 32)
        mode[0] = CALLTYPE_SINGLE
        mode[1] = EXECTYPE_DEFAULT
        return mode
    }

    /// Build the 32-byte ExecMode for a batch call with default execution.
    static func execModeBatch() -> Data {
        var mode = Data(repeating: 0, count: 32)
        mode[0] = CALLTYPE_BATCH
        mode[1] = EXECTYPE_DEFAULT
        return mode
    }

    // MARK: - Single Call Encoding

    /// Encode a single execution call using ERC-7579 packed format.
    /// Format: `abi.encodePacked(target, value, callData)` = 20 + 32 + variable bytes
    static func encodeSingle(_ exec: Execution) -> Data {
        var encoded = Data()
        // target: 20 bytes (packed, no padding)
        encoded += hexToBytes(exec.to)
        // value: 32 bytes big-endian uint256
        encoded += uint256(exec.value)
        // callData: variable length, appended directly
        encoded += exec.data
        return encoded
    }

    // MARK: - Batch Call Encoding

    /// Encode a batch of execution calls using standard ABI encoding.
    /// Format: `abi.encode(Execution[])` where Execution = (address, uint256, bytes)
    static func encodeBatch(_ executions: [Execution]) -> Data {
        // ABI encoding of a dynamic array of tuples:
        // offset to array (32) + length (32) + offsets for each element + element data

        let count = executions.count

        // First encode each tuple
        var encodedTuples = [Data]()
        for exec in executions {
            encodedTuples.append(encodeTuple(exec))
        }

        // Array offset (points to start of array data at position 32)
        var result = Data()
        result += uint256(UInt64(32))

        // Array length
        result += uint256(UInt64(count))

        // Offset table: each entry points to the start of the tuple data
        // relative to the start of the array elements area
        let offsetTableSize = count * 32
        var currentOffset = offsetTableSize
        for tuple in encodedTuples {
            result += uint256(UInt64(currentOffset))
            currentOffset += tuple.count
        }

        // Tuple data
        for tuple in encodedTuples {
            result += tuple
        }

        return result
    }

    // MARK: - Kernel execute() Calldata

    /// Build the full calldata for Kernel's `execute(ExecMode, bytes)` function.
    /// Selector: `0xe9ae5c53` = `execute(bytes32,bytes)`
    static func executeCalldata(single exec: Execution) -> Data {
        let selector = Data([0xe9, 0xae, 0x5c, 0x53]) // execute(bytes32,bytes)
        let mode = execModeSingle()
        let executionData = encodeSingle(exec)

        // ABI encode: execute(bytes32 mode, bytes calldata executionCalldata)
        var params = Data()
        params += mode                          // bytes32 (already 32 bytes)
        params += uint256(UInt64(64))           // offset to bytes parameter
        params += uint256(UInt64(executionData.count))  // bytes length
        params += executionData                 // bytes data
        // Pad to 32-byte boundary
        let padding = (32 - executionData.count % 32) % 32
        if padding > 0 {
            params += Data(repeating: 0, count: padding)
        }

        return selector + params
    }

    /// Build the full calldata for Kernel's `execute(ExecMode, bytes)` with batch calls.
    static func executeCalldata(batch executions: [Execution]) -> Data {
        let selector = Data([0xe9, 0xae, 0x5c, 0x53]) // execute(bytes32,bytes)
        let mode = execModeBatch()
        let executionData = encodeBatch(executions)

        var params = Data()
        params += mode
        params += uint256(UInt64(64))
        params += uint256(UInt64(executionData.count))
        params += executionData
        let padding = (32 - executionData.count % 32) % 32
        if padding > 0 {
            params += Data(repeating: 0, count: padding)
        }

        return selector + params
    }

    // MARK: - Helpers

    /// Encode an Execution tuple for ABI encoding.
    private static func encodeTuple(_ exec: Execution) -> Data {
        let target = hexToBytes(exec.to)
        var encoded = Data()
        // address (left-padded to 32)
        encoded += Data(repeating: 0, count: 32 - target.count) + target
        // value (uint256)
        encoded += uint256(exec.value)
        // offset to bytes data (always 96 = 3 * 32)
        encoded += uint256(UInt64(96))
        // bytes length
        encoded += uint256(UInt64(exec.data.count))
        // bytes data
        encoded += exec.data
        // Pad to 32-byte boundary
        let padding = (32 - exec.data.count % 32) % 32
        if padding > 0 {
            encoded += Data(repeating: 0, count: padding)
        }
        return encoded
    }

    private static func hexToBytes(_ hex: String) -> Data {
        Data(hexString: hex) ?? Data()
    }

    private static func uint256(_ value: UInt64) -> Data {
        var result = Data(repeating: 0, count: 32)
        var v = value
        for i in stride(from: 31, through: 24, by: -1) {
            result[i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return result
    }
}

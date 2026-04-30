import Foundation

// MARK: - ERC-7579 Module Management Encoding
//
// Encodes `installModule(uint256,address,bytes)` and
// `uninstallModule(uint256,address,bytes)` calldata per ERC-7579.
// Both selectors are invoked as a SELF-CALL on the smart account through
// Kernel's `execute(bytes32,bytes)` entry point: the UserOp's callData wraps
// a single execution whose `to` is the account itself and whose `data` is
// the installModule/uninstallModule calldata produced here.
//
// Module type IDs (ERC-7579):
//   1 = Validator
//   2 = Executor
//   3 = Fallback
//   4 = Hook

nonisolated enum KernelModule {

    // MARK: - Errors

    enum EncodingError: Error, CustomStringConvertible {
        case invalidModuleAddress(String)

        var description: String {
            switch self {
            case .invalidModuleAddress(let hex):
                return "installModule/uninstallModule received an invalid module address: \(hex)"
            }
        }
    }

    // MARK: - Module Type Constants

    enum ModuleType: UInt64 {
        case validator = 1
        case executor = 2
        case fallback = 3
        case hook = 4
    }

    // MARK: - Selectors

    /// `installModule(uint256,address,bytes)` — ERC-7579 §6.
    /// Verified: `keccak256("installModule(uint256,address,bytes)")[0:4] == 0x9517e29f`.
    static let installModuleSelector = Data([0x95, 0x17, 0xe2, 0x9f])

    /// `uninstallModule(uint256,address,bytes)` — ERC-7579 §6.
    /// Verified: `keccak256("uninstallModule(uint256,address,bytes)")[0:4] == 0xa71763a8`.
    static let uninstallModuleSelector = Data([0xa7, 0x17, 0x63, 0xa8])

    // MARK: - Calldata Builders

    /// Builds the ABI-encoded calldata for
    /// `installModule(uint256 moduleTypeId, address module, bytes calldata initData)`.
    ///
    /// For validator installs, `initData` is the module-specific init payload
    /// — for Bastion's P256Validator that is the 64-byte concatenation of the
    /// pubkey x and y coordinates (`validator.installData`).
    static func installModuleCalldata(
        type: ModuleType,
        module: String,
        initData: Data
    ) throws -> Data {
        try encode(
            selector: installModuleSelector,
            type: type,
            module: module,
            payload: initData
        )
    }

    /// Builds the ABI-encoded calldata for
    /// `uninstallModule(uint256 moduleTypeId, address module, bytes calldata deInitData)`.
    ///
    /// `deInitData` is module-specific. For simple validators it is typically
    /// empty (`Data()`) — the module discards its state keyed by the caller.
    static func uninstallModuleCalldata(
        type: ModuleType,
        module: String,
        deInitData: Data = Data()
    ) throws -> Data {
        try encode(
            selector: uninstallModuleSelector,
            type: type,
            module: module,
            payload: deInitData
        )
    }

    // MARK: - High-level Helpers

    /// Produces a `KernelEncoding.Execution` that, when passed to
    /// `KernelEncoding.executeCalldata(single:)`, results in the smart
    /// account calling `installModule` on itself.
    static func installModuleExecution(
        accountAddress: String,
        type: ModuleType,
        module: String,
        initData: Data
    ) throws -> KernelEncoding.Execution {
        KernelEncoding.Execution(
            to: accountAddress,
            value: 0,
            data: try installModuleCalldata(type: type, module: module, initData: initData)
        )
    }

    static func uninstallModuleExecution(
        accountAddress: String,
        type: ModuleType,
        module: String,
        deInitData: Data = Data()
    ) throws -> KernelEncoding.Execution {
        KernelEncoding.Execution(
            to: accountAddress,
            value: 0,
            data: try uninstallModuleCalldata(type: type, module: module, deInitData: deInitData)
        )
    }

    // MARK: - Private ABI Encoder

    /// Encodes `<selector><uint256 type><address module><bytes payload>` using
    /// standard ABI rules. Matches what Solidity generates for calls like
    /// `account.installModule(1, P256Validator, pubkey)`.
    private static func encode(
        selector: Data,
        type: ModuleType,
        module: String,
        payload: Data
    ) throws -> Data {
        var params = Data()
        // moduleTypeId : uint256
        params += uint256(type.rawValue)
        // module : address (left-padded to 32). Throws on malformed input
        // rather than silently encoding address(0) — a zero target on an
        // install/uninstall would be both confusing and dangerous.
        let moduleBytes = try addressBytes(module)
        params += Data(repeating: 0, count: 32 - moduleBytes.count) + moduleBytes
        // offset to bytes payload (always 0x60 = 96 — three static slots precede it)
        params += uint256(96)
        // bytes length
        params += uint256(UInt64(payload.count))
        // bytes data, padded to 32-byte boundary
        params += payload
        let padding = (32 - payload.count % 32) % 32
        if padding > 0 {
            params += Data(repeating: 0, count: padding)
        }
        return selector + params
    }

    private static func addressBytes(_ hex: String) throws -> Data {
        guard let data = Data(hexString: hex), data.count == 20 else {
            throw EncodingError.invalidModuleAddress(hex)
        }
        return data
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

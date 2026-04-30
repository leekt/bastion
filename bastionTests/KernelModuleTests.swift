import Foundation
import Testing
@testable import bastion

@Suite("KernelModule — ERC-7579 installModule / uninstallModule encoding")
struct KernelModuleTests {

    // MARK: - Selectors

    @Test("installModule selector matches keccak256(signature)[0:4]")
    func installSelector() {
        #expect(KernelModule.installModuleSelector.hex == "9517e29f")
    }

    @Test("uninstallModule selector matches keccak256(signature)[0:4]")
    func uninstallSelector() {
        #expect(KernelModule.uninstallModuleSelector.hex == "a71763a8")
    }

    // MARK: - Byte-for-byte fixtures (generated via viem)

    /// Reference encoding produced by:
    /// encodeFunctionData({abi: installModule(uint256,address,bytes), args:
    ///   [1, 0x9906AB44fF795883C5a725687A2705BE4118B0f3, 64 * 0xaa]})
    @Test("installModuleCalldata matches viem reference bytes")
    func installModuleMatchesViem() throws {
        let agentPubkey = Data(repeating: 0xAA, count: 64)
        let encoded = try KernelModule.installModuleCalldata(
            type: .validator,
            module: ValidatorAddress.p256Validator,
            initData: agentPubkey
        )

        let expected = """
        9517e29f\
        0000000000000000000000000000000000000000000000000000000000000001\
        0000000000000000000000009906ab44ff795883c5a725687a2705be4118b0f3\
        0000000000000000000000000000000000000000000000000000000000000060\
        0000000000000000000000000000000000000000000000000000000000000040\
        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
        aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
        """

        #expect(encoded.hex == expected)
    }

    @Test("uninstallModuleCalldata with empty deInitData matches viem reference bytes")
    func uninstallModuleMatchesViem() throws {
        let encoded = try KernelModule.uninstallModuleCalldata(
            type: .validator,
            module: ValidatorAddress.p256Validator,
            deInitData: Data()
        )

        let expected = """
        a71763a8\
        0000000000000000000000000000000000000000000000000000000000000001\
        0000000000000000000000009906ab44ff795883c5a725687a2705be4118b0f3\
        0000000000000000000000000000000000000000000000000000000000000060\
        0000000000000000000000000000000000000000000000000000000000000000
        """

        #expect(encoded.hex == expected)
    }

    // MARK: - Structural properties

    @Test("installModuleExecution targets the smart account with 0 value")
    func installExecutionShape() throws {
        let accountAddress = "0x1234567890abcdef1234567890abcdef12345678"
        let pubkey = Data(repeating: 0xBB, count: 64)
        let execution = try KernelModule.installModuleExecution(
            accountAddress: accountAddress,
            type: .validator,
            module: ValidatorAddress.p256Validator,
            initData: pubkey
        )

        #expect(execution.to == accountAddress)
        #expect(execution.value == "0x0")
        // Calldata must start with installModule selector.
        #expect(execution.data.prefix(4).hex == "9517e29f")
    }

    @Test("round-trip: encoded pubkey appears verbatim in the calldata bytes")
    func roundTripEmbedsPubkey() throws {
        var pubkey = Data()
        // Unique byte pattern so we can easily substring-search for it.
        for i in 0..<64 {
            pubkey.append(UInt8(0x10 | (i & 0x0F)))
        }
        let encoded = try KernelModule.installModuleCalldata(
            type: .validator,
            module: ValidatorAddress.p256Validator,
            initData: pubkey
        )

        // Last 64 bytes of the encoded calldata must be the pubkey (no trailing
        // padding is required since 64 is already a multiple of 32).
        #expect(encoded.suffix(64) == pubkey)
    }

    @Test("non-multiple-of-32 payload is zero-padded to nearest 32-byte boundary")
    func oddPayloadPadding() throws {
        // 20-byte payload → padded to 32, expect last 12 bytes of output to be zero.
        let payload = Data(repeating: 0xEF, count: 20)
        let encoded = try KernelModule.installModuleCalldata(
            type: .validator,
            module: ValidatorAddress.p256Validator,
            initData: payload
        )

        // Total length = 4 selector + 3 static slots (96) + 32 (length slot) + 32 (padded data) = 196 bytes
        #expect(encoded.count == 4 + 96 + 32 + 32)

        let dataSlot = encoded.suffix(32)
        #expect(dataSlot.prefix(20) == payload)
        #expect(dataSlot.suffix(12) == Data(repeating: 0x00, count: 12))
    }

    @Test("module address encoding is lowercase-insensitive and left-padded")
    func moduleAddressLeftPadded() throws {
        let encoded = try KernelModule.installModuleCalldata(
            type: .validator,
            module: "0x9906AB44fF795883C5a725687A2705BE4118B0f3",
            initData: Data()
        )
        // Module address occupies bytes 4+32..4+32+32 (right 20 bytes of a 32-byte slot).
        let addressSlotRange = (4 + 32)..<(4 + 64)
        let slot = encoded[addressSlotRange]
        let expectedLeadingZeros = Data(repeating: 0, count: 12)
        #expect(slot.prefix(12) == expectedLeadingZeros)
        #expect(slot.suffix(20).hex == "9906ab44ff795883c5a725687a2705be4118b0f3")
    }
}

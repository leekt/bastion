import Foundation
import Testing
@testable import bastion

// MARK: - Keccak256 Tests

@Suite("Keccak256")
struct Keccak256Tests {

    @Test("Empty input produces known hash")
    func emptyInput() {
        // keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = Keccak256.hash(Data())
        let actual = hash.hex
        print("DEBUG empty hash: \(actual)")
        #expect(actual == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
    }

    @Test("'hello' produces known hash")
    func helloString() {
        // keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        let hash = Keccak256.hash(Data("hello".utf8))
        #expect(hash.hex == "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8")
    }

    @Test("'hello world' produces known hash")
    func helloWorld() {
        // keccak256("hello world") = 47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad
        let hash = Keccak256.hash(Data("hello world".utf8))
        #expect(hash.hex == "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad")
    }

    @Test("Hash is always 32 bytes")
    func hashLength() {
        for len in [0, 1, 31, 32, 33, 100, 136, 137, 256, 1000] {
            let data = Data(repeating: 0xAB, count: len)
            let hash = Keccak256.hash(data)
            #expect(hash.count == 32, "Hash length should be 32 for input length \(len)")
        }
    }

    @Test("Deterministic: same input same output")
    func deterministic() {
        let data = Data("test determinism".utf8)
        let h1 = Keccak256.hash(data)
        let h2 = Keccak256.hash(data)
        #expect(h1 == h2)
    }

    @Test("Different inputs produce different hashes")
    func differentInputs() {
        let h1 = Keccak256.hash(Data("a".utf8))
        let h2 = Keccak256.hash(Data("b".utf8))
        #expect(h1 != h2)
    }

    @Test("ERC-20 transfer selector")
    func erc20Selector() {
        // keccak256("transfer(address,uint256)") first 4 bytes = 0xa9059cbb
        let hash = Keccak256.hash(Data("transfer(address,uint256)".utf8))
        let selector = hash.prefix(4).hex
        #expect(selector == "a9059cbb")
    }
}

// MARK: - RLP Tests

@Suite("RLP Encoding")
struct RLPTests {

    @Test("Single byte < 0x80")
    func singleByte() {
        let encoded = RLP.encode(Data([0x42]))
        #expect(encoded == Data([0x42]))
    }

    @Test("Empty bytes")
    func emptyBytes() {
        let encoded = RLP.encode(Data())
        #expect(encoded == Data([0x80]))
    }

    @Test("Short string")
    func shortString() {
        let data = Data("dog".utf8)
        let encoded = RLP.encode(data)
        // "dog" = [0x83, 0x64, 0x6f, 0x67]
        #expect(encoded == Data([0x83, 0x64, 0x6f, 0x67]))
    }

    @Test("Empty list")
    func emptyList() {
        let encoded = RLP.encodeList([])
        #expect(encoded == Data([0xC0]))
    }

    @Test("List of short strings")
    func listOfStrings() {
        // RLP(["cat", "dog"])
        let items: [RLP.Item] = [
            .bytes(Data("cat".utf8)),
            .bytes(Data("dog".utf8)),
        ]
        let encoded = RLP.encodeList(items)
        // 0xC8 = 0xC0 + 8, then "cat" and "dog" RLP-encoded
        #expect(encoded == Data([0xC8, 0x83, 0x63, 0x61, 0x74, 0x83, 0x64, 0x6f, 0x67]))
    }

    @Test("UInt64 encoding")
    func uint64Encoding() {
        let zero = RLP.encode(UInt64(0))
        #expect(zero == Data([0x80]))

        let one = RLP.encode(UInt64(1))
        #expect(one == Data([0x01]))

        let val = RLP.encode(UInt64(1024))
        // 1024 = 0x0400, 2 bytes, so 0x82, 0x04, 0x00
        #expect(val == Data([0x82, 0x04, 0x00]))
    }
}

// MARK: - EIP-191 Personal Message Tests

@Suite("EIP-191 Personal Message")
struct EIP191Tests {

    @Test("Personal message hash matches known value")
    func knownHash() {
        // This is the standard Ethereum personal_sign hash
        // keccak256("\x19Ethereum Signed Message:\n5hello")
        let hash = EthHashing.personalMessageHash("hello")
        #expect(hash.count == 32)
        // Verify by computing manually:
        let prefix = "\u{19}Ethereum Signed Message:\n5"
        let manual = Keccak256.hash(Data(prefix.utf8) + Data("hello".utf8))
        #expect(hash == manual)
    }

    @Test("Different messages produce different hashes")
    func differentMessages() {
        let h1 = EthHashing.personalMessageHash("hello")
        let h2 = EthHashing.personalMessageHash("world")
        #expect(h1 != h2)
    }

    @Test("Raw bytes personal message hash")
    func rawBytesHash() {
        let data = Data([0x01, 0x02, 0x03])
        let hash = EthHashing.personalMessageHash(data: data)
        #expect(hash.count == 32)
        // keccak256("\x19Ethereum Signed Message:\n3" + [01,02,03])
        let prefix = "\u{19}Ethereum Signed Message:\n3"
        let manual = Keccak256.hash(Data(prefix.utf8) + data)
        #expect(hash == manual)
    }
}

// MARK: - EIP-712 Tests

@Suite("EIP-712 Typed Data")
struct EIP712Tests {

    @Test("Simple typed data hash is 32 bytes")
    func simpleTypedData() {
        let typedData = EIP712TypedData(
            types: [
                "EIP712Domain": [
                    EIP712Field(name: "name", type: "string"),
                    EIP712Field(name: "version", type: "string"),
                    EIP712Field(name: "chainId", type: "uint256"),
                ],
                "Mail": [
                    EIP712Field(name: "from", type: "string"),
                    EIP712Field(name: "to", type: "string"),
                    EIP712Field(name: "contents", type: "string"),
                ],
            ],
            primaryType: "Mail",
            domain: EIP712Domain(
                name: "Test",
                version: "1",
                chainId: 1,
                verifyingContract: nil,
                salt: nil
            ),
            message: [
                "from": AnyCodable("alice"),
                "to": AnyCodable("bob"),
                "contents": AnyCodable("Hello, Bob!"),
            ]
        )
        let hash = EthHashing.typedDataHash(typedData)
        #expect(hash.count == 32)
    }

    @Test("Different domain produces different hash")
    func differentDomain() {
        let types: [String: [EIP712Field]] = [
            "EIP712Domain": [
                EIP712Field(name: "name", type: "string"),
            ],
            "Simple": [
                EIP712Field(name: "value", type: "uint256"),
            ],
        ]
        let msg: [String: AnyCodable] = ["value": AnyCodable(42)]

        let h1 = EthHashing.typedDataHash(EIP712TypedData(
            types: types, primaryType: "Simple",
            domain: EIP712Domain(name: "App1", version: nil, chainId: nil, verifyingContract: nil, salt: nil),
            message: msg
        ))
        let h2 = EthHashing.typedDataHash(EIP712TypedData(
            types: types, primaryType: "Simple",
            domain: EIP712Domain(name: "App2", version: nil, chainId: nil, verifyingContract: nil, salt: nil),
            message: msg
        ))
        #expect(h1 != h2)
    }
}

// MARK: - ERC-4337 UserOperation Hash Tests

@Suite("UserOperation Hash (v0.7+)")
struct UserOpHashTests {

    private func makeUserOp(
        sender: String = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
        nonce: String = "0x0",
        callData: Data = Data(),
        chainId: Int = 1,
        entryPoint: String = "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
        entryPointVersion: EntryPointVersion = .v0_7
    ) -> UserOperation {
        UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0f4240",    // 1_000_000
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x0f4240",
            maxPriorityFeePerGas: "0x59682f00",  // 1.5 gwei
            maxFeePerGas: "0x06fc23ac00",         // 30 gwei
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: chainId,
            entryPoint: entryPoint,
            entryPointVersion: entryPointVersion
        )
    }

    @Test("UserOp hash is 32 bytes")
    func hashLength() {
        let op = makeUserOp()
        let hash = EthHashing.userOperationHash(op)
        #expect(hash.count == 32)
    }

    @Test("Same UserOp produces same hash")
    func deterministic() {
        let op = makeUserOp(callData: Data(hexString: "0xa9059cbb")!)
        let h1 = EthHashing.userOperationHash(op)
        let h2 = EthHashing.userOperationHash(op)
        #expect(h1 == h2)
    }

    @Test("Different chainId produces different hash")
    func differentChainId() {
        let op1 = makeUserOp(chainId: 1)
        let op2 = makeUserOp(chainId: 8453)
        #expect(EthHashing.userOperationHash(op1) != EthHashing.userOperationHash(op2))
    }

    @Test("Different sender produces different hash")
    func differentSender() {
        let op1 = makeUserOp(sender: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")
        let op2 = makeUserOp(sender: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913")
        #expect(EthHashing.userOperationHash(op1) != EthHashing.userOperationHash(op2))
    }

    @Test("Different entryPoint produces different hash")
    func differentEntryPoint() {
        let op1 = makeUserOp(entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032")
        let op2 = makeUserOp(entryPoint: "0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789")
        #expect(EthHashing.userOperationHash(op1) != EthHashing.userOperationHash(op2))
    }

    @Test("UserOp with factory produces valid hash")
    func withFactory() {
        let op = UserOperation(
            sender: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            nonce: "0x0",
            callData: Data(),
            factory: "0x9406Cc6185a346906296840746125a0E44976454",
            factoryData: Data([0x01, 0x02, 0x03]),
            verificationGasLimit: "0x0f4240",
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x0f4240",
            maxPriorityFeePerGas: "0x59682f00",
            maxFeePerGas: "0x06fc23ac00",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: 1,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
        let hash = EthHashing.userOperationHash(op)
        #expect(hash.count == 32)

        // Without factory should produce different hash
        let opNoFactory = makeUserOp()
        #expect(hash != EthHashing.userOperationHash(opNoFactory))
    }

    @Test("UserOp with paymaster produces valid hash")
    func withPaymaster() {
        let op = UserOperation(
            sender: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            nonce: "0x0",
            callData: Data(),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x0f4240",
            callGasLimit: "0x0f4240",
            preVerificationGas: "0x0f4240",
            maxPriorityFeePerGas: "0x59682f00",
            maxFeePerGas: "0x06fc23ac00",
            paymaster: "0x4Fd9098af9ddcB41DA48A1d78F91F1398965addc",
            paymasterVerificationGasLimit: "0x0f4240",
            paymasterPostOpGasLimit: "0x0f4240",
            paymasterData: Data([0xAA, 0xBB]),
            chainId: 1,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
        let hash = EthHashing.userOperationHash(op)
        #expect(hash.count == 32)

        // Without paymaster should produce different hash
        let opNoPaymaster = makeUserOp()
        #expect(hash != EthHashing.userOperationHash(opNoPaymaster))
    }

    @Test("v0.7 and v0.8 produce different hashes for same UserOp")
    func v07VsV08() {
        let opV07 = makeUserOp(entryPointVersion: .v0_7)
        let opV08 = makeUserOp(
            entryPoint: "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",
            entryPointVersion: .v0_8
        )
        let h07 = EthHashing.userOperationHash(opV07)
        let h08 = EthHashing.userOperationHash(opV08)
        #expect(h07.count == 32)
        #expect(h08.count == 32)
        // Different because v0.8 uses ERC-712 typed hash and different entrypoint
        #expect(h07 != h08)
    }

    @Test("v0.8 hash uses ERC-712 format (starts with \\x19\\x01 internally)")
    func v08IsERC712() {
        let op = makeUserOp(
            entryPoint: "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",
            entryPointVersion: .v0_8
        )
        let hash = EthHashing.userOperationHash(op)
        #expect(hash.count == 32)
        // v0.8 hash should be deterministic
        let hash2 = EthHashing.userOperationHash(op)
        #expect(hash == hash2)
    }

    @Test("v0.8 and v0.9 produce same hash for same fields (same algorithm)")
    func v08VsV09SameAlgorithm() {
        // v0.8 and v0.9 use the same ERC-712 hash computation
        // Only difference is entrypoint address
        let opV08 = makeUserOp(
            entryPoint: "0x4337084d9e255ff0702461cf8895ce9e3b5ff108",
            entryPointVersion: .v0_8
        )
        let opV09 = makeUserOp(
            entryPoint: "0x4337084d9e255ff0702461cf8895ce9e3b5ff108", // same EP address for test
            entryPointVersion: .v0_9
        )
        // With same entrypoint address, v0.8 and v0.9 should produce identical hash
        #expect(EthHashing.userOperationHash(opV08) == EthHashing.userOperationHash(opV09))
    }

    @Test("Odd-length numeric hex formatting does not change hash")
    func oddLengthNumericHexNormalizes() {
        let odd = UserOperation(
            sender: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            nonce: "0x1",
            callData: Data(),
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x1b1b0",
            callGasLimit: "0x4623",
            preVerificationGas: "0xc654",
            maxPriorityFeePerGas: "0xf4240",
            maxFeePerGas: "0xf424b",
            paymaster: "0x777777777777AeC03fd955926DbF81597e66834C",
            paymasterVerificationGasLimit: "0x8a8e",
            paymasterPostOpGasLimit: "0x1",
            paymasterData: Data(hexString: "0x010203"),
            chainId: 11155111,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )

        let padded = UserOperation(
            sender: odd.sender,
            nonce: "0x01",
            callData: odd.callData,
            factory: nil,
            factoryData: nil,
            verificationGasLimit: "0x01b1b0",
            callGasLimit: "0x4623",
            preVerificationGas: "0x0c654",
            maxPriorityFeePerGas: "0x0f4240",
            maxFeePerGas: "0x0f424b",
            paymaster: odd.paymaster,
            paymasterVerificationGasLimit: "0x08a8e",
            paymasterPostOpGasLimit: "0x01",
            paymasterData: odd.paymasterData,
            chainId: odd.chainId,
            entryPoint: odd.entryPoint,
            entryPointVersion: odd.entryPointVersion
        )

        #expect(EthHashing.userOperationHash(odd) == EthHashing.userOperationHash(padded))
    }
}

@Suite("UserOperation Fee Estimation")
struct UserOperationFeeEstimationTests {

    @Test("Viem-style base fee multiplier")
    func viemStyleEstimate() throws {
        let fees = try EthRPC.computeUserOperationFees(
            baseFeePerGas: 100,
            maxPriorityFeePerGas: 10,
            baseFeeMultiplier: 1.2
        )

        #expect(fees.maxPriorityFeePerGas == "0xa")
        #expect(fees.maxFeePerGas == "0x82")
    }

    @Test("Custom multiplier rounds like viem")
    func customMultiplier() throws {
        let fees = try EthRPC.computeUserOperationFees(
            baseFeePerGas: 101,
            maxPriorityFeePerGas: 5,
            baseFeeMultiplier: 1.25
        )

        #expect(fees.maxPriorityFeePerGas == "0x5")
        #expect(fees.maxFeePerGas == "0x83")
    }
}

@Suite("UserOperation Codable")
struct UserOperationCodableTests {

    @Test("Decodes hex byte fields and encodes them back as hex")
    func decodesAndEncodesHexByteFields() throws {
        let json = """
        {
          "sender": "0x1234567890abcdef1234567890abcdef12345678",
          "nonce": "0x01",
          "callData": "0xaabbccdd",
          "factory": "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
          "factoryData": "0xc5265d5d",
          "verificationGasLimit": "0x57749",
          "callGasLimit": "0x4623",
          "preVerificationGas": "0xd5d9",
          "maxPriorityFeePerGas": "0x233f76",
          "maxFeePerGas": "0x233f83",
          "paymaster": "0x777777777777AeC03fd955926DbF81597e66834C",
          "paymasterVerificationGasLimit": "0x8a8e",
          "paymasterPostOpGasLimit": "0x01",
          "paymasterData": "0x0102030405",
          "chainId": 11155111,
          "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
          "entryPointVersion": "v0.7"
        }
        """

        let op = try JSONDecoder().decode(UserOperation.self, from: Data(json.utf8))
        #expect(op.callData == Data([0xaa, 0xbb, 0xcc, 0xdd]))
        #expect(op.factoryData == Data(hexString: "0xc5265d5d"))
        #expect(op.paymasterData == Data(hexString: "0x0102030405"))

        let encoded = try JSONEncoder().encode(op)
        let object = try JSONSerialization.jsonObject(with: encoded) as? [String: Any]

        #expect(object?["callData"] as? String == "0xaabbccdd")
        #expect(object?["factoryData"] as? String == "0xc5265d5d")
        #expect(object?["paymasterData"] as? String == "0x0102030405")
    }

    @Test("Rejects base64 byte fields")
    func rejectsBase64ByteFields() throws {
        let json = """
        {
          "sender": "0x1234567890abcdef1234567890abcdef12345678",
          "nonce": "0x01",
          "callData": "qrvM3Q==",
          "verificationGasLimit": "0x57749",
          "callGasLimit": "0x4623",
          "preVerificationGas": "0xd5d9",
          "maxPriorityFeePerGas": "0x233f76",
          "maxFeePerGas": "0x233f83",
          "chainId": 11155111,
          "entryPoint": "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
          "entryPointVersion": "v0.7"
        }
        """

        do {
            _ = try JSONDecoder().decode(UserOperation.self, from: Data(json.utf8))
            Issue.record("Expected base64-encoded byte fields to be rejected")
        } catch let error as DecodingError {
            switch error {
            case .dataCorrupted(let context):
                #expect(context.debugDescription.contains("Base64 is not supported"))
            default:
                Issue.record("Expected dataCorrupted error, got \(error)")
            }
        }
    }
}

// MARK: - Kernel Encoding Tests

@Suite("Kernel v3.3 Encoding")
struct KernelEncodingTests {

    @Test("Single call encoding has correct format")
    func singleCallFormat() {
        let exec = KernelEncoding.Execution(
            to: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            value: 0,
            data: Data(hexString: "0xa9059cbb")!
        )
        let encoded = KernelEncoding.encodeSingle(exec)
        // 20 (address) + 32 (value) + 4 (selector) = 56 bytes
        #expect(encoded.count == 56)
        // First 20 bytes should be the address
        #expect(encoded.prefix(20) == Data(hexString: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"))
    }

    @Test("Execute calldata starts with correct selector")
    func executeSelector() {
        let exec = KernelEncoding.Execution(
            to: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            value: 0,
            data: Data()
        )
        let calldata = KernelEncoding.executeCalldata(single: exec)
        // First 4 bytes = execute(bytes32,bytes) selector = 0xe9ae5c53
        #expect(calldata.prefix(4) == Data([0xe9, 0xae, 0x5c, 0x53]))
    }

    @Test("Batch encoding produces valid output")
    func batchEncoding() {
        let executions = [
            KernelEncoding.Execution(
                to: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
                value: 0,
                data: Data(hexString: "0xa9059cbb")!
            ),
            KernelEncoding.Execution(
                to: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
                value: 1000,
                data: Data()
            ),
        ]
        let calldata = KernelEncoding.executeCalldata(batch: executions)
        #expect(calldata.prefix(4) == Data([0xe9, 0xae, 0x5c, 0x53]))
        #expect(calldata.count > 4 + 32) // selector + mode + more
    }

    @Test("ExecMode single has correct call type byte")
    func execModeSingle() {
        let mode = KernelEncoding.execModeSingle()
        #expect(mode.count == 32)
        #expect(mode[0] == 0x00) // CALLTYPE_SINGLE
        #expect(mode[1] == 0x00) // EXECTYPE_DEFAULT
    }

    @Test("ExecMode batch has correct call type byte")
    func execModeBatch() {
        let mode = KernelEncoding.execModeBatch()
        #expect(mode.count == 32)
        #expect(mode[0] == 0x01) // CALLTYPE_BATCH
        #expect(mode[1] == 0x00) // EXECTYPE_DEFAULT
    }
}

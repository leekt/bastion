import Testing
import Foundation
@preconcurrency import Security
@testable import bastion

// MARK: - P256 Software Key Helper (test-only)

nonisolated enum P256TestHelper {
    /// Creates a P-256 key pair in software (not Secure Enclave) for testing.
    static func createKeyPair() throws -> (privateKey: SecKey, publicKeyX: Data, publicKeyY: Data) {
        var error: Unmanaged<CFError>?
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
        ]
        guard let privateKey = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw NSError(domain: "test", code: 1, userInfo: [NSLocalizedDescriptionKey: "Failed to get public key"])
        }
        guard let pubData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        let x = pubData.subdata(in: 1..<33)
        let y = pubData.subdata(in: 33..<65)
        return (privateKey, x, y)
    }

    /// Sign a raw 32-byte hash with a software P-256 key. Returns r[32] + s[32].
    static func signDigest(hash: Data, privateKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            privateKey,
            .ecdsaSignatureDigestX962SHA256,
            hash as CFData,
            &error
        ) as Data? else {
            throw error!.takeRetainedValue() as Error
        }
        let (r, s) = try SecureEnclaveManager.shared.parseDER(signature)
        return r + s
    }
}

// MARK: - P256Curve Tests

@Suite("P256Curve")
struct P256CurveTests {

    @Test func curveOrderIsCorrect() {
        // N should be 32 bytes
        #expect(P256Curve.N.count == 32)
        #expect(P256Curve.halfN.count == 32)
        // N starts with 0xFF (P-256 order is close to 2^256)
        #expect(P256Curve.N[0] == 0xFF)
        // halfN starts with 0x7F
        #expect(P256Curve.halfN[0] == 0x7F)
    }

    @Test func halfNIsCorrect() {
        // 2 * halfN should be N - 1 (since N is odd)
        // We verify: halfN < N and halfN + 1 byte check
        #expect(P256Curve.compareBigEndian(P256Curve.halfN, P256Curve.N) < 0)
    }

    @Test func normalizeLowS() {
        // s <= N/2 should be returned unchanged
        let lowS = Data(repeating: 0x01, count: 32)
        let result = P256Curve.normalizeS(lowS)
        #expect(result == lowS)
    }

    @Test func normalizeHighS() {
        // s = N - 1 should be normalized to 1
        var nMinus1 = [UInt8](P256Curve.N)
        nMinus1[31] -= 1  // N - 1
        let highS = Data(nMinus1)
        let result = P256Curve.normalizeS(highS)
        // N - (N-1) = 1
        var expected = Data(repeating: 0, count: 32)
        expected[31] = 0x01
        #expect(result == expected)
    }

    @Test func normalizeHalfNIsUnchanged() {
        // s == halfN should be unchanged (s <= N/2)
        let result = P256Curve.normalizeS(P256Curve.halfN)
        #expect(result == P256Curve.halfN)
    }

    @Test func normalizeHalfNPlusOneIsNormalized() {
        // s == halfN + 1 should be normalized (s > N/2)
        var halfNPlus1 = [UInt8](P256Curve.halfN)
        // Add 1 to the last byte (with carry)
        var carry: UInt16 = 1
        for i in stride(from: 31, through: 0, by: -1) {
            let sum = UInt16(halfNPlus1[i]) + carry
            halfNPlus1[i] = UInt8(sum & 0xFF)
            carry = sum >> 8
            if carry == 0 { break }
        }
        let highS = Data(halfNPlus1)
        let result = P256Curve.normalizeS(highS)
        // Should be different from input
        #expect(result != highS)
        // Result should be <= halfN
        #expect(P256Curve.compareBigEndian(result, P256Curve.halfN) <= 0)
    }

    @Test func compareBigEndian() {
        let a = Data([0x00, 0x01])
        let b = Data([0x00, 0x02])
        #expect(P256Curve.compareBigEndian(a, b) < 0)
        #expect(P256Curve.compareBigEndian(b, a) > 0)
        #expect(P256Curve.compareBigEndian(a, a) == 0)
    }
}

// MARK: - P256Validator Unit Tests

@Suite("P256Validator")
struct P256ValidatorTests {

    @Test func validatorAddress() throws {
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        #expect(validator.validatorAddress == ValidatorAddress.p256Validator)
    }

    @Test func validationId() throws {
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let vid = validator.validationId
        #expect(vid.count == 21)
        #expect(vid[0] == 0x01) // VALIDATOR type
        let addrBytes = Data(hexString: ValidatorAddress.p256Validator)!
        #expect(Data(vid.dropFirst()) == addrBytes)
    }

    @Test func installData() throws {
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let data = validator.installData
        #expect(data.count == 64) // x[32] + y[32]
        #expect(Data(data.prefix(32)) == pubX)
        #expect(Data(data.suffix(32)) == pubY)
    }

    @Test func dummySignature() throws {
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let dummy = validator.dummySignature
        #expect(dummy.count == 64) // r[32] + s[32], no v byte
    }

    @Test func signNormalizesS() throws {
        // Create a validator that returns a high s value (> N/2)
        var highS = [UInt8](P256Curve.N)
        highS[31] -= 1  // N - 1, which is > N/2
        let fakeSignature = Data(repeating: 0x01, count: 32) + Data(highS)

        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in fakeSignature }
        )
        let result = try validator.sign(hash: Data(repeating: 0xAB, count: 32))
        #expect(result.count == 64)

        // s should be normalized (N - (N-1) = 1)
        let s = Data(result.suffix(32))
        #expect(P256Curve.compareBigEndian(s, P256Curve.halfN) <= 0)
        var expected = Data(repeating: 0, count: 32)
        expected[31] = 0x01
        #expect(s == expected)
    }

    @Test func signWithRealP256Key() throws {
        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let hash = Keccak256.hash(Data("test message".utf8))
        let sig = try validator.sign(hash: hash)
        #expect(sig.count == 64)

        // s must be <= N/2
        let s = Data(sig.suffix(32))
        #expect(P256Curve.compareBigEndian(s, P256Curve.halfN) <= 0)
    }
}

// MARK: - CalldataDecoder Tests

@Suite("CalldataDecoder")
struct CalldataDecoderTests {

    @Test func decodeSingleETHTransfer() {
        let target = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045" // vitalik.eth
        let exec = KernelEncoding.Execution(to: target, value: 1_000_000_000_000_000_000, data: Data()) // 1 ETH
        let callData = KernelEncoding.executeCalldata(single: exec)

        let op = UserOperation(
            sender: "0x0000000000000000000000000000000000000001",
            nonce: "0x0",
            callData: callData,
            factory: nil, factoryData: nil,
            verificationGasLimit: "0x0", callGasLimit: "0x0",
            preVerificationGas: "0x0", maxPriorityFeePerGas: "0x0", maxFeePerGas: "0x0",
            paymaster: nil, paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil, paymasterData: nil,
            chainId: 1, entryPoint: EntryPointAddress.v0_7, entryPointVersion: .v0_7
        )

        let decoded = CalldataDecoder.decode(op)
        #expect(decoded.chainName == "Ethereum")
        #expect(!decoded.isDeployment)
        #expect(decoded.executions.count == 1)
        #expect(decoded.executions[0].description.contains("ETH"))
        #expect(decoded.executions[0].value == "1000000000000000000")
    }

    @Test func decodeSingleERC20Transfer() {
        // Build transfer(address, uint256) calldata
        let recipient = Data(hexString: "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")!
        var transferData = Data([0xa9, 0x05, 0x9c, 0xbb]) // transfer selector
        transferData += Data(repeating: 0, count: 12) + recipient // padded address
        var amount = Data(repeating: 0, count: 32)
        amount[31] = 0x64 // 100 (raw, 6 decimals = 0.0001 USDC — but we use a non-USDC token here)
        transferData += amount

        let target = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48" // USDC on mainnet
        let exec = KernelEncoding.Execution(to: target, value: 0, data: transferData)
        let callData = KernelEncoding.executeCalldata(single: exec)

        let op = UserOperation(
            sender: "0x0000000000000000000000000000000000000001",
            nonce: "0x0",
            callData: callData,
            factory: nil, factoryData: nil,
            verificationGasLimit: "0x0", callGasLimit: "0x0",
            preVerificationGas: "0x0", maxPriorityFeePerGas: "0x0", maxFeePerGas: "0x0",
            paymaster: nil, paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil, paymasterData: nil,
            chainId: 1, entryPoint: EntryPointAddress.v0_7, entryPointVersion: .v0_7
        )

        let decoded = CalldataDecoder.decode(op)
        #expect(decoded.executions.count == 1)
        #expect(decoded.executions[0].functionName == "transfer")
        #expect(decoded.executions[0].description.contains("USDC"))
        #expect(decoded.executions[0].description.contains("Transfer"))
    }

    @Test func decodeUnknownSelector() {
        var calldata = Data([0x12, 0x34, 0x56, 0x78]) // unknown
        calldata += Data(repeating: 0xAB, count: 32)

        let target = "0x0000000000000000000000000000000000000042"
        let exec = KernelEncoding.Execution(to: target, value: 0, data: calldata)
        let execCallData = KernelEncoding.executeCalldata(single: exec)

        let op = UserOperation(
            sender: "0x0000000000000000000000000000000000000001",
            nonce: "0x0",
            callData: execCallData,
            factory: nil, factoryData: nil,
            verificationGasLimit: "0x0", callGasLimit: "0x0",
            preVerificationGas: "0x0", maxPriorityFeePerGas: "0x0", maxFeePerGas: "0x0",
            paymaster: nil, paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil, paymasterData: nil,
            chainId: 11155111, entryPoint: EntryPointAddress.v0_7, entryPointVersion: .v0_7
        )

        let decoded = CalldataDecoder.decode(op)
        #expect(decoded.chainName == "Sepolia")
        #expect(decoded.executions.count == 1)
        #expect(decoded.executions[0].functionName == "0x12345678")
        #expect(decoded.executions[0].description.contains("0x12345678"))
    }

    @Test func decodeDeployment() {
        let exec = KernelEncoding.Execution(
            to: "0x0000000000000000000000000000000000000001",
            value: 0,
            data: Data()
        )
        let callData = KernelEncoding.executeCalldata(single: exec)

        let op = UserOperation(
            sender: "0x0000000000000000000000000000000000000001",
            nonce: "0x0",
            callData: callData,
            factory: KernelAddress.metaFactory,
            factoryData: Data([0x01, 0x02, 0x03]),
            verificationGasLimit: "0x0", callGasLimit: "0x0",
            preVerificationGas: "0x0", maxPriorityFeePerGas: "0x0", maxFeePerGas: "0x0",
            paymaster: nil, paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil, paymasterData: nil,
            chainId: 11155111, entryPoint: EntryPointAddress.v0_7, entryPointVersion: .v0_7
        )

        let decoded = CalldataDecoder.decode(op)
        #expect(decoded.isDeployment)
    }
}

// MARK: - P256 SmartAccount Tests

@Suite("P256 SmartAccount")
struct P256SmartAccountTests {

    @Test func factoryDataUsesP256Validator() throws {
        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)

        // initializeCalldata should contain the P256 validator's validationId
        let calldata = account.initializeCalldata
        #expect(calldata.prefix(4) == Data(hexString: "0x3c3b752b")) // initialize selector

        // The validationId (bytes21) should be 0x01 + p256 validator address
        let vid = validator.validationId
        #expect(vid.count == 21)
        #expect(vid[0] == 0x01)

        // factoryData should use deployWithFactory selector
        let fd = account.factoryData
        #expect(fd.prefix(4) == Data(hexString: "0xc5265d5d"))
    }

    @Test func nonceKeyUsesP256Address() throws {
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let account = SmartAccount(validator: validator)
        let key = account.nonceKey
        #expect(key.count == 24)
        // Bytes 2..22 should be the P256 validator address
        let addrBytes = Data(hexString: ValidatorAddress.p256Validator)!
        #expect(Data(key[2..<22]) == addrBytes)
    }

    @Test func computeAddressDeterministic() throws {
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let account = SmartAccount(validator: validator)
        let addr1 = account.computeAddress()
        let addr2 = account.computeAddress()
        #expect(addr1 == addr2)
        #expect(addr1.hasPrefix("0x"))
        #expect(addr1.count == 42)
    }

    @Test func differentKeysProduceDifferentAddresses() throws {
        let (_, pubX1, pubY1) = try P256TestHelper.createKeyPair()
        let (_, pubX2, pubY2) = try P256TestHelper.createKeyPair()

        let v1 = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX1, publicKeyY: pubY1,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let v2 = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX2, publicKeyY: pubY2,
            sign: { _ in Data(repeating: 0, count: 64) }
        )

        let a1 = SmartAccount(validator: v1).computeAddress()
        let a2 = SmartAccount(validator: v2).computeAddress()
        #expect(a1 != a2)
    }
}

// MARK: - P256 ZeroDev Integration Tests

@Suite("P256 ZeroDev Integration", .tags(.integration), .serialized)
struct P256ZeroDevIntegrationTests {

    static let chainId = 11155111 // Sepolia
    static let diagFile = "/tmp/bastion_p256_integration.txt"
    static let traceBeneficiary = "0x000000000000000000000000000000000000dEaD"

    private static func resetLog() {
        try? FileManager.default.removeItem(atPath: diagFile)
        FileManager.default.createFile(atPath: diagFile, contents: nil)
    }

    private static func log(_ msg: String) {
        let data = (msg + "\n").data(using: .utf8)!
        if let handle = FileHandle(forWritingAtPath: diagFile) {
            handle.seekToEndOfFile()
            handle.write(data)
            handle.closeFile()
        } else {
            FileManager.default.createFile(atPath: diagFile, contents: data)
        }
    }

    @discardableResult
    private static func verifySignedOperation(
        _ op: UserOperation,
        signature: Data,
        pubX: Data,
        pubY: Data,
        using publicRPC: EthRPC,
        label: String
    ) async throws -> Data {
        let localHash = EthHashing.userOperationHash(op)
        let entryPointHash = try await publicRPC.getUserOpHash(op)
        log("\(label) local hash: 0x\(localHash.hex)")
        log("\(label) EntryPoint hash: 0x\(entryPointHash.hex)")
        #expect(localHash == entryPointHash)

        let verifyCalldata = "0x" + (
            entryPointHash
            + Data(signature.prefix(32))
            + Data(signature.suffix(32))
            + pubX
            + pubY
        ).hex
        let result = try await publicRPC.ethCall(
            to: "0x0000000000000000000000000000000000000100",
            data: verifyCalldata
        )
        let isValid = result.hasSuffix("1")
        log("\(label) precompile result: \(result)")
        log("\(label) signature valid on-chain: \(isValid)")
        #expect(isValid)
        return entryPointHash
    }

    @Test func resolveP256CounterfactualAddress() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)
        let address = try await account.resolveAddress(using: publicRPC)
        #expect(address.hasPrefix("0x"))
        #expect(address.count == 42)
        print("P256 counterfactual address: \(address)")
    }

    @Test func sponsorP256UserOp() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)
        let sender = try await account.resolveAddress(using: publicRPC)

        // No-op: send 0 ETH to self
        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(to: sender, value: 0, data: Data())
        )

        let nonce = try await publicRPC.getNonce(
            sender: sender,
            key: account.nonceKeyUInt192,
            entryPoint: EntryPointAddress.v0_7
        )
        let deployed = try await account.isDeployed(using: publicRPC)

        let op = UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : account.factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: "0x1",
            maxFeePerGas: "0x1",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: Self.chainId,
            entryPoint: EntryPointAddress.v0_7,
            entryPointVersion: .v0_7
        )

        let dummySig = validator.dummySignature
        let rpcOp = UserOperationRPC.from(op, signature: dummySig)

        let sponsor = try await bundler.sponsorUserOperation(
            rpcOp,
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )

        #expect(sponsor.paymaster != nil)
        #expect(sponsor.paymasterData != nil)
        #expect(sponsor.callGasLimit != nil)
        #expect(sponsor.verificationGasLimit != nil)
        #expect(sponsor.preVerificationGas != nil)
        print("P256 UserOp sponsored successfully")
        print("  paymaster: \(sponsor.paymaster ?? "nil")")
        print("  callGasLimit: \(sponsor.callGasLimit ?? "nil")")
    }

    @Test func p256UserOpHashMatchesEntryPoint() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let (_, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { _ in Data(repeating: 0, count: 64) }
        )
        let account = SmartAccount(validator: validator)
        let sender = try await account.resolveAddress(using: publicRPC)

        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(to: sender, value: 0, data: Data())
        )

        let nonce = try await publicRPC.getNonce(
            sender: sender,
            key: account.nonceKeyUInt192,
            entryPoint: EntryPointAddress.v0_7
        )
        let deployed = try await account.isDeployed(using: publicRPC)

        let op = UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : account.factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: "0x1",
            maxFeePerGas: "0x1",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: Self.chainId,
            entryPoint: EntryPointAddress.v0_7,
            entryPointVersion: .v0_7
        )

        let sponsored = try await bundler.sponsorUserOperation(
            UserOperationRPC.from(op, signature: validator.dummySignature),
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )

        let finalOp = UserOperation(
            sender: op.sender,
            nonce: op.nonce,
            callData: op.callData,
            factory: op.factory,
            factoryData: op.factoryData,
            verificationGasLimit: sponsored.verificationGasLimit ?? op.verificationGasLimit,
            callGasLimit: sponsored.callGasLimit ?? op.callGasLimit,
            preVerificationGas: sponsored.preVerificationGas ?? op.preVerificationGas,
            maxPriorityFeePerGas: sponsored.maxPriorityFeePerGas ?? op.maxPriorityFeePerGas,
            maxFeePerGas: sponsored.maxFeePerGas ?? op.maxFeePerGas,
            paymaster: sponsored.paymaster,
            paymasterVerificationGasLimit: sponsored.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: sponsored.paymasterPostOpGasLimit,
            paymasterData: sponsored.paymasterData.flatMap { Data(hexString: $0) },
            chainId: op.chainId,
            entryPoint: op.entryPoint,
            entryPointVersion: op.entryPointVersion
        )

        let localHash = EthHashing.userOperationHash(finalOp)
        let entryPointHash = try await publicRPC.getUserOpHash(finalOp)

        #expect(localHash == entryPointHash)
    }

    @Test func p256SignatureVerifiesAgainstEntryPointHash() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)
        let sender = try await account.resolveAddress(using: publicRPC)

        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(to: sender, value: 0, data: Data())
        )

        let nonce = try await publicRPC.getNonce(
            sender: sender,
            key: account.nonceKeyUInt192,
            entryPoint: EntryPointAddress.v0_7
        )
        let deployed = try await account.isDeployed(using: publicRPC)

        let baseOp = UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : account.factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: "0x1",
            maxFeePerGas: "0x1",
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: Self.chainId,
            entryPoint: EntryPointAddress.v0_7,
            entryPointVersion: .v0_7
        )

        let sponsored = try await bundler.sponsorUserOperation(
            UserOperationRPC.from(baseOp, signature: validator.dummySignature),
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )

        let op = UserOperation(
            sender: baseOp.sender,
            nonce: baseOp.nonce,
            callData: baseOp.callData,
            factory: baseOp.factory,
            factoryData: baseOp.factoryData,
            verificationGasLimit: sponsored.verificationGasLimit ?? baseOp.verificationGasLimit,
            callGasLimit: sponsored.callGasLimit ?? baseOp.callGasLimit,
            preVerificationGas: sponsored.preVerificationGas ?? baseOp.preVerificationGas,
            maxPriorityFeePerGas: sponsored.maxPriorityFeePerGas ?? baseOp.maxPriorityFeePerGas,
            maxFeePerGas: sponsored.maxFeePerGas ?? baseOp.maxFeePerGas,
            paymaster: sponsored.paymaster,
            paymasterVerificationGasLimit: sponsored.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: sponsored.paymasterPostOpGasLimit,
            paymasterData: sponsored.paymasterData.flatMap { Data(hexString: $0) },
            chainId: baseOp.chainId,
            entryPoint: baseOp.entryPoint,
            entryPointVersion: baseOp.entryPointVersion
        )

        let localHash = EthHashing.userOperationHash(op)
        let entryPointHash = try await publicRPC.getUserOpHash(op)
        #expect(localHash == entryPointHash)

        let signature = try account.signUserOperation(op)
        #expect(signature.count == 64)

        let verifyCalldata = "0x" + (
            entryPointHash
            + Data(signature.prefix(32))
            + Data(signature.suffix(32))
            + pubX
            + pubY
        ).hex
        let result = try await publicRPC.ethCall(
            to: "0x0000000000000000000000000000000000000100",
            data: verifyCalldata
        )

        #expect(result.hasSuffix("1"))
    }

    private static func applying(_ sponsor: SponsorResult, to op: UserOperation) -> UserOperation {
        UserOperation(
            sender: op.sender,
            nonce: op.nonce,
            callData: op.callData,
            factory: op.factory,
            factoryData: op.factoryData,
            verificationGasLimit: sponsor.verificationGasLimit ?? op.verificationGasLimit,
            callGasLimit: sponsor.callGasLimit ?? op.callGasLimit,
            preVerificationGas: sponsor.preVerificationGas ?? op.preVerificationGas,
            maxPriorityFeePerGas: sponsor.maxPriorityFeePerGas ?? op.maxPriorityFeePerGas,
            maxFeePerGas: sponsor.maxFeePerGas ?? op.maxFeePerGas,
            paymaster: sponsor.paymaster,
            paymasterVerificationGasLimit: sponsor.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: sponsor.paymasterPostOpGasLimit,
            paymasterData: sponsor.paymasterData.flatMap { Data(hexString: $0) },
            chainId: op.chainId,
            entryPoint: op.entryPoint,
            entryPointVersion: op.entryPointVersion
        )
    }

    private static func applying(
        maxPriorityFeePerGas: String,
        maxFeePerGas: String,
        to op: UserOperation
    ) -> UserOperation {
        UserOperation(
            sender: op.sender,
            nonce: op.nonce,
            callData: op.callData,
            factory: op.factory,
            factoryData: op.factoryData,
            verificationGasLimit: op.verificationGasLimit,
            callGasLimit: op.callGasLimit,
            preVerificationGas: op.preVerificationGas,
            maxPriorityFeePerGas: maxPriorityFeePerGas,
            maxFeePerGas: maxFeePerGas,
            paymaster: op.paymaster,
            paymasterVerificationGasLimit: op.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: op.paymasterPostOpGasLimit,
            paymasterData: op.paymasterData,
            chainId: op.chainId,
            entryPoint: op.entryPoint,
            entryPointVersion: op.entryPointVersion
        )
    }

    private static func requiresBundlerFeeRetry(_ error: Error) -> Bool {
        String(describing: error).contains("maxFeePerGas must be at least")
    }

    private static func traceCommand(
        rpcURL: String,
        op: UserOperation,
        signature: Data
    ) -> String {
        let calldata = handleOpsCalldata(op: op, signature: signature, beneficiary: traceBeneficiary)
        return "cast call \(op.entryPoint) --rpc-url \(rpcURL) --trace --data \(calldata) --evm-version osaka"
    }

    private static func handleOpsCalldata(
        op: UserOperation,
        signature: Data,
        beneficiary: String
    ) -> String {
        let selector = Keccak256.hash(
            Data("handleOps((address,uint256,bytes,bytes,bytes32,uint256,bytes32,bytes,bytes)[],address)".utf8)
        ).prefix(4)

        let tuple = abiEncodeUserOperationTuple(op: op, signature: signature)
        var arrayData = Data()
        arrayData += abiEncodeUInt256(1)
        arrayData += abiEncodeUInt256(32)
        arrayData += tuple

        var calldata = Data(selector)
        calldata += abiEncodeUInt256(64)
        calldata += abiEncodeAddress(beneficiary)
        calldata += arrayData
        return "0x" + calldata.hex
    }

    private static func abiEncodeUserOperationTuple(op: UserOperation, signature: Data) -> Data {
        let initCode = packedInitCode(for: op)
        let paymasterAndData = packedPaymasterAndData(for: op)
        let accountGasLimits = packTwo128(op.verificationGasLimit, op.callGasLimit)
        let gasFees = packTwo128(op.maxPriorityFeePerGas, op.maxFeePerGas)

        let headWords = 9
        let headSize = headWords * 32

        let initCodeData = abiEncodeBytes(initCode)
        let callDataData = abiEncodeBytes(op.callData)
        let paymasterData = abiEncodeBytes(paymasterAndData)
        let signatureData = abiEncodeBytes(signature)

        let initCodeOffset = headSize
        let callDataOffset = initCodeOffset + initCodeData.count
        let paymasterOffset = callDataOffset + callDataData.count
        let signatureOffset = paymasterOffset + paymasterData.count

        var encoded = Data()
        encoded += abiEncodeAddress(op.sender)
        encoded += abiEncodeUInt256FromHex(op.nonce)
        encoded += abiEncodeUInt256(UInt64(initCodeOffset))
        encoded += abiEncodeUInt256(UInt64(callDataOffset))
        encoded += leftPad(accountGasLimits, to: 32)
        encoded += abiEncodeUInt256FromHex(op.preVerificationGas)
        encoded += leftPad(gasFees, to: 32)
        encoded += abiEncodeUInt256(UInt64(paymasterOffset))
        encoded += abiEncodeUInt256(UInt64(signatureOffset))
        encoded += initCodeData
        encoded += callDataData
        encoded += paymasterData
        encoded += signatureData
        return encoded
    }

    private static func packedInitCode(for op: UserOperation) -> Data {
        var initCode = Data()
        if let factory = op.factory {
            initCode += Data(hexString: factory) ?? Data()
            initCode += op.factoryData ?? Data()
        }
        return initCode
    }

    private static func packedPaymasterAndData(for op: UserOperation) -> Data {
        var paymasterAndData = Data()
        if let paymaster = op.paymaster {
            paymasterAndData += Data(hexString: paymaster) ?? Data()
            paymasterAndData += leftPad(Data(hexString: op.paymasterVerificationGasLimit ?? "0x0") ?? Data(), to: 16)
            paymasterAndData += leftPad(Data(hexString: op.paymasterPostOpGasLimit ?? "0x0") ?? Data(), to: 16)
            paymasterAndData += op.paymasterData ?? Data()
        }
        return paymasterAndData
    }

    private static func packTwo128(_ high: String, _ low: String) -> Data {
        leftPad(Data(hexString: high) ?? Data(), to: 16) + leftPad(Data(hexString: low) ?? Data(), to: 16)
    }

    private static func abiEncodeBytes(_ data: Data) -> Data {
        var encoded = abiEncodeUInt256(UInt64(data.count))
        encoded += data
        let padding = (32 - data.count % 32) % 32
        if padding > 0 {
            encoded += Data(repeating: 0, count: padding)
        }
        return encoded
    }

    private static func abiEncodeAddress(_ address: String) -> Data {
        leftPad(Data(hexString: address) ?? Data(), to: 32)
    }

    private static func abiEncodeUInt256(_ value: UInt64) -> Data {
        var result = Data(repeating: 0, count: 32)
        var v = value
        for i in stride(from: 31, through: 24, by: -1) {
            result[i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return result
    }

    private static func abiEncodeUInt256FromHex(_ hex: String) -> Data {
        leftPad(Data(hexString: hex) ?? Data(), to: 32)
    }

    private static func leftPad(_ data: Data, to size: Int) -> Data {
        if data.count >= size { return Data(data.suffix(size)) }
        return Data(repeating: 0, count: size - data.count) + data
    }

    @Test func fullP256UserOpFlow() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        Self.resetLog()
        var finalTraceCommand: String?
        defer {
            Self.log(finalTraceCommand ?? "cast call --trace unavailable")
        }

        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)
        let sender = try await account.resolveAddress(using: publicRPC)
        Self.log("P256 sender: \(sender)")

        // Build UserOp: no-op (send 0 ETH to self)
        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(to: sender, value: 0, data: Data())
        )

        let nonce = try await publicRPC.getNonce(
            sender: sender,
            key: account.nonceKeyUInt192,
            entryPoint: EntryPointAddress.v0_7
        )
        let deployed = try await account.isDeployed(using: publicRPC)
        let estimatedFees = try await publicRPC.estimateUserOperationFeesPerGas()
        let priorityFee = estimatedFees.maxPriorityFeePerGas
        let maxFee = estimatedFees.maxFeePerGas
        Self.log("P256 account deployed: \(deployed)")
        Self.log("Estimated maxPriorityFeePerGas: \(priorityFee)")
        Self.log("Estimated maxFeePerGas: \(maxFee)")

        var op = UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : account.factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: priorityFee,
            maxFeePerGas: maxFee,
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: Self.chainId,
            entryPoint: EntryPointAddress.v0_7,
            entryPointVersion: .v0_7
        )

        // 1. Sponsor (get gas estimates + paymaster data)
        let dummySig = validator.dummySignature
        let dummyRpcOp = UserOperationRPC.from(op, signature: dummySig)

        Self.log("Step 1: Sponsoring...")
        let sponsor = try await bundler.sponsorUserOperation(
            dummyRpcOp,
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )
        Self.log("Sponsored! paymaster: \(sponsor.paymaster ?? "nil")")
        Self.log("  verificationGasLimit: \(sponsor.verificationGasLimit ?? "nil")")
        Self.log("  callGasLimit: \(sponsor.callGasLimit ?? "nil")")
        Self.log("  maxFeePerGas: \(sponsor.maxFeePerGas ?? "nil")")

        // 2. Apply sponsor data to op
        op = Self.applying(sponsor, to: op)

        Self.log("Step 2: Final sponsored payload")
        Self.log("factoryData: \(op.factoryData.map { "0x\($0.hex)" } ?? "nil")")
        Self.log("callData: 0x\(op.callData.hex)")
        Self.log("  sender: \(op.sender)")
        Self.log("  nonce: \(op.nonce)")
        Self.log("  factory: \(op.factory ?? "nil")")
        Self.log("  paymaster: \(op.paymaster ?? "nil")")
        Self.log("  verificationGasLimit: \(op.verificationGasLimit)")
        Self.log("  callGasLimit: \(op.callGasLimit)")
        Self.log("  preVerificationGas: \(op.preVerificationGas)")
        Self.log("  maxPriorityFeePerGas: \(op.maxPriorityFeePerGas)")
        Self.log("  maxFeePerGas: \(op.maxFeePerGas)")
        Self.log("  paymasterData: \(op.paymasterData.map { "0x\($0.hex)" } ?? "nil")")
        Self.log("  paymasterVerificationGasLimit: \(op.paymasterVerificationGasLimit ?? "nil")")
        Self.log("  paymasterPostOpGasLimit: \(op.paymasterPostOpGasLimit ?? "nil")")

        Self.log("Step 3: Signing final payload...")
        var signature = try account.signUserOperation(op)
        #expect(signature.count == 64)
        Self.log("Final P256 signature: 0x\(signature.hex)")

        let s = Data(signature.suffix(32))
        #expect(P256Curve.compareBigEndian(s, P256Curve.halfN) <= 0)
        Self.log("s normalized: \(P256Curve.compareBigEndian(s, P256Curve.halfN) <= 0)")

        try await Self.verifySignedOperation(
            op,
            signature: signature,
            pubX: pubX,
            pubY: pubY,
            using: publicRPC,
            label: "Final"
        )

        // 4. Send to bundler
        Self.log("Step 4: Sending to bundler...")
        finalTraceCommand = Self.traceCommand(
            rpcURL: config.sepoliaRPCURL,
            op: op,
            signature: signature
        )
        let userOpHash: String
        do {
            userOpHash = try await bundler.sendUserOperation(
                UserOperationRPC.from(op, signature: signature),
                entryPoint: EntryPointAddress.v0_7,
                chainId: Self.chainId
            )
            Self.log("P256 UserOp sent! Hash: \(userOpHash)")
            #expect(userOpHash.hasPrefix("0x"))
        } catch {
            if Self.requiresBundlerFeeRetry(error) {
                Self.log("Retrying with bundler gas price...")
                let bundlerGasPrice = try await bundler.userOperationGasPrice(chainId: Self.chainId)
                op = Self.applying(
                    maxPriorityFeePerGas: bundlerGasPrice.standard.maxPriorityFeePerGas,
                    maxFeePerGas: bundlerGasPrice.standard.maxFeePerGas,
                    to: op
                )
                let retrySponsor = try await bundler.sponsorUserOperation(
                    UserOperationRPC.from(op, signature: validator.dummySignature),
                    entryPoint: EntryPointAddress.v0_7,
                    chainId: Self.chainId
                )
                op = Self.applying(retrySponsor, to: op)
                signature = try account.signUserOperation(op)
                try await Self.verifySignedOperation(
                    op,
                    signature: signature,
                    pubX: pubX,
                    pubY: pubY,
                    using: publicRPC,
                    label: "Retry"
                )
                finalTraceCommand = Self.traceCommand(
                    rpcURL: config.sepoliaRPCURL,
                    op: op,
                    signature: signature
                )
                userOpHash = try await bundler.sendUserOperation(
                    UserOperationRPC.from(op, signature: signature),
                    entryPoint: EntryPointAddress.v0_7,
                    chainId: Self.chainId
                )
                Self.log("P256 UserOp sent after bundler fee retry! Hash: \(userOpHash)")
            } else {
                Self.log("sendUserOperation FAILED: \(error)")
                throw error
            }
        }

        // 5. Poll for receipt (up to 60s)
        var receipt: UserOperationReceipt?
        for attempt in 1...12 {
            try await Task.sleep(nanoseconds: 5_000_000_000) // 5s
            receipt = try await bundler.getUserOperationReceipt(
                userOpHash: userOpHash,
                chainId: Self.chainId
            )
            if receipt != nil {
                print("P256 UserOp confirmed after \(attempt * 5)s")
                break
            }
            print("  waiting... attempt \(attempt)/12")
        }

        if let receipt {
            print("P256 UserOp receipt:")
            print("  success: \(receipt.success)")
            print("  txHash: \(receipt.receipt?.transactionHash ?? "nil")")
            #expect(receipt.success)
        } else {
            print("P256 UserOp not confirmed within 60s (may still be pending)")
        }
    }
}

// MARK: - Base Sepolia E2E (P256Validator deployed at 0x9906AB44fF795883C5a725687A2705BE4118B0f3)

@Suite("P256 Base Sepolia E2E", .tags(.integration), .serialized)
struct P256BaseSepoliaIntegrationTests {

    static let chainId = 84532 // Base Sepolia
    static let diagFile = "/tmp/bastion_p256_base_sepolia.txt"

    private static func resetLog() {
        try? FileManager.default.removeItem(atPath: diagFile)
        FileManager.default.createFile(atPath: diagFile, contents: nil)
    }

    private static func log(_ msg: String) {
        let data = (msg + "\n").data(using: .utf8)!
        if let handle = FileHandle(forWritingAtPath: diagFile) {
            handle.seekToEndOfFile()
            handle.write(data)
            handle.closeFile()
        } else {
            FileManager.default.createFile(atPath: diagFile, contents: data)
        }
    }

    private static func applying(_ sponsor: SponsorResult, to op: UserOperation) -> UserOperation {
        UserOperation(
            sender: op.sender,
            nonce: op.nonce,
            callData: op.callData,
            factory: op.factory,
            factoryData: op.factoryData,
            verificationGasLimit: sponsor.verificationGasLimit ?? op.verificationGasLimit,
            callGasLimit: sponsor.callGasLimit ?? op.callGasLimit,
            preVerificationGas: sponsor.preVerificationGas ?? op.preVerificationGas,
            maxPriorityFeePerGas: sponsor.maxPriorityFeePerGas ?? op.maxPriorityFeePerGas,
            maxFeePerGas: sponsor.maxFeePerGas ?? op.maxFeePerGas,
            paymaster: sponsor.paymaster,
            paymasterVerificationGasLimit: sponsor.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: sponsor.paymasterPostOpGasLimit,
            paymasterData: sponsor.paymasterData.flatMap { Data(hexString: $0) },
            chainId: op.chainId,
            entryPoint: op.entryPoint,
            entryPointVersion: op.entryPointVersion
        )
    }

    private static func applying(
        maxPriorityFeePerGas: String,
        maxFeePerGas: String,
        to op: UserOperation
    ) -> UserOperation {
        UserOperation(
            sender: op.sender,
            nonce: op.nonce,
            callData: op.callData,
            factory: op.factory,
            factoryData: op.factoryData,
            verificationGasLimit: op.verificationGasLimit,
            callGasLimit: op.callGasLimit,
            preVerificationGas: op.preVerificationGas,
            maxPriorityFeePerGas: maxPriorityFeePerGas,
            maxFeePerGas: maxFeePerGas,
            paymaster: op.paymaster,
            paymasterVerificationGasLimit: op.paymasterVerificationGasLimit,
            paymasterPostOpGasLimit: op.paymasterPostOpGasLimit,
            paymasterData: op.paymasterData,
            chainId: op.chainId,
            entryPoint: op.entryPoint,
            entryPointVersion: op.entryPointVersion
        )
    }

    @Test func p256ValidatorHasCode() async throws {
        guard let config = LiveTestConfig.current,
              let rpcURL = config.baseSepoliaRPCURL else { return }
        let rpc = EthRPC(rpcURLString: rpcURL)
        let code = try await rpc.getCode(address: ValidatorAddress.p256Validator)
        #expect(code.count > 2, "P256Validator not deployed on Base Sepolia")
        print("P256Validator code length on Base Sepolia: \(code.count) chars")
    }

    @Test func resolveCounterfactualAddress() async throws {
        guard let config = LiveTestConfig.current,
              let rpcURL = config.baseSepoliaRPCURL else { return }
        let rpc = EthRPC(rpcURLString: rpcURL)
        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)
        let address = try await account.resolveAddress(using: rpc)
        #expect(address.hasPrefix("0x"))
        #expect(address.count == 42)
        print("P256 Base Sepolia counterfactual address: \(address)")
    }

    @Test func fullP256UserOpFlowBaseSepolia() async throws {
        guard let config = LiveTestConfig.current,
              let rpcURL = config.baseSepoliaRPCURL else { return }
        let publicRPC = EthRPC(rpcURLString: rpcURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        Self.resetLog()
        var finalTraceCommand: String?
        defer {
            Self.log(finalTraceCommand ?? "cast call --trace unavailable")
            if let path = Self.diagFile as String? {
                print("Diagnostic log: \(path)")
            }
        }

        let (privKey, pubX, pubY) = try P256TestHelper.createKeyPair()
        Self.log("pubX: 0x\(pubX.hex)")
        Self.log("pubY: 0x\(pubY.hex)")

        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: pubX,
            publicKeyY: pubY,
            sign: { hash in try P256TestHelper.signDigest(hash: hash, privateKey: privKey) }
        )
        let account = SmartAccount(validator: validator)
        let sender = try await account.resolveAddress(using: publicRPC)
        Self.log("P256 Base Sepolia sender: \(sender)")

        // No-op: send 0 ETH to self
        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(to: sender, value: 0, data: Data())
        )

        let nonce = try await publicRPC.getNonce(
            sender: sender,
            key: account.nonceKeyUInt192,
            entryPoint: EntryPointAddress.v0_7
        )
        let deployed = try await account.isDeployed(using: publicRPC)
        let estimatedFees = try await publicRPC.estimateUserOperationFeesPerGas()
        Self.log("Account deployed: \(deployed)")
        Self.log("Estimated fees: priority=\(estimatedFees.maxPriorityFeePerGas) max=\(estimatedFees.maxFeePerGas)")

        var op = UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : account.factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: estimatedFees.maxPriorityFeePerGas,
            maxFeePerGas: estimatedFees.maxFeePerGas,
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: Self.chainId,
            entryPoint: EntryPointAddress.v0_7,
            entryPointVersion: .v0_7
        )

        // 1. Sponsor
        let dummySig = validator.dummySignature
        Self.log("Step 1: Sponsoring on Base Sepolia...")
        let sponsor = try await bundler.sponsorUserOperation(
            UserOperationRPC.from(op, signature: dummySig),
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )
        Self.log("Sponsored! paymaster: \(sponsor.paymaster ?? "nil")")

        // 2. Apply sponsor data
        op = Self.applying(sponsor, to: op)

        // 3. Sign
        Self.log("Step 2: Signing...")
        let localHash = EthHashing.userOperationHash(op)
        Self.log("Local UserOp hash: 0x\(localHash.hex)")

        var signature = try account.signUserOperation(op)
        #expect(signature.count == 64)
        Self.log("Signature: 0x\(signature.hex)")

        let s = Data(signature.suffix(32))
        #expect(P256Curve.compareBigEndian(s, P256Curve.halfN) <= 0, "s not normalized")

        // Verify against P256 precompile
        let verifyCalldata = "0x" + (
            localHash
            + Data(signature.prefix(32))
            + Data(signature.suffix(32))
            + pubX
            + pubY
        ).hex
        let precompileResult = try await publicRPC.ethCall(
            to: "0x0000000000000000000000000000000000000100",
            data: verifyCalldata
        )
        Self.log("P256 precompile result: \(precompileResult)")
        #expect(precompileResult.hasSuffix("1"), "P256 precompile verification failed")

        // 4. Send
        Self.log("Step 3: Sending to bundler...")
        finalTraceCommand = "cast call --trace --rpc-url \(rpcURL) --from 0x0000000071727De22E5E9d8BAf0edAc6f37da032 ..."
        let userOpHash: String
        do {
            userOpHash = try await bundler.sendUserOperation(
                UserOperationRPC.from(op, signature: signature),
                entryPoint: EntryPointAddress.v0_7,
                chainId: Self.chainId
            )
            Self.log("UserOp sent! Hash: \(userOpHash)")
            #expect(userOpHash.hasPrefix("0x"))
        } catch {
            Self.log("sendUserOperation FAILED: \(error)")
            // Retry with bundler gas price
            Self.log("Retrying with bundler gas price...")
            let bundlerGasPrice = try await bundler.userOperationGasPrice(chainId: Self.chainId)
            op = Self.applying(
                maxPriorityFeePerGas: bundlerGasPrice.standard.maxPriorityFeePerGas,
                maxFeePerGas: bundlerGasPrice.standard.maxFeePerGas,
                to: op
            )
            let retrySponsor = try await bundler.sponsorUserOperation(
                UserOperationRPC.from(op, signature: validator.dummySignature),
                entryPoint: EntryPointAddress.v0_7,
                chainId: Self.chainId
            )
            op = Self.applying(retrySponsor, to: op)
            signature = try account.signUserOperation(op)
            userOpHash = try await bundler.sendUserOperation(
                UserOperationRPC.from(op, signature: signature),
                entryPoint: EntryPointAddress.v0_7,
                chainId: Self.chainId
            )
            Self.log("UserOp sent after retry! Hash: \(userOpHash)")
        }

        // 5. Poll for receipt
        var receipt: UserOperationReceipt?
        for attempt in 1...12 {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            receipt = try await bundler.getUserOperationReceipt(
                userOpHash: userOpHash,
                chainId: Self.chainId
            )
            if receipt != nil {
                Self.log("UserOp confirmed after \(attempt * 5)s")
                break
            }
            Self.log("  waiting... attempt \(attempt)/12")
        }

        if let receipt {
            Self.log("Receipt: success=\(receipt.success) tx=\(receipt.receipt?.transactionHash ?? "nil")")
            print("Base Sepolia P256 UserOp receipt:")
            print("  success: \(receipt.success)")
            print("  txHash: \(receipt.receipt?.transactionHash ?? "nil")")
            #expect(receipt.success, "UserOp execution failed on-chain")
        } else {
            Self.log("UserOp not confirmed within 60s")
            print("Base Sepolia P256 UserOp not confirmed within 60s (may still be pending)")
        }
    }
}

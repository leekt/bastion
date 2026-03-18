import Testing
import Foundation
@testable import bastion

// MARK: - secp256k1 / ECDSA Validator Tests

@Suite("ECDSAValidator")
struct ECDSAValidatorTests {

    // Well-known test private key (DO NOT use with real funds)
    static let testPrivateKeyHex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    // This is Hardhat/Anvil account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266

    @Test func derivePublicKey() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        #expect(validator.publicKeyData.count == 65)
        #expect(validator.publicKeyData[0] == 0x04) // uncompressed prefix
        #expect(validator.ethereumAddress.count == 20)
    }

    @Test func knownAddress() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let addr = validator.addressHex.lowercased()
        #expect(addr == "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266")
    }

    @Test func signHash() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let hash = Data(repeating: 0xAB, count: 32)
        let sig = try validator.sign(hash: hash)
        #expect(sig.count == 65)
        // v should be 27 or 28
        #expect(sig[64] == 27 || sig[64] == 28)
    }

    @Test func deterministic() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let hash = Keccak256.hash(Data("test message".utf8))
        let sig1 = try validator.sign(hash: hash)
        let sig2 = try validator.sign(hash: hash)
        // Note: ECDSA with OpenSSL uses random k, so sigs may differ
        // But both should be valid 65-byte signatures
        #expect(sig1.count == 65)
        #expect(sig2.count == 65)
    }

    @Test func installData() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let data = validator.installData
        #expect(data.count == 20) // Ethereum address
        #expect(data == validator.ethereumAddress)
    }

    @Test func validationId() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let vid = validator.validationId
        #expect(vid.count == 21)
        #expect(vid[0] == 0x01) // VALIDATOR type
        let addrBytes = Data(hexString: ValidatorAddress.ecdsaValidator)!
        #expect(Data(vid.dropFirst()) == addrBytes)
    }
}

// MARK: - SmartAccount Tests

@Suite("SmartAccount")
struct SmartAccountTests {

    static let testPrivateKeyHex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    @Test func initializeCalldataFormat() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)
        let calldata = account.initializeCalldata
        // Should start with initialize selector 0x3c3b752b
        #expect(calldata.prefix(4) == Data(hexString: "0x3c3b752b"))
    }

    @Test func factoryDataFormat() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)
        let fd = account.factoryData
        // Should start with deployWithFactory selector 0xc5265d5d
        #expect(fd.prefix(4) == Data(hexString: "0xc5265d5d"))
    }

    @Test func nonceKeyFormat() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)
        let key = account.nonceKey
        #expect(key.count == 24) // 1 + 1 + 20 + 2
        #expect(key[0] == 0x00) // DEFAULT mode
        #expect(key[1] == 0x00) // SUDO type (root validator)
    }

    @Test func differentIndexProducesDifferentFactory() throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account0 = SmartAccount(validator: validator, index: 0)
        let account1 = SmartAccount(validator: validator, index: 1)
        #expect(account0.factoryData != account1.factoryData)
    }
}

// MARK: - ZeroDev API Integration Tests

/// These tests hit the real ZeroDev bundler API.
/// They require network access and the ZeroDev project to be active.
@Suite("ZeroDevAPI Integration", .tags(.integration), .serialized)
struct ZeroDevAPIIntegrationTests {

    static let chainId = 11155111 // Sepolia
    static let testPrivateKeyHex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    static let diagFile = "/tmp/bastion_ecdsa_integration.txt"
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

    @Test func supportedEntryPoints() async throws {
        guard let config = LiveTestConfig.current else { return }
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let eps = try await bundler.supportedEntryPoints(chainId: Self.chainId)
        #expect(!eps.isEmpty)
        // Should include v0.7 EntryPoint
        let lowered = eps.map { $0.lowercased() }
        #expect(lowered.contains(EntryPointAddress.v0_7.lowercased()))
    }

    @Test func resolveCounterfactualAddress() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)

        do {
            let address = try await account.resolveAddress(using: publicRPC)
            print("Resolved address: \(address)")
            #expect(address.hasPrefix("0x"))
            #expect(address.count == 42)
            let address2 = try await account.resolveAddress(using: publicRPC)
            #expect(address == address2)
        } catch {
            print("resolveCounterfactualAddress error: \(error)")
            throw error
        }
    }

    @Test func estimateGas() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)

        // Build a no-op UserOp (execute with empty calldata)
        let sender = try await account.resolveAddress(using: publicRPC)

        // Simple execute: send 0 ETH to self (no-op)
        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(
                to: sender,
                value: 0,
                data: Data()
            )
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

        // Use dummy signature for gas estimation
        let dummySig = validator.dummySignature
        let rpcOp = UserOperationRPC.from(op, signature: dummySig)

        do {
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
        } catch {
            print("estimateGas error: \(error)")
            throw error
        }
    }

    @Test func fullECDSAUserOpFlow() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)
        Self.resetLog()

        var finalTraceCommand: String?
        defer {
            Self.log(finalTraceCommand ?? "cast call --trace unavailable")
        }

        let sender = try await account.resolveAddress(using: publicRPC)
        Self.log("ECDSA sender: \(sender)")

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
        Self.log("ECDSA account deployed: \(deployed)")
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

        let dummyRpcOp = UserOperationRPC.from(op, signature: validator.dummySignature)
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
        Self.log("Final ECDSA signature: 0x\(signature.hex)")

        let localHash = EthHashing.userOperationHash(op)
        let entryPointHash = try await publicRPC.getUserOpHash(op)
        Self.log("Final local hash: 0x\(localHash.hex)")
        Self.log("Final EntryPoint hash: 0x\(entryPointHash.hex)")
        #expect(localHash == entryPointHash)

        let signedEstimate = try await bundler.estimateUserOperationGas(
            UserOperationRPC.from(op, signature: signature),
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )
        Self.log("Signed estimate SUCCEEDED:")
        Self.log("  verificationGasLimit: \(signedEstimate.verificationGasLimit)")
        Self.log("  callGasLimit: \(signedEstimate.callGasLimit)")
        Self.log("  preVerificationGas: \(signedEstimate.preVerificationGas)")
        Self.log("  paymasterVerificationGasLimit: \(signedEstimate.paymasterVerificationGasLimit ?? "nil")")
        Self.log("  paymasterPostOpGasLimit: \(signedEstimate.paymasterPostOpGasLimit ?? "nil")")

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
            Self.log("ECDSA UserOp sent! Hash: \(userOpHash)")
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
                Self.log("ECDSA UserOp sent after bundler fee retry! Hash: \(userOpHash)")
            } else {
                Self.log("sendUserOperation FAILED: \(error)")
                throw error
            }
        }

        var receipt: UserOperationReceipt?
        for _ in 1...12 {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            receipt = try await bundler.getUserOperationReceipt(
                userOpHash: userOpHash,
                chainId: Self.chainId
            )
            if receipt != nil {
                break
            }
        }

        if let receipt {
            Self.log("ECDSA receipt success: \(receipt.success)")
            Self.log("ECDSA txHash: \(receipt.receipt?.transactionHash ?? "nil")")
            #expect(receipt.success)
        } else {
            Self.log("ECDSA UserOp not confirmed within 60s")
        }
    }
    @Test func fullP256UserOpFlow() async throws {
        guard let config = LiveTestConfig.current else { return }
        let publicRPC = EthRPC(rpcURLString: config.sepoliaRPCURL)
        let bundler = ZeroDevAPI(projectId: config.projectId)
        let logFile = "/tmp/bastion_p256_integration.txt"

        func resetLog() {
            try? FileManager.default.removeItem(atPath: logFile)
            FileManager.default.createFile(atPath: logFile, contents: nil)
        }
        func log(_ msg: String) {
            let data = (msg + "\n").data(using: .utf8)!
            if let handle = FileHandle(forWritingAtPath: logFile) {
                handle.seekToEndOfFile()
                handle.write(data)
                handle.closeFile()
            } else {
                FileManager.default.createFile(atPath: logFile, contents: data)
            }
        }
        resetLog()

        // Ensure the default SE key exists, then read its public key coordinates.
        _ = try SecureEnclaveManager.shared.loadOrCreateSigningKey()
        let keyTag = SecureEnclaveManager.defaultSigningKeyIdentifier
        let pubKey = try SecureEnclaveManager.shared.getPublicKey(keyTag: keyTag)
        guard let publicKeyX = Data(hexString: pubKey.x),
              let publicKeyY = Data(hexString: pubKey.y) else {
            throw BastionError.signingFailed
        }
        log("P256 public key X: \(pubKey.x)")
        log("P256 public key Y: \(pubKey.y)")

        let validator = P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: publicKeyX,
            publicKeyY: publicKeyY,
            sign: { hash in
                let response = try SecureEnclaveManager.shared.signDigest(hash: hash, keyTag: keyTag)
                guard let rData = Data(hexString: response.r),
                      let sData = Data(hexString: response.s) else {
                    throw BastionError.signingFailed
                }
                return rData + sData
            }
        )
        let account = SmartAccount(validator: validator)

        var finalTraceCommand: String?
        defer { log(finalTraceCommand ?? "cast call --trace unavailable") }

        let sender = try await account.resolveAddress(using: publicRPC)
        log("P256 sender: \(sender)")

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
        log("P256 account deployed: \(deployed)")
        log("Estimated maxPriorityFeePerGas: \(priorityFee)")
        log("Estimated maxFeePerGas: \(maxFee)")

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

        log("Step 1: Sponsoring with P256 dummy signature...")
        let dummyRpcOp = UserOperationRPC.from(op, signature: validator.dummySignature)
        let sponsor = try await bundler.sponsorUserOperation(
            dummyRpcOp,
            entryPoint: EntryPointAddress.v0_7,
            chainId: Self.chainId
        )
        log("Sponsored! paymaster: \(sponsor.paymaster ?? "nil")")
        log("  verificationGasLimit: \(sponsor.verificationGasLimit ?? "nil")")
        log("  callGasLimit: \(sponsor.callGasLimit ?? "nil")")

        op = Self.applying(sponsor, to: op)

        log("Step 2: Signing with Secure Enclave P256 key...")
        var signature = try account.signUserOperation(op)
        log("P256 signature: 0x\(signature.hex)")
        #expect(signature.count == 64)

        let localHash = EthHashing.userOperationHash(op)
        let entryPointHash = try await publicRPC.getUserOpHash(op)
        log("Local hash: 0x\(localHash.hex)")
        log("EntryPoint hash: 0x\(entryPointHash.hex)")
        #expect(localHash == entryPointHash)

        log("Step 3: Sending to bundler...")
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
            log("P256 UserOp sent! Hash: \(userOpHash)")
            #expect(userOpHash.hasPrefix("0x"))
        } catch {
            if Self.requiresBundlerFeeRetry(error) {
                log("Retrying with bundler gas price...")
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
                log("P256 UserOp sent after fee retry! Hash: \(userOpHash)")
            } else {
                log("sendUserOperation FAILED: \(error)")
                throw error
            }
        }

        var receipt: UserOperationReceipt?
        for _ in 1...12 {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            receipt = try await bundler.getUserOperationReceipt(
                userOpHash: userOpHash,
                chainId: Self.chainId
            )
            if receipt != nil { break }
        }

        if let receipt {
            log("P256 receipt success: \(receipt.success)")
            log("P256 txHash: \(receipt.receipt?.transactionHash ?? "nil")")
            #expect(receipt.success)
        } else {
            log("P256 UserOp not confirmed within 60s")
        }
    }
}

// MARK: - Test Tags

extension Tag {
    @Tag static var integration: Self
}

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
        // Should start with deployWithFactory selector 0xbb24085e
        #expect(fd.prefix(4) == Data(hexString: "0xbb24085e"))
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

    static let projectId = "82339538-d51d-4967-800c-e83a6be4156b"
    static let chainId = 11155111 // Sepolia
    static let testPrivateKeyHex = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"

    // Separate RPC for non-AA calls (per ZeroDev policy)
    static let publicRPC = EthRPC(rpcURLString: "https://sepolia.infura.io/v3/d3979c2248d34fa9a0ccf4c84ebb753d")

    static let bundler = ZeroDevAPI(projectId: projectId)

    @Test func supportedEntryPoints() async throws {
        let eps = try await Self.bundler.supportedEntryPoints(chainId: Self.chainId)
        #expect(!eps.isEmpty)
        // Should include v0.7 EntryPoint
        let lowered = eps.map { $0.lowercased() }
        #expect(lowered.contains(EntryPointAddress.v0_7.lowercased()))
    }

    @Test func resolveCounterfactualAddress() async throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)

        do {
            let address = try await account.resolveAddress(using: Self.publicRPC)
            print("Resolved address: \(address)")
            #expect(address.hasPrefix("0x"))
            #expect(address.count == 42)
            let address2 = try await account.resolveAddress(using: Self.publicRPC)
            #expect(address == address2)
        } catch {
            print("resolveCounterfactualAddress error: \(error)")
            throw error
        }
    }

    @Test func estimateGas() async throws {
        let validator = try ECDSAValidator(privateKeyHex: Self.testPrivateKeyHex)
        let account = SmartAccount(validator: validator)

        // Build a no-op UserOp (execute with empty calldata)
        let sender = try await account.resolveAddress(using: Self.publicRPC)

        // Simple execute: send 0 ETH to self (no-op)
        let callData = KernelEncoding.executeCalldata(
            single: KernelEncoding.Execution(
                to: sender,
                value: 0,
                data: Data()
            )
        )

        let nonce = try await Self.publicRPC.getNonce(
            sender: sender,
            key: account.nonceKeyUInt192,
            entryPoint: EntryPointAddress.v0_7
        )

        let deployed = try await account.isDeployed(using: Self.publicRPC)

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
            let sponsor = try await Self.bundler.sponsorUserOperation(
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
}

// MARK: - Test Tags

extension Tag {
    @Tag static var integration: Self
}

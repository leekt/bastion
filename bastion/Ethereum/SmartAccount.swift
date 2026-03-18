import Foundation

// MARK: - Kernel v3.3 Smart Account

/// Manages a Kernel v3.3 smart account: address computation, init data, nonce encoding, signing.
nonisolated final class SmartAccount: Sendable {
    let validator: any KernelValidator
    let entryPointVersion: EntryPointVersion
    let index: UInt64

    /// Computed counterfactual address (set after calling `computeAddress`).
    private let _address: LockIsolated<String?>

    var address: String? { _address.value }

    init(
        validator: any KernelValidator,
        entryPointVersion: EntryPointVersion = .v0_7,
        index: UInt64 = 0
    ) {
        self.validator = validator
        self.entryPointVersion = entryPointVersion
        self.index = index
        self._address = LockIsolated(nil)
    }

    // MARK: - Factory Data (for account deployment)

    /// Encode the MetaFactory `deployWithFactory(factory, createData, salt)` calldata.
    /// This is the `factoryData` field in the UserOperation for first-time deployment.
    var factoryData: Data {
        let selector = Data(hexString: "0xc5265d5d")! // deployWithFactory(address,bytes,uint256)
        let factoryAddr = Data(hexString: KernelAddress.factory)!
        let createData = initializeCalldata
        let salt = uint256(index)

        // ABI encode: deployWithFactory(address factory, bytes createData, bytes32 salt)
        var params = Data()
        // factory address (padded to 32)
        params += leftPad(factoryAddr, to: 32)
        // offset to createData (3 * 32 = 96)
        params += uint256(96)
        // salt
        params += salt
        // createData length
        params += uint256(UInt64(createData.count))
        // createData bytes
        params += createData
        // pad to 32-byte boundary
        let padding = (32 - createData.count % 32) % 32
        if padding > 0 {
            params += Data(repeating: 0, count: padding)
        }

        return selector + params
    }

    /// The Kernel `initialize(bytes21, address, bytes, bytes, bytes[])` calldata.
    var initializeCalldata: Data {
        let selector = Data(hexString: "0x3c3b752b")! // initialize(bytes21,address,bytes,bytes,bytes[])
        let validationId = validator.validationId // 21 bytes
        let hook = Data(repeating: 0, count: 20) // address(0) = no hook
        let validatorData = validator.installData
        let hookData = Data()
        let initConfig: [Data] = []

        // ABI encode the initialize call
        var params = Data()
        // bytes21 validationId — right-padded to 32
        var vidPadded = validationId
        vidPadded += Data(repeating: 0, count: 32 - validationId.count)
        params += vidPadded
        // address hook — left-padded to 32
        params += leftPad(hook, to: 32)
        // offset to validatorData (dynamic — 5 slots * 32 = 160)
        params += uint256(160)
        // offset to hookData
        let validatorDataSlots = 1 + ceilDiv(validatorData.count, 32)
        let hookDataOffset = 160 + UInt64(validatorDataSlots * 32)
        params += uint256(hookDataOffset)
        // offset to initConfig
        let hookDataSlots = 1 + ceilDiv(hookData.count, 32)
        let initConfigOffset = hookDataOffset + UInt64(hookDataSlots * 32)
        params += uint256(initConfigOffset)
        // validatorData (bytes)
        params += uint256(UInt64(validatorData.count))
        params += validatorData
        params += Data(repeating: 0, count: (32 - validatorData.count % 32) % 32)
        // hookData (bytes)
        params += uint256(UInt64(hookData.count))
        params += hookData
        params += Data(repeating: 0, count: (32 - hookData.count % 32) % 32)
        // initConfig (bytes[]) — empty array
        params += uint256(UInt64(initConfig.count))

        return selector + params
    }

    // MARK: - Nonce Key Encoding

    /// Encode the nonce key for Kernel v3.3.
    /// Format: mode(1B) + validationType(1B) + validatorAddress(20B) + nonceKey(2B)
    /// For root validator in default mode: `0x00 + 0x00 + validatorAddr + 0x0000`
    var nonceKey: Data {
        var key = Data()
        key += Data([0x00]) // VALIDATION_MODE.DEFAULT
        key += Data([0x00]) // VALIDATION_TYPE.SUDO (root validator)
        key += Data(hexString: validator.validatorAddress) ?? Data(repeating: 0, count: 20)
        key += Data([0x00, 0x00]) // nonceKey = 0
        return key
    }

    /// Get the nonce key as a uint192 for the EntryPoint `getNonce(address, uint192)` call.
    var nonceKeyUInt192: String {
        "0x" + nonceKey.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Address Resolution

    /// Compute the counterfactual address using CREATE2.
    /// `address = keccak256(0xff || factory || actualSalt || initCodeHash)[12:]`
    /// `actualSalt = keccak256(abi.encodePacked(createData, userSalt))`
    func computeAddress() -> String {
        if let existing = _address.value { return existing }

        let createData = initializeCalldata
        let userSalt = uint256(index)

        // actualSalt = keccak256(createData || userSalt)
        let actualSalt = Keccak256.hash(createData + userSalt)

        let factory = Data(hexString: KernelAddress.factory)!
        let initCodeHash = Data(hexString: KernelV3_3.initCodeHash)!

        // CREATE2: keccak256(0xff || factory || actualSalt || initCodeHash)
        var preimage = Data([0xff])
        preimage += factory
        preimage += actualSalt
        preimage += initCodeHash
        let hash = Keccak256.hash(preimage)

        // Address = last 20 bytes
        let addrBytes = hash.suffix(20)
        let addr = "0x" + addrBytes.map { String(format: "%02x", $0) }.joined()
        _address.setValue(addr)
        return addr
    }

    /// Resolve address (computes locally, no RPC needed).
    func resolveAddress(using rpc: EthRPC) async throws -> String {
        computeAddress()
    }

    /// Set address directly (e.g. if already known).
    func setAddress(_ addr: String) {
        _address.setValue(addr)
    }

    // MARK: - Account Deployment Check

    /// Check if the account is already deployed on-chain.
    func isDeployed(using rpc: EthRPC) async throws -> Bool {
        guard let addr = address else { return false }
        let code = try await rpc.getCode(address: addr)
        return code != "0x" && code != "0x0" && !code.isEmpty
    }

    // MARK: - Build UserOperation

    /// Build a UserOperation for this account.
    func buildUserOperation(
        callData: Data,
        using rpc: EthRPC,
        bundler: ZeroDevAPI,
        chainId: Int
    ) async throws -> UserOperation {
        let sender = try await resolveAddress(using: rpc)
        let deployed = try await isDeployed(using: rpc)

        // Get nonce from EntryPoint
        let nonce = try await rpc.getNonce(
            sender: sender,
            key: nonceKeyUInt192,
            entryPoint: EntryPointAddress.address(for: entryPointVersion)
        )
        let fees = try await rpc.estimateUserOperationFeesPerGas()

        let op = UserOperation(
            sender: sender,
            nonce: nonce,
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
            maxFeePerGas: fees.maxFeePerGas,
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: chainId,
            entryPoint: EntryPointAddress.address(for: entryPointVersion),
            entryPointVersion: entryPointVersion
        )

        return op
    }

    /// Build a sponsored no-op UserOperation that executes a 0 ETH self-call.
    /// Used to generate a valid current-account request for approval/send flows.
    func buildSponsoredUserOperation(
        callData: Data,
        using rpc: EthRPC,
        bundler: ZeroDevAPI,
        chainId: Int
    ) async throws -> UserOperation {
        let sender = try await resolveAddress(using: rpc)
        let deployed = try await isDeployed(using: rpc)
        let gasPrice = try await bundler.userOperationGasPrice(chainId: chainId)

        var op = UserOperation(
            sender: sender,
            nonce: try await rpc.getNonce(
                sender: sender,
                key: nonceKeyUInt192,
                entryPoint: EntryPointAddress.address(for: entryPointVersion)
            ),
            callData: callData,
            factory: deployed ? nil : KernelAddress.metaFactory,
            factoryData: deployed ? nil : factoryData,
            verificationGasLimit: "0x0",
            callGasLimit: "0x0",
            preVerificationGas: "0x0",
            maxPriorityFeePerGas: gasPrice.standard.maxPriorityFeePerGas,
            maxFeePerGas: gasPrice.standard.maxFeePerGas,
            paymaster: nil,
            paymasterVerificationGasLimit: nil,
            paymasterPostOpGasLimit: nil,
            paymasterData: nil,
            chainId: chainId,
            entryPoint: EntryPointAddress.address(for: entryPointVersion),
            entryPointVersion: entryPointVersion
        )

        let sponsor = try await bundler.sponsorUserOperation(
            UserOperationRPC.from(op, signature: validator.dummySignature),
            entryPoint: op.entryPoint,
            chainId: chainId
        )
        op = Self.applying(sponsor, to: op)
        return op
    }

    /// Sign a UserOperation hash with this account's validator.
    func signUserOperation(_ op: UserOperation) throws -> Data {
        let hash = EthHashing.userOperationHash(op)
        return try validator.sign(hash: hash)
    }

    // MARK: - Helpers

    private func leftPad(_ data: Data, to size: Int) -> Data {
        if data.count >= size { return Data(data.prefix(size)) }
        return Data(repeating: 0, count: size - data.count) + data
    }

    private func uint256(_ value: UInt64) -> Data {
        var result = Data(repeating: 0, count: 32)
        var v = value
        for i in stride(from: 31, through: 24, by: -1) {
            result[i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return result
    }

    private func ceilDiv(_ a: Int, _ b: Int) -> Int {
        (a + b - 1) / b
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
}

// MARK: - Thread-safe wrapper

nonisolated final class LockIsolated<T>: @unchecked Sendable {
    private var _value: T
    private let lock = NSLock()

    init(_ value: T) { _value = value }

    var value: T {
        lock.lock()
        defer { lock.unlock() }
        return _value
    }

    func setValue(_ newValue: T) {
        lock.lock()
        defer { lock.unlock() }
        _value = newValue
    }
}

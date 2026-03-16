import Foundation

// MARK: - Ethereum Hashing

/// Computes Ethereum-specific hashes for the three signing operation types.
/// Each produces a 32-byte keccak256 hash that will be fed to the Secure Enclave for P-256 signing.
nonisolated enum EthHashing {

    // MARK: - EIP-191: Personal Message Signing

    /// Computes `keccak256("\x19Ethereum Signed Message:\n{len}" || message)`.
    static func personalMessageHash(_ message: String) -> Data {
        let messageBytes = Data(message.utf8)
        let prefix = "\u{19}Ethereum Signed Message:\n\(messageBytes.count)"
        let prefixBytes = Data(prefix.utf8)
        return Keccak256.hash(prefixBytes + messageBytes)
    }

    /// Same as above but for raw bytes (hex input).
    static func personalMessageHash(data: Data) -> Data {
        let prefix = "\u{19}Ethereum Signed Message:\n\(data.count)"
        let prefixBytes = Data(prefix.utf8)
        return Keccak256.hash(prefixBytes + data)
    }

    // MARK: - EIP-712: Typed Structured Data Signing

    /// Computes `keccak256("\x19\x01" || domainSeparator || structHash)`.
    static func typedDataHash(_ typedData: EIP712TypedData) -> Data {
        let domainSeparator = hashStruct("EIP712Domain", data: domainValues(typedData.domain), types: typedData.types)
        let structHash = hashStruct(typedData.primaryType, data: typedData.message, types: typedData.types)
        return Keccak256.hash(Data([0x19, 0x01]) + domainSeparator + structHash)
    }

    // MARK: - ERC-4337: UserOperation Hash

    /// Computes the UserOperation hash as defined by the EntryPoint contract.
    ///
    /// **v0.7**: `keccak256(abi.encode(packHash, entryPoint, chainId))`
    ///   - packHash = `keccak256(abi.encode(sender, nonce, keccak256(initCode), ...))`
    ///
    /// **v0.8+**: ERC-712 typed data hash
    ///   - `keccak256("\x19\x01" || domainSeparator || structHash)`
    ///   - structHash = `keccak256(abi.encode(PACKED_USEROP_TYPEHASH, sender, nonce, ...))`
    ///   - domainSeparator uses name="ERC4337", version="1", chainId, verifyingContract=entryPoint
    static func userOperationHash(_ op: UserOperation) -> Data {
        switch op.entryPointVersion {
        case .v0_7:
            return userOpHashV07(op)
        case .v0_8, .v0_9:
            return userOpHashV08(op)
        }
    }

    // MARK: - v0.7 Hash

    /// v0.7: `keccak256(abi.encode(keccak256(pack(userOp)), entryPoint, chainId))`
    private static func userOpHashV07(_ op: UserOperation) -> Data {
        let innerHash = packHashInner(op, includeTypeHash: false)

        var encoded = Data()
        encoded += abiEncode(innerHash)
        encoded += abiEncodeAddress(op.entryPoint)
        encoded += abiEncodeUInt256(UInt64(op.chainId))
        return Keccak256.hash(encoded)
    }

    // MARK: - v0.8+ Hash (ERC-712)

    /// PACKED_USEROP_TYPEHASH for v0.8+ EntryPoint
    private static let packedUserOpTypeHash: Data = Keccak256.hash(Data(
        "PackedUserOperation(address sender,uint256 nonce,bytes initCode,bytes callData,bytes32 accountGasLimits,uint256 preVerificationGas,bytes32 gasFees,bytes paymasterAndData)".utf8
    ))

    /// EIP712Domain typehash
    private static let eip712DomainTypeHash: Data = Keccak256.hash(Data(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)".utf8
    ))

    /// v0.8+: `keccak256("\x19\x01" || domainSeparator || structHash)`
    private static func userOpHashV08(_ op: UserOperation) -> Data {
        // Domain separator: keccak256(abi.encode(domainTypeHash, keccak256("ERC4337"), keccak256("1"), chainId, entryPoint))
        var domainData = Data()
        domainData += eip712DomainTypeHash
        domainData += Keccak256.hash(Data("ERC4337".utf8))
        domainData += Keccak256.hash(Data("1".utf8))
        domainData += abiEncodeUInt256(UInt64(op.chainId))
        domainData += abiEncodeAddress(op.entryPoint)
        let domainSeparator = Keccak256.hash(domainData)

        let structHash = packHashInner(op, includeTypeHash: true)

        return Keccak256.hash(Data([0x19, 0x01]) + domainSeparator + structHash)
    }

    // MARK: - Shared Pack Hash

    /// Compute keccak256 of the packed UserOp fields.
    /// For v0.7: no type hash prefix in the abi.encode
    /// For v0.8+: includes PACKED_USEROP_TYPEHASH as first element
    private static func packHashInner(_ op: UserOperation, includeTypeHash: Bool) -> Data {
        // Build initCode: factory + factoryData (empty if no factory)
        var initCode = Data()
        if let factory = op.factory {
            initCode += hexToBytes(factory)
            initCode += op.factoryData ?? Data()
        }

        // Build accountGasLimits: bytes32 = verificationGasLimit (uint128) || callGasLimit (uint128)
        let accountGasLimits = packTwo128(op.verificationGasLimit, op.callGasLimit)

        // Build gasFees: bytes32 = maxPriorityFeePerGas (uint128) || maxFeePerGas (uint128)
        let gasFees = packTwo128(op.maxPriorityFeePerGas, op.maxFeePerGas)

        // Build paymasterAndData: paymaster + paymasterVerificationGasLimit + paymasterPostOpGasLimit + paymasterData
        var paymasterAndData = Data()
        if let paymaster = op.paymaster {
            paymasterAndData += hexToBytes(paymaster)
            paymasterAndData += padUInt128(op.paymasterVerificationGasLimit ?? "0x0")
            paymasterAndData += padUInt128(op.paymasterPostOpGasLimit ?? "0x0")
            paymasterAndData += op.paymasterData ?? Data()
        }

        var packed = Data()
        if includeTypeHash {
            packed += packedUserOpTypeHash
        }
        packed += abiEncodeAddress(op.sender)
        packed += abiEncodeUInt256FromHex(op.nonce)
        packed += abiEncode(Keccak256.hash(initCode))
        packed += abiEncode(Keccak256.hash(op.callData))
        packed += accountGasLimits                              // bytes32 raw
        packed += abiEncodeUInt256FromHex(op.preVerificationGas)
        packed += gasFees                                       // bytes32 raw
        packed += abiEncode(Keccak256.hash(paymasterAndData))
        return Keccak256.hash(packed)
    }

    // MARK: - ABI Encoding Helpers

    /// Left-pad data to 32 bytes.
    private static func abiEncode(_ data: Data) -> Data {
        if data.count >= 32 { return Data(data.prefix(32)) }
        return Data(repeating: 0, count: 32 - data.count) + data
    }

    /// ABI-encode an address (20 bytes, left-padded to 32).
    private static func abiEncodeAddress(_ address: String) -> Data {
        let bytes = hexToBytes(address)
        if bytes.count >= 32 { return Data(bytes.prefix(32)) }
        return Data(repeating: 0, count: 32 - bytes.count) + bytes
    }

    /// ABI-encode a UInt64 as uint256.
    private static func abiEncodeUInt256(_ value: UInt64) -> Data {
        var result = Data(repeating: 0, count: 32)
        var v = value
        for i in stride(from: 31, through: 24, by: -1) {
            result[i] = UInt8(v & 0xFF)
            v >>= 8
        }
        return result
    }

    /// ABI-encode a hex string as uint256 (left-padded to 32 bytes).
    private static func abiEncodeUInt256FromHex(_ hex: String) -> Data {
        let bytes = hexToBytes(hex)
        if bytes.isEmpty { return Data(repeating: 0, count: 32) }
        if bytes.count >= 32 { return Data(bytes.prefix(32)) }
        return Data(repeating: 0, count: 32 - bytes.count) + bytes
    }

    /// Pack two uint128 hex values into a single bytes32: high || low.
    private static func packTwo128(_ high: String, _ low: String) -> Data {
        padUInt128(high) + padUInt128(low)
    }

    /// Left-pad a hex value to exactly 16 bytes (uint128).
    private static func padUInt128(_ hex: String) -> Data {
        let bytes = hexToBytes(hex)
        if bytes.isEmpty { return Data(repeating: 0, count: 16) }
        if bytes.count >= 16 { return Data(bytes.prefix(16)) }
        return Data(repeating: 0, count: 16 - bytes.count) + bytes
    }

    /// Convert hex string (with or without 0x) to raw bytes.
    private static func hexToBytes(_ hex: String) -> Data {
        Data(hexString: hex) ?? Data()
    }

    // MARK: - EIP-712 Helpers

    private static func domainValues(_ domain: EIP712Domain) -> [String: AnyCodable] {
        var values = [String: AnyCodable]()
        if let name = domain.name { values["name"] = AnyCodable(name) }
        if let version = domain.version { values["version"] = AnyCodable(version) }
        if let chainId = domain.chainId { values["chainId"] = AnyCodable(chainId) }
        if let contract = domain.verifyingContract { values["verifyingContract"] = AnyCodable(contract) }
        if let salt = domain.salt { values["salt"] = AnyCodable(salt) }
        return values
    }

    /// `hashStruct(T) = keccak256(typeHash(T) || encodeData(T))`
    private static func hashStruct(_ typeName: String, data: [String: AnyCodable], types: [String: [EIP712Field]]) -> Data {
        let typeHash = encodeType(typeName, types: types)
        let encodedData = encodeData(typeName, data: data, types: types)
        return Keccak256.hash(typeHash + encodedData)
    }

    /// `typeHash(T) = keccak256(encodeType(T))`
    private static func encodeType(_ typeName: String, types: [String: [EIP712Field]]) -> Data {
        guard let fields = types[typeName] else { return Data() }
        var deps = Set<String>()
        collectDeps(typeName, types: types, deps: &deps)
        deps.remove(typeName)

        var typeString = formatType(typeName, fields: fields)
        for dep in deps.sorted() {
            if let depFields = types[dep] {
                typeString += formatType(dep, fields: depFields)
            }
        }
        return Keccak256.hash(Data(typeString.utf8))
    }

    private static func formatType(_ name: String, fields: [EIP712Field]) -> String {
        let params = fields.map { "\($0.type) \($0.name)" }.joined(separator: ",")
        return "\(name)(\(params))"
    }

    private static func collectDeps(_ typeName: String, types: [String: [EIP712Field]], deps: inout Set<String>) {
        guard !deps.contains(typeName), let fields = types[typeName] else { return }
        deps.insert(typeName)
        for field in fields {
            let baseType = field.type.replacingOccurrences(of: "[]", with: "")
            if types[baseType] != nil {
                collectDeps(baseType, types: types, deps: &deps)
            }
        }
    }

    private static func encodeData(_ typeName: String, data: [String: AnyCodable], types: [String: [EIP712Field]]) -> Data {
        guard let fields = types[typeName] else { return Data() }
        var encoded = Data()
        for field in fields {
            let value = data[field.name]
            encoded += encodeField(field.type, value: value, types: types)
        }
        return encoded
    }

    private static func encodeField(_ type: String, value: AnyCodable?, types: [String: [EIP712Field]]) -> Data {
        guard let value = value else {
            return Data(repeating: 0, count: 32)
        }

        if type == "string" {
            if let str = value.value as? String {
                return Keccak256.hash(Data(str.utf8))
            }
            return Data(repeating: 0, count: 32)
        }
        if type == "bytes" {
            if let str = value.value as? String, let data = Data(hexString: str) {
                return Keccak256.hash(data)
            }
            return Data(repeating: 0, count: 32)
        }

        if type.hasSuffix("[]") {
            let baseType = String(type.dropLast(2))
            if let arr = value.value as? [Any] {
                var encoded = Data()
                for item in arr {
                    encoded += encodeField(baseType, value: AnyCodable(item), types: types)
                }
                return Keccak256.hash(encoded)
            }
            return Keccak256.hash(Data())
        }

        if types[type] != nil {
            if let dict = value.value as? [String: Any] {
                let codableDict = dict.mapValues { AnyCodable($0) }
                return hashStruct(type, data: codableDict, types: types)
            }
            return Data(repeating: 0, count: 32)
        }

        return encodeAtomic(type, value: value)
    }

    private static func encodeAtomic(_ type: String, value: AnyCodable) -> Data {
        var result = Data(repeating: 0, count: 32)

        if type == "address" {
            if let str = value.value as? String {
                let clean = str.hasPrefix("0x") ? String(str.dropFirst(2)) : str
                if let bytes = Data(hexString: "0x" + clean), bytes.count == 20 {
                    result.replaceSubrange(12..<32, with: bytes)
                }
            }
            return result
        }

        if type == "bool" {
            if let b = value.value as? Bool, b {
                result[31] = 1
            } else if let n = value.value as? Int, n != 0 {
                result[31] = 1
            }
            return result
        }

        if type.hasPrefix("uint") || type.hasPrefix("int") {
            if let n = value.value as? Int {
                var v = UInt64(bitPattern: Int64(n))
                for i in stride(from: 31, through: 24, by: -1) {
                    result[i] = UInt8(v & 0xFF)
                    v >>= 8
                }
            } else if let str = value.value as? String {
                let clean = str.hasPrefix("0x") ? String(str.dropFirst(2)) : str
                if let data = Data(hexString: "0x" + clean) {
                    let start = 32 - data.count
                    if start >= 0 {
                        result.replaceSubrange(start..<32, with: data)
                    }
                } else if let n = UInt128(str) {
                    var v = n
                    for i in stride(from: 31, through: 0, by: -1) {
                        result[i] = UInt8(truncatingIfNeeded: v & 0xFF)
                        v >>= 8
                        if v == 0 { break }
                    }
                }
            }
            return result
        }

        if type.hasPrefix("bytes") && type != "bytes" {
            if let str = value.value as? String, let data = Data(hexString: str) {
                let len = min(data.count, 32)
                result.replaceSubrange(0..<len, with: data.prefix(len))
            }
            return result
        }

        return result
    }
}

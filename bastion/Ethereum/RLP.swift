import Foundation

// MARK: - RLP Encoding

/// Recursive Length Prefix encoding used by Ethereum for transaction serialization.
/// Spec: https://ethereum.org/en/developers/docs/data-structures-and-encoding/rlp/
nonisolated enum RLP {

    /// RLP-encodable item: either raw bytes or a list of items.
    enum Item {
        case bytes(Data)
        case list([Item])
    }

    static func encode(_ item: Item) -> Data {
        switch item {
        case .bytes(let data):
            return encodeBytes(data)
        case .list(let items):
            let payload = items.reduce(Data()) { $0 + encode($1) }
            return encodeLength(payload.count, offset: 0xC0) + payload
        }
    }

    // MARK: - Convenience Encoders

    /// Encode a list of items.
    static func encodeList(_ items: [Item]) -> Data {
        encode(.list(items))
    }

    /// Encode raw bytes.
    static func encode(_ data: Data) -> Data {
        encode(.bytes(data))
    }

    /// Encode a UInt as big-endian bytes (no leading zeros).
    static func encode(_ value: UInt64) -> Data {
        if value == 0 {
            return encode(.bytes(Data()))
        }
        return encode(.bytes(bigEndian(value)))
    }

    /// Encode a decimal string as big-endian unsigned integer bytes.
    static func encodeDecimalString(_ decimal: String) -> Data {
        guard let value = UInt128(decimal), value > 0 else {
            return encode(.bytes(Data()))
        }
        return encode(.bytes(bigEndianUInt128(value)))
    }

    /// Encode a hex string (with or without 0x prefix) as bytes.
    static func encodeHex(_ hex: String) -> Data {
        let clean = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        if clean.isEmpty {
            return encode(.bytes(Data()))
        }
        guard let data = Data(hexString: "0x" + clean) else {
            return encode(.bytes(Data()))
        }
        return encode(.bytes(data))
    }

    /// Encode an Ethereum address (20 bytes from hex).
    static func encodeAddress(_ address: String) -> Data {
        let clean = address.hasPrefix("0x") ? String(address.dropFirst(2)) : address
        guard clean.count == 40, let data = Data(hexString: "0x" + clean) else {
            return encode(.bytes(Data()))
        }
        return encode(.bytes(data))
    }

    // MARK: - Private

    private static func encodeBytes(_ data: Data) -> Data {
        if data.count == 1 && data[0] < 0x80 {
            return data
        }
        return encodeLength(data.count, offset: 0x80) + data
    }

    private static func encodeLength(_ length: Int, offset: UInt8) -> Data {
        if length < 56 {
            return Data([offset + UInt8(length)])
        }
        let lenBytes = bigEndian(UInt64(length))
        return Data([offset + 55 + UInt8(lenBytes.count)]) + lenBytes
    }

    /// Convert UInt64 to big-endian bytes with no leading zeros.
    private static func bigEndian(_ value: UInt64) -> Data {
        var v = value
        var bytes = [UInt8]()
        while v > 0 {
            bytes.insert(UInt8(v & 0xFF), at: 0)
            v >>= 8
        }
        return Data(bytes)
    }

    /// Convert UInt128 to big-endian bytes with no leading zeros.
    private static func bigEndianUInt128(_ value: UInt128) -> Data {
        var v = value
        var bytes = [UInt8]()
        while v > 0 {
            bytes.insert(UInt8(truncatingIfNeeded: v & 0xFF), at: 0)
            v >>= 8
        }
        return Data(bytes)
    }
}

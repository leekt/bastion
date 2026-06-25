import Foundation

// PR5: Classifier for permit-style typed-data signatures.
//
// EIP-712 typed-data is the most dangerous shape Bastion signs because
// the user-visible blob looks innocuous ("just a structured message")
// but can grant on-chain spending or execution authority. Three
// shapes matter today:
//
// 1. ERC-2612 Permit — `primaryType: "Permit"` on an ERC-20 token's
//    EIP-712 domain. Sets `allowance(owner, spender) = value` until
//    `deadline`. The spender then calls `transferFrom` whenever it
//    wants. Single signature → unbounded later transfers.
// 2. Uniswap Permit2 — verifyingContract is the canonical Permit2
//    address (0x000000000022D473030F116dDEE9F6B43aC78BA3). Three
//    sub-types:
//    - `PermitSingle` / `PermitBatch` set up an off-chain allowance
//    - `PermitTransferFrom` / `PermitBatchTransferFrom` execute a
//      one-shot transfer authorized by the signature.
// 3. ERC-7702 set-code — typed-data domain "Authorization", grants
//    delegate authority to a contract for a one-shot or persistent
//    code-set. Treated as an even higher risk because it can install
//    arbitrary code on the signer's EOA.
//
// The classifier is pure: it inspects shape + verifyingContract +
// primaryType + field names and returns a typed `Classification`. No
// network, no actor state. Used by the approval UI to render an
// extra-loud warning with spender/amount/expiry callouts so the user
// understands what they're actually signing.

/// Canonical Uniswap Permit2 address — same on every chain Permit2 is
/// deployed to. Comparisons are case-insensitive.
nonisolated let permit2CanonicalAddress = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

nonisolated enum PermitClassification: Sendable, Equatable {

    /// ERC-2612 permit on an ERC-20 token. `token` is the verifyingContract
    /// (the token itself). `amount` is decimal-as-string preserving
    /// uint256 precision; UI formats per token decimals.
    case erc2612(spender: String, amount: String, deadline: String, token: String?)

    /// Uniswap Permit2 — single-token allowance grant.
    case permit2Single(token: String, spender: String, amount: String, expiration: String, nonce: String)

    /// Uniswap Permit2 — batch allowance grant. Token list parallel to amounts.
    case permit2Batch(spender: String, tokens: [String], amounts: [String], expiration: String)

    /// Uniswap Permit2 — single-shot transfer authorization.
    case permit2TransferFrom(token: String, spender: String, amount: String, deadline: String)

    /// Uniswap Permit2 — batch single-shot transfer authorization.
    case permit2BatchTransferFrom(tokens: [String], amounts: [String], spender: String, deadline: String)

    /// ERC-7702 authorization — installs delegate code on signer's EOA.
    case erc7702Delegation(delegate: String, chainId: String, nonce: String)

    /// Short, human-facing label for headlines / chips.
    var label: String {
        switch self {
        case .erc2612: return "ERC-2612 Permit"
        case .permit2Single: return "Permit2 — single allowance"
        case .permit2Batch: return "Permit2 — batch allowance"
        case .permit2TransferFrom: return "Permit2 — transfer authorization"
        case .permit2BatchTransferFrom: return "Permit2 — batch transfer authorization"
        case .erc7702Delegation: return "ERC-7702 delegation"
        }
    }

    /// True for shapes that grant lasting (off-chain) spending power. The
    /// approval UI uses this to escalate the warning level above the
    /// already-cautious "you're signing typed data" baseline.
    var grantsLastingAllowance: Bool {
        switch self {
        case .erc2612, .permit2Single, .permit2Batch, .erc7702Delegation:
            return true
        case .permit2TransferFrom, .permit2BatchTransferFrom:
            // One-shot — still risky but not lasting.
            return false
        }
    }
}

nonisolated enum PermitClassifier {

    /// Returns a non-nil classification when the typed-data matches one
    /// of the dangerous shapes above. Returns nil for anything else —
    /// the UI then falls back to its generic typed-data rendering.
    static func classify(_ typed: EIP712TypedData) -> PermitClassification? {
        if let result = classifyERC2612(typed) { return result }
        if let result = classifyPermit2(typed) { return result }
        if let result = classifyERC7702(typed) { return result }
        return nil
    }

    // MARK: - ERC-2612 Permit

    private static func classifyERC2612(_ typed: EIP712TypedData) -> PermitClassification? {
        guard typed.primaryType == "Permit" else { return nil }
        guard let permitFields = typed.types["Permit"] else { return nil }
        let fieldNames = Set(permitFields.map(\.name))
        // Canonical ERC-2612 Permit has exactly these five fields.
        guard fieldNames == ["owner", "spender", "value", "nonce", "deadline"] else { return nil }
        // If the verifyingContract is the canonical Permit2 address,
        // route to the Permit2 classifier instead — the preview fixture
        // uses this shape even though it's technically a misnomer.
        if isPermit2VerifyingContract(typed.domain.verifyingContract) {
            return nil
        }
        guard let spender = stringValue(typed.message["spender"]),
              let amount = stringValue(typed.message["value"]),
              let deadline = stringValue(typed.message["deadline"]) else {
            return nil
        }
        return .erc2612(
            spender: spender,
            amount: amount,
            deadline: deadline,
            token: typed.domain.verifyingContract
        )
    }

    // MARK: - Permit2

    private static func classifyPermit2(_ typed: EIP712TypedData) -> PermitClassification? {
        guard isPermit2VerifyingContract(typed.domain.verifyingContract) else { return nil }

        switch typed.primaryType {
        case "PermitSingle":
            return classifyPermit2Single(typed)
        case "PermitBatch":
            return classifyPermit2Batch(typed)
        case "PermitTransferFrom":
            return classifyPermit2TransferFrom(typed)
        case "PermitBatchTransferFrom":
            return classifyPermit2BatchTransferFrom(typed)
        case "Permit":
            // Some implementations route through the bare "Permit"
            // primaryType but on the Permit2 contract. Treat as Single
            // if the field shape matches.
            if let result = classifyPermit2SingleFromBarePermit(typed) {
                return result
            }
            return nil
        default:
            return nil
        }
    }

    private static func classifyPermit2Single(_ typed: EIP712TypedData) -> PermitClassification? {
        // PermitSingle wraps a PermitDetails struct — pull the inner fields.
        guard let details = nested(typed.message["details"]),
              let token = stringValue(any: details["token"]),
              let amount = stringValue(any: details["amount"]),
              let expiration = stringValue(any: details["expiration"]),
              let nonce = stringValue(any: details["nonce"]),
              let spender = stringValue(typed.message["spender"]) else {
            return nil
        }
        return .permit2Single(
            token: token,
            spender: spender,
            amount: amount,
            expiration: expiration,
            nonce: nonce
        )
    }

    private static func classifyPermit2SingleFromBarePermit(_ typed: EIP712TypedData) -> PermitClassification? {
        guard let permitFields = typed.types["Permit"] else { return nil }
        let fieldNames = Set(permitFields.map(\.name))
        guard fieldNames == ["owner", "spender", "value", "nonce", "deadline"] else { return nil }
        guard let spender = stringValue(typed.message["spender"]),
              let amount = stringValue(typed.message["value"]),
              let deadline = stringValue(typed.message["deadline"]),
              let nonce = stringValue(typed.message["nonce"]) else {
            return nil
        }
        // Bare-Permit-on-Permit2 doesn't carry a token field; surface as
        // Permit2 Single with the verifying contract as the token slot
        // (so the UI can still render a coherent Spender row).
        return .permit2Single(
            token: typed.domain.verifyingContract ?? "",
            spender: spender,
            amount: amount,
            expiration: deadline,
            nonce: nonce
        )
    }

    private static func classifyPermit2Batch(_ typed: EIP712TypedData) -> PermitClassification? {
        guard let detailsArray = arrayValue(typed.message["details"]) else { return nil }
        var tokens: [String] = []
        var amounts: [String] = []
        var expirations: [String] = []
        for entry in detailsArray {
            guard let dict = entry as? [String: Any],
                  let token = stringValue(any: dict["token"]),
                  let amount = stringValue(any: dict["amount"]),
                  let expiration = stringValue(any: dict["expiration"]) else {
                continue
            }
            tokens.append(token)
            amounts.append(amount)
            expirations.append(expiration)
        }
        guard !tokens.isEmpty,
              let spender = stringValue(typed.message["spender"]) else {
            return nil
        }
        // Use the earliest expiration so the UI shows the worst case
        // (the user is committed at least until then).
        let earliest = expirations.compactMap(UInt64.init).min().map(String.init) ?? expirations.first ?? ""
        return .permit2Batch(spender: spender, tokens: tokens, amounts: amounts, expiration: earliest)
    }

    private static func classifyPermit2TransferFrom(_ typed: EIP712TypedData) -> PermitClassification? {
        guard let permitted = nested(typed.message["permitted"]),
              let token = stringValue(any: permitted["token"]),
              let amount = stringValue(any: permitted["amount"]),
              let spender = stringValue(typed.message["spender"]),
              let deadline = stringValue(typed.message["deadline"]) else {
            return nil
        }
        return .permit2TransferFrom(token: token, spender: spender, amount: amount, deadline: deadline)
    }

    private static func classifyPermit2BatchTransferFrom(_ typed: EIP712TypedData) -> PermitClassification? {
        guard let permitted = arrayValue(typed.message["permitted"]),
              let spender = stringValue(typed.message["spender"]),
              let deadline = stringValue(typed.message["deadline"]) else {
            return nil
        }
        var tokens: [String] = []
        var amounts: [String] = []
        for entry in permitted {
            guard let dict = entry as? [String: Any],
                  let token = stringValue(any: dict["token"]),
                  let amount = stringValue(any: dict["amount"]) else {
                continue
            }
            tokens.append(token)
            amounts.append(amount)
        }
        guard !tokens.isEmpty else { return nil }
        return .permit2BatchTransferFrom(
            tokens: tokens,
            amounts: amounts,
            spender: spender,
            deadline: deadline
        )
    }

    // MARK: - ERC-7702

    private static func classifyERC7702(_ typed: EIP712TypedData) -> PermitClassification? {
        // ERC-7702 isn't strictly EIP-712, but typed-data wallets that
        // implement the SET_CODE preview surface it as a typed-data
        // request with primaryType "Authorization" and fields
        // (chainId, address, nonce). Conservative match on shape so we
        // don't mis-flag unrelated "Authorization" types from other
        // protocols.
        guard typed.primaryType == "Authorization" else { return nil }
        guard let fields = typed.types["Authorization"] else { return nil }
        let fieldNames = Set(fields.map(\.name))
        guard fieldNames == ["chainId", "address", "nonce"] else { return nil }
        guard let delegate = stringValue(typed.message["address"]),
              let chainId = stringValue(typed.message["chainId"]),
              let nonce = stringValue(typed.message["nonce"]) else {
            return nil
        }
        return .erc7702Delegation(delegate: delegate, chainId: chainId, nonce: nonce)
    }

    // MARK: - Helpers

    private static func isPermit2VerifyingContract(_ verifying: String?) -> Bool {
        guard let verifying else { return false }
        return verifying.caseInsensitiveCompare(permit2CanonicalAddress) == .orderedSame
    }

    private static func stringValue(_ codable: AnyCodable?) -> String? {
        guard let codable else { return nil }
        return stringValue(any: codable.value)
    }

    private static func stringValue(any: Any?) -> String? {
        switch any {
        case let s as String: return s
        case let i as Int: return String(i)
        case let i as Int64: return String(i)
        case let u as UInt64: return String(u)
        case let d as Double: return String(d)
        default: return nil
        }
    }

    private static func nested(_ codable: AnyCodable?) -> [String: Any]? {
        guard let codable else { return nil }
        return codable.value as? [String: Any]
    }

    private static func arrayValue(_ codable: AnyCodable?) -> [Any]? {
        guard let codable else { return nil }
        return codable.value as? [Any]
    }
}

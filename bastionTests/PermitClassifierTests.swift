import Testing
@testable import bastion
import Foundation

// PR5 tests: PermitClassifier identifies the dangerous typed-data
// shapes that grant on-chain spending or execution authority. Each
// shape is covered by a positive test (recognized) plus targeted
// negative tests (false positives we explicitly do NOT want).

private let usdcAddress = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
private let permit2 = "0x000000000022D473030F116dDEE9F6B43aC78BA3"

private func typedData(
    primaryType: String,
    types: [String: [EIP712Field]],
    domain: EIP712Domain,
    message: [String: AnyCodable]
) -> EIP712TypedData {
    EIP712TypedData(types: types, primaryType: primaryType, domain: domain, message: message)
}

@Suite("PermitClassifier — typed-data risk identification")
struct PermitClassifierTests {

    // MARK: - ERC-2612

    @Test("ERC-2612 Permit on a token contract is recognised")
    func erc2612BasicShape() {
        let typed = typedData(
            primaryType: "Permit",
            types: [
                "Permit": [
                    EIP712Field(name: "owner", type: "address"),
                    EIP712Field(name: "spender", type: "address"),
                    EIP712Field(name: "value", type: "uint256"),
                    EIP712Field(name: "nonce", type: "uint256"),
                    EIP712Field(name: "deadline", type: "uint256"),
                ],
            ],
            domain: EIP712Domain(name: "USD Coin", version: "2", chainId: 1, verifyingContract: usdcAddress, salt: nil),
            message: [
                "owner": AnyCodable("0x1111111111111111111111111111111111111111"),
                "spender": AnyCodable("0xCAFECAFECAFECAFECAFECAFECAFECAFECAFECAFE"),
                "value": AnyCodable("1000000000"),
                "nonce": AnyCodable("3"),
                "deadline": AnyCodable("1800000000"),
            ]
        )
        guard case .erc2612(let spender, let amount, let deadline, let token) = PermitClassifier.classify(typed) else {
            Issue.record("Expected .erc2612"); return
        }
        #expect(spender.lowercased() == "0xcafecafecafecafecafecafecafecafecafecafe")
        #expect(amount == "1000000000")
        #expect(deadline == "1800000000")
        #expect(token?.lowercased() == usdcAddress.lowercased())
    }

    @Test("Mismatched primaryType is not classified as ERC-2612")
    func erc2612NotPermitPrimaryType() {
        let typed = typedData(
            primaryType: "OrderApproval",
            types: ["OrderApproval": []],
            domain: EIP712Domain(name: "X", version: "1", chainId: 1, verifyingContract: usdcAddress, salt: nil),
            message: [:]
        )
        #expect(PermitClassifier.classify(typed) == nil)
    }

    @Test("Permit-shaped typed data with Permit2 verifyingContract is NOT erc2612")
    func erc2612FallsThroughOnPermit2Address() {
        let typed = typedData(
            primaryType: "Permit",
            types: [
                "Permit": [
                    EIP712Field(name: "owner", type: "address"),
                    EIP712Field(name: "spender", type: "address"),
                    EIP712Field(name: "value", type: "uint256"),
                    EIP712Field(name: "nonce", type: "uint256"),
                    EIP712Field(name: "deadline", type: "uint256"),
                ],
            ],
            domain: EIP712Domain(name: "Permit2", version: "1", chainId: 1, verifyingContract: permit2, salt: nil),
            message: [
                "owner": AnyCodable("0x1"),
                "spender": AnyCodable("0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"),
                "value": AnyCodable("100"),
                "nonce": AnyCodable("1"),
                "deadline": AnyCodable("9999"),
            ]
        )
        guard case .permit2Single = PermitClassifier.classify(typed) else {
            Issue.record("Expected permit2Single (bare Permit on Permit2)"); return
        }
    }

    // MARK: - Permit2 Single

    @Test("Permit2 PermitSingle is recognised with details + spender")
    func permit2SingleRecognized() {
        let typed = typedData(
            primaryType: "PermitSingle",
            types: [
                "PermitSingle": [
                    EIP712Field(name: "details", type: "PermitDetails"),
                    EIP712Field(name: "spender", type: "address"),
                    EIP712Field(name: "sigDeadline", type: "uint256"),
                ],
                "PermitDetails": [
                    EIP712Field(name: "token", type: "address"),
                    EIP712Field(name: "amount", type: "uint160"),
                    EIP712Field(name: "expiration", type: "uint48"),
                    EIP712Field(name: "nonce", type: "uint48"),
                ],
            ],
            domain: EIP712Domain(name: "Permit2", version: nil, chainId: 1, verifyingContract: permit2, salt: nil),
            message: [
                "details": AnyCodable([
                    "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                    "amount": "5000000",
                    "expiration": "1900000000",
                    "nonce": "0",
                ]),
                "spender": AnyCodable("0xCAFE000000000000000000000000000000000123"),
                "sigDeadline": AnyCodable("1800000000"),
            ]
        )
        guard case .permit2Single(let token, let spender, let amount, let expiration, let nonce) = PermitClassifier.classify(typed) else {
            Issue.record("Expected permit2Single"); return
        }
        #expect(token.lowercased() == usdcAddress.lowercased())
        #expect(spender.lowercased() == "0xcafe000000000000000000000000000000000123")
        #expect(amount == "5000000")
        #expect(expiration == "1900000000")
        #expect(nonce == "0")
    }

    @Test("Permit2 verifyingContract match is case-insensitive")
    func permit2AddressCaseInsensitive() {
        let typed = typedData(
            primaryType: "PermitSingle",
            types: ["PermitSingle": [], "PermitDetails": []],
            domain: EIP712Domain(name: "Permit2", version: nil, chainId: 1, verifyingContract: permit2.lowercased(), salt: nil),
            message: [
                "details": AnyCodable([
                    "token": usdcAddress, "amount": "1", "expiration": "1", "nonce": "1",
                ]),
                "spender": AnyCodable("0xc0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ff"),
            ]
        )
        if case .permit2Single = PermitClassifier.classify(typed) {} else {
            Issue.record("Expected permit2Single regardless of address casing")
        }
    }

    // MARK: - Permit2 Batch

    @Test("Permit2 PermitBatch yields earliest expiration as the headline")
    func permit2BatchEarliestExpiration() {
        let typed = typedData(
            primaryType: "PermitBatch",
            types: ["PermitBatch": [], "PermitDetails": []],
            domain: EIP712Domain(name: "Permit2", version: nil, chainId: 1, verifyingContract: permit2, salt: nil),
            message: [
                "details": AnyCodable([
                    [
                        "token": usdcAddress, "amount": "100", "expiration": "2000000000", "nonce": "0",
                    ],
                    [
                        "token": "0x6B175474E89094C44Da98b954EedeAC495271d0F", // DAI
                        "amount": "200", "expiration": "1500000000", "nonce": "0",
                    ],
                ]),
                "spender": AnyCodable("0xCAFE000000000000000000000000000000000123"),
            ]
        )
        guard case .permit2Batch(_, let tokens, let amounts, let earliestExpiration) = PermitClassifier.classify(typed) else {
            Issue.record("Expected permit2Batch"); return
        }
        #expect(tokens.count == 2)
        #expect(amounts == ["100", "200"])
        #expect(earliestExpiration == "1500000000")
    }

    // MARK: - Permit2 TransferFrom (one-shot)

    @Test("Permit2 PermitTransferFrom is one-shot, doesn't grant lasting allowance")
    func permit2TransferFromOneShot() {
        let typed = typedData(
            primaryType: "PermitTransferFrom",
            types: ["PermitTransferFrom": [], "TokenPermissions": []],
            domain: EIP712Domain(name: "Permit2", version: nil, chainId: 1, verifyingContract: permit2, salt: nil),
            message: [
                "permitted": AnyCodable([
                    "token": usdcAddress, "amount": "5000000",
                ]),
                "spender": AnyCodable("0xCAFE000000000000000000000000000000000456"),
                "nonce": AnyCodable("0"),
                "deadline": AnyCodable("1800000000"),
            ]
        )
        guard case .permit2TransferFrom(let token, let spender, let amount, let deadline) = PermitClassifier.classify(typed) else {
            Issue.record("Expected permit2TransferFrom"); return
        }
        #expect(token.lowercased() == usdcAddress.lowercased())
        #expect(spender.lowercased() == "0xcafe000000000000000000000000000000000456")
        #expect(amount == "5000000")
        #expect(deadline == "1800000000")
        let classification = PermitClassifier.classify(typed)
        #expect(classification?.grantsLastingAllowance == false)
    }

    @Test("Permit2 PermitBatchTransferFrom is one-shot batch transfer authorization")
    func permit2BatchTransferFromOneShot() {
        let typed = typedData(
            primaryType: "PermitBatchTransferFrom",
            types: ["PermitBatchTransferFrom": [], "TokenPermissions": []],
            domain: EIP712Domain(name: "Permit2", version: nil, chainId: 1, verifyingContract: permit2, salt: nil),
            message: [
                "permitted": AnyCodable([
                    [
                        "token": usdcAddress,
                        "amount": "5000000",
                    ],
                    [
                        "token": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
                        "amount": "7000000",
                    ],
                ]),
                "spender": AnyCodable("0xCAFE000000000000000000000000000000000789"),
                "nonce": AnyCodable("0"),
                "deadline": AnyCodable("1800000000"),
            ]
        )
        guard case .permit2BatchTransferFrom(let tokens, let amounts, let spender, let deadline) = PermitClassifier.classify(typed) else {
            Issue.record("Expected permit2BatchTransferFrom"); return
        }
        #expect(tokens.count == 2)
        #expect(amounts == ["5000000", "7000000"])
        #expect(spender.lowercased() == "0xcafe000000000000000000000000000000000789")
        #expect(deadline == "1800000000")
        #expect(PermitClassifier.classify(typed)?.grantsLastingAllowance == false)
    }

    // MARK: - ERC-7702

    @Test("ERC-7702 Authorization is recognised by primaryType + canonical fields")
    func erc7702Recognized() {
        let typed = typedData(
            primaryType: "Authorization",
            types: [
                "Authorization": [
                    EIP712Field(name: "chainId", type: "uint256"),
                    EIP712Field(name: "address", type: "address"),
                    EIP712Field(name: "nonce", type: "uint256"),
                ],
            ],
            domain: EIP712Domain(name: "ERC-7702", version: "1", chainId: 1, verifyingContract: nil, salt: nil),
            message: [
                "chainId": AnyCodable("1"),
                "address": AnyCodable("0xDe1eA15D8e1eA15D8e1eA15D8e1eA15D8e1eA15D"),
                "nonce": AnyCodable("0"),
            ]
        )
        guard case .erc7702Delegation(let delegate, let chainId, let nonce) = PermitClassifier.classify(typed) else {
            Issue.record("Expected erc7702Delegation"); return
        }
        #expect(delegate.lowercased() == "0xde1ea15d8e1ea15d8e1ea15d8e1ea15d8e1ea15d")
        #expect(chainId == "1")
        #expect(nonce == "0")
    }

    @Test("Generic 'Authorization' from another protocol is NOT classified as ERC-7702")
    func nonERC7702Authorization() {
        let typed = typedData(
            primaryType: "Authorization",
            types: [
                "Authorization": [
                    EIP712Field(name: "user", type: "address"),
                    EIP712Field(name: "scope", type: "string"),
                ],
            ],
            domain: EIP712Domain(name: "X", version: "1", chainId: 1, verifyingContract: nil, salt: nil),
            message: [:]
        )
        #expect(PermitClassifier.classify(typed) == nil)
    }

    // MARK: - Behaviour bits

    @Test("grantsLastingAllowance is true for permit shapes, false for transferFrom")
    func lastingAllowanceClassification() {
        let lasting: [PermitClassification] = [
            .erc2612(spender: "x", amount: "1", deadline: "1", token: nil),
            .permit2Single(token: "x", spender: "y", amount: "1", expiration: "1", nonce: "0"),
            .permit2Batch(spender: "y", tokens: ["x"], amounts: ["1"], expiration: "1"),
            .erc7702Delegation(delegate: "x", chainId: "1", nonce: "0"),
        ]
        for c in lasting { #expect(c.grantsLastingAllowance) }
        let oneShot = PermitClassification.permit2TransferFrom(token: "x", spender: "y", amount: "1", deadline: "1")
        #expect(oneShot.grantsLastingAllowance == false)
        let batchOneShot = PermitClassification.permit2BatchTransferFrom(tokens: ["x"], amounts: ["1"], spender: "y", deadline: "1")
        #expect(batchOneShot.grantsLastingAllowance == false)
    }

    @Test("Permit warning presentation covers every risky typed-data shape")
    func permitWarningPresentationCoversEveryRiskyShape() {
        typealias Presentation = SigningPermitWarningPresentation
        typealias Row = SigningPermitWarningPresentation.Row

        let erc2612 = Presentation.make(classification: .erc2612(
            spender: "0xCAFECAFECAFECAFECAFECAFECAFECAFECAFECAFE",
            amount: "1000000000",
            deadline: "1800000000",
            token: usdcAddress
        ))
        #expect(erc2612.label == "ERC-2612 Permit")
        #expect(erc2612.showsLastingAllowance == true)
        #expect(erc2612.accessibilityLabel == "ERC-2612 Permit")
        #expect(erc2612.accessibilityHint.contains("spender pull tokens"))
        #expect(erc2612.rows == [
            Row(key: "Token", value: .address(value: usdcAddress, muted: true)),
            Row(key: "Spender", value: .address(value: "0xCAFECAFECAFECAFECAFECAFECAFECAFECAFECAFE", muted: false)),
            Row(key: "Amount", value: .text("1000000000")),
            Row(key: "Deadline", value: .expiry("1800000000")),
        ])

        let permit2Single = Presentation.make(classification: .permit2Single(
            token: usdcAddress,
            spender: "0xCAFE000000000000000000000000000000000123",
            amount: "5000000",
            expiration: "1900000000",
            nonce: "0"
        ))
        #expect(permit2Single.label == "Permit2 — single allowance")
        #expect(permit2Single.showsLastingAllowance == true)
        #expect(permit2Single.explanation.contains("Uniswap Permit2 allowance"))
        #expect(permit2Single.rows == [
            Row(key: "Token", value: .address(value: usdcAddress, muted: true)),
            Row(key: "Spender", value: .address(value: "0xCAFE000000000000000000000000000000000123", muted: false)),
            Row(key: "Amount", value: .text("5000000")),
            Row(key: "Expires", value: .expiry("1900000000")),
            Row(key: "Nonce", value: .text("0")),
        ])

        let permit2Batch = Presentation.make(classification: .permit2Batch(
            spender: "0xCAFE000000000000000000000000000000000123",
            tokens: [usdcAddress, "0x6B175474E89094C44Da98b954EedeAC495271d0F"],
            amounts: ["100"],
            expiration: "1500000000"
        ))
        #expect(permit2Batch.label == "Permit2 — batch allowance")
        #expect(permit2Batch.showsLastingAllowance == true)
        #expect(permit2Batch.rows == [
            Row(key: "Spender", value: .address(value: "0xCAFE000000000000000000000000000000000123", muted: false)),
            Row(key: "Earliest", value: .expiry("1500000000")),
            Row(key: "Token 1", value: .tokenAmount(token: usdcAddress, amount: "100")),
            Row(key: "Token 2", value: .tokenAmount(token: "0x6B175474E89094C44Da98b954EedeAC495271d0F", amount: "?")),
        ])

        let transferFrom = Presentation.make(classification: .permit2TransferFrom(
            token: usdcAddress,
            spender: "0xCAFE000000000000000000000000000000000456",
            amount: "5000000",
            deadline: "1800000000"
        ))
        #expect(transferFrom.label == "Permit2 — transfer authorization")
        #expect(transferFrom.showsLastingAllowance == false)
        #expect(transferFrom.explanation.contains("one-shot transfer authorization"))
        #expect(transferFrom.rows == [
            Row(key: "Token", value: .address(value: usdcAddress, muted: true)),
            Row(key: "Spender", value: .address(value: "0xCAFE000000000000000000000000000000000456", muted: false)),
            Row(key: "Amount", value: .text("5000000")),
            Row(key: "Deadline", value: .expiry("1800000000")),
        ])

        let batchTransferFrom = Presentation.make(classification: .permit2BatchTransferFrom(
            tokens: [usdcAddress],
            amounts: ["7000000"],
            spender: "0xCAFE000000000000000000000000000000000789",
            deadline: "1800000000"
        ))
        #expect(batchTransferFrom.label == "Permit2 — batch transfer authorization")
        #expect(batchTransferFrom.showsLastingAllowance == false)
        #expect(batchTransferFrom.rows == [
            Row(key: "Spender", value: .address(value: "0xCAFE000000000000000000000000000000000789", muted: false)),
            Row(key: "Deadline", value: .expiry("1800000000")),
            Row(key: "Token 1", value: .tokenAmount(token: usdcAddress, amount: "7000000")),
        ])

        let delegation = Presentation.make(classification: .erc7702Delegation(
            delegate: "0xDe1eA15D8e1eA15D8e1eA15D8e1eA15D8e1eA15D",
            chainId: "1",
            nonce: "0"
        ))
        #expect(delegation.label == "ERC-7702 delegation")
        #expect(delegation.showsLastingAllowance == true)
        #expect(delegation.explanation.contains("installs delegate code"))
        #expect(delegation.rows == [
            Row(key: "Delegate", value: .address(value: "0xDe1eA15D8e1eA15D8e1eA15D8e1eA15D8e1eA15D", muted: false)),
            Row(key: "Chain", value: .text("1")),
            Row(key: "Nonce", value: .text("0")),
        ])
    }

    @Test("Plain typed-data without any permit pattern stays unclassified")
    func unrelatedPasses() {
        let typed = typedData(
            primaryType: "Order",
            types: [
                "Order": [
                    EIP712Field(name: "maker", type: "address"),
                    EIP712Field(name: "taker", type: "address"),
                    EIP712Field(name: "amount", type: "uint256"),
                ],
            ],
            domain: EIP712Domain(name: "Some Exchange", version: "1", chainId: 1, verifyingContract: usdcAddress, salt: nil),
            message: [:]
        )
        #expect(PermitClassifier.classify(typed) == nil)
    }
}

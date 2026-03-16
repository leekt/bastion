import Foundation

enum SigningRequestPreviewFactory {
    static func policyReview() -> ApprovalRequest {
        ApprovalRequest(
            request: SignRequest(
                operation: .typedData(sampleTypedData()),
                requestID: "preview-policy-review",
                timestamp: Date(),
                clientBundleId: "com.bastion.preview"
            ),
            mode: .policyReview
        )
    }

    static func ruleOverride() -> ApprovalRequest {
        ApprovalRequest(
            request: SignRequest(
                operation: .userOperation(sampleUserOperation()),
                requestID: "preview-rule-override",
                timestamp: Date(),
                clientBundleId: "com.bastion.preview"
            ),
            mode: .ruleOverride([
                "Outside allowed hours (09:00 - 18:00)",
                "Target 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48 not in allowlist for chain 11155111",
                "USDC spending limit exceeded: 50 USDC per day",
            ])
        )
    }

    private static func sampleTypedData() -> EIP712TypedData {
        EIP712TypedData(
            types: [
                "EIP712Domain": [
                    EIP712Field(name: "name", type: "string"),
                    EIP712Field(name: "version", type: "string"),
                    EIP712Field(name: "chainId", type: "uint256"),
                    EIP712Field(name: "verifyingContract", type: "address"),
                ],
                "Permit": [
                    EIP712Field(name: "owner", type: "address"),
                    EIP712Field(name: "spender", type: "address"),
                    EIP712Field(name: "value", type: "uint256"),
                    EIP712Field(name: "nonce", type: "uint256"),
                    EIP712Field(name: "deadline", type: "uint256"),
                ],
            ],
            primaryType: "Permit",
            domain: EIP712Domain(
                name: "Permit2",
                version: "1",
                chainId: 11155111,
                verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3",
                salt: nil
            ),
            message: [
                "deadline": AnyCodable("1710000000"),
                "nonce": AnyCodable("7"),
                "owner": AnyCodable("0x1234567890abcdef1234567890abcdef12345678"),
                "spender": AnyCodable("0x7777777777777777777777777777777777777777"),
                "value": AnyCodable("50000000"),
            ]
        )
    }

    private static func sampleUserOperation() -> UserOperation {
        let transferData = Data(hexString: "0xa9059cbb000000000000000000000000f39fd6e51aad88f6f4ce6ab8827279cfffb9226600000000000000000000000000000000000000000000000000000000004c4b40") ?? Data()
        let callData = KernelEncoding.executeCalldata(
            single: .init(
                to: "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
                value: 0,
                data: transferData
            )
        )

        return UserOperation(
            sender: "0x2dda58a793fe8b895f2b5d452f05fd9a0d4357af",
            nonce: "0x01",
            callData: callData,
            factory: "0xd703aaE79538628d27099B8c4f621bE4CCd142d5",
            factoryData: Data(hexString: "0xc5265d5d") ?? Data(),
            verificationGasLimit: "0x57749",
            callGasLimit: "0x4623",
            preVerificationGas: "0xd5d9",
            maxPriorityFeePerGas: "0x233f76",
            maxFeePerGas: "0x233f83",
            paymaster: "0x777777777777AeC03fd955926DbF81597e66834C",
            paymasterVerificationGasLimit: "0x8a8e",
            paymasterPostOpGasLimit: "0x01",
            paymasterData: Data(hexString: "0x0102030405") ?? Data(),
            chainId: 11155111,
            entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
            entryPointVersion: .v0_7
        )
    }
}

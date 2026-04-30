import Foundation

// MARK: - Wallet Group On-Chain Operations (Phase 2)
//
// Builds, signs (with the owner's sudo SE key), and optionally submits the
// `installModule` / `uninstallModule` UserOperations that attach and detach
// per-agent validator modules to the group's smart account.
//
// The owner's SE key is the sudo validator — only it can install or remove
// agent validators on-chain. Bastion's RuleEngine is the off-chain
// authorization layer and must always require biometric/passcode auth before
// submitting one of these UserOps.

extension RuleEngine {

    // MARK: - Public Errors

    enum WalletGroupChainError: Error, CustomStringConvertible {
        case groupNotFound
        case memberNotFound
        case agentAlreadyInstalled(txHash: String)
        case agentNotInstalled
        case groupAddressUnresolved
        case invalidPubkey
        case submissionFailed(String)

        var description: String {
            switch self {
            case .groupNotFound: return "Wallet group not found"
            case .memberNotFound: return "Agent membership not found"
            case .agentAlreadyInstalled(let hash): return "Agent validator already installed (tx \(hash))"
            case .agentNotInstalled: return "Agent validator is not installed on-chain"
            case .groupAddressUnresolved: return "Wallet group has no resolved smart account address"
            case .invalidPubkey: return "Owner or agent public key could not be decoded"
            case .submissionFailed(let reason): return "UserOperation submission failed: \(reason)"
            }
        }
    }

    // MARK: - Result Types

    /// Returned from `installAgentOnChain` / `uninstallAgentOnChain`. When
    /// `submit: false`, `userOpHash` + `txHash` are nil and the caller can
    /// later submit the UserOp themselves (the `userOpRPC` field contains
    /// the signed UserOp in bundler-ready JSON form).
    struct WalletGroupChainResult: Sendable {
        let groupId: String
        let memberId: String
        let chainId: Int
        /// Bundler-encoded UserOp (same shape ZeroDev expects on
        /// `eth_sendUserOperation`). Always populated.
        let userOpRPC: UserOperationRPC
        /// EntryPoint UserOp hash, if submitted.
        let userOpHash: String?
        /// On-chain transaction hash, if a receipt arrived in time.
        let txHash: String?
        /// Updated membership after optional `markAgentInstalled` side-effect.
        let membership: AgentMembership?
    }

    // MARK: - Install

    /// Builds (and optionally submits) the UserOp that installs an agent's
    /// P256Validator on the group's smart account. Requires owner
    /// biometric/passcode — this is a sudo operation.
    ///
    /// - Parameters:
    ///   - groupId: Target wallet group.
    ///   - memberId: Agent membership to install.
    ///   - chainId: Chain to perform the install on. Must be a value the owner
    ///     has configured a bundler + RPC for.
    ///   - projectId: ZeroDev project ID (falls back to the one in
    ///     `bundlerPreferences` if nil).
    ///   - submit: If true, the UserOp is sent to the bundler and the function
    ///     polls for a receipt. If false, the signed UserOp is returned for
    ///     the caller to submit through a different bundler.
    ///   - waitForReceiptSeconds: How long to poll `eth_getUserOperationReceipt`
    ///     before returning. 0 skips polling.
    func installAgentOnChain(
        groupId: String,
        memberId: String,
        chainId: Int,
        projectId: String? = nil,
        submit: Bool,
        waitForReceiptSeconds: Int = 30
    ) async throws -> WalletGroupChainResult {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to install an agent validator on-chain"
        )

        ensureConfigLoadedIfNeeded()

        let (group, member) = try loadGroupAndMember(groupId: groupId, memberId: memberId)
        if case .installed(let hash) = member.installStatus {
            throw WalletGroupChainError.agentAlreadyInstalled(txHash: hash)
        }
        guard let accountAddress = group.accountAddress else {
            throw WalletGroupChainError.groupAddressUnresolved
        }

        // Build the execution: account.installModule(VALIDATOR, agentValidatorAddr, agentPubkey).
        let agentPubkey = try loadPubkeyData(keyTag: member.keyTag)
        let agentValidatorAddress = member.validatorAddress ?? ValidatorAddress.p256Validator
        let execution = try KernelModule.installModuleExecution(
            accountAddress: accountAddress,
            type: .validator,
            module: agentValidatorAddress,
            initData: agentPubkey
        )

        let result = try await submitOwnerSignedExecution(
            group: group,
            chainId: chainId,
            projectId: projectId,
            execution: execution,
            submit: submit,
            waitForReceiptSeconds: waitForReceiptSeconds
        )

        // If we got a tx hash back, record the install on the membership.
        var updatedMember: AgentMembership? = nil
        if let txHash = result.txHash ?? result.userOpHash, submit {
            updatedMember = try await markAgentInstalled(
                groupId: groupId,
                memberId: memberId,
                txHash: txHash,
                validatorAddress: agentValidatorAddress
            )
        }

        auditLog.record(AuditEvent(
            type: .walletGroupAgentInstalled,
            dataPrefix: "walletgroup.\(groupId.prefix(8)).agent.\(memberId.prefix(8))",
            reason: submit
                ? "Submitted install UserOp for agent \(memberId.prefix(8)); txHash=\(result.txHash ?? result.userOpHash ?? "pending")"
                : "Built install UserOp for agent \(memberId.prefix(8)) (not submitted)"
        ))

        return WalletGroupChainResult(
            groupId: groupId,
            memberId: memberId,
            chainId: chainId,
            userOpRPC: result.userOpRPC,
            userOpHash: result.userOpHash,
            txHash: result.txHash,
            membership: updatedMember ?? member
        )
    }

    // MARK: - Uninstall

    /// Builds (and optionally submits) the UserOp that uninstalls an agent's
    /// validator from the group's smart account. Requires owner
    /// biometric/passcode.
    ///
    /// Note: `removeAgentFromGroup` revokes the agent *off-chain* (deletes the
    /// SE key and flips the install status to `.revoked`). This method
    /// additionally submits the on-chain uninstall UserOp so the module is
    /// detached from the Kernel account.
    func uninstallAgentOnChain(
        groupId: String,
        memberId: String,
        chainId: Int,
        projectId: String? = nil,
        submit: Bool,
        waitForReceiptSeconds: Int = 30
    ) async throws -> WalletGroupChainResult {
        try await authManager.authenticate(
            policy: .biometricOrPasscode,
            reason: "Authenticate to uninstall an agent validator on-chain"
        )

        ensureConfigLoadedIfNeeded()

        let (group, member) = try loadGroupAndMember(groupId: groupId, memberId: memberId)
        guard let accountAddress = group.accountAddress else {
            throw WalletGroupChainError.groupAddressUnresolved
        }

        let agentValidatorAddress = member.validatorAddress ?? ValidatorAddress.p256Validator
        let execution = try KernelModule.uninstallModuleExecution(
            accountAddress: accountAddress,
            type: .validator,
            module: agentValidatorAddress,
            deInitData: Data()
        )

        let result = try await submitOwnerSignedExecution(
            group: group,
            chainId: chainId,
            projectId: projectId,
            execution: execution,
            submit: submit,
            waitForReceiptSeconds: waitForReceiptSeconds
        )

        auditLog.record(AuditEvent(
            type: .walletGroupAgentRemoved,
            dataPrefix: "walletgroup.\(groupId.prefix(8)).agent.\(memberId.prefix(8))",
            reason: submit
                ? "Submitted uninstall UserOp for agent \(memberId.prefix(8)); txHash=\(result.txHash ?? result.userOpHash ?? "pending")"
                : "Built uninstall UserOp for agent \(memberId.prefix(8)) (not submitted)"
        ))

        return WalletGroupChainResult(
            groupId: groupId,
            memberId: memberId,
            chainId: chainId,
            userOpRPC: result.userOpRPC,
            userOpHash: result.userOpHash,
            txHash: result.txHash,
            membership: member
        )
    }

    // MARK: - Shared Path

    private struct RawChainSubmissionResult {
        let userOpRPC: UserOperationRPC
        let userOpHash: String?
        let txHash: String?
    }

    /// Builds, sponsors, signs (with owner SE key), and optionally submits
    /// a UserOp whose callData wraps a single execution targeting the group's
    /// smart account. Returns the signed UserOp in RPC form plus the bundler
    /// response (hash + receipt) when `submit == true`.
    private func submitOwnerSignedExecution(
        group: WalletGroup,
        chainId: Int,
        projectId: String?,
        execution: KernelEncoding.Execution,
        submit: Bool,
        waitForReceiptSeconds: Int
    ) async throws -> RawChainSubmissionResult {
        // Resolve ZeroDev project ID (explicit argument > app config).
        let resolvedProjectId = try resolveZeroDevProjectId(explicit: projectId)
        let bundler = ZeroDevAPI(projectId: resolvedProjectId)
        let rpc = ownerChainRPC(chainId: chainId, bundler: bundler)

        // Build an owner P256Validator whose signing closure uses the owner SE key.
        let ownerValidator = try ownerP256Validator(for: group)
        let ownerAccount = SmartAccount(validator: ownerValidator)
        ownerAccount.setAddress(group.accountAddress!)

        // Wrap the execution in a Kernel execute() callData.
        let callData = KernelEncoding.executeCalldata(single: execution)

        // Build + sponsor the UserOp through the owner's account.
        var op = try await ownerAccount.buildSponsoredUserOperation(
            callData: callData,
            using: rpc,
            bundler: bundler,
            chainId: chainId
        )

        // Sign the UserOp hash with the owner's validator.
        let signature = try ownerAccount.signUserOperation(op)
        let rpcOp = UserOperationRPC.from(op, signature: signature)

        guard submit else {
            return RawChainSubmissionResult(userOpRPC: rpcOp, userOpHash: nil, txHash: nil)
        }

        // Submit via ZeroDev.
        let userOpHash: String
        do {
            userOpHash = try await bundler.sendUserOperation(
                rpcOp,
                entryPoint: op.entryPoint,
                chainId: chainId
            )
        } catch {
            throw WalletGroupChainError.submissionFailed(String(describing: error))
        }

        // Poll for receipt (best effort — returns nil if timeout).
        var txHash: String? = nil
        if waitForReceiptSeconds > 0 {
            let deadline = Date().addingTimeInterval(TimeInterval(waitForReceiptSeconds))
            while Date() < deadline {
                if let receipt = try? await bundler.getUserOperationReceipt(
                    userOpHash: userOpHash,
                    chainId: chainId
                ), let hash = receipt.receipt?.transactionHash {
                    txHash = hash
                    break
                }
                try? await Task.sleep(nanoseconds: 1_500_000_000)
            }
        }

        // Silence unused-variable warning on `op` (build-time mutable).
        _ = op

        return RawChainSubmissionResult(userOpRPC: rpcOp, userOpHash: userOpHash, txHash: txHash)
    }

    // MARK: - Helpers

    private func loadGroupAndMember(
        groupId: String,
        memberId: String
    ) throws -> (WalletGroup, AgentMembership) {
        guard let group = config.walletGroups.first(where: { $0.id == groupId }) else {
            throw WalletGroupChainError.groupNotFound
        }
        guard let member = group.member(id: memberId) else {
            throw WalletGroupChainError.memberNotFound
        }
        return (group, member)
    }

    private func loadPubkeyData(keyTag: String) throws -> Data {
        let pub = try SecureEnclaveManager.shared.getPublicKey(keyTag: keyTag)
        guard let x = Data(hexString: pub.x), let y = Data(hexString: pub.y),
              x.count == 32, y.count == 32 else {
            throw WalletGroupChainError.invalidPubkey
        }
        return x + y
    }

    private func ownerP256Validator(for group: WalletGroup) throws -> P256Validator {
        let pub = try SecureEnclaveManager.shared.getPublicKey(keyTag: group.ownerKeyTag)
        guard let x = Data(hexString: pub.x), let y = Data(hexString: pub.y) else {
            throw WalletGroupChainError.invalidPubkey
        }
        let ownerKeyTag = group.ownerKeyTag
        return P256Validator(
            validatorAddress: ValidatorAddress.p256Validator,
            publicKeyX: x,
            publicKeyY: y,
            sign: { digest in
                let resp = try SecureEnclaveManager.shared.signDigest(
                    hash: digest,
                    keyTag: ownerKeyTag
                )
                guard let r = Data(hexString: resp.r), let s = Data(hexString: resp.s),
                      r.count == 32, s.count == 32 else {
                    throw WalletGroupChainError.invalidPubkey
                }
                return r + s
            }
        )
    }

    private func resolveZeroDevProjectId(explicit: String?) throws -> String {
        if let explicit, !explicit.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return explicit
        }
        if let configured = config.bundlerPreferences.zeroDevProjectId?
            .trimmingCharacters(in: .whitespacesAndNewlines),
           !configured.isEmpty {
            return configured
        }
        throw WalletGroupChainError.submissionFailed(
            "ZeroDev project ID is not configured in Bastion settings"
        )
    }

    private func ownerChainRPC(chainId: Int, bundler: ZeroDevAPI) -> EthRPC {
        if let endpoint = config.bundlerPreferences.chainRPCs.first(where: { $0.chainId == chainId }),
           let url = URL(string: endpoint.rpcURL) {
            return EthRPC(rpcURL: url)
        }
        return EthRPC(rpcURL: bundler.rpcURL(chainId: chainId))
    }
}

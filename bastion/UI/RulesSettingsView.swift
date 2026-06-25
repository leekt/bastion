import AppKit
import Combine
import SwiftUI

// Settings window — Bastion v2 redesign.
// Sidebar (Defaults/Clients/Wallet groups + Rule templates) → main panel with
// per-target caps, global cap tiles, auth quick-picker, validator state, and
// an unsaved-changes save bar with diff sheet. Mirrors settings-v2.jsx.

nonisolated enum SettingsSelection: Hashable, Sendable {
    case defaultProfile
    case appPreferences
    case ruleTemplates
    case addressBook
    case policySimulator
    case policyHistory
    case highValueRule
    case client(id: String)
    case walletGroup(id: String)

    var stableID: String {
        switch self {
        case .defaultProfile: return "default-profile"
        case .appPreferences: return "app-preferences"
        case .ruleTemplates: return "rule-templates"
        case .addressBook: return "address-book"
        case .policySimulator: return "policy-simulator"
        case .policyHistory: return "policy-history"
        case .highValueRule: return "high-value-rule"
        case .client(let id): return "client-\(id)"
        case .walletGroup(let id): return "wallet-group-\(id)"
        }
    }
}

nonisolated enum SettingsApprovalPreviewTiming {
    static let presentationDelay: TimeInterval = 0.15
}

@MainActor
enum SettingsApprovalPreviewPresenter {
    static func hideSettingsWindowBeforePreview(_ window: NSWindow?) {
        ApprovalPreviewWindowHider.hideHostWindowsBeforePreview(primary: window)
    }
}

nonisolated enum SettingsSidebarIcon: Equatable, Sendable {
    case shield
    case gear
    case templates
    case warning
    case book
    case simulator
    case history
    case group
    case none
}

nonisolated enum SettingsMainPanelRoute: Equatable, Sendable {
    case defaultProfile
    case appPreferences
    case ruleTemplates
    case addressBook
    case policySimulator
    case policyHistory
    case highValueRule
    case client(id: String)
    case walletGroup(id: String)
    case emptySelection
}

nonisolated struct SettingsSidebarItemPresentation: Identifiable, Equatable, Sendable {
    let id: String
    let label: String
    let sublabel: String?
    let selection: SettingsSelection
    let icon: SettingsSidebarIcon
    let selected: Bool
}

nonisolated struct SettingsNavigationPresentation: Equatable, Sendable {
    let showsFakeTitleBar: Bool
    let defaultItems: [SettingsSidebarItemPresentation]
    let clientItems: [SettingsSidebarItemPresentation]
    let clientsEmptyMessage: String?
    let walletGroupItems: [SettingsSidebarItemPresentation]
    let walletGroupsEmptyMessage: String?
    let mainPanelRoute: SettingsMainPanelRoute

    static func make(config: BastionConfig, selection: SettingsSelection) -> SettingsNavigationPresentation {
        let clientItems = config.clientProfiles.map { profile in
            item(
                label: profile.label ?? profile.bundleId,
                sublabel: profile.bundleId,
                selection: .client(id: profile.id),
                icon: .none,
                currentSelection: selection
            )
        }
        let walletGroupItems = config.walletGroups.map { group in
            item(
                label: group.label.isEmpty ? "Wallet Group" : group.label,
                sublabel: nil,
                selection: .walletGroup(id: group.id),
                icon: .group,
                currentSelection: selection
            )
        }

        return SettingsNavigationPresentation(
            showsFakeTitleBar: false,
            defaultItems: defaultItems(currentSelection: selection),
            clientItems: clientItems,
            clientsEmptyMessage: clientItems.isEmpty ? "No agents paired yet" : nil,
            walletGroupItems: walletGroupItems,
            walletGroupsEmptyMessage: walletGroupItems.isEmpty ? "No groups" : nil,
            mainPanelRoute: mainPanelRoute(config: config, selection: selection)
        )
    }

    static func mainPanelRoute(config: BastionConfig, selection: SettingsSelection) -> SettingsMainPanelRoute {
        switch selection {
        case .defaultProfile:
            return .defaultProfile
        case .appPreferences:
            return .appPreferences
        case .ruleTemplates:
            return .ruleTemplates
        case .addressBook:
            return .addressBook
        case .policySimulator:
            return .policySimulator
        case .policyHistory:
            return .policyHistory
        case .highValueRule:
            return .highValueRule
        case .client(let id):
            return config.clientProfiles.contains(where: { $0.id == id }) ? .client(id: id) : .emptySelection
        case .walletGroup(let id):
            return config.walletGroups.contains(where: { $0.id == id }) ? .walletGroup(id: id) : .emptySelection
        }
    }

    private static func defaultItems(currentSelection: SettingsSelection) -> [SettingsSidebarItemPresentation] {
        [
            item(label: "Default profile", selection: .defaultProfile, icon: .shield, currentSelection: currentSelection),
            item(label: "App preferences", selection: .appPreferences, icon: .gear, currentSelection: currentSelection),
            item(label: "Rule templates", selection: .ruleTemplates, icon: .templates, currentSelection: currentSelection),
            item(label: "High-value rule", selection: .highValueRule, icon: .warning, currentSelection: currentSelection),
            item(label: "Address book", selection: .addressBook, icon: .book, currentSelection: currentSelection),
            item(label: "Policy simulator", selection: .policySimulator, icon: .simulator, currentSelection: currentSelection),
            item(label: "Policy history", selection: .policyHistory, icon: .history, currentSelection: currentSelection),
        ]
    }

    private static func item(
        label: String,
        sublabel: String? = nil,
        selection: SettingsSelection,
        icon: SettingsSidebarIcon,
        currentSelection: SettingsSelection
    ) -> SettingsSidebarItemPresentation {
        SettingsSidebarItemPresentation(
            id: selection.stableID,
            label: label,
            sublabel: sublabel,
            selection: selection,
            icon: icon,
            selected: selection == currentSelection
        )
    }
}

nonisolated enum ValidatorUninstallPreflight: Equatable, Sendable {
    case ready(groupId: String, memberId: String, chainId: Int)
    case blocked(message: String)

    static let missingWalletGroupMessage = "This client is not linked to an on-chain wallet group."

    static func evaluate(profile: ClientProfile, walletGroups: [WalletGroup]) -> ValidatorUninstallPreflight {
        guard let groupId = profile.walletGroupId,
              let memberId = profile.membershipId,
              let group = walletGroups.first(where: { $0.id == groupId }),
              let chainId = group.chainIds.first else {
            return .blocked(message: missingWalletGroupMessage)
        }
        return .ready(groupId: groupId, memberId: memberId, chainId: chainId)
    }
}

nonisolated struct ValidatorActionFeedback: Equatable, Sendable {
    let message: String
    let isError: Bool

    static let revokeAuthCancelled = ValidatorActionFeedback(
        message: "Revoke cancelled.",
        isError: false
    )

    static func noLocalKey(profileName: String) -> ValidatorActionFeedback {
        ValidatorActionFeedback(
            message: "No local key found for \(profileName).",
            isError: true
        )
    }

    static func revokedLocalKey(profileName: String) -> ValidatorActionFeedback {
        ValidatorActionFeedback(
            message: "Revoked local key for \(profileName).",
            isError: false
        )
    }

    static func uninstallSubmitted(profileName: String, chainName: String) -> ValidatorActionFeedback {
        ValidatorActionFeedback(
            message: "Submitted validator uninstall for \(profileName) on \(chainName).",
            isError: false
        )
    }

    static func uninstallFailed(_ error: Error) -> ValidatorActionFeedback {
        ValidatorActionFeedback(
            message: "Uninstall failed: \(error.localizedDescription)",
            isError: true
        )
    }
}

nonisolated enum EthereumAddressInput {
    static func canonical(_ s: String) -> String {
        let stripped = strippedAddress(s)
        return "0x\(stripped.lowercased())"
    }

    static func isValid(_ s: String) -> Bool {
        let stripped = strippedAddress(s)
        guard stripped.count == 40 else { return false }
        return stripped.allSatisfy { $0.isHexDigit }
    }

    private static func strippedAddress(_ s: String) -> String {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.lowercased().hasPrefix("0x") ? String(trimmed.dropFirst(2)) : trimmed
    }
}

nonisolated struct AddressBookEntryDraft: Equatable, Sendable {
    static let addressError = "Address must be a 20-byte Ethereum address."
    static let labelError = "Label is required."
    static let chainIdError = "Chain ID must be a positive integer."

    var address: String
    var label: String
    var chainId: String

    var validationMessage: String? {
        if !EthereumAddressInput.isValid(address) {
            return Self.addressError
        }
        if trimmedLabel.isEmpty {
            return Self.labelError
        }
        if hasInvalidChainId {
            return Self.chainIdError
        }
        return nil
    }

    func makeEntry() -> AddressBookEntry? {
        guard validationMessage == nil else { return nil }
        return AddressBookEntry(
            address: EthereumAddressInput.canonical(address),
            label: String(trimmedLabel.prefix(64)),
            chainId: parsedChainId
        )
    }

    private var trimmedLabel: String {
        label.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var trimmedChainId: String {
        chainId.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var parsedChainId: Int? {
        guard !trimmedChainId.isEmpty else { return nil }
        guard let parsed = Int(trimmedChainId), parsed > 0 else { return nil }
        return parsed
    }

    private var hasInvalidChainId: Bool {
        !trimmedChainId.isEmpty && parsedChainId == nil
    }
}

nonisolated struct AddressBookRowPresentation: Equatable, Sendable {
    let removeAccessibilityLabel: String
    let removeHelp: String

    static func make(_ entry: AddressBookEntry) -> AddressBookRowPresentation {
        let chainScope = entry.chainId.map { " on chain \($0)" } ?? " on any chain"
        let label = "Remove address label \(entry.label)"
        let help = "Remove \(entry.label) for \(entry.address)\(chainScope)"
        return AddressBookRowPresentation(
            removeAccessibilityLabel: label,
            removeHelp: help
        )
    }
}

nonisolated struct TargetAllowlistEntry: Equatable, Sendable {
    let chainId: Int
    let address: String
    let usdcDailyCap: Double?

    var usdcAllowanceRaw: String? {
        guard let usdcDailyCap else { return nil }
        return String(Int64((usdcDailyCap * 1_000_000).rounded()))
    }
}

nonisolated struct TargetAllowlistEntryDraft: Equatable, Sendable {
    static let chainIdError = "Chain ID must be a positive integer."
    static let addressError = "Target must be a 20-byte Ethereum address."
    static let usdcCapError = "USDC cap must be a positive number."
    static let usdcCapTooLargeError = "USDC cap is too large."
    static let maximumUsdcCap = Double(Int64.max) / 1_000_000

    var chainId: String
    var address: String
    var usdcDailyCap: String

    var validationMessage: String? {
        if parsedChainId == nil {
            return Self.chainIdError
        }
        if !EthereumAddressInput.isValid(address) {
            return Self.addressError
        }
        if let capError {
            return capError
        }
        return nil
    }

    func makeEntry() -> TargetAllowlistEntry? {
        guard validationMessage == nil, let chainId = parsedChainId else { return nil }
        return TargetAllowlistEntry(
            chainId: chainId,
            address: EthereumAddressInput.canonical(address),
            usdcDailyCap: parsedUsdcDailyCap
        )
    }

    private var parsedChainId: Int? {
        let trimmed = chainId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parsed = Int(trimmed), parsed > 0 else { return nil }
        return parsed
    }

    private var parsedUsdcDailyCap: Double? {
        let trimmed = usdcDailyCap.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty,
              let parsed = Double(trimmed),
              parsed.isFinite,
              parsed > 0,
              parsed <= Self.maximumUsdcCap else { return nil }
        return parsed
    }

    private var capError: String? {
        let trimmed = usdcDailyCap.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard let parsed = Double(trimmed), parsed.isFinite, parsed > 0 else {
            return Self.usdcCapError
        }
        guard parsed <= Self.maximumUsdcCap else {
            return Self.usdcCapTooLargeError
        }
        return nil
    }
}

nonisolated struct TargetAllowlistRowPresentation: Equatable, Sendable {
    let removeAccessibilityLabel: String
    let removeHelp: String

    static func make(chainId: Int, address: String) -> TargetAllowlistRowPresentation {
        let canonical = EthereumAddressInput.canonical(address)
        return TargetAllowlistRowPresentation(
            removeAccessibilityLabel: "Remove target \(canonical) on chain \(chainId)",
            removeHelp: "Remove \(canonical) from the chain \(chainId) target allowlist and clear its per-target cap."
        )
    }
}

nonisolated enum TargetAllowlistMutation {
    static func add(_ entry: TargetAllowlistEntry, to rules: RuleConfig) -> RuleConfig {
        let key = String(entry.chainId)
        let normalized = EthereumAddressInput.canonical(entry.address)
        var updated = rules
        var allowed = updated.allowedTargets ?? [:]
        var addresses = allowed[key] ?? []

        if !addresses.contains(where: { $0.caseInsensitiveCompare(normalized) == .orderedSame }) {
            addresses.append(normalized)
        }
        allowed[key] = addresses.sorted()
        updated.allowedTargets = allowed

        if let raw = entry.usdcAllowanceRaw {
            updated.spendingLimits.removeAll {
                $0.targetAddress?.caseInsensitiveCompare(normalized) == .orderedSame && $0.token == .usdc
            }
            updated.spendingLimits.append(
                SpendingLimitRule(token: .usdc, allowance: raw, windowSeconds: 86_400, targetAddress: normalized)
            )
        }

        return updated
    }

    static func remove(chainId: Int, address: String, from rules: RuleConfig) -> RuleConfig {
        let normalized = EthereumAddressInput.canonical(address)
        let key = String(chainId)
        var updated = rules
        var allowed = updated.allowedTargets ?? [:]
        var addresses = allowed[key] ?? []

        addresses.removeAll { $0.caseInsensitiveCompare(normalized) == .orderedSame }
        if addresses.isEmpty {
            allowed.removeValue(forKey: key)
        } else {
            allowed[key] = addresses
        }

        updated.allowedTargets = allowed.isEmpty ? nil : allowed
        updated.spendingLimits.removeAll {
            $0.targetAddress?.caseInsensitiveCompare(normalized) == .orderedSame
        }
        return updated
    }

    static func targetLimit(for address: String, in rules: RuleConfig) -> SpendingLimitRule? {
        let normalized = EthereumAddressInput.canonical(address)
        return rules.spendingLimits.first {
            $0.targetAddress?.caseInsensitiveCompare(normalized) == .orderedSame
        }
    }
}

nonisolated enum TargetAllowlistPresentation {
    static let emptyLabel = "—"

    static func capLabel(for address: String, in rules: RuleConfig) -> String {
        guard let limit = TargetAllowlistMutation.targetLimit(for: address, in: rules) else {
            return emptyLabel
        }
        return "\(formatAllowance(limit.allowance, token: limit.token)) \(limit.token.displayName)"
    }

    static func usedLabel(for address: String, in rules: RuleConfig, stateStore: StateStore) -> String {
        guard let limit = TargetAllowlistMutation.targetLimit(for: address, in: rules) else {
            return emptyLabel
        }
        let status = stateStore.spendingLimitStatus(rule: limit)
        return "\(formatAllowance(status.spent, token: limit.token)) \(limit.token.displayName)"
    }

    private static func formatAllowance(_ raw: String, token: TokenIdentifier) -> String {
        GlobalCapTilePresentation.formatAllowance(raw, decimals: token.decimals)
    }
}

nonisolated struct PosturePickerSegmentPresentation: Equatable, Sendable {
    let posture: SigningPosture
    let shortLabel: String
    let accessibilityLabel: String
    let accessibilityHint: String
    let isSelected: Bool
}

nonisolated enum PosturePickerPresentation {
    static let orderedPostures: [SigningPosture] = [
        .enforceRulesAndAutoSign,
        .enforceRulesAndRequireApproval,
        .requireApprovalWithoutRuleEvaluation,
    ]

    static func segments(selected: SigningPosture) -> [PosturePickerSegmentPresentation] {
        orderedPostures.map { posture in
            PosturePickerSegmentPresentation(
                posture: posture,
                shortLabel: shortLabel(for: posture),
                accessibilityLabel: posture.displayName,
                accessibilityHint: posture.hint,
                isSelected: posture == selected
            )
        }
    }

    private static func shortLabel(for posture: SigningPosture) -> String {
        switch posture {
        case .enforceRulesAndAutoSign:
            return "Auto-sign"
        case .enforceRulesAndRequireApproval:
            return "Always confirm"
        case .requireApprovalWithoutRuleEvaluation:
            return "Skip rules"
        }
    }
}

nonisolated struct CapTilePresentation: Equatable, Sendable {
    let label: String
    let value: String
    let used: Double?
    let total: Double?
    let unit: String
    let warn: Bool

    var showsUsage: Bool {
        guard let used, let total else { return false }
        return used >= 0 && total > 0
    }
}

nonisolated enum GlobalCapTilePresentation {
    static func spendingLimit(
        prefix: String,
        rule: SpendingLimitRule,
        status: SpendingLimitStatus
    ) -> CapTilePresentation {
        let decimals = rule.token.decimals
        return CapTilePresentation(
            label: label(prefix: prefix, windowSeconds: rule.windowSeconds),
            value: formatAllowance(status.allowance, decimals: decimals),
            used: tokenAmount(status.spent, decimals: decimals),
            total: tokenAmount(status.allowance, decimals: decimals),
            unit: " \(rule.token.displayName)",
            warn: status.remaining == "0"
        )
    }

    static func rateLimit(rule: RateLimitRule, status: RateLimitStatus) -> CapTilePresentation {
        CapTilePresentation(
            label: "Signatures/\(RateLimitRule.formatWindow(rule.windowSeconds))",
            value: "\(rule.maxRequests)",
            used: Double(status.currentCount),
            total: Double(status.maxRequests),
            unit: "",
            warn: status.remaining == 0
        )
    }

    static func allowedHours(_ hours: AllowedHours?) -> CapTilePresentation {
        let value: String
        if let hours {
            value = String(format: "%02d:00 – %02d:00", hours.start, hours.end)
        } else {
            value = "any time"
        }

        return CapTilePresentation(
            label: "Allowed hours",
            value: value,
            used: nil,
            total: nil,
            unit: "",
            warn: false
        )
    }

    static func tokenAmount(_ raw: String, decimals: Int) -> Double {
        Double(raw).map { $0 / pow(10, Double(decimals)) } ?? 0
    }

    static func formatAllowance(_ raw: String, decimals: Int) -> String {
        let n = tokenAmount(raw, decimals: decimals)
        if n == n.rounded() && n < 1e9 {
            return String(Int(n))
        }
        return String(format: n < 1 ? "%.4g" : "%.2f", n)
    }

    private static func label(prefix: String, windowSeconds: Int?) -> String {
        guard let windowSeconds else { return "\(prefix)/lifetime" }
        return "\(prefix)/\(RateLimitRule.formatWindow(windowSeconds))"
    }
}

nonisolated struct AuthOptionPresentation: Equatable, Sendable {
    let policy: AuthPolicy
    let label: String
    let hint: String
    let isSelected: Bool
}

nonisolated enum AuthPolicyPickerPresentation {
    static let violationWarning = "Rule violations always require owner authentication, regardless of this setting."

    static let orderedPolicies: [AuthPolicy] = [
        .open,
        .biometric,
        .biometricOrPasscode,
    ]

    static func options(selected: AuthPolicy) -> [AuthOptionPresentation] {
        orderedPolicies.map { policy in
            AuthOptionPresentation(
                policy: policy,
                label: label(for: policy),
                hint: hint(for: policy),
                isSelected: policy == selected
            )
        }
    }

    private static func label(for policy: AuthPolicy) -> String {
        switch policy {
        case .open:
            return "Silent"
        case .biometric:
            return "Biometric"
        case .biometricOrPasscode:
            return "Always confirm"
        case .passcode:
            return "Passcode"
        }
    }

    private static func hint(for policy: AuthPolicy) -> String {
        switch policy {
        case .open:
            return "Complete matching requests"
        case .biometric:
            return "Touch ID required after rules pass"
        case .biometricOrPasscode:
            return "Owner approves every request"
        case .passcode:
            return "Device passcode required after rules pass"
        }
    }
}

nonisolated struct HighValueRuleDraft: Equatable, Sendable {
    static let requiredThresholdError = "Threshold is required when high-value confirmation is enabled."
    static let positiveThresholdError = "Threshold must be a positive number."

    var enabled: Bool
    var thresholdText: String
    var confirmationPhrase: String

    var validationMessage: String? {
        guard enabled else { return nil }
        guard !trimmedThresholdText.isEmpty else {
            return Self.requiredThresholdError
        }
        guard thresholdUsd != nil else {
            return Self.positiveThresholdError
        }
        return nil
    }

    var thresholdUsd: Double? {
        guard let parsed = Double(trimmedThresholdText), parsed.isFinite, parsed > 0 else {
            return nil
        }
        return parsed
    }

    var normalizedConfirmationPhrase: String {
        let trimmed = confirmationPhrase.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? HighValueRule.default.confirmationPhrase : trimmed
    }

    static func thresholdText(for thresholdUsd: Double) -> String {
        thresholdUsd.rounded() == thresholdUsd ? String(Int(thresholdUsd)) : String(thresholdUsd)
    }

    private var trimmedThresholdText: String {
        thresholdText.trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

nonisolated enum ZeroDevProjectIdInput {
    static func normalized(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }
}

nonisolated struct ChainRPCPreferenceDraft: Equatable, Sendable {
    static let chainIdError = "Chain ID must be a positive integer."
    static let rpcURLError = "RPC URL must be an http or https URL."

    var chainId: String
    var rpcURL: String

    var validationMessage: String? {
        if parsedChainId == nil {
            return Self.chainIdError
        }
        if normalizedRPCURL == nil {
            return Self.rpcURLError
        }
        return nil
    }

    func makePreference() -> ChainRPCPreference? {
        guard validationMessage == nil,
              let chainId = parsedChainId,
              let rpcURL = normalizedRPCURL else { return nil }
        return ChainRPCPreference(chainId: chainId, rpcURL: rpcURL)
    }

    static func upsert(_ preference: ChainRPCPreference, into preferences: BundlerPreferences) -> BundlerPreferences {
        var updated = preferences
        if let idx = updated.chainRPCs.firstIndex(where: { $0.chainId == preference.chainId }) {
            updated.chainRPCs[idx] = preference
        } else {
            updated.chainRPCs.append(preference)
            updated.chainRPCs.sort { $0.chainId < $1.chainId }
        }
        return updated
    }

    private var parsedChainId: Int? {
        let trimmed = chainId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let parsed = Int(trimmed), parsed > 0 else { return nil }
        return parsed
    }

    private var normalizedRPCURL: String? {
        let trimmed = rpcURL.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed),
              let scheme = url.scheme?.lowercased(),
              ["http", "https"].contains(scheme),
              url.host != nil else { return nil }
        return trimmed
    }
}

nonisolated struct RPCProbePresentation: Equatable, Sendable {
    let buttonTitle: String
    let isButtonDisabled: Bool

    static func make(isProbing: Bool, endpointCount: Int) -> RPCProbePresentation {
        RPCProbePresentation(
            buttonTitle: isProbing ? "Probing…" : "Probe now",
            isButtonDisabled: isProbing || endpointCount == 0
        )
    }

    static func status(for sample: RPCHealthSample?) -> RPCStatus {
        sample?.status ?? .unknown
    }

    static func latencyLabel(_ sample: RPCHealthSample?) -> String {
        guard let sample else { return "not probed" }
        if sample.status != .ok, let error = sample.error {
            return error
        }
        if let latency = sample.latencyMs {
            return "\(latency)ms"
        }
        return sample.error ?? "timeout"
    }
}

nonisolated struct SaveBarPresentation: Equatable, Sendable {
    let changeCount: Int
    let subtitle: String
    let saveButtonTitle: String
    let actionsDisabled: Bool
}

nonisolated enum SettingsDiffPresentation {
    static func hasUnsavedChanges(saved: BastionConfig, draft: BastionConfig) -> Bool {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        guard let draftData = try? encoder.encode(draft),
              let savedData = try? encoder.encode(saved) else {
            return false
        }
        return draftData != savedData
    }

    static func saveBar(saved: BastionConfig, draft: BastionConfig, isSaving: Bool) -> SaveBarPresentation {
        let changeCount = diffLines(saved: saved, draft: draft).count
        return SaveBarPresentation(
            changeCount: changeCount,
            subtitle: "\(changeCount) changes will affect running agents on next request",
            saveButtonTitle: isSaving ? "Saving…" : "Save",
            actionsDisabled: isSaving
        )
    }

    static func diffLines(saved: BastionConfig, draft: BastionConfig) -> [DiffLine] {
        var lines: [DiffLine] = []
        if saved.authPolicy != draft.authPolicy {
            lines.append(DiffLine(
                removed: "Auth policy: \(saved.authPolicy.displayName)",
                added: "Auth policy: \(draft.authPolicy.displayName)"
            ))
        }

        let savedHours = formatHours(saved.rules.allowedHours)
        let draftHours = formatHours(draft.rules.allowedHours)
        if savedHours != draftHours {
            lines.append(DiffLine(
                removed: "Allowed hours: \(savedHours)",
                added: "Allowed hours: \(draftHours)"
            ))
        }

        if saved.rules.spendingLimits.count != draft.rules.spendingLimits.count {
            lines.append(DiffLine(
                removed: "Spending limits: \(saved.rules.spendingLimits.count) rules",
                added: "Spending limits: \(draft.rules.spendingLimits.count) rules"
            ))
        }

        if saved.rules.rateLimits.count != draft.rules.rateLimits.count {
            lines.append(DiffLine(
                removed: "Rate limits: \(saved.rules.rateLimits.count) rules",
                added: "Rate limits: \(draft.rules.rateLimits.count) rules"
            ))
        }

        if saved.rules.rawMessagePolicy.enabled != draft.rules.rawMessagePolicy.enabled {
            lines.append(DiffLine(
                removed: "Raw message signing: \(saved.rules.rawMessagePolicy.enabled ? "on" : "off")",
                added: "Raw message signing: \(draft.rules.rawMessagePolicy.enabled ? "on" : "off")"
            ))
        }

        if saved.rules.typedDataPolicy.enabled != draft.rules.typedDataPolicy.enabled {
            lines.append(DiffLine(
                removed: "EIP-712 typed data: \(saved.rules.typedDataPolicy.enabled ? "on" : "off")",
                added: "EIP-712 typed data: \(draft.rules.typedDataPolicy.enabled ? "on" : "off")"
            ))
        }
        let savedProjectId = ZeroDevProjectIdInput.normalized(saved.bundlerPreferences.zeroDevProjectId ?? "")
        let draftProjectId = ZeroDevProjectIdInput.normalized(draft.bundlerPreferences.zeroDevProjectId ?? "")
        if savedProjectId != draftProjectId {
            lines.append(DiffLine(
                removed: "ZeroDev project ID: \(savedProjectId == nil ? "unset" : "configured")",
                added: "ZeroDev project ID: \(draftProjectId == nil ? "unset" : "configured")"
            ))
        }
        if saved.bundlerPreferences.chainRPCs.map(\.chainId) != draft.bundlerPreferences.chainRPCs.map(\.chainId)
            || saved.bundlerPreferences.chainRPCs.map(\.rpcURL) != draft.bundlerPreferences.chainRPCs.map(\.rpcURL) {
            lines.append(DiffLine(
                removed: "RPC endpoints: \(saved.bundlerPreferences.chainRPCs.count) configured",
                added: "RPC endpoints: \(draft.bundlerPreferences.chainRPCs.count) configured"
            ))
        }
        return lines
    }

    static func formatHours(_ hours: AllowedHours?) -> String {
        guard let h = hours else { return "any time" }
        return String(format: "%02d:00–%02d:00", h.start, h.end)
    }
}

nonisolated struct PolicyHistoryRestoreResult: Sendable {
    let draftConfig: BastionConfig
    let selection: SettingsSelection
    let statusMessage: String
    let statusIsError: Bool
    let requiresSave: Bool
}

nonisolated enum PolicyHistoryRestore {
    static func loadDraft(_ config: BastionConfig, savedConfig: BastionConfig? = nil) -> PolicyHistoryRestoreResult {
        PolicyHistoryRestoreResult(
            draftConfig: config,
            selection: .defaultProfile,
            statusMessage: "Loaded version into draft. Review and Save to apply.",
            statusIsError: false,
            requiresSave: savedConfig.map { SettingsDiffPresentation.hasUnsavedChanges(saved: $0, draft: config) } ?? true
        )
    }
}

nonisolated struct PolicyHistoryRecoveryCardPresentation: Equatable, Sendable {
    let title: String
    let metadata: String
    let exportButtonTitle: String
    let exportButtonDisabled: Bool
    let loadBackupButtonTitle: String?
    let exportStatus: String?
    let exportError: String?
}

nonisolated struct PolicyHistoryBackupCardPresentation: Equatable, Sendable {
    let title: String
    let metadata: String
    let loadButtonTitle: String
}

nonisolated struct PolicyHistoryVersionRowPresentation: Equatable, Sendable, Identifiable {
    let id: String
    let timestamp: String
    let summary: String
    let restoreButtonTitle: String

    static func make(version: PolicyVersion, timeZone: TimeZone = .current) -> PolicyHistoryVersionRowPresentation {
        PolicyHistoryVersionRowPresentation(
            id: version.id,
            timestamp: PolicyHistoryPanelPresentation.displayTimestamp(version.timestamp, timeZone: timeZone),
            summary: version.summary,
            restoreButtonTitle: "Restore"
        )
    }
}

nonisolated struct PolicyHistoryPanelPresentation: Equatable, Sendable {
    let title: String
    let subtitle: String
    let recovery: PolicyHistoryRecoveryCardPresentation?
    let backup: PolicyHistoryBackupCardPresentation?
    let savedVersionsTitle: String
    let emptyVersionsMessage: String?
    let versions: [PolicyHistoryVersionRowPresentation]

    static func make(
        versions: [PolicyVersion],
        premigrationBackup: BastionConfig?,
        recoverySnapshot: RuleEngine.ConfigRecoverySnapshot?,
        recoveryExportStatus: String?,
        recoveryExportError: String?,
        recoveryExportIsExporting: Bool = false,
        timeZone: TimeZone = .current
    ) -> PolicyHistoryPanelPresentation {
        PolicyHistoryPanelPresentation(
            title: "Policy history",
            subtitle: "Every saved policy change is snapshotted. Restore an older version with biometric auth.",
            recovery: recoverySnapshot.map {
                PolicyHistoryRecoveryCardPresentation(
                    title: "Corrupt config recovery",
                    metadata: "\($0.reason) · \($0.byteCount) bytes · \(displayTimestamp($0.capturedAt, timeZone: timeZone))",
                    exportButtonTitle: recoveryExportIsExporting ? "Exporting…" : "Export raw",
                    exportButtonDisabled: recoveryExportIsExporting,
                    loadBackupButtonTitle: premigrationBackup == nil ? nil : "Load backup",
                    exportStatus: recoveryExportStatus,
                    exportError: recoveryExportError
                )
            },
            backup: premigrationBackup.map {
                PolicyHistoryBackupCardPresentation(
                    title: "Pre-migration backup",
                    metadata: "Schema v\($0.version) · auth=\($0.authPolicy.rawValue) · clients=\($0.clientProfiles.count)",
                    loadButtonTitle: "Load backup"
                )
            },
            savedVersionsTitle: "Saved versions",
            emptyVersionsMessage: versions.isEmpty ? "No prior versions recorded yet." : nil,
            versions: versions.map {
                PolicyHistoryVersionRowPresentation.make(version: $0, timeZone: timeZone)
            }
        )
    }

    static func displayTimestamp(_ date: Date, timeZone: TimeZone = .current) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateStyle = .medium
        formatter.timeStyle = .medium
        return formatter.string(from: date)
    }
}

nonisolated enum PolicyRecoverySnapshotExportPresentation {
    static func defaultFileName(for date: Date, timeZone: TimeZone = .current) -> String {
        "bastion-corrupt-config-\(timestamp(date, timeZone: timeZone)).json"
    }

    static func successMessage(for url: URL) -> String {
        "Exported \(url.lastPathComponent)"
    }

    static func failureMessage(for error: Error) -> String {
        "Export failed: \(error.localizedDescription)"
    }

    private static func timestamp(_ date: Date, timeZone: TimeZone) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = timeZone
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: date)
    }
}

nonisolated struct PolicyRecoverySnapshotExportState: Equatable, Sendable {
    var status: String?
    var error: String?
    var isExporting = false

    mutating func beginExport() -> Bool {
        guard !isExporting else { return false }
        isExporting = true
        status = nil
        error = nil
        return true
    }

    mutating func cancelExport() {
        isExporting = false
    }

    mutating func succeed(url: URL) {
        status = PolicyRecoverySnapshotExportPresentation.successMessage(for: url)
        error = nil
        isExporting = false
    }

    mutating func fail(_ error: Error) {
        status = nil
        self.error = PolicyRecoverySnapshotExportPresentation.failureMessage(for: error)
        isExporting = false
    }
}

struct RulesSettingsView: View {
    @State private var draftConfig: BastionConfig = .default
    @State private var savedConfig: BastionConfig = .default
    @State private var selection: SettingsSelection = .defaultProfile
    @State private var isSaving = false
    @State private var statusMessage = ""
    @State private var statusIsError = false
    @State private var showDiffSheet = false
    @State private var showPairingFlow = false
    @Environment(\.dismiss) private var dismissSettings

    private let ruleEngine = RuleEngine.shared

    var hasUnsavedChanges: Bool {
        SettingsDiffPresentation.hasUnsavedChanges(saved: savedConfig, draft: draftConfig)
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            HStack(spacing: 0) {
                sidebar.frame(width: 230)
                MacDivider()
                mainPanel
            }

            if hasUnsavedChanges {
                saveBar.transition(.move(edge: .bottom))
            }
        }
        .frame(minWidth: 980, minHeight: 640)
        .background(Color.paper)
        .onAppear { loadConfig() }
        .sheet(isPresented: $showDiffSheet) {
            DiffSheet(diffLines: diffLines(),
                      isSaving: isSaving,
                      onCancel: { showDiffSheet = false },
                      onSave: { showDiffSheet = false; persistDraft() })
        }
        .sheet(isPresented: $showPairingFlow) {
            PairingFlowView { result in
                finishPairing(result)
            }
        }
    }

    // MARK: - Sidebar

    private var sidebar: some View {
        let navigation = SettingsNavigationPresentation.make(config: draftConfig, selection: selection)
        return VStack(alignment: .leading, spacing: 0) {
            // Note: the v2 redesign mock-up assumed a chromeless window and
            // drew a fake "Bastion · Settings" label + decorative traffic
            // lights here. The SwiftUI `Settings` scene gives this window
            // a real macOS title bar, so the fake header used to stack on
            // top of the real one. Killing the fake row removes both
            // visual clutter and the cosmetic "red/yellow/green dots that
            // don't do anything" complaint.
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    SidebarSection(title: "Defaults") {
                        ForEach(navigation.defaultItems) { item in
                            sidebarRow(item)
                        }
                    }

                    SidebarSection(title: "Clients", trailing: AnyView(
                        Button {
                            showPairingFlow = true
                        } label: { Text("+").font(.system(size: 12)) }
                            .bastionButton(.ghost, size: .small)
                    )) {
                        if let message = navigation.clientsEmptyMessage {
                            Text(message)
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                        }
                        ForEach(navigation.clientItems) { item in
                            sidebarRow(item, statusDot: .idle)
                        }
                    }

                    SidebarSection(title: "Wallet groups") {
                        if let message = navigation.walletGroupsEmptyMessage {
                            Text(message)
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                                .padding(.horizontal, 12).padding(.vertical, 6)
                        }
                        ForEach(navigation.walletGroupItems) { item in
                            sidebarRow(item)
                        }
                    }
                }
                .padding(.vertical, 4)
            }

            BastionDivider()

            VStack(spacing: 8) {
                Button {
                    AuditHistoryWindowManager.shared.showWindow()
                } label: {
                    HStack {
                        Text("Audit history")
                        Spacer()
                        Text("⌘⇧H")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Color.ink400)
                    }
                    .frame(maxWidth: .infinity)
                }
                .bastionButton(.default)
                if !statusMessage.isEmpty {
                    Text(statusMessage)
                        .font(.system(size: 11))
                        .foregroundStyle(statusIsError ? Color.bastionBad : Color.bastionOk)
                        .lineLimit(2)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }
            .padding(10)
        }
        .background(Color.ink50)
    }

    private func sidebarRow(
        _ item: SettingsSidebarItemPresentation,
        statusDot: StatusDot.State? = nil
    ) -> some View {
        SidebarRow(
            label: item.label,
            sublabel: item.sublabel,
            icon: sidebarIcon(item.icon),
            statusDot: statusDot,
            selected: item.selected
        ) {
            selection = item.selection
        }
    }

    private func sidebarIcon(_ icon: SettingsSidebarIcon) -> AnyView? {
        switch icon {
        case .shield:
            return AnyView(ShieldGlyph(size: 13, color: .ink500))
        case .gear:
            return AnyView(GearGlyph(size: 13))
        case .templates:
            return AnyView(TemplatesGlyph(size: 13))
        case .warning:
            return AnyView(WarnGlyph(size: 13))
        case .book:
            return AnyView(BookGlyph(size: 13))
        case .simulator:
            return AnyView(SimulatorGlyph(size: 13))
        case .history:
            return AnyView(HistoryGlyph(size: 13))
        case .group:
            return AnyView(GroupGlyph(size: 13))
        case .none:
            return nil
        }
    }

    // MARK: - Main panel

    @ViewBuilder
    private var mainPanel: some View {
        switch SettingsNavigationPresentation.mainPanelRoute(config: draftConfig, selection: selection) {
        case .appPreferences:
            AppPreferencesPanel(
                bundlerPreferences: Binding(
                    get: { draftConfig.bundlerPreferences },
                    set: { draftConfig.bundlerPreferences = $0 }
                )
            )
        case .addressBook:
            AddressBookPanel(addressBook: Binding(
                get: { draftConfig.addressBook },
                set: { draftConfig.addressBook = $0 }
            ))
        case .policySimulator:
            PolicySimulatorView(config: draftConfig)
        case .policyHistory:
            PolicyHistoryPanel(onRestore: restoreVersion)
        case .highValueRule:
            HighValueRulePanel(highValue: Binding(
                get: { draftConfig.highValue },
                set: { draftConfig.highValue = $0 }
            ))
        case .ruleTemplates:
            RuleTemplatesPanel(
                profileCount: draftConfig.clientProfiles.count,
                onApplyToDefault: applyTemplateToDefault,
                onPair: { showPairingFlow = true }
            )
        case .defaultProfile:
            ProfilePanel(
                profileLabel: "Default profile",
                profileSubtitle: "Applies to clients without an explicit profile",
                rulesBinding: Binding(
                    get: { draftConfig.rules },
                    set: { draftConfig.rules = $0 }
                ),
                authPolicyBinding: Binding(
                    get: { draftConfig.authPolicy },
                    set: { draftConfig.authPolicy = $0 }
                ),
                profile: nil,
                onLaunchTestApproval: launchTestApproval,
                onLaunchTestViolation: launchTestViolation
            )
        case .client(let id):
            if let idx = draftConfig.clientProfiles.firstIndex(where: { $0.id == id }) {
                ProfilePanel(
                    profileLabel: draftConfig.clientProfiles[idx].label ?? draftConfig.clientProfiles[idx].bundleId,
                    profileSubtitle: draftConfig.clientProfiles[idx].bundleId,
                    rulesBinding: Binding(
                        get: { draftConfig.clientProfiles[idx].rules },
                        set: { draftConfig.clientProfiles[idx].rules = $0 }
                    ),
                    authPolicyBinding: Binding(
                        get: { draftConfig.clientProfiles[idx].authPolicy ?? draftConfig.authPolicy },
                        set: { draftConfig.clientProfiles[idx].authPolicy = $0 }
                    ),
                    profile: draftConfig.clientProfiles[idx],
                    onLaunchTestApproval: launchTestApproval,
                    onLaunchTestViolation: launchTestViolation
                )
            } else {
                EmptySelection()
            }
        case .walletGroup(let id):
            if let group = draftConfig.walletGroups.first(where: { $0.id == id }) {
                WalletGroupPanel(group: group)
            } else {
                EmptySelection()
            }
        case .emptySelection:
            EmptySelection()
        }
    }

    // MARK: - Save bar

    private var saveBar: some View {
        let presentation = SettingsDiffPresentation.saveBar(
            saved: savedConfig,
            draft: draftConfig,
            isSaving: isSaving
        )
        return HStack {
            VStack(alignment: .leading, spacing: 1) {
                Text("Unsaved changes")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(Color.bastionAccentDeep)
                Text(presentation.subtitle)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.ink500)
            }
            Spacer()
            Button("Discard") { draftConfig = savedConfig }
                .bastionButton(.default)
                .disabled(presentation.actionsDisabled)
            Button("Review diff") { showDiffSheet = true }
                .bastionButton(.default)
                .disabled(presentation.actionsDisabled)
            Button(presentation.saveButtonTitle) { persistDraft() }
                .bastionButton(.primary)
                .disabled(presentation.actionsDisabled)
        }
        .padding(EdgeInsets(top: 12, leading: 28, bottom: 12, trailing: 28))
        .background(
            Color.bastionAccentSoft.opacity(0.55)
                .overlay(Color.paper.opacity(0.65))
        )
        .overlay(BastionDivider(), alignment: .top)
    }

    // MARK: - Logic

    private func loadConfig() {
        let cfg = ruleEngine.config
        draftConfig = cfg
        savedConfig = cfg
        if case .client(let id) = selection,
           !cfg.clientProfiles.contains(where: { $0.id == id }) {
            selection = .defaultProfile
        }
    }

    /// Loads a previous policy version into the draft config. The save bar
    /// will appear so the owner can review and confirm — this never restores
    /// silently.
    private func restoreVersion(_ config: BastionConfig) {
        let result = PolicyHistoryRestore.loadDraft(config, savedConfig: savedConfig)
        draftConfig = result.draftConfig
        selection = result.selection
        statusMessage = result.statusMessage
        statusIsError = result.statusIsError
    }

    private func persistDraft() {
        guard !isSaving else { return }
        isSaving = true
        statusMessage = ""
        let snapshot = draftConfig
        Task {
            do {
                try await ruleEngine.updateConfig(snapshot)
                await MainActor.run {
                    savedConfig = snapshot
                    statusMessage = "Saved"
                    statusIsError = false
                    isSaving = false
                }
            } catch {
                await MainActor.run {
                    statusMessage = "Error: \(error.localizedDescription)"
                    statusIsError = true
                    isSaving = false
                }
            }
        }
    }

    private func launchTestApproval() {
        #if DEBUG
        launchApprovalPreview(SigningRequestPreviewFactory.policyReview())
        #endif
    }

    private func launchTestViolation() {
        #if DEBUG
        launchApprovalPreview(SigningRequestPreviewFactory.ruleOverride())
        #endif
    }

    #if DEBUG
    private func launchApprovalPreview(_ approval: ApprovalRequest) {
        let settingsWindow = NSApp.keyWindow
        dismissSettings()
        SettingsApprovalPreviewPresenter.hideSettingsWindowBeforePreview(settingsWindow)
        DispatchQueue.main.asyncAfter(deadline: .now() + SettingsApprovalPreviewTiming.presentationDelay) {
            SigningRequestPanelManager.shared.showRequest(
                approval,
                onApprove: {},
                onDeny: {}
            )
        }
    }
    #endif

    private func applyTemplateToDefault(_ template: PairingPolicyTemplate) {
        let result = RuleTemplateApplication.applyToDefault(template, config: draftConfig)
        draftConfig = result.config
        statusMessage = result.statusMessage
        statusIsError = result.statusIsError
        selection = result.selection
    }

    private func finishPairing(_ result: PairingResult) {
        let bundleId = result.bundleId
        guard !bundleId.isEmpty else {
            statusMessage = "Pairing failed: bundle ID is required"
            statusIsError = true
            return
        }

        var rules = result.template.rules
        rules.allowedChains = result.allowedChains.isEmpty ? nil : result.allowedChains

        if let existing = draftConfig.clientProfiles.firstIndex(where: { $0.bundleId.caseInsensitiveCompare(bundleId) == .orderedSame }) {
            draftConfig.clientProfiles[existing].label = result.displayName.isEmpty ? nil : result.displayName
            draftConfig.clientProfiles[existing].authPolicy = result.template.authPolicy
            draftConfig.clientProfiles[existing].rules = rules
            selection = .client(id: draftConfig.clientProfiles[existing].id)
        } else {
            let profile = ClientProfile(
                bundleId: bundleId,
                label: result.displayName.isEmpty ? nil : result.displayName,
                authPolicy: result.template.authPolicy,
                rules: rules
            )
            draftConfig.clientProfiles.append(profile)
            draftConfig.clientProfiles.sort {
                $0.displayDescription.localizedCaseInsensitiveCompare($1.displayDescription) == .orderedAscending
            }
            selection = .client(id: profile.id)
        }

        statusMessage = "Paired \(result.displayName.isEmpty ? bundleId : result.displayName)"
        statusIsError = false
    }

    private func diffLines() -> [DiffLine] {
        SettingsDiffPresentation.diffLines(saved: savedConfig, draft: draftConfig)
    }
}

// MARK: - MacDivider (vertical 1px hairline)

private struct MacDivider: View {
    var body: some View {
        Rectangle().fill(Color.ink150).frame(width: 1)
    }
}

// MARK: - Sidebar bits

private struct SidebarSection<Content: View>: View {
    let title: String
    var trailing: AnyView? = nil
    @ViewBuilder let content: () -> Content

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack {
                BastionSectionLabel(text: title)
                Spacer()
                if let trailing { trailing }
            }
            .padding(EdgeInsets(top: 8, leading: 12, bottom: 4, trailing: 12))
            content()
        }
        .padding(.bottom, 6)
    }
}

private struct SidebarRow: View {
    let label: String
    var sublabel: String? = nil
    var icon: AnyView? = nil
    var statusDot: StatusDot.State? = nil
    let selected: Bool
    let action: () -> Void

    @State private var hovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: 8) {
                if let icon {
                    icon.frame(width: 16)
                } else if let dot = statusDot {
                    StatusDot(state: dot)
                        .padding(.horizontal, 4.5)
                } else {
                    Color.clear.frame(width: 16)
                }
                VStack(alignment: .leading, spacing: 1) {
                    Text(label)
                        .font(.system(size: 12.5, weight: selected ? .medium : .regular))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    if let sublabel {
                        Text(sublabel)
                            .font(.system(size: 10.5, design: .monospaced))
                            .foregroundStyle(Color.ink500)
                            .lineLimit(1)
                            .truncationMode(.middle)
                    }
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 8).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(selected ? Color.paper : (hovered ? Color.ink100 : .clear))
                    .overlay(
                        RoundedRectangle(cornerRadius: 6)
                            .strokeBorder(selected ? Color.ink150 : .clear, lineWidth: 1)
                    )
                    .shadow(color: selected ? Color.black.opacity(0.04) : .clear, radius: 1, y: 1)
            )
        }
        .buttonStyle(.plain)
        .onHover { hovered = $0 }
        .padding(.horizontal, 8)
        .padding(.bottom, 1)
        .accessibilityLabel(sublabel.map { "\(label), \($0)" } ?? label)
        .accessibilityAddTraits(selected ? [.isSelected, .isButton] : .isButton)
    }
}

private struct GearGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "gear")
            .font(.system(size: size, weight: .regular))
            .foregroundStyle(Color.ink500)
    }
}

private struct GroupGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "person.2.fill")
            .font(.system(size: size * 0.85))
            .foregroundStyle(Color.ink500)
    }
}

private struct TemplatesGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "list.bullet.rectangle.portrait")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct WarnGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "exclamationmark.triangle")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct BookGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "book")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct SimulatorGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "play.rectangle")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct HistoryGlyph: View {
    var size: CGFloat = 14
    var body: some View {
        Image(systemName: "clock.arrow.circlepath")
            .font(.system(size: size * 0.95))
            .foregroundStyle(Color.ink500)
    }
}

private struct EmptySelection: View {
    var body: some View {
        VStack(spacing: 6) {
            Spacer()
            Text("Selection unavailable").font(.system(size: 14, weight: .medium))
            Text("The item you selected no longer exists.")
                .font(.system(size: 12))
                .foregroundStyle(Color.ink500)
            Spacer()
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

// MARK: - Profile panel (default OR per-client)

private struct ProfilePanel: View {
    let profileLabel: String
    let profileSubtitle: String
    @Binding var rulesBinding: RuleConfig
    @Binding var authPolicyBinding: AuthPolicy
    let profile: ClientProfile?
    let onLaunchTestApproval: () -> Void
    let onLaunchTestViolation: () -> Void

    @State private var validatorActionMessage: String? = nil
    @State private var validatorActionIsError = false
    @State private var validatorActionInFlight = false
    @State private var showAddTarget = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            header
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    operationsCard
                    targetsCard
                    globalCapsCard
                    authCard
                    if let profile { validatorCard(profile: profile) }
                }
                .padding(EdgeInsets(top: 18, leading: 28, bottom: 80, trailing: 28))
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .sheet(isPresented: $showAddTarget) {
            AddTargetSheet { entry in
                addTarget(entry)
                showAddTarget = false
            } onCancel: {
                showAddTarget = false
            }
        }
    }

    private var header: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 10) {
                    Text(profileLabel)
                        .font(.system(size: 18, weight: .semibold))
                        .kerning(-0.36)
                    BastionChip(label: profileSubtitle, style: .outline)
                    if let profile, let activity = profileActivity(profile) {
                        BastionChip(label: activity.label, style: activity.style,
                                    leading: AnyView(StatusDot(state: activity.dot)))
                    }
                }
                if let profile, let address = accountAddressForProfile(profile) {
                    HStack(spacing: 10) {
                        Text("Account").font(.system(size: 12)).foregroundStyle(Color.ink500)
                        AddressView(address: address)
                    }
                }
            }
            Spacer()
            #if DEBUG
            HStack(spacing: 8) {
                Button("Test approval", action: onLaunchTestApproval)
                    .bastionButton(.default)
                Button("Test violation", action: onLaunchTestViolation)
                    .bastionButton(.danger)
            }
            #endif
        }
        .padding(EdgeInsets(top: 18, leading: 28, bottom: 16, trailing: 28))
    }

    private var operationsCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 0) {
                BastionSectionHeader(
                    title: "Operations",
                    subtitle: "Posture per operation type. Posture replaces the old enable/approve toggle pair so the behaviour you pick is unambiguous."
                )
                PosturePicker(
                    label: "Raw / personal-sign messages",
                    hint: "EIP-191. No chain or contract binding.",
                    binding: Binding(
                        get: { rulesBinding.rawMessagePolicy.posture },
                        set: { rulesBinding.rawMessagePolicy.posture = $0 }
                    )
                )
                BastionDivider()
                PosturePicker(
                    label: "EIP-712 typed data",
                    hint: "Domain allowlist + JSON subset matching enforced below.",
                    binding: Binding(
                        get: { rulesBinding.typedDataPolicy.posture },
                        set: { rulesBinding.typedDataPolicy.posture = $0 }
                    )
                )
                BastionDivider()
                PosturePicker(
                    label: "ERC-4337 user operations",
                    hint: "Calldata-decoded targets and spending caps enforced below.",
                    binding: Binding(
                        get: { rulesBinding.userOpPosture },
                        set: { rulesBinding.userOpPosture = $0 }
                    )
                )
            }
        }
    }

    private var targetsCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(
                    title: "Targets & per-target caps",
                    subtitle: "Decoded inner-call destinations. Each can have its own daily spend cap."
                ) {
                    Button {
                        showAddTarget = true
                    } label: { Text("Add target").font(.system(size: 12)) }
                        .bastionButton(.default, size: .small)
                }

                if (rulesBinding.allowedTargets ?? [:]).isEmpty {
                    Text("No targets configured. Without an allowlist, every decoded inner-call target is allowed.")
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                        .padding(.vertical, 4)
                } else {
                    targetTable
                }
            }
        }
    }

    private var targetTable: some View {
        let entries: [(chainId: Int, addr: String)] = (rulesBinding.allowedTargets ?? [:])
            .flatMap { (chainKey, addrs) -> [(Int, String)] in
                guard let chainId = Int(chainKey) else { return [] }
                return addrs.map { (chainId, $0) }
            }
            .sorted { $0.0 == $1.0 ? $0.1 < $1.1 : $0.0 < $1.0 }

        return VStack(spacing: 0) {
            HStack {
                Text("Chain").frame(width: 110, alignment: .leading)
                Text("Target").frame(maxWidth: .infinity, alignment: .leading)
                Text("Daily cap").frame(width: 130, alignment: .leading)
                Text("Used 24h").frame(width: 110, alignment: .leading)
                Color.clear.frame(width: 24)
            }
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(Color.ink500)
            .padding(.bottom, 6)
            BastionDivider()
            ForEach(Array(entries.enumerated()), id: \.offset) { _, row in
                let presentation = TargetAllowlistRowPresentation.make(chainId: row.chainId, address: row.addr)
                HStack(spacing: 8) {
                    ChainBadge(chainId: row.chainId, size: .small).frame(width: 110, alignment: .leading)
                    AddressView(address: row.addr).frame(maxWidth: .infinity, alignment: .leading)
                    Text(targetCapLabel(for: row.addr))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .frame(width: 130, alignment: .leading)
                    Text(targetUsedLabel(for: row.addr))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .frame(width: 110, alignment: .leading)
                    Button {
                        removeTarget(chainId: row.chainId, address: row.addr)
                    } label: {
                        CloseGlyph(size: 11, color: .ink500)
                    }
                        .bastionButton(.ghost, size: .small)
                        .accessibilityLabel(presentation.removeAccessibilityLabel)
                        .help(presentation.removeHelp)
                        .frame(width: 24)
                }
                .padding(.vertical, 12)
                Rectangle().fill(Color.ink150).frame(height: 1)
            }
        }
    }

    private var globalCapsCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(
                    title: "Global caps",
                    subtitle: "Apply across all targets. Tightest cap wins."
                )
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    if let usdc = spendingLimit(for: .usdc) {
                        let status = StateStore.shared.spendingLimitStatus(rule: usdc)
                        CapTile(presentation: GlobalCapTilePresentation.spendingLimit(
                            prefix: "Total USDC",
                            rule: usdc,
                            status: status
                        ))
                    }
                    if let eth = spendingLimit(for: .eth) {
                        let status = StateStore.shared.spendingLimitStatus(rule: eth)
                        CapTile(presentation: GlobalCapTilePresentation.spendingLimit(
                            prefix: "Total ETH",
                            rule: eth,
                            status: status
                        ))
                    }
                    if let rl = rulesBinding.rateLimits.first {
                        let status = StateStore.shared.rateLimitStatus(rule: rl)
                        CapTile(presentation: GlobalCapTilePresentation.rateLimit(rule: rl, status: status))
                    }
                    CapTile(presentation: GlobalCapTilePresentation.allowedHours(rulesBinding.allowedHours))
                }
            }
        }
    }

    private var authCard: some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(
                    title: "Authentication policy",
                    subtitle: "When rules pass, what should Bastion do?"
                )
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 8) {
                    ForEach(AuthPolicyPickerPresentation.options(selected: authPolicyBinding), id: \.policy) { option in
                        AuthOption(option: option) { authPolicyBinding = option.policy }
                    }
                }
                HStack(alignment: .top, spacing: 10) {
                    ShieldGlyph(size: 14, color: .bastionAccentDeep)
                    Text(AuthPolicyPickerPresentation.violationWarning)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.bastionAccentDeep)
                }
                .padding(.m)
                .background(
                    RoundedRectangle(cornerRadius: 8).fill(Color.bastionAccentSoft)
                )
            }
        }
    }

    @ViewBuilder
    private func validatorCard(profile: ClientProfile) -> some View {
        BastionCard {
            VStack(alignment: .leading, spacing: 12) {
                BastionSectionHeader(title: "On-chain validator")
                HStack(spacing: 14) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 8).fill(Color.bastionOkSoft)
                        CheckGlyph(size: 16, color: .bastionOk)
                    }
                    .frame(width: 36, height: 36)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Validator key tag")
                            .font(.system(size: 13, weight: .medium))
                        HStack(spacing: 6) {
                            Text("Tag")
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                            Text(profile.keyTag)
                                .font(.system(size: 11.5, design: .monospaced))
                                .foregroundStyle(Color.ink700)
                        }
                    }
                    Spacer()
                }
                .padding(14)
                .background(
                    RoundedRectangle(cornerRadius: 10).fill(Color.ink50)
                        .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.ink150, lineWidth: 1))
                )

                BastionSectionHeader(
                    title: "Revoke",
                    subtitle: profile.isGroupMember
                        ? "Revoke local key destroys the SE key on this Mac. Uninstall on-chain validator submits a UserOp removing this agent from the smart account."
                        : "Revoke local key destroys this agent's Secure Enclave key on this Mac."
                )
                HStack(spacing: 8) {
                    Button("Revoke local key") {
                        Task { await revokeLocalKey(profile: profile) }
                    }
                    .bastionButton(.danger, size: .small)
                    .disabled(validatorActionInFlight)

                    if profile.isGroupMember {
                        Button("Uninstall on-chain validator") {
                            Task {
                                await uninstallOnChain(profile: profile)
                            }
                        }
                        .bastionButton(.danger, size: .small)
                        .disabled(validatorActionInFlight)
                    }
                }
                if let validatorActionMessage {
                    Text(validatorActionMessage)
                        .font(.system(size: 11.5, weight: validatorActionIsError ? .medium : .regular))
                        .foregroundStyle(validatorActionIsError ? Color.bastionBad : Color.bastionOk)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    /// Destroys the agent's Secure Enclave key on this Mac. Requires owner
    /// biometric/passcode — without auth a malicious app could synthesize
    /// clicks and permanently delete signing keys.
    private func revokeLocalKey(profile: ClientProfile) async {
        await withValidatorAction {
            do {
                try await AuthManager.shared.authenticate(
                    policy: .biometricOrPasscode,
                    reason: "Authorize destruction of \(profileDisplayName(profile))'s signing key"
                )
            } catch {
                setValidatorActionFeedback(.revokeAuthCancelled)
                NSLog("[Bastion] Revoke local key cancelled: %@", String(describing: error))
                return
            }
            let removed = SecureEnclaveManager.shared.deleteSigningKeys(keyTags: [profile.keyTag])
            if removed.isEmpty {
                setValidatorActionFeedback(.noLocalKey(profileName: profileDisplayName(profile)))
            } else {
                setValidatorActionFeedback(.revokedLocalKey(profileName: profileDisplayName(profile)))
            }
            NSLog("[Bastion] Revoked local key for %@ — removed: %@",
                  profileDisplayName(profile),
                  removed.joined(separator: ", "))
        }
    }

    private func uninstallOnChain(profile: ClientProfile) async {
        await withValidatorAction {
            let preflight = ValidatorUninstallPreflight.evaluate(
                profile: profile,
                walletGroups: RuleEngine.shared.config.walletGroups
            )
            guard case .ready(let groupId, let memberId, let chainId) = preflight else {
                if case .blocked(let message) = preflight {
                    setValidatorActionMessage(message, isError: true)
                }
                NSLog("[Bastion] Uninstall skipped — profile has no wallet group membership or chain")
                return
            }
            do {
                _ = try await RuleEngine.shared.uninstallAgentOnChain(
                    groupId: groupId,
                    memberId: memberId,
                    chainId: chainId,
                    projectId: nil,
                    submit: true
                )
                setValidatorActionFeedback(.uninstallSubmitted(
                    profileName: profileDisplayName(profile),
                    chainName: ChainConfig.name(for: chainId)
                ))
            } catch {
                setValidatorActionFeedback(.uninstallFailed(error))
                NSLog("[Bastion] Uninstall failed: %@", String(describing: error))
            }
        }
    }

    private func setValidatorActionFeedback(_ feedback: ValidatorActionFeedback) {
        setValidatorActionMessage(feedback.message, isError: feedback.isError)
    }

    private func setValidatorActionMessage(_ message: String, isError: Bool = false) {
        validatorActionMessage = message
        validatorActionIsError = isError
    }

    private func withValidatorAction(_ operation: () async -> Void) async {
        guard !validatorActionInFlight else { return }
        validatorActionInFlight = true
        defer { validatorActionInFlight = false }
        validatorActionMessage = nil
        await operation()
    }

    private func profileDisplayName(_ profile: ClientProfile) -> String {
        profile.label ?? profile.bundleId
    }

    // MARK: - Helpers

    /// Derives an activity chip from the audit log — shows "Active" when the
    /// profile signed something in the last hour, "Idle" otherwise. Returns
    /// nil so the chip is hidden entirely if nothing's ever been signed.
    private struct ActivityChip {
        let label: String
        let style: BastionChip.Style
        let dot: StatusDot.State
    }

    private func profileActivity(_ profile: ClientProfile) -> ActivityChip? {
        let displayName = profile.label ?? profile.bundleId
        guard let last = AuditLog.shared.latestTimestamp(forClientDisplayName: displayName) else {
            return nil
        }
        let elapsed = Date().timeIntervalSince(last)
        if elapsed < 3600 {
            return ActivityChip(label: "Active", style: .ok, dot: .ok)
        }
        if elapsed < 86_400 {
            return ActivityChip(label: "Idle today", style: .neutral, dot: .idle)
        }
        return ActivityChip(label: "Inactive", style: .neutral, dot: .idle)
    }

    private func accountAddressForProfile(_ profile: ClientProfile) -> String? {
        // Non-creating lookup: if the SE key doesn't exist yet (fresh
        // profile, never signed) we return nil instead of triggering a
        // biometric prompt to materialise one. The header just hides the
        // address until the first real sign creates the key.
        SecureEnclaveManager.shared.getPublicKeyIfExists(keyTag: profile.keyTag)?.accountAddress
    }

    private func spendingLimit(for token: TokenIdentifier) -> SpendingLimitRule? {
        rulesBinding.spendingLimits.first { rule in
            switch (rule.token, token) {
            case (.eth, .eth): return true
            case (.usdc, .usdc): return true
            case (.erc20(let a, let c), .erc20(let b, let d)):
                return a.caseInsensitiveCompare(b) == .orderedSame && c == d
            default: return false
            }
        }
    }

    private func tokenAmount(_ raw: String, decimals: Int) -> Double {
        GlobalCapTilePresentation.tokenAmount(raw, decimals: decimals)
    }

    private func formatAllowance(_ raw: String, decimals: Int) -> String {
        GlobalCapTilePresentation.formatAllowance(raw, decimals: decimals)
    }

    private func removeTarget(chainId: Int, address: String) {
        rulesBinding = TargetAllowlistMutation.remove(chainId: chainId, address: address, from: rulesBinding)
    }

    private func addTarget(_ entry: TargetAllowlistEntry) {
        rulesBinding = TargetAllowlistMutation.add(entry, to: rulesBinding)
    }

    private func targetCapLabel(for address: String) -> String {
        TargetAllowlistPresentation.capLabel(for: address, in: rulesBinding)
    }

    private func targetUsedLabel(for address: String) -> String {
        TargetAllowlistPresentation.usedLabel(for: address, in: rulesBinding, stateStore: .shared)
    }

    private func targetLimit(for address: String) -> SpendingLimitRule? {
        TargetAllowlistMutation.targetLimit(for: address, in: rulesBinding)
    }
}

private struct AddTargetSheet: View {
    let onAdd: (TargetAllowlistEntry) -> Void
    let onCancel: () -> Void

    @State private var chainId = "8453"
    @State private var address = ""
    @State private var usdcDailyCap = ""
    @State private var error: String?

    private var draft: TargetAllowlistEntryDraft {
        TargetAllowlistEntryDraft(chainId: chainId, address: address, usdcDailyCap: usdcDailyCap)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(title: "Add target", subtitle: "Allow a decoded inner-call destination for this profile.")
            BastionDivider()
            VStack(alignment: .leading, spacing: 12) {
                labeledField("Chain ID", text: $chainId, placeholder: "8453")
                    .font(.system(size: 13, design: .monospaced))
                labeledField("Target address", text: $address, placeholder: "0x...")
                    .font(.system(size: 13, design: .monospaced))
                labeledField("USDC daily cap", text: $usdcDailyCap, placeholder: "optional")
                    .font(.system(size: 13, design: .monospaced))
                if let error {
                    Text(error)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(Color.bastionBad)
                }
            }
            .padding(18)
            BastionDivider()
            HStack {
                Spacer()
                Button("Cancel", action: onCancel).bastionButton(.default)
                Button("Add", action: submit).bastionButton(.primary)
            }
            .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
            .background(Color.ink50)
        }
        .frame(width: 440)
        .background(Color.paper)
    }

    private func labeledField(_ label: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(.system(size: 11.5))
                .foregroundStyle(Color.ink500)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    private func submit() {
        guard let entry = draft.makeEntry() else {
            error = draft.validationMessage
            return
        }
        onAdd(entry)
    }
}

// MARK: - CapTile

// Posture picker — three-way SigningPosture selector rendered as a
// macOS-style segmented control. PR2 introduced the picker as three
// individual button pills in a row; polish task #52 redesigns it as a
// single rounded container with one selected segment so it reads as a
// group rather than three loose buttons. The selected segment carries
// the dark fill, unselected segments are paper-on-light with a subtle
// hover state.
private struct PosturePicker: View {
    let label: String
    let hint: String
    @Binding var binding: SigningPosture

    private static let cornerRadius: CGFloat = 7
    private static let segmentHeight: CGFloat = 28

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            VStack(alignment: .leading, spacing: 2) {
                Text(label).font(.system(size: 13)).foregroundStyle(Color.ink900)
                Text(hint).font(.system(size: 12)).foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)
            }
            segmentedControl
        }
        .padding(.vertical, 10)
    }

    private var segmentedControl: some View {
        let segments = PosturePickerPresentation.segments(selected: binding)
        return HStack(spacing: 0) {
            ForEach(Array(segments.enumerated()), id: \.element.posture) { index, segment in
                segmentButton(segment: segment)
                if index < segments.count - 1 {
                    // Hairline divider between segments — hidden when
                    // either neighbour is selected (the selected pill's
                    // outline already provides the boundary).
                    Rectangle()
                        .fill(Color.ink200)
                        .frame(width: 1, height: 14)
                        .opacity(neighbourSelected(at: index) ? 0 : 1)
                }
            }
        }
        .frame(height: Self.segmentHeight)
        .background(
            RoundedRectangle(cornerRadius: Self.cornerRadius)
                .fill(Color.ink50)
                .overlay(
                    RoundedRectangle(cornerRadius: Self.cornerRadius)
                        .strokeBorder(Color.ink150, lineWidth: 1)
                )
        )
    }

    private func segmentButton(segment: PosturePickerSegmentPresentation) -> some View {
        let isSelected = segment.isSelected
        return Button {
            withAnimation(.easeOut(duration: 0.12)) { binding = segment.posture }
        } label: {
            Text(segment.shortLabel)
                .font(.system(size: 11.5, weight: isSelected ? .semibold : .medium))
                .foregroundStyle(isSelected ? Color.paper : Color.ink700)
                .frame(maxWidth: .infinity)
                .frame(height: Self.segmentHeight - 4)
                .background(
                    RoundedRectangle(cornerRadius: Self.cornerRadius - 2)
                        .fill(isSelected ? Color.ink900 : .clear)
                        .padding(2)
                )
                .help(segment.accessibilityHint)
        }
        .buttonStyle(.plain)
        .accessibilityLabel(segment.accessibilityLabel)
        .accessibilityHint(segment.accessibilityHint)
        .accessibilityAddTraits(isSelected ? .isSelected : [])
    }

    /// True if either segment immediately around index `i` (i.e. i or i+1)
    /// is selected. We hide the inter-segment hairline next to the
    /// selected pill so the pill's own outline stays visually clean.
    private func neighbourSelected(at i: Int) -> Bool {
        let cases = PosturePickerPresentation.orderedPostures
        guard i + 1 < cases.count else { return false }
        return binding == cases[i] || binding == cases[i + 1]
    }
}

private struct CapTile: View {
    let label: String
    let value: String
    var used: Double? = nil
    var total: Double? = nil
    var unit: String = ""
    var warn: Bool = false

    init(label: String, value: String, used: Double? = nil, total: Double? = nil, unit: String = "", warn: Bool = false) {
        self.label = label
        self.value = value
        self.used = used
        self.total = total
        self.unit = unit
        self.warn = warn
    }

    init(presentation: CapTilePresentation) {
        self.init(
            label: presentation.label,
            value: presentation.value,
            used: presentation.used,
            total: presentation.total,
            unit: presentation.unit,
            warn: presentation.warn
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(label).font(.system(size: 12)).foregroundStyle(Color.ink500)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(value)
                    .font(.system(size: 17, weight: .semibold, design: .monospaced))
                    .kerning(-0.17)
                Text(unit).font(.system(size: 11.5)).foregroundStyle(Color.ink500)
            }
            if let used, let total, total > 0 {
                BastionQuota(used: used, total: total, label: "Used today", unit: unit)
            }
        }
        .padding(14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(warn ? Color.bastionBadSoft.opacity(0.45) : Color.ink50)
                .overlay(
                    RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(warn ? Color.bastionBad.opacity(0.45) : Color.ink150, lineWidth: 1)
                )
        )
    }
}

// MARK: - AuthOption

private struct AuthOption: View {
    let label: String
    let hint: String
    let selected: Bool
    let action: () -> Void

    init(label: String, hint: String, selected: Bool, action: @escaping () -> Void) {
        self.label = label
        self.hint = hint
        self.selected = selected
        self.action = action
    }

    init(option: AuthOptionPresentation, action: @escaping () -> Void) {
        self.init(
            label: option.label,
            hint: option.hint,
            selected: option.isSelected,
            action: action
        )
    }

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 8) {
                    ZStack {
                        Circle()
                            .strokeBorder(selected ? Color.ink900 : Color.ink300, lineWidth: 1.5)
                            .frame(width: 14, height: 14)
                        if selected {
                            Circle().fill(Color.ink900).frame(width: 7, height: 7)
                        }
                    }
                    Text(label).font(.system(size: 13, weight: .medium)).foregroundStyle(Color.ink900)
                }
                Text(hint).font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(EdgeInsets(top: 12, leading: 14, bottom: 12, trailing: 14))
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: 10)
                    .fill(selected ? Color.ink50 : Color.paper)
                    .overlay(
                        RoundedRectangle(cornerRadius: 10)
                            .strokeBorder(selected ? Color.ink700 : Color.ink150, lineWidth: 1)
                    )
            )
        }
        .buttonStyle(.plain)
        .accessibilityLabel(label)
        .accessibilityHint(hint)
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}

// MARK: - App preferences panel

private struct AppPreferencesPanel: View {
    @Binding var bundlerPreferences: BundlerPreferences
    @Bindable private var rpcMonitor = RPCHealthMonitor.shared
    @State private var showAddChain = false

    private func dotState(for status: RPCStatus) -> StatusDot.State {
        switch status {
        case .ok:   return .ok
        case .warn: return .warn
        case .bad:  return .bad
        case .unknown: return .idle
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "App preferences",
                subtitle: "ZeroDev project ID + per-chain RPCs."
            )
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    BastionCard {
                        VStack(alignment: .leading, spacing: 6) {
                            BastionSectionHeader(title: "ZeroDev")
                            Text("Project ID")
                                .font(.system(size: 11.5))
                                .foregroundStyle(Color.ink500)
                            TextField("zd_proj_…", text: Binding(
                                get: { bundlerPreferences.zeroDevProjectId ?? "" },
                                set: {
                                    bundlerPreferences.zeroDevProjectId = ZeroDevProjectIdInput.normalized($0)
                                }
                            ))
                            .textFieldStyle(.plain)
                            .font(.system(size: 13, design: .monospaced))
                            .padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))
                            .background(
                                RoundedRectangle(cornerRadius: 7)
                                    .fill(Color.paper)
                                    .overlay(RoundedRectangle(cornerRadius: 7).strokeBorder(Color.ink200, lineWidth: 1))
                            )
                        }
                    }
                    BastionCard {
                        VStack(alignment: .leading, spacing: 0) {
                            BastionSectionHeader(title: "RPC endpoints") {
                                Button {
                                    showAddChain = true
                                } label: { Text("Add chain").font(.system(size: 12)) }
                                    .bastionButton(.default, size: .small)
                            }
                            if bundlerPreferences.chainRPCs.isEmpty {
                                Text("No RPCs configured.")
                                    .font(.system(size: 12))
                                    .foregroundStyle(Color.ink500)
                                    .padding(.vertical, 12)
                            }
                            ForEach(bundlerPreferences.chainRPCs.indices, id: \.self) { idx in
                                Rectangle().fill(Color.ink150).frame(height: 1)
                                let sample = rpcMonitor.samples[bundlerPreferences.chainRPCs[idx].chainId]
                                HStack(spacing: 12) {
                                    ChainBadge(chainId: bundlerPreferences.chainRPCs[idx].chainId, size: .small)
                                        .frame(width: 130, alignment: .leading)
                                    Text(bundlerPreferences.chainRPCs[idx].rpcURL)
                                        .font(.system(size: 12, design: .monospaced))
                                        .foregroundStyle(Color.ink700)
                                        .lineLimit(1)
                                        .truncationMode(.middle)
                                    Spacer()
                                    HStack(spacing: 5) {
                                        StatusDot(state: dotState(for: RPCProbePresentation.status(for: sample)))
                                        Text(RPCProbePresentation.latencyLabel(sample))
                                            .font(.system(size: 11))
                                            .foregroundStyle(Color.ink500)
                                    }
                                }
                                .padding(.vertical, 12)
                            }
                            HStack {
                                Spacer()
                                let probePresentation = RPCProbePresentation.make(
                                    isProbing: rpcMonitor.isProbing,
                                    endpointCount: bundlerPreferences.chainRPCs.count
                                )
                                Button {
                                    rpcMonitor.probeNow()
                                } label: {
                                    Text(probePresentation.buttonTitle)
                                        .font(.system(size: 11))
                                }
                                    .bastionButton(.ghost, size: .small)
                                    .disabled(probePresentation.isButtonDisabled)
                            }
                            .padding(.top, 4)
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .sheet(isPresented: $showAddChain) {
            AddChainSheet { preference in
                upsertChainRPC(preference)
                showAddChain = false
            } onCancel: {
                showAddChain = false
            }
        }
    }

    private func upsertChainRPC(_ preference: ChainRPCPreference) {
        bundlerPreferences = ChainRPCPreferenceDraft.upsert(preference, into: bundlerPreferences)
    }
}

private struct AddChainSheet: View {
    let onAdd: (ChainRPCPreference) -> Void
    let onCancel: () -> Void

    @State private var chainId = "8453"
    @State private var rpcURL = ""
    @State private var error: String?

    private var draft: ChainRPCPreferenceDraft {
        ChainRPCPreferenceDraft(chainId: chainId, rpcURL: rpcURL)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(title: "Add RPC endpoint", subtitle: "Configure a chain RPC used for simulation, nonce lookup, and fees.")
            BastionDivider()
            VStack(alignment: .leading, spacing: 12) {
                labeledField("Chain ID", text: $chainId, placeholder: "8453")
                    .font(.system(size: 13, design: .monospaced))
                labeledField("RPC URL", text: $rpcURL, placeholder: "https://...")
                    .font(.system(size: 13, design: .monospaced))
                if let error {
                    Text(error)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(Color.bastionBad)
                }
            }
            .padding(18)
            BastionDivider()
            HStack {
                Spacer()
                Button("Cancel", action: onCancel).bastionButton(.default)
                Button("Add", action: submit).bastionButton(.primary)
            }
            .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
            .background(Color.ink50)
        }
        .frame(width: 460)
        .background(Color.paper)
    }

    private func labeledField(_ label: String, text: Binding<String>, placeholder: String) -> some View {
        VStack(alignment: .leading, spacing: 5) {
            Text(label)
                .font(.system(size: 11.5))
                .foregroundStyle(Color.ink500)
            TextField(placeholder, text: text)
                .textFieldStyle(.roundedBorder)
        }
    }

    private func submit() {
        guard let preference = draft.makePreference() else {
            error = draft.validationMessage
            return
        }
        onAdd(preference)
    }
}

// MARK: - Rule templates panel (preset cards)

nonisolated struct RuleTemplateMetricPresentation: Equatable, Sendable {
    let key: String
    let value: String
}

nonisolated struct RuleTemplateCardPresentation: Identifiable, Equatable, Sendable {
    let id: String
    let template: PairingPolicyTemplate
    let title: String
    let hint: String
    let metrics: [RuleTemplateMetricPresentation]
    let applyButtonTitle: String
    let pairButtonTitle: String

    static func make(_ template: PairingPolicyTemplate) -> RuleTemplateCardPresentation {
        RuleTemplateCardPresentation(
            id: template.id,
            template: template,
            title: template.title,
            hint: template.hint,
            metrics: [
                RuleTemplateMetricPresentation(key: "USDC/DAY", value: metric("USDC", template: template)),
                RuleTemplateMetricPresentation(key: "ETH/DAY", value: metric("ETH", template: template)),
                RuleTemplateMetricPresentation(key: "RATE", value: rateMetric(template: template)),
                RuleTemplateMetricPresentation(key: "AUTH", value: template.authPolicy.displayName),
            ],
            applyButtonTitle: "Apply to default",
            pairButtonTitle: "Pair agent"
        )
    }

    private static func metric(_ tokenName: String, template: PairingPolicyTemplate) -> String {
        let token = tokenName == "USDC" ? TokenIdentifier.usdc : TokenIdentifier.eth
        guard let limit = template.rules.spendingLimits.first(where: { rule in
            switch (token, rule.token) {
            case (.usdc, .usdc), (.eth, .eth):
                return true
            default:
                return false
            }
        }) else {
            return "-"
        }

        let decimals = tokenName == "USDC" ? 6 : 18
        let raw = Double(limit.allowance) ?? 0
        let amount = raw / pow(10, Double(decimals))
        let formatted = amount == amount.rounded() ? String(Int(amount)) : String(format: "%.4g", amount)
        let window = limit.windowSeconds.map { "/\(RateLimitRule.formatWindow($0))" } ?? ""
        return "\(formatted)\(window)"
    }

    private static func rateMetric(template: PairingPolicyTemplate) -> String {
        guard let limit = template.rules.rateLimits.first else { return "-" }
        return "\(limit.maxRequests)/\(RateLimitRule.formatWindow(limit.windowSeconds))"
    }
}

nonisolated struct RuleTemplatesPanelPresentation: Equatable, Sendable {
    let title: String
    let subtitle: String
    let newAgentButtonTitle: String
    let cards: [RuleTemplateCardPresentation]

    static func make() -> RuleTemplatesPanelPresentation {
        RuleTemplatesPanelPresentation(
            title: "Rule templates",
            subtitle: "Reusable starting points for new agents. Apply one to defaults or pair an agent from it.",
            newAgentButtonTitle: "+ New agent",
            cards: PairingPolicyTemplate.allCases
                .filter { $0 != .custom }
                .map(RuleTemplateCardPresentation.make)
        )
    }
}

nonisolated struct RuleTemplateDefaultApplyResult: Sendable {
    let config: BastionConfig
    let statusMessage: String
    let statusIsError: Bool
    let selection: SettingsSelection
}

nonisolated enum RuleTemplateApplication {
    static func applyToDefault(
        _ template: PairingPolicyTemplate,
        config: BastionConfig
    ) -> RuleTemplateDefaultApplyResult {
        var updated = config
        updated.authPolicy = template.authPolicy
        updated.rules = template.rules
        return RuleTemplateDefaultApplyResult(
            config: updated,
            statusMessage: "Applied \(template.title) to the default profile",
            statusIsError: false,
            selection: .defaultProfile
        )
    }
}

private struct RuleTemplatesPanel: View {
    let profileCount: Int
    let onApplyToDefault: (PairingPolicyTemplate) -> Void
    let onPair: () -> Void

    private var presentation: RuleTemplatesPanelPresentation {
        RuleTemplatesPanelPresentation.make()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: presentation.title,
                subtitle: presentation.subtitle
            ) {
                Button { onPair() } label: { Text(presentation.newAgentButtonTitle).font(.system(size: 12)) }
                    .bastionButton(.primary, size: .small)
            }
            BastionDivider()
            ScrollView {
                LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 14) {
                    ForEach(presentation.cards) { card in
                        TemplateCardView(
                            presentation: card,
                            profileCount: profileCount,
                            onApplyToDefault: { onApplyToDefault(card.template) },
                            onPair: onPair
                        )
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }

    private struct TemplateCardView: View {
        let presentation: RuleTemplateCardPresentation
        let profileCount: Int
        let onApplyToDefault: () -> Void
        let onPair: () -> Void

        var body: some View {
            BastionCard(padding: 16) {
                VStack(alignment: .leading, spacing: 10) {
                    Text(presentation.title).font(.system(size: 14, weight: .semibold))
                    Text(presentation.hint).font(.system(size: 12)).foregroundStyle(Color.ink500)
                    LazyVGrid(columns: [GridItem(.flexible()), GridItem(.flexible())], spacing: 8) {
                        ForEach(presentation.metrics, id: \.key) { metric in
                            TemplateKV(key: metric.key, value: metric.value)
                        }
                    }
                    .padding(10)
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(Color.ink50)
                            .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.ink150, lineWidth: 1))
                    )
                    HStack(spacing: 8) {
                        Button(presentation.applyButtonTitle, action: onApplyToDefault)
                            .bastionButton(.default, size: .small)
                        Button(presentation.pairButtonTitle, action: onPair)
                            .bastionButton(.ghost, size: .small)
                        Spacer()
                        // Profile→template attribution isn't tracked yet, so a
                        // "Used by N" count would be guessed. Hidden until
                        // ClientProfile gains a templateId reference.
                    }
                }
            }
        }
    }

    private struct TemplateKV: View {
        let key: String
        let value: String
        var body: some View {
            VStack(alignment: .leading, spacing: 2) {
                Text(key)
                    .font(.system(size: 10, weight: .semibold))
                    .kerning(0.4)
                    .foregroundStyle(Color.ink500)
                Text(value)
                    .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                    .foregroundStyle(Color.ink900)
            }
        }
    }
}

// MARK: - Address book panel

private struct AddressBookPanel: View {
    @Binding var addressBook: [AddressBookEntry]

    @State private var newAddress: String = ""
    @State private var newLabel: String = ""
    @State private var newChainId: String = ""
    @State private var addError: String? = nil

    private var draft: AddressBookEntryDraft {
        AddressBookEntryDraft(address: newAddress, label: newLabel, chainId: newChainId)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "Address book",
                subtitle: "Label addresses (Treasury, USDC, Uniswap Router, etc.) to make approvals and audit easier to read."
            )
            BastionDivider()

            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    BastionCard {
                        VStack(alignment: .leading, spacing: 8) {
                            BastionSectionHeader(title: "Add entry")
                            HStack(spacing: 8) {
                                TextField("Address (0x…)", text: $newAddress)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 12, design: .monospaced))
                                TextField("Label", text: $newLabel)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 12))
                                TextField("Chain ID (optional)", text: $newChainId)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 12, design: .monospaced))
                                    .frame(width: 140)
                                Button("Add") { addEntry() }
                                    .bastionButton(.primary, size: .small)
                            }
                            if let addError {
                                Text(addError)
                                    .font(.system(size: 11.5, weight: .medium))
                                    .foregroundStyle(Color.bastionBad)
                            }
                        }
                    }

                    BastionCard {
                        VStack(alignment: .leading, spacing: 0) {
                            BastionSectionHeader(title: "Entries")
                            if addressBook.isEmpty {
                                Text("No labels yet. Add a few above.")
                                    .font(.system(size: 12))
                                    .foregroundStyle(Color.ink500)
                                    .padding(.vertical, 12)
                            }
                            ForEach(addressBook) { entry in
                                let presentation = AddressBookRowPresentation.make(entry)
                                Rectangle().fill(Color.ink150).frame(height: 1)
                                HStack(spacing: 12) {
                                    Text(entry.label)
                                        .font(.system(size: 13, weight: .medium))
                                        .frame(width: 160, alignment: .leading)
                                    AddressView(address: entry.address)
                                    if let chain = entry.chainId {
                                        ChainBadge(chainId: chain, size: .small)
                                    } else {
                                        BastionChip(label: "any chain", style: .outline)
                                    }
                                    Spacer()
                                    Button {
                                        addressBook.removeAll { $0.id == entry.id }
                                    } label: {
                                        CloseGlyph(size: 11, color: .ink500)
                                    }
                                        .bastionButton(.ghost, size: .small)
                                        .accessibilityLabel(presentation.removeAccessibilityLabel)
                                        .help(presentation.removeHelp)
                                }
                                .padding(.vertical, 12)
                            }
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
    }

    private func addEntry() {
        addError = nil
        guard let entry = draft.makeEntry() else {
            addError = draft.validationMessage
            return
        }
        addressBook.append(entry)
        newAddress = ""
        newLabel = ""
        newChainId = ""
    }
}

// MARK: - High-value rule panel

private struct HighValueRulePanel: View {
    @Binding var highValue: HighValueRule

    @State private var thresholdField: String = ""

    private var draft: HighValueRuleDraft {
        HighValueRuleDraft(
            enabled: highValue.enabled,
            thresholdText: thresholdField,
            confirmationPhrase: highValue.confirmationPhrase
        )
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: "High-value rule",
                subtitle: "When a transfer exceeds the threshold, the approval popup forces the owner to type a confirmation phrase before signing."
            )
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    BastionCard {
                        VStack(alignment: .leading, spacing: 12) {
                            BastionToggleRow(
                                label: "Enable high-value confirmation",
                                hint: "Owners type a phrase to confirm transfers above the threshold.",
                                isOn: $highValue.enabled
                            )
                            BastionDivider()
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Threshold (USD-equivalent)").font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                                TextField("10000", text: thresholdBinding)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 13, design: .monospaced))
                                if let thresholdError {
                                    Text(thresholdError)
                                        .font(.system(size: 11.5, weight: .medium))
                                        .foregroundStyle(Color.bastionBad)
                                }
                            }
                            VStack(alignment: .leading, spacing: 4) {
                                Text("Confirmation phrase").font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                                TextField("TRANSFER", text: confirmationPhraseBinding)
                                    .textFieldStyle(.roundedBorder)
                                    .font(.system(size: 13, design: .monospaced))
                            }
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .onAppear {
            thresholdField = HighValueRuleDraft.thresholdText(for: highValue.thresholdUsd)
        }
    }

    private var thresholdBinding: Binding<String> {
        Binding(
            get: { thresholdField },
            set: { newValue in
                thresholdField = newValue
                let next = HighValueRuleDraft(
                    enabled: highValue.enabled,
                    thresholdText: newValue,
                    confirmationPhrase: highValue.confirmationPhrase
                )
                if let parsed = next.thresholdUsd {
                    highValue.thresholdUsd = parsed
                }
            }
        )
    }

    private var thresholdError: String? {
        draft.validationMessage
    }

    private var confirmationPhraseBinding: Binding<String> {
        Binding(
            get: { highValue.confirmationPhrase },
            set: { newValue in
                highValue.confirmationPhrase = HighValueRuleDraft(
                    enabled: highValue.enabled,
                    thresholdText: thresholdField,
                    confirmationPhrase: newValue
                ).normalizedConfirmationPhrase
            }
        )
    }
}

// MARK: - Policy version history panel

private struct PolicyHistoryPanel: View {
    let onRestore: (BastionConfig) -> Void

    @State private var versions: [PolicyVersion] = []
    @State private var premigrationBackup: BastionConfig? = nil
    @State private var recoverySnapshot: RuleEngine.ConfigRecoverySnapshot? = nil
    @State private var recoveryExportState = PolicyRecoverySnapshotExportState()

    private var presentation: PolicyHistoryPanelPresentation {
        PolicyHistoryPanelPresentation.make(
            versions: versions,
            premigrationBackup: premigrationBackup,
            recoverySnapshot: recoverySnapshot,
            recoveryExportStatus: recoveryExportState.status,
            recoveryExportError: recoveryExportState.error,
            recoveryExportIsExporting: recoveryExportState.isExporting
        )
    }

    var body: some View {
        let presentation = self.presentation
        VStack(alignment: .leading, spacing: 0) {
            BastionPanelHeader(
                title: presentation.title,
                subtitle: presentation.subtitle
            )
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    if let recovery = presentation.recovery, let recoverySnapshot {
                        BastionCard {
                            VStack(alignment: .leading, spacing: 10) {
                                HStack(alignment: .top, spacing: 12) {
                                    VStack(alignment: .leading, spacing: 4) {
                                        BastionSectionHeader(title: recovery.title)
                                        Text(recovery.metadata)
                                            .font(.system(size: 11.5))
                                            .foregroundStyle(Color.ink500)
                                    }
                                    Spacer()
                                    Button(recovery.exportButtonTitle) { exportRecoverySnapshot(recoverySnapshot) }
                                        .bastionButton(.default, size: .small)
                                        .disabled(recovery.exportButtonDisabled)
                                    if let loadBackupButtonTitle = recovery.loadBackupButtonTitle,
                                       let premigrationBackup {
                                        Button(loadBackupButtonTitle) { onRestore(premigrationBackup) }
                                            .bastionButton(.primary, size: .small)
                                    }
                                }
                                if let recoveryExportError = recovery.exportError {
                                    Text(recoveryExportError)
                                        .font(.system(size: 11.5, weight: .medium))
                                        .foregroundStyle(Color.bastionBad)
                                }
                                if let recoveryExportStatus = recovery.exportStatus {
                                    Text(recoveryExportStatus)
                                        .font(.system(size: 11.5))
                                        .foregroundStyle(Color.bastionOk)
                                }
                            }
                        }
                    }

                    if let backup = presentation.backup, let premigrationBackup {
                        BastionCard {
                            HStack(spacing: 12) {
                                VStack(alignment: .leading, spacing: 4) {
                                    BastionSectionHeader(title: backup.title)
                                    Text(backup.metadata)
                                        .font(.system(size: 11.5))
                                        .foregroundStyle(Color.ink500)
                                }
                                Spacer()
                                Button(backup.loadButtonTitle) { onRestore(premigrationBackup) }
                                    .bastionButton(.default, size: .small)
                            }
                        }
                    }

                    BastionCard {
                        VStack(alignment: .leading, spacing: 0) {
                            BastionSectionHeader(title: presentation.savedVersionsTitle)
                            if let emptyVersionsMessage = presentation.emptyVersionsMessage {
                                Text(emptyVersionsMessage)
                                    .font(.system(size: 12))
                                    .foregroundStyle(Color.ink500)
                                    .padding(.vertical, 12)
                            }
                            ForEach(versions) { version in
                                let row = presentation.versions.first { $0.id == version.id }
                                    ?? PolicyHistoryVersionRowPresentation.make(version: version)
                                Rectangle().fill(Color.ink150).frame(height: 1)
                                HStack(spacing: 12) {
                                    VStack(alignment: .leading, spacing: 2) {
                                        Text(row.timestamp)
                                            .font(.system(size: 12.5, weight: .medium, design: .monospaced))
                                        Text(row.summary)
                                            .font(.system(size: 11))
                                            .foregroundStyle(Color.ink500)
                                    }
                                    Spacer()
                                    Button(row.restoreButtonTitle) { onRestore(version.config) }
                                        .bastionButton(.default, size: .small)
                                }
                                .padding(.vertical, 12)
                            }
                        }
                    }
                }
                .padding(.bastionPanelContent)
                .frame(maxWidth: .infinity, alignment: .topLeading)
            }
        }
        .onAppear {
            versions = ConfigVersionStore.shared.versions()
            premigrationBackup = RuleEngine.shared.restoreConfigBackup()
            recoverySnapshot = RuleEngine.shared.configRecoverySnapshot()
        }
    }

    private func exportRecoverySnapshot(_ snapshot: RuleEngine.ConfigRecoverySnapshot) {
        guard recoveryExportState.beginExport() else { return }
        let savePanel = NSSavePanel()
        savePanel.nameFieldStringValue = PolicyRecoverySnapshotExportPresentation.defaultFileName(for: snapshot.capturedAt)
        savePanel.canCreateDirectories = true
        savePanel.title = "Export corrupt Bastion config"
        savePanel.begin { response in
            guard response == .OK, let url = savePanel.url else {
                DispatchQueue.main.async {
                    recoveryExportState.cancelExport()
                }
                return
            }
            do {
                try snapshot.rawConfig.write(to: url, options: .atomic)
                DispatchQueue.main.async {
                    recoveryExportState.succeed(url: url)
                }
            } catch {
                DispatchQueue.main.async {
                    recoveryExportState.fail(error)
                }
            }
        }
    }
}

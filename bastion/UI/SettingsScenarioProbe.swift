import Foundation

nonisolated struct SettingsScenarioProbeCheck: Codable, Equatable, Sendable {
    let name: String
    let passed: Bool
}

nonisolated struct SettingsScenarioSaveBarSnapshot: Codable, Equatable, Sendable {
    let changeCount: Int
    let subtitle: String
    let saveButtonTitle: String
    let actionsDisabled: Bool

    init(_ presentation: SaveBarPresentation) {
        changeCount = presentation.changeCount
        subtitle = presentation.subtitle
        saveButtonTitle = presentation.saveButtonTitle
        actionsDisabled = presentation.actionsDisabled
    }
}

nonisolated struct SettingsScenarioDiffRow: Codable, Equatable, Sendable {
    let removed: String
    let added: String
}

nonisolated struct SettingsSaveDiffScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let unchangedHasUnsavedChanges: Bool
    let changedHasUnsavedChanges: Bool
    let diffRows: [SettingsScenarioDiffRow]
    let idleSaveBar: SettingsScenarioSaveBarSnapshot
    let savingSaveBar: SettingsScenarioSaveBarSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsPostureSegmentSnapshot: Codable, Equatable, Sendable {
    let posture: String
    let shortLabel: String
    let accessibilityLabel: String
    let accessibilityHint: String
    let isSelected: Bool

    init(_ segment: PosturePickerSegmentPresentation) {
        posture = segment.posture.rawValue
        shortLabel = segment.shortLabel
        accessibilityLabel = segment.accessibilityLabel
        accessibilityHint = segment.accessibilityHint
        isSelected = segment.isSelected
    }
}

nonisolated struct SettingsPostureDraftSnapshot: Codable, Equatable, Sendable {
    let rawMessagePosture: String
    let typedDataPosture: String
    let userOperationPosture: String

    init(_ rules: RuleConfig) {
        rawMessagePosture = rules.rawMessagePolicy.posture.rawValue
        typedDataPosture = rules.typedDataPolicy.posture.rawValue
        userOperationPosture = rules.userOpPosture.rawValue
    }
}

nonisolated struct SettingsPostureScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let selectedPosture: String
    let selectedSegments: [SettingsPostureSegmentSnapshot]
    let selectedStatesByPosture: [String: [Bool]]
    let defaultDraft: SettingsPostureDraftSnapshot
    let mutatedDraft: SettingsPostureDraftSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsAuthOptionSnapshot: Codable, Equatable, Sendable {
    let policy: String
    let label: String
    let hint: String
    let isSelected: Bool

    init(_ option: AuthOptionPresentation) {
        policy = option.policy.rawValue
        label = option.label
        hint = option.hint
        isSelected = option.isSelected
    }
}

nonisolated struct SettingsAuthPolicyScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let selectedPolicy: String
    let options: [SettingsAuthOptionSnapshot]
    let selectedStatesByPolicy: [String: [Bool]]
    let defaultDraftPolicy: String
    let mutatedDraftPolicy: String
    let violationWarning: String
    let ownerAuthDecisions: [String: Bool]
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsChainRPCPreferenceSnapshot: Codable, Equatable, Sendable {
    let chainId: Int
    let rpcURL: String

    init(_ preference: ChainRPCPreference) {
        chainId = preference.chainId
        rpcURL = preference.rpcURL
    }
}

nonisolated struct SettingsProjectIdScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let nilReadValue: String
    let existingReadValue: String
    let trimmedInputValue: String?
    let newlineInputValue: String?
    let emptyInputValue: String?
    let whitespaceInputValue: String?
    let afterSetProjectId: String?
    let afterClearProjectId: String?
    let chainRPCsPreserved: [SettingsChainRPCPreferenceSnapshot]
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsRPCChainScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let validPreference: SettingsChainRPCPreferenceSnapshot?
    let updatedChainRPCs: [SettingsChainRPCPreferenceSnapshot]
    let replacedChainRPCs: [SettingsChainRPCPreferenceSnapshot]
    let zeroDevProjectIdPreserved: String?
    let validationMessages: [String: String?]
    let hasUnsavedChangesAfterAdd: Bool
    let diffRows: [SettingsScenarioDiffRow]
    let saveBar: SettingsScenarioSaveBarSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsRPCProbeControlSnapshot: Codable, Equatable, Sendable {
    let buttonTitle: String
    let isButtonDisabled: Bool

    init(_ presentation: RPCProbePresentation) {
        buttonTitle = presentation.buttonTitle
        isButtonDisabled = presentation.isButtonDisabled
    }
}

nonisolated struct SettingsRPCProbeSampleSnapshot: Codable, Equatable, Sendable {
    let chainId: Int
    let status: String
    let latencyMs: Int?
    let error: String?
    let presentationStatus: String
    let latencyLabel: String

    init(_ sample: RPCHealthSample?) {
        chainId = sample?.chainId ?? -1
        status = sample?.status.rawValue ?? RPCStatus.unknown.rawValue
        latencyMs = sample?.latencyMs
        error = sample?.error
        presentationStatus = RPCProbePresentation.status(for: sample).rawValue
        latencyLabel = RPCProbePresentation.latencyLabel(sample)
    }
}

nonisolated struct SettingsRPCProbeScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let emptyControl: SettingsRPCProbeControlSnapshot
    let readyControl: SettingsRPCProbeControlSnapshot
    let probingControl: SettingsRPCProbeControlSnapshot
    let okSample: SettingsRPCProbeSampleSnapshot
    let httpErrorSample: SettingsRPCProbeSampleSnapshot
    let malformedSample: SettingsRPCProbeSampleSnapshot
    let invalidURLSample: SettingsRPCProbeSampleSnapshot
    let requestedMethods: [String]
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsRuleTemplateMetricSnapshot: Codable, Equatable, Sendable {
    let key: String
    let value: String

    init(_ metric: RuleTemplateMetricPresentation) {
        key = metric.key
        value = metric.value
    }
}

nonisolated struct SettingsRuleTemplateCardSnapshot: Codable, Equatable, Sendable {
    let id: String
    let template: String
    let title: String
    let hint: String
    let metrics: [SettingsRuleTemplateMetricSnapshot]
    let applyButtonTitle: String
    let pairButtonTitle: String

    init(_ card: RuleTemplateCardPresentation) {
        id = card.id
        template = card.template.rawValue
        title = card.title
        hint = card.hint
        metrics = card.metrics.map(SettingsRuleTemplateMetricSnapshot.init)
        applyButtonTitle = card.applyButtonTitle
        pairButtonTitle = card.pairButtonTitle
    }
}

nonisolated struct SettingsRuleTemplatesScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let title: String
    let subtitle: String
    let newAgentButtonTitle: String
    let cards: [SettingsRuleTemplateCardSnapshot]
    let appliedStatusMessage: String
    let appliedStatusIsError: Bool
    let appliedSelection: String
    let appliedAuthPolicy: String
    let appliedAllowedChains: [Int]?
    let appliedAllowedHoursStart: Int?
    let appliedAllowedHoursEnd: Int?
    let appliedRateLimitCount: Int
    let appliedSpendingAllowances: [String]
    let existingClientProfileIds: [String]
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsTargetAddEntrySnapshot: Codable, Equatable, Sendable {
    let chainId: Int
    let address: String
    let usdcDailyCap: Double?
    let usdcAllowanceRaw: String?

    init(_ entry: TargetAllowlistEntry) {
        chainId = entry.chainId
        address = entry.address
        usdcDailyCap = entry.usdcDailyCap
        usdcAllowanceRaw = entry.usdcAllowanceRaw
    }
}

nonisolated struct SettingsTargetAddScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let validEntry: SettingsTargetAddEntrySnapshot?
    let allowedTargets: [String: [String]]
    let matchingTargetCount: Int
    let matchingCapCount: Int
    let capAllowanceRaw: String?
    let capWindowSeconds: Int?
    let capLabel: String
    let usedLabel: String
    let duplicateTargetCount: Int
    let duplicateCapCount: Int
    let uncappedTargetHasCap: Bool
    let validationMessages: [String: String?]
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsTargetRemoveRowSnapshot: Codable, Equatable, Sendable {
    let removeAccessibilityLabel: String
    let removeHelp: String

    init(_ presentation: TargetAllowlistRowPresentation) {
        removeAccessibilityLabel = presentation.removeAccessibilityLabel
        removeHelp = presentation.removeHelp
    }
}

nonisolated struct SettingsTargetRemoveScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let rowPresentation: SettingsTargetRemoveRowSnapshot
    let beforeAllowedTargets: [String: [String]]
    let afterAllowedTargets: [String: [String]]?
    let updatedSpendingAllowances: [String]
    let removedLimitBeforeAllowance: String?
    let removedLimitAfterExists: Bool
    let remainingLimitToken: String?
    let emptiedAllowedTargetsNil: Bool
    let emptiedSpendingLimitCount: Int
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsGlobalCapTileSnapshot: Codable, Equatable, Sendable {
    let label: String
    let value: String
    let used: Double?
    let total: Double?
    let unit: String
    let warn: Bool
    let showsUsage: Bool

    init(_ presentation: CapTilePresentation) {
        label = presentation.label
        value = presentation.value
        used = presentation.used
        total = presentation.total
        unit = presentation.unit
        warn = presentation.warn
        showsUsage = presentation.showsUsage
    }
}

nonisolated struct SettingsGlobalCapsScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let usdcTile: SettingsGlobalCapTileSnapshot
    let ethTile: SettingsGlobalCapTileSnapshot
    let rateTile: SettingsGlobalCapTileSnapshot
    let hoursTile: SettingsGlobalCapTileSnapshot
    let unrestrictedHoursTile: SettingsGlobalCapTileSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsAddressBookEntrySnapshot: Codable, Equatable, Sendable {
    let address: String
    let label: String
    let chainId: Int?

    init(_ entry: AddressBookEntry) {
        address = entry.address
        label = entry.label
        chainId = entry.chainId
    }
}

nonisolated struct SettingsAddressBookRowSnapshot: Codable, Equatable, Sendable {
    let removeAccessibilityLabel: String
    let removeHelp: String

    init(_ presentation: AddressBookRowPresentation) {
        removeAccessibilityLabel = presentation.removeAccessibilityLabel
        removeHelp = presentation.removeHelp
    }
}

nonisolated struct SettingsAddressBookScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let validEntry: SettingsAddressBookEntrySnapshot?
    let anyChainEntry: SettingsAddressBookEntrySnapshot?
    let validRowPresentation: SettingsAddressBookRowSnapshot?
    let anyChainRowPresentation: SettingsAddressBookRowSnapshot?
    let storedEntryCount: Int
    let entryCountAfterRemove: Int
    let decodedHeadline: String
    let decodedRecipientLabel: String?
    let validationMessages: [String: String?]
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsHighValueConfirmationSnapshot: Codable, Equatable, Sendable {
    let requiredPhrase: String?
    let message: String?
    let placeholder: String?
    let wrongTextSatisfied: Bool?
    let correctTextSatisfied: Bool?
    let wrongTextCanSubmit: Bool
    let correctTextCanSubmit: Bool
    let correctTextCanTriggerPrimary: Bool
}

nonisolated struct SettingsHighValueScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let validThreshold: Double?
    let validConfirmationPhrase: String
    let defaultedConfirmationPhrase: String
    let missingThresholdMessage: String?
    let invalidThresholdMessage: String?
    let disabledBlankThresholdMessage: String?
    let integerThresholdText: String
    let decimalThresholdText: String
    let ruleEngineConfirmationPhrase: String?
    let belowThresholdConfirmationPhrase: String?
    let approvalConfirmation: SettingsHighValueConfirmationSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsPolicyHistoryRecoverySnapshot: Codable, Equatable, Sendable {
    let title: String
    let metadata: String
    let exportButtonTitle: String
    let exportButtonDisabled: Bool
    let loadBackupButtonTitle: String?
    let exportStatus: String?
    let exportError: String?

    init(_ presentation: PolicyHistoryRecoveryCardPresentation) {
        title = presentation.title
        metadata = presentation.metadata
        exportButtonTitle = presentation.exportButtonTitle
        exportButtonDisabled = presentation.exportButtonDisabled
        loadBackupButtonTitle = presentation.loadBackupButtonTitle
        exportStatus = presentation.exportStatus
        exportError = presentation.exportError
    }
}

nonisolated struct SettingsPolicyHistoryBackupSnapshot: Codable, Equatable, Sendable {
    let title: String
    let metadata: String
    let loadButtonTitle: String

    init(_ presentation: PolicyHistoryBackupCardPresentation) {
        title = presentation.title
        metadata = presentation.metadata
        loadButtonTitle = presentation.loadButtonTitle
    }
}

nonisolated struct SettingsPolicyHistoryVersionSnapshot: Codable, Equatable, Sendable {
    let id: String
    let timestamp: String
    let summary: String
    let restoreButtonTitle: String

    init(_ presentation: PolicyHistoryVersionRowPresentation) {
        id = presentation.id
        timestamp = presentation.timestamp
        summary = presentation.summary
        restoreButtonTitle = presentation.restoreButtonTitle
    }
}

nonisolated struct SettingsPolicyHistoryScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let title: String
    let subtitle: String
    let recovery: SettingsPolicyHistoryRecoverySnapshot?
    let exportingRecovery: SettingsPolicyHistoryRecoverySnapshot?
    let backup: SettingsPolicyHistoryBackupSnapshot?
    let savedVersionsTitle: String
    let emptyVersionsMessage: String?
    let versions: [SettingsPolicyHistoryVersionSnapshot]
    let restoreStatusMessage: String
    let restoreRequiresSave: Bool
    let restoreSelection: String
    let restoredAuthPolicy: String
    let restoredClientProfileIds: [String]
    let restoredWalletGroupIds: [String]
    let restoredAllowedHoursStart: Int?
    let restoredAllowedHoursEnd: Int?
    let noOpRequiresSave: Bool
    let exportFileName: String
    let exportSuccessMessage: String
    let exportFailureMessage: String
    let exportBeginAccepted: Bool
    let duplicateExportBeginRejected: Bool
    let exportStateStatusAfterSuccess: String?
    let exportStateErrorAfterFailure: String?
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsPolicySimulatorResultSnapshot: Codable, Equatable, Sendable {
    let allowed: Bool?
    let summary: String?
    let reasons: [String]
    let error: String?

    init(_ evaluation: PolicySimulatorEvaluation) {
        switch evaluation {
        case .result(let result):
            allowed = result.allowed
            summary = result.summary
            reasons = result.reasons
            error = nil
        case .error(let message):
            allowed = nil
            summary = nil
            reasons = []
            error = message
        }
    }
}

nonisolated struct SettingsPolicySimulatorScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let canEvaluateBlank: Bool
    let canEvaluateSample: Bool
    let sampleUserOperationLength: Int
    let allowedResult: SettingsPolicySimulatorResultSnapshot
    let deniedResult: SettingsPolicySimulatorResultSnapshot
    let emptyInputError: String?
    let invalidCallDataError: String?
    let invalidEntryPointVersionError: String?
    let malformedJSONErrorPrefixMatched: Bool
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct SettingsScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

private final class SettingsScenarioMemoryKeychain: KeychainBackend, @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.bastion.settings-scenario-memory-keychain")
    private var storage: [String: Data] = [:]

    func read(account: String) -> Data? {
        queue.sync { storage[account] }
    }

    func readResult(account: String) -> KeychainReadResult {
        queue.sync {
            if let data = storage[account] {
                return .found(data)
            }
            return .missing
        }
    }

    @discardableResult
    func write(account: String, data: Data) -> Bool {
        queue.sync {
            storage[account] = data
            return true
        }
    }

    @discardableResult
    func delete(account: String) -> Bool {
        queue.sync {
            storage.removeValue(forKey: account) != nil
        }
    }
}

private struct SettingsScenarioRPCMockResponse: Sendable {
    let statusCode: Int
    let body: String
}

private final class SettingsScenarioRPCURLProtocol: URLProtocol, @unchecked Sendable {
    private nonisolated(unsafe) static var responses: [String: SettingsScenarioRPCMockResponse] = [:]
    private nonisolated(unsafe) static var requestedMethods: [String] = []
    private static let lock = NSLock()
    private static let host = "bastion-rpc-probe.local"

    static func reset(responses newResponses: [String: SettingsScenarioRPCMockResponse]) {
        lock.lock()
        responses = newResponses
        requestedMethods = []
        lock.unlock()
    }

    static func capturedRequestedMethods() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        return requestedMethods
    }

    override class func canInit(with request: URLRequest) -> Bool {
        request.url?.host == host
    }

    override class func canonicalRequest(for request: URLRequest) -> URLRequest {
        request
    }

    override func startLoading() {
        guard let url = request.url else {
            client?.urlProtocol(self, didFailWithError: URLError(.badURL))
            return
        }

        Self.lock.lock()
        Self.requestedMethods.append(request.httpMethod ?? "<none>")
        let response = Self.responses[url.path] ?? SettingsScenarioRPCMockResponse(
            statusCode: 404,
            body: #"{"jsonrpc":"2.0","id":1,"error":{"message":"not found"}}"#
        )
        Self.lock.unlock()

        guard let httpResponse = HTTPURLResponse(
            url: url,
            statusCode: response.statusCode,
            httpVersion: "HTTP/1.1",
            headerFields: ["Content-Type": "application/json"]
        ) else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }

        client?.urlProtocol(self, didReceive: httpResponse, cacheStoragePolicy: .notAllowed)
        client?.urlProtocol(self, didLoad: Data(response.body.utf8))
        client?.urlProtocolDidFinishLoading(self)
    }

    override func stopLoading() {}
}

nonisolated enum SettingsScenarioProbe {
    static let saveDiffScenario = "saveDiff"
    static let postureControlsScenario = "postureControls"
    static let authPolicyScenario = "authPolicy"
    static let projectIdScenario = "projectId"
    static let rpcChainScenario = "rpcChain"
    static let rpcProbeScenario = "rpcProbe"
    static let ruleTemplatesScenario = "ruleTemplates"
    static let targetAddScenario = "targetAdd"
    static let targetRemoveScenario = "targetRemove"
    static let globalCapsScenario = "globalCaps"
    static let addressBookScenario = "addressBook"
    static let highValueScenario = "highValue"
    static let policyHistoryScenario = "policyHistory"
    static let policySimulatorScenario = "policySimulator"

    static func run(scenario: String) async throws -> SettingsScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case saveDiffScenario:
            let response = saveDiff()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: ["diffRowCount": String(response.diffRows.count)],
                data: try encoder.encode(response)
            )
        case postureControlsScenario:
            let response = postureControls()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: ["selectedPosture": response.selectedPosture],
                data: try encoder.encode(response)
            )
        case authPolicyScenario:
            let response = authPolicy()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: ["selectedPolicy": response.selectedPolicy],
                data: try encoder.encode(response)
            )
        case projectIdScenario:
            let response = projectId()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: ["afterSetProjectId": response.afterSetProjectId ?? ""],
                data: try encoder.encode(response)
            )
        case rpcChainScenario:
            let response = rpcChain()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: ["chainRPCCount": String(response.updatedChainRPCs.count)],
                data: try encoder.encode(response)
            )
        case rpcProbeScenario:
            let response = await rpcProbe()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "okStatus": response.okSample.status,
                    "httpErrorLabel": response.httpErrorSample.latencyLabel,
                ],
                data: try encoder.encode(response)
            )
        case ruleTemplatesScenario:
            let response = ruleTemplates()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "templateCount": String(response.cards.count),
                    "appliedAuthPolicy": response.appliedAuthPolicy,
                ],
                data: try encoder.encode(response)
            )
        case targetAddScenario:
            let response = targetAdd()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "matchingTargetCount": String(response.matchingTargetCount),
                    "matchingCapCount": String(response.matchingCapCount),
                ],
                data: try encoder.encode(response)
            )
        case targetRemoveScenario:
            let response = targetRemove()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "removedLimitAfterExists": String(response.removedLimitAfterExists),
                    "emptiedAllowedTargetsNil": String(response.emptiedAllowedTargetsNil),
                ],
                data: try encoder.encode(response)
            )
        case globalCapsScenario:
            let response = globalCaps()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "usdcWarn": String(response.usdcTile.warn),
                    "ethWarn": String(response.ethTile.warn),
                    "rateWarn": String(response.rateTile.warn),
                ],
                data: try encoder.encode(response)
            )
        case addressBookScenario:
            let response = addressBook()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "storedEntryCount": String(response.storedEntryCount),
                    "entryCountAfterRemove": String(response.entryCountAfterRemove),
                ],
                data: try encoder.encode(response)
            )
        case highValueScenario:
            let response = highValue()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "validThreshold": response.validThreshold.map { String($0) } ?? "<nil>",
                    "requiredPhrase": response.approvalConfirmation.requiredPhrase ?? "<nil>",
                ],
                data: try encoder.encode(response)
            )
        case policyHistoryScenario:
            let response = policyHistory()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "versionCount": String(response.versions.count),
                    "restoreRequiresSave": String(response.restoreRequiresSave),
                ],
                data: try encoder.encode(response)
            )
        case policySimulatorScenario:
            let response = policySimulator()
            return SettingsScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "allowed": response.allowedResult.allowed.map(String.init) ?? "<nil>",
                    "deniedReasons": String(response.deniedResult.reasons.count),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.settings-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown settings scenario: \(scenario). Use \(saveDiffScenario), \(postureControlsScenario), \(authPolicyScenario), \(projectIdScenario), \(rpcChainScenario), \(rpcProbeScenario), \(ruleTemplatesScenario), \(targetAddScenario), \(targetRemoveScenario), \(globalCapsScenario), \(addressBookScenario), \(highValueScenario), \(policyHistoryScenario), or \(policySimulatorScenario)."
                ]
            )
        }
    }

    static func saveDiff() -> SettingsSaveDiffScenarioProbeResponse {
        let saved = BastionConfig.default
        var unchanged = saved
        var changed = saved

        unchanged.rules.allowedHours = saved.rules.allowedHours

        changed.authPolicy = .biometric
        changed.rules.allowedHours = AllowedHours(start: 9, end: 17)
        changed.rules.spendingLimits.append(SpendingLimitRule(
            id: "usdc-daily",
            token: .usdc,
            allowance: "1000000",
            windowSeconds: 86_400
        ))
        changed.rules.rateLimits.append(RateLimitRule(
            id: "requests",
            maxRequests: 5,
            windowSeconds: 3_600
        ))
        changed.rules.rawMessagePolicy.enabled = false
        changed.rules.typedDataPolicy.enabled = false

        let unchangedHasUnsavedChanges = SettingsDiffPresentation.hasUnsavedChanges(saved: saved, draft: unchanged)
        let changedHasUnsavedChanges = SettingsDiffPresentation.hasUnsavedChanges(saved: saved, draft: changed)
        let diffRows = SettingsDiffPresentation.diffLines(saved: saved, draft: changed).map {
            SettingsScenarioDiffRow(removed: $0.removed, added: $0.added)
        }
        let idleSaveBar = SettingsScenarioSaveBarSnapshot(
            SettingsDiffPresentation.saveBar(saved: saved, draft: changed, isSaving: false)
        )
        let savingSaveBar = SettingsScenarioSaveBarSnapshot(
            SettingsDiffPresentation.saveBar(saved: saved, draft: changed, isSaving: true)
        )

        let expectedRows = [
            SettingsScenarioDiffRow(
                removed: "Auth policy: Biometric or Passcode",
                added: "Auth policy: Biometric Only"
            ),
            SettingsScenarioDiffRow(
                removed: "Allowed hours: any time",
                added: "Allowed hours: 09:00\u{2013}17:00"
            ),
            SettingsScenarioDiffRow(
                removed: "Spending limits: 0 rules",
                added: "Spending limits: 1 rules"
            ),
            SettingsScenarioDiffRow(
                removed: "Rate limits: 0 rules",
                added: "Rate limits: 1 rules"
            ),
            SettingsScenarioDiffRow(
                removed: "Raw message signing: on",
                added: "Raw message signing: off"
            ),
            SettingsScenarioDiffRow(
                removed: "EIP-712 typed data: on",
                added: "EIP-712 typed data: off"
            ),
        ]
        let checks = [
            SettingsScenarioProbeCheck(
                name: "unchanged_config_has_no_unsaved_changes",
                passed: unchangedHasUnsavedChanges == false
            ),
            SettingsScenarioProbeCheck(
                name: "changed_config_has_unsaved_changes",
                passed: changedHasUnsavedChanges == true
            ),
            SettingsScenarioProbeCheck(
                name: "semantic_diff_rows_match_expected_settings_changes",
                passed: diffRows == expectedRows
            ),
            SettingsScenarioProbeCheck(
                name: "idle_save_bar_shows_six_changes_and_enabled_save",
                passed: idleSaveBar == SettingsScenarioSaveBarSnapshot(SaveBarPresentation(
                    changeCount: 6,
                    subtitle: "6 changes will affect running agents on next request",
                    saveButtonTitle: "Save",
                    actionsDisabled: false
                ))
            ),
            SettingsScenarioProbeCheck(
                name: "saving_save_bar_disables_actions_and_shows_saving_title",
                passed: savingSaveBar == SettingsScenarioSaveBarSnapshot(SaveBarPresentation(
                    changeCount: 6,
                    subtitle: "6 changes will affect running agents on next request",
                    saveButtonTitle: "Saving\u{2026}",
                    actionsDisabled: true
                ))
            ),
        ]

        return SettingsSaveDiffScenarioProbeResponse(
            scenario: saveDiffScenario,
            passed: checks.allSatisfy(\.passed),
            unchangedHasUnsavedChanges: unchangedHasUnsavedChanges,
            changedHasUnsavedChanges: changedHasUnsavedChanges,
            diffRows: diffRows,
            idleSaveBar: idleSaveBar,
            savingSaveBar: savingSaveBar,
            checks: checks
        )
    }

    static func authPolicy() -> SettingsAuthPolicyScenarioProbeResponse {
        var draft = BastionConfig.default
        let defaultDraftPolicy = draft.authPolicy.rawValue
        draft.authPolicy = .biometric

        let selectedOptions = AuthPolicyPickerPresentation.options(selected: draft.authPolicy)
            .map(SettingsAuthOptionSnapshot.init)
        let selectedStatesByPolicy = Dictionary(
            uniqueKeysWithValues: AuthPolicyPickerPresentation.orderedPolicies.map { policy in
                (
                    policy.rawValue,
                    AuthPolicyPickerPresentation.options(selected: policy).map(\.isSelected)
                )
            }
        )

        draft.authPolicy = .open
        let mutatedToOpen = draft.authPolicy
        draft.authPolicy = .biometricOrPasscode
        let mutatedToAlwaysConfirm = draft.authPolicy

        let ownerAuthDecisions = [
            "silentRuleMatchedBiometric": SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: false,
                authPolicy: .biometric
            ),
            "manualOpen": SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: true,
                authPolicy: .open
            ),
            "manualBiometric": SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: true,
                authPolicy: .biometric
            ),
            "manualAlwaysConfirm": SigningManager.requiresOwnerAuthenticationAfterApproval(
                requiresInteractiveReview: true,
                authPolicy: .biometricOrPasscode
            ),
        ]

        let checks = [
            SettingsScenarioProbeCheck(
                name: "auth_options_keep_order_labels_hints_and_selected_state",
                passed: selectedOptions == [
                    SettingsAuthOptionSnapshot(AuthOptionPresentation(
                        policy: .open,
                        label: "Silent",
                        hint: "Complete matching requests",
                        isSelected: false
                    )),
                    SettingsAuthOptionSnapshot(AuthOptionPresentation(
                        policy: .biometric,
                        label: "Biometric",
                        hint: "Touch ID required after rules pass",
                        isSelected: true
                    )),
                    SettingsAuthOptionSnapshot(AuthOptionPresentation(
                        policy: .biometricOrPasscode,
                        label: "Always confirm",
                        hint: "Owner approves every request",
                        isSelected: false
                    )),
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "each_policy_projects_exactly_one_selected_option",
                passed: selectedStatesByPolicy == [
                    AuthPolicy.open.rawValue: [true, false, false],
                    AuthPolicy.biometric.rawValue: [false, true, false],
                    AuthPolicy.biometricOrPasscode.rawValue: [false, false, true],
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "auth_policy_binding_mutates_draft_policy",
                passed: defaultDraftPolicy == AuthPolicy.biometricOrPasscode.rawValue
                    && mutatedToOpen == .open
                    && mutatedToAlwaysConfirm == .biometricOrPasscode
            ),
            SettingsScenarioProbeCheck(
                name: "violation_owner_auth_warning_copy_is_stable",
                passed: AuthPolicyPickerPresentation.violationWarning == "Rule violations always require owner authentication, regardless of this setting."
            ),
            SettingsScenarioProbeCheck(
                name: "owner_auth_decisions_match_policy_for_matching_and_manual_review",
                passed: ownerAuthDecisions == [
                    "silentRuleMatchedBiometric": false,
                    "manualOpen": false,
                    "manualBiometric": true,
                    "manualAlwaysConfirm": true,
                ]
            ),
        ]

        return SettingsAuthPolicyScenarioProbeResponse(
            scenario: authPolicyScenario,
            passed: checks.allSatisfy(\.passed),
            selectedPolicy: AuthPolicy.biometric.rawValue,
            options: selectedOptions,
            selectedStatesByPolicy: selectedStatesByPolicy,
            defaultDraftPolicy: defaultDraftPolicy,
            mutatedDraftPolicy: draft.authPolicy.rawValue,
            violationWarning: AuthPolicyPickerPresentation.violationWarning,
            ownerAuthDecisions: ownerAuthDecisions,
            checks: checks
        )
    }

    static func projectId() -> SettingsProjectIdScenarioProbeResponse {
        let nilReadValue = BundlerPreferences.default.zeroDevProjectId ?? ""
        let existingPreferences = BundlerPreferences(
            zeroDevProjectId: "zd_existing_owner",
            chainRPCs: [
                ChainRPCPreference(chainId: 10, rpcURL: "https://optimism.example.com"),
                ChainRPCPreference(chainId: 8453, rpcURL: "https://base.example.com/rpc"),
            ]
        )
        let existingReadValue = existingPreferences.zeroDevProjectId ?? ""
        let trimmedInputValue = ZeroDevProjectIdInput.normalized(" zd_project_owner ")
        let newlineInputValue = ZeroDevProjectIdInput.normalized("\nzd_project_owner\t")
        let emptyInputValue = ZeroDevProjectIdInput.normalized("")
        let whitespaceInputValue = ZeroDevProjectIdInput.normalized("   ")

        var draft = existingPreferences
        draft.zeroDevProjectId = ZeroDevProjectIdInput.normalized("  zd_project_runtime  ")
        let afterSetProjectId = draft.zeroDevProjectId
        let preservedAfterSet = draft.chainRPCs.map(SettingsChainRPCPreferenceSnapshot.init)
        draft.zeroDevProjectId = ZeroDevProjectIdInput.normalized(" \n\t ")
        let afterClearProjectId = draft.zeroDevProjectId
        let preservedAfterClear = draft.chainRPCs.map(SettingsChainRPCPreferenceSnapshot.init)

        let expectedChainRPCs = existingPreferences.chainRPCs.map(SettingsChainRPCPreferenceSnapshot.init)
        let checks = [
            SettingsScenarioProbeCheck(
                name: "project_id_text_field_reads_nil_as_empty_string",
                passed: nilReadValue == ""
            ),
            SettingsScenarioProbeCheck(
                name: "project_id_text_field_reads_existing_value",
                passed: existingReadValue == "zd_existing_owner"
            ),
            SettingsScenarioProbeCheck(
                name: "project_id_input_trims_surrounding_whitespace",
                passed: trimmedInputValue == "zd_project_owner"
                    && newlineInputValue == "zd_project_owner"
            ),
            SettingsScenarioProbeCheck(
                name: "project_id_input_clears_empty_and_whitespace_values",
                passed: emptyInputValue == nil && whitespaceInputValue == nil
            ),
            SettingsScenarioProbeCheck(
                name: "project_id_binding_sets_trimmed_value_and_clears_blank",
                passed: afterSetProjectId == "zd_project_runtime" && afterClearProjectId == nil
            ),
            SettingsScenarioProbeCheck(
                name: "project_id_binding_preserves_rpc_preferences",
                passed: preservedAfterSet == expectedChainRPCs && preservedAfterClear == expectedChainRPCs
            ),
        ]

        return SettingsProjectIdScenarioProbeResponse(
            scenario: projectIdScenario,
            passed: checks.allSatisfy(\.passed),
            nilReadValue: nilReadValue,
            existingReadValue: existingReadValue,
            trimmedInputValue: trimmedInputValue,
            newlineInputValue: newlineInputValue,
            emptyInputValue: emptyInputValue,
            whitespaceInputValue: whitespaceInputValue,
            afterSetProjectId: afterSetProjectId,
            afterClearProjectId: afterClearProjectId,
            chainRPCsPreserved: preservedAfterSet,
            checks: checks
        )
    }

    static func rpcChain() -> SettingsRPCChainScenarioProbeResponse {
        let validDraft = ChainRPCPreferenceDraft(
            chainId: " 8453 ",
            rpcURL: " https://base.example.com/rpc?token=abc "
        )
        let validPreference = validDraft.makePreference()
        let seededPreferences = BundlerPreferences(
            zeroDevProjectId: "zd_project_owner",
            chainRPCs: [
                ChainRPCPreference(chainId: 10, rpcURL: "https://optimism.example.com")
            ]
        )
        var updatedPreferences = seededPreferences
        if let validPreference {
            updatedPreferences = ChainRPCPreferenceDraft.upsert(validPreference, into: updatedPreferences)
        }
        let replacement = ChainRPCPreferenceDraft(
            chainId: "10",
            rpcURL: " http://localhost:8545 "
        ).makePreference()
        var replacedPreferences = updatedPreferences
        if let replacement {
            replacedPreferences = ChainRPCPreferenceDraft.upsert(replacement, into: replacedPreferences)
        }

        let invalidChain = ChainRPCPreferenceDraft(chainId: "0", rpcURL: "https://rpc.example.com")
        let invalidScheme = ChainRPCPreferenceDraft(chainId: "1", rpcURL: "ftp://rpc.example.com")
        let missingHost = ChainRPCPreferenceDraft(chainId: "1", rpcURL: "https://")
        let validationMessages: [String: String?] = [
            "valid": validDraft.validationMessage,
            "invalidChain": invalidChain.validationMessage,
            "invalidScheme": invalidScheme.validationMessage,
            "missingHost": missingHost.validationMessage,
        ]

        var savedConfig = BastionConfig.default
        savedConfig.bundlerPreferences = seededPreferences
        var draftConfig = savedConfig
        draftConfig.bundlerPreferences = updatedPreferences
        let hasUnsavedChangesAfterAdd = SettingsDiffPresentation.hasUnsavedChanges(
            saved: savedConfig,
            draft: draftConfig
        )
        let diffRows = SettingsDiffPresentation.diffLines(saved: savedConfig, draft: draftConfig).map {
            SettingsScenarioDiffRow(removed: $0.removed, added: $0.added)
        }
        let saveBar = SettingsScenarioSaveBarSnapshot(
            SettingsDiffPresentation.saveBar(saved: savedConfig, draft: draftConfig, isSaving: false)
        )

        let updatedSnapshots = updatedPreferences.chainRPCs.map(SettingsChainRPCPreferenceSnapshot.init)
        let replacedSnapshots = replacedPreferences.chainRPCs.map(SettingsChainRPCPreferenceSnapshot.init)
        let expectedUpdated = [
            SettingsChainRPCPreferenceSnapshot(ChainRPCPreference(chainId: 10, rpcURL: "https://optimism.example.com")),
            SettingsChainRPCPreferenceSnapshot(ChainRPCPreference(chainId: 8453, rpcURL: "https://base.example.com/rpc?token=abc")),
        ]
        let expectedReplaced = [
            SettingsChainRPCPreferenceSnapshot(ChainRPCPreference(chainId: 10, rpcURL: "http://localhost:8545")),
            SettingsChainRPCPreferenceSnapshot(ChainRPCPreference(chainId: 8453, rpcURL: "https://base.example.com/rpc?token=abc")),
        ]
        let checks = [
            SettingsScenarioProbeCheck(
                name: "valid_rpc_chain_draft_trims_and_normalizes_values",
                passed: validPreference?.chainId == 8453
                    && validPreference?.rpcURL == "https://base.example.com/rpc?token=abc"
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_chain_upsert_appends_and_sorts_new_chain",
                passed: updatedSnapshots == expectedUpdated
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_chain_upsert_replaces_existing_chain_without_duplication",
                passed: replacedSnapshots == expectedReplaced
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_chain_upsert_preserves_project_id",
                passed: updatedPreferences.zeroDevProjectId == "zd_project_owner"
                    && replacedPreferences.zeroDevProjectId == "zd_project_owner"
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_chain_validation_messages_cover_chain_scheme_and_host",
                passed: validationMessages == [
                    "valid": nil,
                    "invalidChain": ChainRPCPreferenceDraft.chainIdError,
                    "invalidScheme": ChainRPCPreferenceDraft.rpcURLError,
                    "missingHost": ChainRPCPreferenceDraft.rpcURLError,
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_chain_add_marks_settings_unsaved_and_shows_save_bar",
                passed: hasUnsavedChangesAfterAdd
                    && diffRows == [
                        SettingsScenarioDiffRow(
                            removed: "RPC endpoints: 1 configured",
                            added: "RPC endpoints: 2 configured"
                        )
                    ]
                    && saveBar == SettingsScenarioSaveBarSnapshot(SaveBarPresentation(
                        changeCount: 1,
                        subtitle: "1 changes will affect running agents on next request",
                        saveButtonTitle: "Save",
                        actionsDisabled: false
                    ))
            ),
        ]

        return SettingsRPCChainScenarioProbeResponse(
            scenario: rpcChainScenario,
            passed: checks.allSatisfy(\.passed),
            validPreference: validPreference.map(SettingsChainRPCPreferenceSnapshot.init),
            updatedChainRPCs: updatedSnapshots,
            replacedChainRPCs: replacedSnapshots,
            zeroDevProjectIdPreserved: updatedPreferences.zeroDevProjectId,
            validationMessages: validationMessages,
            hasUnsavedChangesAfterAdd: hasUnsavedChangesAfterAdd,
            diffRows: diffRows,
            saveBar: saveBar,
            checks: checks
        )
    }

    static func rpcProbe() async -> SettingsRPCProbeScenarioProbeResponse {
        SettingsScenarioRPCURLProtocol.reset(responses: [
            "/ok": SettingsScenarioRPCMockResponse(
                statusCode: 200,
                body: #"{"jsonrpc":"2.0","id":1,"result":"0x2a"}"#
            ),
            "/http-500": SettingsScenarioRPCMockResponse(
                statusCode: 500,
                body: #"{"jsonrpc":"2.0","id":1,"error":{"message":"boom"}}"#
            ),
            "/malformed": SettingsScenarioRPCMockResponse(
                statusCode: 200,
                body: #"{"jsonrpc":"2.0","id":1,"error":{"message":"missing result"}}"#
            ),
        ])

        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [SettingsScenarioRPCURLProtocol.self]
        let session = URLSession(configuration: configuration)
        defer {
            session.invalidateAndCancel()
            SettingsScenarioRPCURLProtocol.reset(responses: [:])
        }

        let emptyControl = SettingsRPCProbeControlSnapshot(
            RPCProbePresentation.make(isProbing: false, endpointCount: 0)
        )
        let readyControl = SettingsRPCProbeControlSnapshot(
            RPCProbePresentation.make(isProbing: false, endpointCount: 3)
        )
        let probingControl = SettingsRPCProbeControlSnapshot(
            RPCProbePresentation.make(isProbing: true, endpointCount: 3)
        )

        let preferences = BundlerPreferences(
            zeroDevProjectId: "zd_project_owner",
            chainRPCs: [
                ChainRPCPreference(chainId: 8453, rpcURL: "https://bastion-rpc-probe.local/ok"),
                ChainRPCPreference(chainId: 10, rpcURL: "https://bastion-rpc-probe.local/http-500"),
                ChainRPCPreference(chainId: 11155111, rpcURL: "https://bastion-rpc-probe.local/malformed"),
                ChainRPCPreference(chainId: 1, rpcURL: "ftp://bastion-rpc-probe.local/invalid"),
            ]
        )
        let samples = await RPCHealthMonitor.shared.probe(preferences: preferences, session: session)
        let okSample = SettingsRPCProbeSampleSnapshot(samples[8453])
        let httpErrorSample = SettingsRPCProbeSampleSnapshot(samples[10])
        let malformedSample = SettingsRPCProbeSampleSnapshot(samples[11155111])
        let invalidURLSample = SettingsRPCProbeSampleSnapshot(samples[1])
        let requestedMethods = SettingsScenarioRPCURLProtocol.capturedRequestedMethods()

        let checks = [
            SettingsScenarioProbeCheck(
                name: "rpc_probe_button_states_disable_empty_and_inflight_while_enabling_ready",
                passed: emptyControl == SettingsRPCProbeControlSnapshot(RPCProbePresentation.make(isProbing: false, endpointCount: 0))
                    && readyControl == SettingsRPCProbeControlSnapshot(RPCProbePresentation.make(isProbing: false, endpointCount: 3))
                    && probingControl == SettingsRPCProbeControlSnapshot(RPCProbePresentation.make(isProbing: true, endpointCount: 3))
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_probe_posts_eth_block_number_to_each_http_endpoint",
                passed: requestedMethods == ["POST", "POST", "POST"]
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_probe_ok_response_records_ok_status_and_latency_label",
                passed: okSample.chainId == 8453
                    && okSample.status == RPCStatus.ok.rawValue
                    && okSample.presentationStatus == RPCStatus.ok.rawValue
                    && okSample.latencyMs != nil
                    && okSample.latencyLabel.hasSuffix("ms")
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_probe_http_error_records_bad_status_and_error_label",
                passed: httpErrorSample.chainId == 10
                    && httpErrorSample.status == RPCStatus.bad.rawValue
                    && httpErrorSample.presentationStatus == RPCStatus.bad.rawValue
                    && httpErrorSample.error == "HTTP 500"
                    && httpErrorSample.latencyLabel == "HTTP 500"
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_probe_missing_result_records_warn_status_and_no_result_label",
                passed: malformedSample.chainId == 11155111
                    && malformedSample.status == RPCStatus.warn.rawValue
                    && malformedSample.presentationStatus == RPCStatus.warn.rawValue
                    && malformedSample.error == "No result"
                    && malformedSample.latencyLabel == "No result"
            ),
            SettingsScenarioProbeCheck(
                name: "rpc_probe_invalid_url_records_bad_status_without_network_request",
                passed: invalidURLSample.chainId == 1
                    && invalidURLSample.status == RPCStatus.bad.rawValue
                    && invalidURLSample.presentationStatus == RPCStatus.bad.rawValue
                    && invalidURLSample.error == "Invalid URL"
                    && invalidURLSample.latencyLabel == "Invalid URL"
            ),
        ]

        return SettingsRPCProbeScenarioProbeResponse(
            scenario: rpcProbeScenario,
            passed: checks.allSatisfy(\.passed),
            emptyControl: emptyControl,
            readyControl: readyControl,
            probingControl: probingControl,
            okSample: okSample,
            httpErrorSample: httpErrorSample,
            malformedSample: malformedSample,
            invalidURLSample: invalidURLSample,
            requestedMethods: requestedMethods,
            checks: checks
        )
    }

    static func ruleTemplates() -> SettingsRuleTemplatesScenarioProbeResponse {
        let presentation = RuleTemplatesPanelPresentation.make()
        let cards = presentation.cards.map(SettingsRuleTemplateCardSnapshot.init)

        var config = BastionConfig.default
        config.authPolicy = .open
        config.rules = .default
        config.clientProfiles = [
            ClientProfile(
                id: "client-a",
                bundleId: "com.example.agent",
                label: "Example Agent",
                rules: .default
            )
        ]

        let result = RuleTemplateApplication.applyToDefault(.treasury, config: config)
        let appliedRules = result.config.rules
        let appliedAllowances = appliedRules.spendingLimits
            .map { "\($0.token.displayName):\($0.allowance):\($0.windowSeconds ?? 0)" }
            .sorted()

        let treasuryCard = cards.first { $0.template == PairingPolicyTemplate.treasury.rawValue }
        let readOnlyCard = cards.first { $0.template == PairingPolicyTemplate.readOnly.rawValue }
        let checks = [
            SettingsScenarioProbeCheck(
                name: "template_panel_copy_and_inventory",
                passed: presentation.title == "Rule templates"
                    && presentation.subtitle == "Reusable starting points for new agents. Apply one to defaults or pair an agent from it."
                    && presentation.subtitle.contains("edit") == false
                    && presentation.subtitle.contains("clone") == false
                    && presentation.newAgentButtonTitle == "+ New agent"
                    && cards.map(\.template) == ["conservative", "readOnly", "treasury"]
            ),
            SettingsScenarioProbeCheck(
                name: "template_cards_expose_metrics_and_actions",
                passed: treasuryCard?.metrics == [
                    SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "USDC/DAY", value: "10000/day")),
                    SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "ETH/DAY", value: "5/day")),
                    SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "RATE", value: "10/hour")),
                    SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "AUTH", value: "Biometric or Passcode")),
                ]
                    && readOnlyCard?.metrics == [
                        SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "USDC/DAY", value: "0/day")),
                        SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "ETH/DAY", value: "0/day")),
                        SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "RATE", value: "200/hour")),
                        SettingsRuleTemplateMetricSnapshot(RuleTemplateMetricPresentation(key: "AUTH", value: "Biometric Only")),
                    ]
                    && cards.allSatisfy { $0.applyButtonTitle == "Apply to default" && $0.pairButtonTitle == "Pair agent" }
            ),
            SettingsScenarioProbeCheck(
                name: "custom_template_hidden_from_reusable_cards",
                passed: cards.contains { $0.template == PairingPolicyTemplate.custom.rawValue } == false
            ),
            SettingsScenarioProbeCheck(
                name: "apply_treasury_template_mutates_default_auth_and_rules",
                passed: result.config.authPolicy == .biometricOrPasscode
                    && appliedRules.userOpPosture == .enforceRulesAndRequireApproval
                    && appliedRules.allowedHours?.start == 9
                    && appliedRules.allowedHours?.end == 18
                    && appliedRules.allowedChains == [1, 8453]
                    && appliedRules.rateLimits.map(\.maxRequests) == [10]
                    && appliedRules.rateLimits.map(\.windowSeconds) == [3_600]
                    && appliedRules.rawMessagePolicy.enabled == false
                    && appliedRules.typedDataPolicy.requireExplicitApproval == true
                    && appliedRules.spendingLimits.contains { $0.token == .usdc && $0.allowance == "10000000000" && $0.windowSeconds == 86_400 }
                    && appliedRules.spendingLimits.contains { $0.token == .eth && $0.allowance == "5000000000000000000" && $0.windowSeconds == 86_400 }
            ),
            SettingsScenarioProbeCheck(
                name: "apply_treasury_preserves_client_profiles_and_routes_to_defaults",
                passed: result.config.clientProfiles.map(\.id) == ["client-a"]
                    && result.statusMessage == "Applied Treasury custodian to the default profile"
                    && result.statusIsError == false
                    && result.selection == .defaultProfile
            ),
        ]

        return SettingsRuleTemplatesScenarioProbeResponse(
            scenario: ruleTemplatesScenario,
            passed: checks.allSatisfy(\.passed),
            title: presentation.title,
            subtitle: presentation.subtitle,
            newAgentButtonTitle: presentation.newAgentButtonTitle,
            cards: cards,
            appliedStatusMessage: result.statusMessage,
            appliedStatusIsError: result.statusIsError,
            appliedSelection: result.selection.stableID,
            appliedAuthPolicy: result.config.authPolicy.rawValue,
            appliedAllowedChains: appliedRules.allowedChains,
            appliedAllowedHoursStart: appliedRules.allowedHours?.start,
            appliedAllowedHoursEnd: appliedRules.allowedHours?.end,
            appliedRateLimitCount: appliedRules.rateLimits.count,
            appliedSpendingAllowances: appliedAllowances,
            existingClientProfileIds: result.config.clientProfiles.map(\.id),
            checks: checks
        )
    }

    static func targetAdd() -> SettingsTargetAddScenarioProbeResponse {
        let mixedAddress = "0XABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"
        let validDraft = TargetAllowlistEntryDraft(
            chainId: " 8453 ",
            address: " \(mixedAddress) ",
            usdcDailyCap: " 12.5 "
        )
        let validEntry = validDraft.makeEntry()
        var addedRules = RuleConfig.default
        if let validEntry {
            addedRules = TargetAllowlistMutation.add(validEntry, to: addedRules)
        }

        var duplicateRules = addedRules
        if let validEntry {
            duplicateRules = TargetAllowlistMutation.add(validEntry, to: duplicateRules)
        }

        let canonicalTarget = validEntry?.address ?? ""
        let matchingTargets = addedRules.allowedTargets?["8453"]?.filter {
            $0.caseInsensitiveCompare(canonicalTarget) == .orderedSame
        } ?? []
        let matchingCaps = addedRules.spendingLimits.filter {
            $0.targetAddress?.caseInsensitiveCompare(canonicalTarget) == .orderedSame && $0.token == .usdc
        }
        let duplicateTargets = duplicateRules.allowedTargets?["8453"]?.filter {
            $0.caseInsensitiveCompare(canonicalTarget) == .orderedSame
        } ?? []
        let duplicateCaps = duplicateRules.spendingLimits.filter {
            $0.targetAddress?.caseInsensitiveCompare(canonicalTarget) == .orderedSame && $0.token == .usdc
        }
        let capRule = matchingCaps.first
        let stateStore = StateStore(keychain: SettingsScenarioMemoryKeychain())
        if let capRule {
            _ = stateStore.recordSpend(ruleId: capRule.id, amount: "2500000", windowSeconds: capRule.windowSeconds)
        }
        let capLabel = TargetAllowlistPresentation.capLabel(for: canonicalTarget, in: addedRules)
        let usedLabel = TargetAllowlistPresentation.usedLabel(for: canonicalTarget, in: addedRules, stateStore: stateStore)

        let uncappedAddress = "1111111111111111111111111111111111111111"
        let uncappedEntry = TargetAllowlistEntryDraft(
            chainId: "1",
            address: uncappedAddress,
            usdcDailyCap: " "
        ).makeEntry()
        var uncappedRules = RuleConfig.default
        if let uncappedEntry {
            uncappedRules = TargetAllowlistMutation.add(uncappedEntry, to: uncappedRules)
        }
        let uncappedTargetHasCap = uncappedRules.spendingLimits.contains {
            $0.targetAddress?.caseInsensitiveCompare(uncappedEntry?.address ?? "") == .orderedSame
        }

        let invalidChain = TargetAllowlistEntryDraft(chainId: "0", address: uncappedAddress, usdcDailyCap: "")
        let invalidAddress = TargetAllowlistEntryDraft(chainId: "1", address: "0x123", usdcDailyCap: "")
        let zeroCap = TargetAllowlistEntryDraft(chainId: "1", address: uncappedAddress, usdcDailyCap: "0")
        let hugeCap = TargetAllowlistEntryDraft(chainId: "1", address: uncappedAddress, usdcDailyCap: "1e20")
        let validationMessages: [String: String?] = [
            "valid": validDraft.validationMessage,
            "invalidChain": invalidChain.validationMessage,
            "invalidAddress": invalidAddress.validationMessage,
            "zeroCap": zeroCap.validationMessage,
            "hugeCap": hugeCap.validationMessage,
        ]

        let checks = [
            SettingsScenarioProbeCheck(
                name: "valid_draft_canonicalizes_chain_address_and_cap",
                passed: validEntry == TargetAllowlistEntry(
                    chainId: 8453,
                    address: "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd",
                    usdcDailyCap: 12.5
                )
            ),
            SettingsScenarioProbeCheck(
                name: "target_add_stores_canonical_target_under_positive_chain_id",
                passed: matchingTargets == ["0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"]
            ),
            SettingsScenarioProbeCheck(
                name: "target_add_creates_positive_usdc_daily_cap",
                passed: matchingCaps.count == 1
                    && matchingCaps.first?.allowance == "12500000"
                    && matchingCaps.first?.windowSeconds == 86_400
                    && matchingCaps.first?.targetAddress == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
            ),
            SettingsScenarioProbeCheck(
                name: "duplicate_add_does_not_duplicate_target_or_cap",
                passed: duplicateTargets.count == 1 && duplicateCaps.count == 1
            ),
            SettingsScenarioProbeCheck(
                name: "uncapped_target_add_does_not_create_spending_limit",
                passed: uncappedEntry?.address == "0x1111111111111111111111111111111111111111" && !uncappedTargetHasCap
            ),
            SettingsScenarioProbeCheck(
                name: "inline_validation_messages_cover_chain_address_zero_cap_and_huge_cap",
                passed: validationMessages == [
                    "valid": nil,
                    "invalidChain": TargetAllowlistEntryDraft.chainIdError,
                    "invalidAddress": TargetAllowlistEntryDraft.addressError,
                    "zeroCap": TargetAllowlistEntryDraft.usdcCapError,
                    "hugeCap": TargetAllowlistEntryDraft.usdcCapTooLargeError,
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "per_target_cap_label_uses_rule_formatter",
                passed: capLabel == "12.50 USDC"
            ),
            SettingsScenarioProbeCheck(
                name: "per_target_used_label_reads_state_store_status",
                passed: usedLabel == "2.50 USDC"
            ),
        ]

        return SettingsTargetAddScenarioProbeResponse(
            scenario: targetAddScenario,
            passed: checks.allSatisfy(\.passed),
            validEntry: validEntry.map(SettingsTargetAddEntrySnapshot.init),
            allowedTargets: addedRules.allowedTargets ?? [:],
            matchingTargetCount: matchingTargets.count,
            matchingCapCount: matchingCaps.count,
            capAllowanceRaw: capRule?.allowance,
            capWindowSeconds: capRule?.windowSeconds,
            capLabel: capLabel,
            usedLabel: usedLabel,
            duplicateTargetCount: duplicateTargets.count,
            duplicateCapCount: duplicateCaps.count,
            uncappedTargetHasCap: uncappedTargetHasCap,
            validationMessages: validationMessages,
            checks: checks
        )
    }

    static func targetRemove() -> SettingsTargetRemoveScenarioProbeResponse {
        let removed = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        let remaining = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        let otherChain = "0xcccccccccccccccccccccccccccccccccccccccc"

        var rules = RuleConfig.default
        rules.allowedTargets = [
            "8453": [removed, remaining],
            "1": [otherChain],
        ]
        rules.spendingLimits = [
            SpendingLimitRule(token: .usdc, allowance: "12500000", windowSeconds: 86_400, targetAddress: removed),
            SpendingLimitRule(token: .eth, allowance: "1000000000000000000", windowSeconds: nil, targetAddress: remaining),
            SpendingLimitRule(token: .usdc, allowance: "50000000", windowSeconds: 86_400),
        ]

        let rowPresentation = TargetAllowlistRowPresentation.make(
            chainId: 8453,
            address: " 0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA "
        )
        let removedLimitBefore = TargetAllowlistMutation.targetLimit(
            for: "0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            in: rules
        )
        let updated = TargetAllowlistMutation.remove(
            chainId: 8453,
            address: " 0XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA ",
            from: rules
        )
        let removedLimitAfter = TargetAllowlistMutation.targetLimit(for: removed, in: updated)
        let remainingLimit = TargetAllowlistMutation.targetLimit(for: remaining.uppercased(), in: updated)

        var single = RuleConfig.default
        single.allowedTargets = ["10": [removed]]
        single.spendingLimits = [
            SpendingLimitRule(token: .usdc, allowance: "1000000", windowSeconds: 86_400, targetAddress: removed),
        ]
        let emptied = TargetAllowlistMutation.remove(chainId: 10, address: removed, from: single)

        let checks = [
            SettingsScenarioProbeCheck(
                name: "remove_row_accessibility_explains_target_chain_and_cap_consequence",
                passed: rowPresentation == TargetAllowlistRowPresentation(
                    removeAccessibilityLabel: "Remove target 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa on chain 8453",
                    removeHelp: "Remove 0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa from the chain 8453 target allowlist and clear its per-target cap."
                )
            ),
            SettingsScenarioProbeCheck(
                name: "remove_deletes_only_matching_target_from_chain_allowlist",
                passed: updated.allowedTargets?["8453"] == [remaining]
                    && updated.allowedTargets?["1"] == [otherChain]
            ),
            SettingsScenarioProbeCheck(
                name: "remove_prunes_removed_target_cap_and_preserves_unrelated_caps",
                passed: updated.spendingLimits.map(\.allowance) == ["1000000000000000000", "50000000"]
            ),
            SettingsScenarioProbeCheck(
                name: "removed_target_limit_lookup_returns_nil",
                passed: removedLimitBefore?.allowance == "12500000" && removedLimitAfter == nil
            ),
            SettingsScenarioProbeCheck(
                name: "remaining_target_limit_lookup_is_case_insensitive",
                passed: remainingLimit?.token == .eth
            ),
            SettingsScenarioProbeCheck(
                name: "removing_last_target_collapses_allowed_targets_to_nil",
                passed: emptied.allowedTargets == nil && emptied.spendingLimits.isEmpty
            ),
        ]

        return SettingsTargetRemoveScenarioProbeResponse(
            scenario: targetRemoveScenario,
            passed: checks.allSatisfy(\.passed),
            rowPresentation: SettingsTargetRemoveRowSnapshot(rowPresentation),
            beforeAllowedTargets: rules.allowedTargets ?? [:],
            afterAllowedTargets: updated.allowedTargets,
            updatedSpendingAllowances: updated.spendingLimits.map(\.allowance),
            removedLimitBeforeAllowance: removedLimitBefore?.allowance,
            removedLimitAfterExists: removedLimitAfter != nil,
            remainingLimitToken: remainingLimit?.token.displayName,
            emptiedAllowedTargetsNil: emptied.allowedTargets == nil,
            emptiedSpendingLimitCount: emptied.spendingLimits.count,
            checks: checks
        )
    }

    static func globalCaps() -> SettingsGlobalCapsScenarioProbeResponse {
        let stateStore = StateStore(keychain: SettingsScenarioMemoryKeychain())
        let usdcRule = SpendingLimitRule(
            id: "scenario-usdc",
            token: .usdc,
            allowance: "250000000",
            windowSeconds: 86_400
        )
        let ethRule = SpendingLimitRule(
            id: "scenario-eth",
            token: .eth,
            allowance: "1000000000000000000",
            windowSeconds: nil
        )
        let rateRule = RateLimitRule(id: "scenario-rate", maxRequests: 3, windowSeconds: 3_600)
        _ = stateStore.recordSpend(ruleId: usdcRule.id, amount: "150250000", windowSeconds: usdcRule.windowSeconds)
        _ = stateStore.recordSpend(ruleId: ethRule.id, amount: "1000000000000000000", windowSeconds: ethRule.windowSeconds)
        _ = stateStore.recordRequest(ruleId: rateRule.id, windowSeconds: rateRule.windowSeconds)
        _ = stateStore.recordRequest(ruleId: rateRule.id, windowSeconds: rateRule.windowSeconds)
        _ = stateStore.recordRequest(ruleId: rateRule.id, windowSeconds: rateRule.windowSeconds)

        let usdcTile = SettingsGlobalCapTileSnapshot(GlobalCapTilePresentation.spendingLimit(
            prefix: "Total USDC",
            rule: usdcRule,
            status: stateStore.spendingLimitStatus(rule: usdcRule)
        ))
        let ethTile = SettingsGlobalCapTileSnapshot(GlobalCapTilePresentation.spendingLimit(
            prefix: "Total ETH",
            rule: ethRule,
            status: stateStore.spendingLimitStatus(rule: ethRule)
        ))
        let rateTile = SettingsGlobalCapTileSnapshot(GlobalCapTilePresentation.rateLimit(
            rule: rateRule,
            status: stateStore.rateLimitStatus(rule: rateRule)
        ))
        let hoursTile = SettingsGlobalCapTileSnapshot(GlobalCapTilePresentation.allowedHours(AllowedHours(start: 9, end: 17)))
        let unrestrictedHoursTile = SettingsGlobalCapTileSnapshot(GlobalCapTilePresentation.allowedHours(nil))

        let checks = [
            SettingsScenarioProbeCheck(
                name: "usdc_cap_tile_formats_allowance_usage_and_non_warn_state",
                passed: usdcTile == SettingsGlobalCapTileSnapshot(CapTilePresentation(
                    label: "Total USDC/day",
                    value: "250",
                    used: 150.25,
                    total: 250.0,
                    unit: " USDC",
                    warn: false
                ))
            ),
            SettingsScenarioProbeCheck(
                name: "eth_cap_tile_reads_state_store_and_warns_when_exhausted",
                passed: ethTile == SettingsGlobalCapTileSnapshot(CapTilePresentation(
                    label: "Total ETH/lifetime",
                    value: "1",
                    used: 1.0,
                    total: 1.0,
                    unit: " ETH",
                    warn: true
                ))
            ),
            SettingsScenarioProbeCheck(
                name: "rate_tile_reads_state_store_count_and_warns_when_exhausted",
                passed: rateTile == SettingsGlobalCapTileSnapshot(CapTilePresentation(
                    label: "Signatures/hour",
                    value: "3",
                    used: 3.0,
                    total: 3.0,
                    unit: "",
                    warn: true
                ))
            ),
            SettingsScenarioProbeCheck(
                name: "allowed_hours_tile_formats_restricted_window_without_usage",
                passed: hoursTile == SettingsGlobalCapTileSnapshot(CapTilePresentation(
                    label: "Allowed hours",
                    value: "09:00 \u{2013} 17:00",
                    used: nil,
                    total: nil,
                    unit: "",
                    warn: false
                ))
            ),
            SettingsScenarioProbeCheck(
                name: "unrestricted_hours_tile_formats_any_time_without_usage",
                passed: unrestrictedHoursTile == SettingsGlobalCapTileSnapshot(CapTilePresentation(
                    label: "Allowed hours",
                    value: "any time",
                    used: nil,
                    total: nil,
                    unit: "",
                    warn: false
                ))
            ),
        ]

        return SettingsGlobalCapsScenarioProbeResponse(
            scenario: globalCapsScenario,
            passed: checks.allSatisfy(\.passed),
            usdcTile: usdcTile,
            ethTile: ethTile,
            rateTile: rateTile,
            hoursTile: hoursTile,
            unrestrictedHoursTile: unrestrictedHoursTile,
            checks: checks
        )
    }

    static func addressBook() -> SettingsAddressBookScenarioProbeResponse {
        let mixedAddress = "0XABCDEFabcdefABCDEFabcdefABCDEFabcdefABCD"
        let longLabel = String(repeating: "L", count: 70)
        let validDraft = AddressBookEntryDraft(
            address: " \(mixedAddress) ",
            label: " \(longLabel) ",
            chainId: " 8453 "
        )
        let validEntry = validDraft.makeEntry()

        let bareAddress = "1111111111111111111111111111111111111111"
        let anyChainEntry = AddressBookEntryDraft(
            address: bareAddress,
            label: " Treasury ",
            chainId: " "
        ).makeEntry()

        var storedEntries = [AddressBookEntry]()
        if let validEntry {
            storedEntries.append(validEntry)
        }
        if let anyChainEntry {
            storedEntries.append(anyChainEntry)
        }
        let storedEntryCount = storedEntries.count
        if let validEntry {
            storedEntries.removeAll { $0.id == validEntry.id }
        }
        let entryCountAfterRemove = storedEntries.count

        let invalidAddress = AddressBookEntryDraft(address: "0x123", label: "Treasury", chainId: "1")
        let blankLabel = AddressBookEntryDraft(address: bareAddress, label: "   ", chainId: "")
        let invalidChain = AddressBookEntryDraft(address: bareAddress, label: "Treasury", chainId: "0")
        let validationMessages: [String: String?] = [
            "valid": validDraft.validationMessage,
            "invalidAddress": invalidAddress.validationMessage,
            "blankLabel": blankLabel.validationMessage,
            "invalidChain": invalidChain.validationMessage,
        ]

        let recipient = "0x2222222222222222222222222222222222222222"
        let token = USDCAddresses.address(for: 8453) ?? "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
        let approval = ApprovalRequest(
            request: scenarioUserOpRequest(
                chainId: 8453,
                callData: scenarioKernelSingleCallData(
                    target: token,
                    calldata: erc20TransferCalldata(to: recipient, amount: 12_345_678)
                ),
                requestID: "settings-address-book-scenario",
                clientBundleId: "com.example.agent",
                submission: UserOperationSubmissionRequest(projectId: "project-123")
            ),
            mode: .policyReview,
            clientContext: scenarioClient()
        )
        var labelledConfig = BastionConfig.default
        labelledConfig.addressBook = [
            AddressBookEntry(address: recipient, label: "Treasury vault", chainId: 8453),
        ]
        let decoded = SigningRequestDecodedPresentation.make(approval: approval, config: labelledConfig)
        let decodedRecipientLabel = decodedAddressLabel(in: decoded, key: "To")

        let validRow = validEntry.map(AddressBookRowPresentation.make)
        let anyChainRow = anyChainEntry.map(AddressBookRowPresentation.make)
        let expectedLongLabel = String(repeating: "L", count: 64)
        let checks = [
            SettingsScenarioProbeCheck(
                name: "valid_address_book_draft_trims_canonicalizes_and_bounds_label",
                passed: validEntry?.address == "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd"
                    && validEntry?.label == expectedLongLabel
                    && validEntry?.chainId == 8453
            ),
            SettingsScenarioProbeCheck(
                name: "any_chain_address_book_entry_trims_label_and_leaves_chain_nil",
                passed: anyChainEntry?.address == "0x1111111111111111111111111111111111111111"
                    && anyChainEntry?.label == "Treasury"
                    && anyChainEntry?.chainId == nil
                    && anyChainRow?.removeHelp == "Remove Treasury for 0x1111111111111111111111111111111111111111 on any chain"
            ),
            SettingsScenarioProbeCheck(
                name: "address_book_validation_messages_cover_address_label_and_chain_errors",
                passed: validationMessages == [
                    "valid": nil,
                    "invalidAddress": AddressBookEntryDraft.addressError,
                    "blankLabel": AddressBookEntryDraft.labelError,
                    "invalidChain": AddressBookEntryDraft.chainIdError,
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "address_book_remove_row_copy_names_label_address_and_chain_scope",
                passed: validRow == AddressBookRowPresentation(
                    removeAccessibilityLabel: "Remove address label \(expectedLongLabel)",
                    removeHelp: "Remove \(expectedLongLabel) for 0xabcdefabcdefabcdefabcdefabcdefabcdefabcd on chain 8453"
                )
            ),
            SettingsScenarioProbeCheck(
                name: "address_book_remove_action_deletes_only_matching_entry_id",
                passed: storedEntryCount == 2
                    && entryCountAfterRemove == 1
                    && storedEntries.first?.label == "Treasury"
            ),
            SettingsScenarioProbeCheck(
                name: "approval_decoding_resolves_address_book_label_for_matching_chain",
                passed: decoded.headline == "Send 12345678"
                    && decodedRecipientLabel == "Treasury vault"
            ),
        ]

        return SettingsAddressBookScenarioProbeResponse(
            scenario: addressBookScenario,
            passed: checks.allSatisfy(\.passed),
            validEntry: validEntry.map(SettingsAddressBookEntrySnapshot.init),
            anyChainEntry: anyChainEntry.map(SettingsAddressBookEntrySnapshot.init),
            validRowPresentation: validRow.map(SettingsAddressBookRowSnapshot.init),
            anyChainRowPresentation: anyChainRow.map(SettingsAddressBookRowSnapshot.init),
            storedEntryCount: storedEntryCount,
            entryCountAfterRemove: entryCountAfterRemove,
            decodedHeadline: decoded.headline,
            decodedRecipientLabel: decodedRecipientLabel,
            validationMessages: validationMessages,
            checks: checks
        )
    }

    static func highValue() -> SettingsHighValueScenarioProbeResponse {
        let valid = HighValueRuleDraft(
            enabled: true,
            thresholdText: " 250.5 ",
            confirmationPhrase: " CONFIRM "
        )
        let blankPhrase = HighValueRuleDraft(
            enabled: true,
            thresholdText: "100",
            confirmationPhrase: "   "
        )
        let missingThreshold = HighValueRuleDraft(
            enabled: true,
            thresholdText: "   ",
            confirmationPhrase: "CONFIRM"
        )
        let invalidThreshold = HighValueRuleDraft(
            enabled: true,
            thresholdText: "0",
            confirmationPhrase: "CONFIRM"
        )
        let disabledBlankThreshold = HighValueRuleDraft(
            enabled: false,
            thresholdText: "",
            confirmationPhrase: "CONFIRM"
        )

        var rules = RuleConfig.default
        rules.userOpPosture = .enforceRulesAndAutoSign
        let highValueConfig = BastionConfig(
            authPolicy: .open,
            rules: rules,
            highValue: HighValueRule(enabled: true, thresholdUsd: 100, confirmationPhrase: "")
        )
        let engine = RuleEngine(keychain: SettingsScenarioMemoryKeychain())
        let request = scenarioUserOpRequest(requestID: "settings-high-value-scenario")
        let belowThresholdConfirmationPhrase = engine.highValueConfirmationPhrase(
            for: request,
            config: highValueConfig,
            simulatedSpendObservations: [SimulatedSpendObservation(token: .usdc, amount: "99999999")]
        )
        let ruleEngineConfirmationPhrase = engine.highValueConfirmationPhrase(
            for: request,
            config: highValueConfig,
            simulatedSpendObservations: [SimulatedSpendObservation(token: .usdc, amount: "100000000")]
        )

        let approval = ApprovalRequest(
            request: request,
            mode: .ruleOverride(["High-value transfer exceeded: 100 USD"]),
            clientContext: scenarioClient(),
            typedConfirmationPhrase: " CONFIRM "
        )
        let wrongPresentation = SigningTypedConfirmationPresentation.make(
            approval: approval,
            confirmationText: " wrong "
        )
        let correctPresentation = SigningTypedConfirmationPresentation.make(
            approval: approval,
            confirmationText: " CONFIRM "
        )
        let wrongCanSubmit = SigningRequestPresentation.canSubmitApproval(
            approval: approval,
            confirmationText: " wrong "
        )
        let correctCanSubmit = SigningRequestPresentation.canSubmitApproval(
            approval: approval,
            confirmationText: " CONFIRM "
        )
        let correctCanTrigger = SigningRequestPresentation.make(
            approval: approval,
            remainingSeconds: 42,
            showRaw: false,
            authStage: .idle,
            confirmationText: " CONFIRM "
        ).canTriggerPrimary
        let approvalConfirmation = SettingsHighValueConfirmationSnapshot(
            requiredPhrase: correctPresentation?.requiredPhrase,
            message: correctPresentation?.message,
            placeholder: correctPresentation?.placeholder,
            wrongTextSatisfied: wrongPresentation?.isSatisfied,
            correctTextSatisfied: correctPresentation?.isSatisfied,
            wrongTextCanSubmit: wrongCanSubmit,
            correctTextCanSubmit: correctCanSubmit,
            correctTextCanTriggerPrimary: correctCanTrigger
        )

        let checks = [
            SettingsScenarioProbeCheck(
                name: "high_value_draft_accepts_positive_threshold_and_trims_phrase",
                passed: valid.validationMessage == nil
                    && valid.thresholdUsd == 250.5
                    && valid.normalizedConfirmationPhrase == "CONFIRM"
            ),
            SettingsScenarioProbeCheck(
                name: "high_value_blank_phrase_defaults_to_safe_phrase",
                passed: blankPhrase.normalizedConfirmationPhrase == HighValueRule.default.confirmationPhrase
            ),
            SettingsScenarioProbeCheck(
                name: "high_value_validation_messages_cover_missing_invalid_and_disabled_thresholds",
                passed: missingThreshold.validationMessage == HighValueRuleDraft.requiredThresholdError
                    && invalidThreshold.validationMessage == HighValueRuleDraft.positiveThresholdError
                    && disabledBlankThreshold.validationMessage == nil
            ),
            SettingsScenarioProbeCheck(
                name: "high_value_threshold_text_formats_integer_and_decimal_values",
                passed: HighValueRuleDraft.thresholdText(for: 10_000) == "10000"
                    && HighValueRuleDraft.thresholdText(for: 250.5) == "250.5"
            ),
            SettingsScenarioProbeCheck(
                name: "high_value_rule_engine_requires_default_phrase_at_threshold_only",
                passed: belowThresholdConfirmationPhrase == nil
                    && ruleEngineConfirmationPhrase == HighValueRule.default.confirmationPhrase
            ),
            SettingsScenarioProbeCheck(
                name: "high_value_approval_gate_blocks_wrong_phrase_and_enables_correct_phrase",
                passed: approvalConfirmation.requiredPhrase == "CONFIRM"
                    && approvalConfirmation.message == "This request changes a spend or limit boundary. Type CONFIRM to continue."
                    && approvalConfirmation.placeholder == "Type CONFIRM"
                    && approvalConfirmation.wrongTextSatisfied == false
                    && approvalConfirmation.correctTextSatisfied == true
                    && approvalConfirmation.wrongTextCanSubmit == false
                    && approvalConfirmation.correctTextCanSubmit == true
                    && approvalConfirmation.correctTextCanTriggerPrimary == true
            ),
        ]

        return SettingsHighValueScenarioProbeResponse(
            scenario: highValueScenario,
            passed: checks.allSatisfy(\.passed),
            validThreshold: valid.thresholdUsd,
            validConfirmationPhrase: valid.normalizedConfirmationPhrase,
            defaultedConfirmationPhrase: blankPhrase.normalizedConfirmationPhrase,
            missingThresholdMessage: missingThreshold.validationMessage,
            invalidThresholdMessage: invalidThreshold.validationMessage,
            disabledBlankThresholdMessage: disabledBlankThreshold.validationMessage,
            integerThresholdText: HighValueRuleDraft.thresholdText(for: 10_000),
            decimalThresholdText: HighValueRuleDraft.thresholdText(for: 250.5),
            ruleEngineConfirmationPhrase: ruleEngineConfirmationPhrase,
            belowThresholdConfirmationPhrase: belowThresholdConfirmationPhrase,
            approvalConfirmation: approvalConfirmation,
            checks: checks
        )
    }

    static func policyHistory() -> SettingsPolicyHistoryScenarioProbeResponse {
        var historical = BastionConfig.default
        historical.version = 7
        historical.authPolicy = .biometric
        historical.clientProfiles = [
            ClientProfile(
                id: "restored-client",
                bundleId: "com.example.restored",
                label: "Restored Agent",
                rules: .default
            )
        ]
        historical.walletGroups = [
            WalletGroup(id: "restored-group", label: "Restored Group", chainIds: [8453])
        ]
        historical.rules.allowedHours = AllowedHours(start: 10, end: 16)

        var premigration = BastionConfig.default
        premigration.version = 5
        premigration.authPolicy = .open
        premigration.clientProfiles = [
            ClientProfile(
                id: "legacy-client",
                bundleId: "com.example.legacy",
                label: "Legacy Agent",
                rules: .default
            )
        ]

        let utc = TimeZone(secondsFromGMT: 0) ?? .current
        let recoveryDate = Date(timeIntervalSince1970: 0)
        let recoverySnapshot = RuleEngine.ConfigRecoverySnapshot(
            capturedAt: recoveryDate,
            reason: "Stored config could not be decoded",
            rawConfig: Data("{bad".utf8)
        )
        let versionTimestamp = Date(timeIntervalSince1970: 3_600)
        let version = PolicyVersion(
            id: "policy-version-1",
            timestamp: versionTimestamp,
            summary: "auth=biometric · clients=1 · groups=1 · templates=0",
            config: historical
        )
        let presentation = PolicyHistoryPanelPresentation.make(
            versions: [version],
            premigrationBackup: premigration,
            recoverySnapshot: recoverySnapshot,
            recoveryExportStatus: "Exported recovery.json",
            recoveryExportError: nil,
            timeZone: utc
        )
        let exportingPresentation = PolicyHistoryPanelPresentation.make(
            versions: [],
            premigrationBackup: nil,
            recoverySnapshot: recoverySnapshot,
            recoveryExportStatus: nil,
            recoveryExportError: nil,
            recoveryExportIsExporting: true,
            timeZone: utc
        )
        let emptyPresentation = PolicyHistoryPanelPresentation.make(
            versions: [],
            premigrationBackup: nil,
            recoverySnapshot: nil,
            recoveryExportStatus: nil,
            recoveryExportError: nil,
            timeZone: utc
        )

        let exportError = NSError(
            domain: NSCocoaErrorDomain,
            code: NSFileNoSuchFileError,
            userInfo: [NSLocalizedDescriptionKey: "missing destination"]
        )
        let exportFileName = PolicyRecoverySnapshotExportPresentation.defaultFileName(
            for: recoveryDate,
            timeZone: utc
        )
        let exportSuccessMessage = PolicyRecoverySnapshotExportPresentation.successMessage(
            for: URL(fileURLWithPath: "/tmp/recovery.json")
        )
        let exportFailureMessage = PolicyRecoverySnapshotExportPresentation.failureMessage(for: exportError)

        var exportState = PolicyRecoverySnapshotExportState(
            status: "old.json",
            error: "Export failed: stale",
            isExporting: false
        )
        let exportBeginAccepted = exportState.beginExport()
        let duplicateExportBeginRejected = exportState.beginExport() == false
        exportState.cancelExport()
        _ = exportState.beginExport()
        exportState.succeed(url: URL(fileURLWithPath: "/tmp/recovery.json"))
        let exportStateStatusAfterSuccess = exportState.status
        _ = exportState.beginExport()
        exportState.fail(exportError)
        let exportStateErrorAfterFailure = exportState.error

        let restoreResult = PolicyHistoryRestore.loadDraft(historical, savedConfig: .default)
        let noOpResult = PolicyHistoryRestore.loadDraft(.default, savedConfig: .default)
        let versions = presentation.versions.map(SettingsPolicyHistoryVersionSnapshot.init)
        let checks = [
            SettingsScenarioProbeCheck(
                name: "policy_history_panel_lists_recovery_backup_and_saved_versions",
                passed: presentation.title == "Policy history"
                    && presentation.subtitle == "Every saved policy change is snapshotted. Restore an older version with biometric auth."
                    && presentation.recovery == PolicyHistoryRecoveryCardPresentation(
                        title: "Corrupt config recovery",
                        metadata: "Stored config could not be decoded · 4 bytes · \(PolicyHistoryPanelPresentation.displayTimestamp(recoveryDate, timeZone: utc))",
                        exportButtonTitle: "Export raw",
                        exportButtonDisabled: false,
                        loadBackupButtonTitle: "Load backup",
                        exportStatus: "Exported recovery.json",
                        exportError: nil
                    )
                    && presentation.backup == PolicyHistoryBackupCardPresentation(
                        title: "Pre-migration backup",
                        metadata: "Schema v5 · auth=open · clients=1",
                        loadButtonTitle: "Load backup"
                    )
                    && versions == [
                        SettingsPolicyHistoryVersionSnapshot(PolicyHistoryVersionRowPresentation(
                            id: "policy-version-1",
                            timestamp: PolicyHistoryPanelPresentation.displayTimestamp(versionTimestamp, timeZone: utc),
                            summary: "auth=biometric · clients=1 · groups=1 · templates=0",
                            restoreButtonTitle: "Restore"
                        ))
                    ]
            ),
            SettingsScenarioProbeCheck(
                name: "policy_history_empty_and_exporting_states_are_stable",
                passed: exportingPresentation.recovery?.exportButtonTitle == "Exporting…"
                    && exportingPresentation.recovery?.exportButtonDisabled == true
                    && emptyPresentation.emptyVersionsMessage == "No prior versions recorded yet."
                    && emptyPresentation.versions.isEmpty
            ),
            SettingsScenarioProbeCheck(
                name: "policy_history_recovery_export_copy_and_state_machine_are_stable",
                passed: exportFileName == "bastion-corrupt-config-19700101-000000.json"
                    && exportSuccessMessage == "Exported recovery.json"
                    && exportFailureMessage == "Export failed: missing destination"
                    && exportBeginAccepted
                    && duplicateExportBeginRejected
                    && exportStateStatusAfterSuccess == "Exported recovery.json"
                    && exportStateErrorAfterFailure == "Export failed: missing destination"
            ),
            SettingsScenarioProbeCheck(
                name: "policy_history_restore_loads_historical_config_into_unsaved_default_profile_draft",
                passed: restoreResult.draftConfig.version == 7
                    && restoreResult.draftConfig.authPolicy == .biometric
                    && restoreResult.draftConfig.clientProfiles.map(\.id) == ["restored-client"]
                    && restoreResult.draftConfig.walletGroups.map(\.id) == ["restored-group"]
                    && restoreResult.draftConfig.rules.allowedHours?.start == 10
                    && restoreResult.draftConfig.rules.allowedHours?.end == 16
                    && restoreResult.selection == .defaultProfile
                    && restoreResult.statusMessage == "Loaded version into draft. Review and Save to apply."
                    && restoreResult.statusIsError == false
                    && restoreResult.requiresSave == true
            ),
            SettingsScenarioProbeCheck(
                name: "policy_history_noop_restore_does_not_require_save",
                passed: noOpResult.requiresSave == false
            ),
        ]

        return SettingsPolicyHistoryScenarioProbeResponse(
            scenario: policyHistoryScenario,
            passed: checks.allSatisfy(\.passed),
            title: presentation.title,
            subtitle: presentation.subtitle,
            recovery: presentation.recovery.map(SettingsPolicyHistoryRecoverySnapshot.init),
            exportingRecovery: exportingPresentation.recovery.map(SettingsPolicyHistoryRecoverySnapshot.init),
            backup: presentation.backup.map(SettingsPolicyHistoryBackupSnapshot.init),
            savedVersionsTitle: presentation.savedVersionsTitle,
            emptyVersionsMessage: emptyPresentation.emptyVersionsMessage,
            versions: versions,
            restoreStatusMessage: restoreResult.statusMessage,
            restoreRequiresSave: restoreResult.requiresSave,
            restoreSelection: restoreResult.selection.stableID,
            restoredAuthPolicy: restoreResult.draftConfig.authPolicy.rawValue,
            restoredClientProfileIds: restoreResult.draftConfig.clientProfiles.map(\.id),
            restoredWalletGroupIds: restoreResult.draftConfig.walletGroups.map(\.id),
            restoredAllowedHoursStart: restoreResult.draftConfig.rules.allowedHours?.start,
            restoredAllowedHoursEnd: restoreResult.draftConfig.rules.allowedHours?.end,
            noOpRequiresSave: noOpResult.requiresSave,
            exportFileName: exportFileName,
            exportSuccessMessage: exportSuccessMessage,
            exportFailureMessage: exportFailureMessage,
            exportBeginAccepted: exportBeginAccepted,
            duplicateExportBeginRejected: duplicateExportBeginRejected,
            exportStateStatusAfterSuccess: exportStateStatusAfterSuccess,
            exportStateErrorAfterFailure: exportStateErrorAfterFailure,
            checks: checks
        )
    }

    static func policySimulator() -> SettingsPolicySimulatorScenarioProbeResponse {
        let engine = RuleEngine(keychain: SettingsScenarioMemoryKeychain())
        let timestamp = Date(timeIntervalSince1970: 0)
        let sample = PolicySimulatorEvaluator.sampleUserOperationJSON
        let canEvaluateBlank = PolicySimulatorEvaluator.canEvaluate(" \n\t ")
        let canEvaluateSample = PolicySimulatorEvaluator.canEvaluate(sample)

        let allowed = SettingsPolicySimulatorResultSnapshot(PolicySimulatorEvaluator.evaluate(
            sample,
            config: .default,
            engine: engine,
            requestID: "settings-policy-simulator-allowed",
            timestamp: timestamp
        ))
        var chainLocked = BastionConfig.default
        chainLocked.rules.allowedChains = [1]
        let denied = SettingsPolicySimulatorResultSnapshot(PolicySimulatorEvaluator.evaluate(
            sample,
            config: chainLocked,
            engine: engine,
            requestID: "settings-policy-simulator-denied",
            timestamp: timestamp
        ))
        let emptyInput = SettingsPolicySimulatorResultSnapshot(PolicySimulatorEvaluator.evaluate(
            " \n ",
            config: .default,
            engine: engine,
            requestID: "settings-policy-simulator-empty",
            timestamp: timestamp
        ))
        let invalidCallData = #"""
        {
          "sender": "0x4c7a3df6c0e2db14ab39a8f4c98e1d5a3e89b21d",
          "nonce": "0x1",
          "callData": "0xzz",
          "chainId": 8453,
          "entryPointVersion": "v0.7"
        }
        """#
        let invalidCallDataResult = SettingsPolicySimulatorResultSnapshot(PolicySimulatorEvaluator.evaluate(
            invalidCallData,
            config: .default,
            engine: engine,
            requestID: "settings-policy-simulator-invalid-calldata",
            timestamp: timestamp
        ))
        let invalidVersion = sample.replacingOccurrences(
            of: "\"entryPointVersion\": \"v0.7\"",
            with: "\"entryPointVersion\": \"v1\""
        )
        let invalidVersionResult = SettingsPolicySimulatorResultSnapshot(PolicySimulatorEvaluator.evaluate(
            invalidVersion,
            config: .default,
            engine: engine,
            requestID: "settings-policy-simulator-invalid-version",
            timestamp: timestamp
        ))
        let malformedJSONResult = SettingsPolicySimulatorResultSnapshot(PolicySimulatorEvaluator.evaluate(
            "{",
            config: .default,
            engine: engine,
            requestID: "settings-policy-simulator-malformed",
            timestamp: timestamp
        ))
        let expectedInvalidCallDataError = "\(PolicySimulatorEvaluator.decodeErrorPrefix)\(PolicySimulatorEvaluator.invalidCallDataError)"
        let expectedInvalidVersionError = "\(PolicySimulatorEvaluator.decodeErrorPrefix)\(PolicySimulatorEvaluator.invalidEntryPointVersionError)"
        let malformedPrefixMatched = malformedJSONResult.error?.hasPrefix(PolicySimulatorEvaluator.decodeErrorPrefix) ?? false

        let checks = [
            SettingsScenarioProbeCheck(
                name: "policy_simulator_gates_blank_input_and_accepts_generated_sample",
                passed: canEvaluateBlank == false
                    && canEvaluateSample == true
                    && sample.contains("\"entryPointVersion\": \"v0.7\"")
            ),
            SettingsScenarioProbeCheck(
                name: "policy_simulator_allows_sample_against_default_policy",
                passed: allowed.allowed == true
                    && allowed.summary == "Rule engine would sign this silently or after configured auth."
                    && allowed.reasons.isEmpty
                    && allowed.error == nil
            ),
            SettingsScenarioProbeCheck(
                name: "policy_simulator_reports_draft_policy_denial_reasons",
                passed: denied.allowed == false
                    && denied.summary == "Rule engine would block this and require owner override."
                    && denied.reasons == ["Chain Base (8453) not allowed"]
                    && denied.error == nil
            ),
            SettingsScenarioProbeCheck(
                name: "policy_simulator_reports_empty_input_and_decode_errors",
                passed: emptyInput.error == PolicySimulatorEvaluator.emptyInputError
                    && invalidCallDataResult.error == expectedInvalidCallDataError
                    && invalidVersionResult.error == expectedInvalidVersionError
                    && malformedPrefixMatched
            ),
        ]

        return SettingsPolicySimulatorScenarioProbeResponse(
            scenario: policySimulatorScenario,
            passed: checks.allSatisfy(\.passed),
            canEvaluateBlank: canEvaluateBlank,
            canEvaluateSample: canEvaluateSample,
            sampleUserOperationLength: sample.count,
            allowedResult: allowed,
            deniedResult: denied,
            emptyInputError: emptyInput.error,
            invalidCallDataError: invalidCallDataResult.error,
            invalidEntryPointVersionError: invalidVersionResult.error,
            malformedJSONErrorPrefixMatched: malformedPrefixMatched,
            checks: checks
        )
    }

    static func postureControls() -> SettingsPostureScenarioProbeResponse {
        let selectedPosture = SigningPosture.enforceRulesAndRequireApproval
        let selectedSegments = PosturePickerPresentation.segments(selected: selectedPosture).map {
            SettingsPostureSegmentSnapshot($0)
        }
        let selectedStatesByPosture = Dictionary(uniqueKeysWithValues: PosturePickerPresentation.orderedPostures.map { posture in
            (
                posture.rawValue,
                PosturePickerPresentation.segments(selected: posture).map(\.isSelected)
            )
        })

        var draft = BastionConfig.default
        let defaultDraft = SettingsPostureDraftSnapshot(draft.rules)
        draft.rules.rawMessagePolicy.posture = .enforceRulesAndAutoSign
        draft.rules.typedDataPolicy.posture = .requireApprovalWithoutRuleEvaluation
        draft.rules.userOpPosture = .enforceRulesAndAutoSign
        let mutatedDraft = SettingsPostureDraftSnapshot(draft.rules)

        let expectedOrder = [
            SigningPosture.enforceRulesAndAutoSign.rawValue,
            SigningPosture.enforceRulesAndRequireApproval.rawValue,
            SigningPosture.requireApprovalWithoutRuleEvaluation.rawValue,
        ]
        let checks = [
            SettingsScenarioProbeCheck(
                name: "posture_picker_order_matches_auto_confirm_skip_rules",
                passed: selectedSegments.map(\.posture) == expectedOrder
            ),
            SettingsScenarioProbeCheck(
                name: "compact_labels_match_visible_segment_copy",
                passed: selectedSegments.map(\.shortLabel) == ["Auto-sign", "Always confirm", "Skip rules"]
            ),
            SettingsScenarioProbeCheck(
                name: "accessibility_labels_preserve_full_posture_names",
                passed: selectedSegments.map(\.accessibilityLabel) == [
                    SigningPosture.enforceRulesAndAutoSign.displayName,
                    SigningPosture.enforceRulesAndRequireApproval.displayName,
                    SigningPosture.requireApprovalWithoutRuleEvaluation.displayName,
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "accessibility_hints_preserve_full_posture_meaning",
                passed: selectedSegments.map(\.accessibilityHint) == [
                    SigningPosture.enforceRulesAndAutoSign.hint,
                    SigningPosture.enforceRulesAndRequireApproval.hint,
                    SigningPosture.requireApprovalWithoutRuleEvaluation.hint,
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "selected_state_projects_for_each_posture",
                passed: selectedStatesByPosture == [
                    SigningPosture.enforceRulesAndAutoSign.rawValue: [true, false, false],
                    SigningPosture.enforceRulesAndRequireApproval.rawValue: [false, true, false],
                    SigningPosture.requireApprovalWithoutRuleEvaluation.rawValue: [false, false, true],
                ]
            ),
            SettingsScenarioProbeCheck(
                name: "default_draft_starts_all_operations_at_always_confirm",
                passed: defaultDraft == SettingsPostureDraftSnapshot(RuleConfig.default)
            ),
            SettingsScenarioProbeCheck(
                name: "draft_mutation_updates_all_operation_posture_fields_independently",
                passed: mutatedDraft == SettingsPostureDraftSnapshot(RuleConfig(
                    userOpPosture: .enforceRulesAndAutoSign,
                    rawMessagePolicy: RawMessagePolicy(posture: .enforceRulesAndAutoSign),
                    typedDataPolicy: TypedDataPolicy(posture: .requireApprovalWithoutRuleEvaluation)
                ))
            ),
        ]

        return SettingsPostureScenarioProbeResponse(
            scenario: postureControlsScenario,
            passed: checks.allSatisfy(\.passed),
            selectedPosture: selectedPosture.rawValue,
            selectedSegments: selectedSegments,
            selectedStatesByPosture: selectedStatesByPosture,
            defaultDraft: defaultDraft,
            mutatedDraft: mutatedDraft,
            checks: checks
        )
    }

    private static func scenarioClient() -> ClientSigningContext {
        ClientSigningContext(
            bundleId: "com.example.agent",
            profileId: "scenario-client",
            profileLabel: "Example Agent",
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.client.scenario-client",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
    }

    private static func scenarioUserOpRequest(
        sender: String = "0x1234567890abcdef1234567890abcdef12345678",
        chainId: Int = 1,
        callData: Data? = nil,
        requestID: String,
        clientBundleId: String? = nil,
        submission: UserOperationSubmissionRequest? = nil
    ) -> SignRequest {
        SignRequest(
            operation: .userOperation(UserOperation(
                sender: sender,
                nonce: "0x0",
                callData: callData ?? scenarioKernelSingleCallData(
                    target: "0x0000000000000000000000000000000000000001"
                ),
                factory: nil,
                factoryData: nil,
                verificationGasLimit: "0x0f4240",
                callGasLimit: "0x0f4240",
                preVerificationGas: "0x0f4240",
                maxPriorityFeePerGas: "0x59682f00",
                maxFeePerGas: "0x06fc23ac00",
                paymaster: nil,
                paymasterVerificationGasLimit: nil,
                paymasterPostOpGasLimit: nil,
                paymasterData: nil,
                chainId: chainId,
                entryPoint: "0x0000000071727De22E5E9d8BAf0edAc6f37da032",
                entryPointVersion: .v0_7
            )),
            requestID: requestID,
            timestamp: Date(timeIntervalSince1970: 0),
            clientBundleId: clientBundleId,
            userOperationSubmission: submission
        )
    }

    private static func scenarioKernelSingleCallData(
        target: String,
        value: UInt64 = 0,
        calldata: Data = Data()
    ) -> Data {
        KernelEncoding.executeCalldata(single: .init(to: target, value: value, data: calldata))
    }

    private static func erc20TransferCalldata(to recipient: String, amount: UInt64) -> Data {
        Data([0xa9, 0x05, 0x9c, 0xbb]) + paddedAddress(recipient) + uint256(amount)
    }

    private static func paddedAddress(_ address: String) -> Data {
        Data(repeating: 0, count: 12) + (Data(hexString: address) ?? Data())
    }

    private static func uint256(_ value: UInt64) -> Data {
        var data = Data(repeating: 0, count: 32)
        var bigEndian = value.bigEndian
        withUnsafeBytes(of: &bigEndian) { bytes in
            data.replaceSubrange(24..<32, with: bytes)
        }
        return data
    }

    private static func decodedAddressLabel(
        in presentation: SigningRequestDecodedPresentation,
        key: String
    ) -> String? {
        guard let row = presentation.rows.first(where: { $0.key == key }) else {
            return nil
        }
        if case .address(_, _, let label) = row.value {
            return label
        }
        return nil
    }
}

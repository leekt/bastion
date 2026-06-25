import Foundation

nonisolated struct AuditHistoryScenarioChipSnapshot: Codable, Equatable, Sendable {
    let label: String
    let tone: String

    init(_ chip: AuditChipPresentation) {
        label = chip.label
        tone = AuditHistoryScenarioProbe.toneName(chip.tone)
    }
}

nonisolated struct AuditHistoryScenarioRowSnapshot: Codable, Equatable, Sendable {
    let id: String
    let clientDisplayName: String
    let operationTitle: String
    let executionMode: String
    let outcome: AuditHistoryScenarioChipSnapshot
    let chainId: Int?
    let disclosureSymbol: String
    let accessibilityHint: String
    let rowHelp: String

    init(_ row: AuditRowPresentation) {
        id = row.id
        clientDisplayName = row.clientDisplayName
        operationTitle = row.operationTitle
        executionMode = row.executionMode.rawValue
        outcome = AuditHistoryScenarioChipSnapshot(row.outcome)
        chainId = row.chainId
        disclosureSymbol = row.disclosureSymbol
        accessibilityHint = row.accessibilityHint
        rowHelp = row.rowHelp
    }
}

nonisolated struct AuditHistoryScenarioTimelineSnapshot: Codable, Equatable, Sendable {
    let resultLabel: String
    let isLast: Bool
    let isDenied: Bool
    let dotTone: String
    let transactionHash: String?
    let transactionChainId: Int?
    let transactionActionLabel: String?
    let copiedActionLabel: String?
    let reason: String?

    init(_ row: AuditTimelineEntryPresentation) {
        resultLabel = row.resultLabel
        isLast = row.isLast
        isDenied = row.isDenied
        dotTone = AuditHistoryScenarioProbe.toneName(row.dotTone)
        transactionHash = row.transactionHash
        transactionChainId = row.transactionChainId
        transactionActionLabel = row.transactionActionLabel
        copiedActionLabel = row.transactionAction?.label(copied: true)
        reason = row.reason
    }
}

nonisolated struct AuditHistoryScenarioExpandedSnapshot: Codable, Equatable, Sendable {
    let requestID: String
    let operationKindLabel: String
    let executionMode: String
    let rulePath: AuditHistoryScenarioChipSnapshot
    let transactionHash: String?
    let transactionChainId: Int?
    let auditSignature: AuditHistoryScenarioChipSnapshot
    let tamperedAuditSignature: AuditHistoryScenarioChipSnapshot
    let timelineRows: [AuditHistoryScenarioTimelineSnapshot]

    init(record: AuditRequestRecord) {
        let detail = AuditExpandedDetailPresentation.make(record, auditIntegrityBroken: false)
        let tampered = AuditExpandedDetailPresentation.make(record, auditIntegrityBroken: true)
        requestID = detail.requestID
        operationKindLabel = detail.operationKindLabel
        executionMode = detail.executionMode.rawValue
        rulePath = AuditHistoryScenarioChipSnapshot(detail.rulePath)
        transactionHash = detail.transactionHash
        transactionChainId = detail.transactionChainId
        auditSignature = AuditHistoryScenarioChipSnapshot(detail.auditSignature)
        tamperedAuditSignature = AuditHistoryScenarioChipSnapshot(tampered.auditSignature)
        timelineRows = detail.timelineRows.map(AuditHistoryScenarioTimelineSnapshot.init)
    }
}

nonisolated struct AuditHistoryScenarioFilterSnapshot: Codable, Equatable, Sendable {
    let allIds: [String]
    let overrideIds: [String]
    let silentIds: [String]
    let failedIds: [String]
    let searchedSavedViewCleared: Bool
    let searchedIds: [String]
    let dropdownSavedViewCleared: Bool
    let clientFilteredIds: [String]
    let chainFilteredIds: [String]
    let clearedSearch: String
    let clearedSavedViewIsNil: Bool
    let clearedHasActiveFilters: Bool
    let normalizedIdentityStable: Bool
}

nonisolated struct AuditHistoryScenarioExportSnapshot: Codable, Equatable, Sendable {
    let title: String
    let subtitle: String
    let optionLabels: [String]
    let selectedLabel: String?
    let saveButtonTitle: String
    let saveInFlightButtonTitle: String
    let duplicateSaveBlocked: Bool
    let errorMessageAfterFormatChange: String?
    let signedFilenameSuffix: String
    let signedBundleRecordCount: Int
    let signedBundleInstallId: String
    let signedBundleSignaturePrefix: String?
    let plainJSONRecordCount: Int
    let csvHeader: String
    let csvContainsEscapedReason: Bool
}

nonisolated struct AuditHistoryScenarioTamperSnapshot: Codable, Equatable, Sendable {
    let brokenTitle: String
    let brokenMessage: String
    let brokenTone: String
    let exportButtonTitle: String?
    let recoverButtonTitle: String?
    let recoveringButtonTitle: String?
    let recoveringDisablesActions: Bool
    let failedRecoveryError: String?
    let recoveredTitle: String
    let recoveredDismissButtonTitle: String?
    let recoveredDetail: String?
}

nonisolated struct AuditHistoryScenarioRedactionSnapshot: Codable, Equatable, Sendable {
    let payloadsRemoved: Bool
    let clientAddress: String?
    let transactionHash: String?
    let digestHex: String?
    let redactAllSummary: String?
    let redactAllDetails: [String]?
}

nonisolated struct AuditHistoryScenarioAtomSnapshot: Codable, Equatable, Sendable {
    let shortPrefixed: String
    let shortBare: String
    let copyResetDelay: Double
    let staleCopyResetPrevented: Bool
    let chainBadges: [String]
    let statusDotLabels: [String]
    let signOnlyChipLabel: String
    let signOnlyChipStyle: String
    let approveAndSendChipLabel: String
    let approveAndSendChipStyle: String
    let fontSizes: [String: Double]
    let spacingValues: [String: Double]
    let radii: [String: Double]
}

nonisolated struct AuditHistoryScenarioProbeResponse: Codable, Equatable, Sendable {
    let scenario: String
    let passed: Bool
    let filters: AuditHistoryScenarioFilterSnapshot
    let collapsedRow: AuditHistoryScenarioRowSnapshot
    let expandedRow: AuditHistoryScenarioRowSnapshot
    let expandedDetail: AuditHistoryScenarioExpandedSnapshot
    let export: AuditHistoryScenarioExportSnapshot
    let tamperRecovery: AuditHistoryScenarioTamperSnapshot
    let redaction: AuditHistoryScenarioRedactionSnapshot
    let atoms: AuditHistoryScenarioAtomSnapshot
    let checks: [SettingsScenarioProbeCheck]
}

nonisolated struct AuditHistoryScenarioEncodedProbeResponse: Sendable {
    let scenario: String
    let passed: Bool
    let diagnosticContext: [String: String]
    let data: Data
}

nonisolated enum AuditHistoryScenarioProbe {
    static let overviewScenario = "overview"

    static func run(scenario: String) throws -> AuditHistoryScenarioEncodedProbeResponse {
        let encoder = JSONEncoder()
        switch scenario {
        case overviewScenario:
            let response = try overview()
            return AuditHistoryScenarioEncodedProbeResponse(
                scenario: response.scenario,
                passed: response.passed,
                diagnosticContext: [
                    "checks": String(response.checks.count),
                    "timelineRows": String(response.expandedDetail.timelineRows.count),
                    "exportOptions": String(response.export.optionLabels.count),
                    "chainBadges": String(response.atoms.chainBadges.count),
                ],
                data: try encoder.encode(response)
            )
        default:
            throw NSError(
                domain: "com.bastion.audit-history-scenario-probe",
                code: 1,
                userInfo: [
                    NSLocalizedDescriptionKey: "Unknown audit-history scenario: \(scenario). Use \(overviewScenario)."
                ]
            )
        }
    }

    static func overview() throws -> AuditHistoryScenarioProbeResponse {
        let records = makeRecords()
        let filterSnapshot = makeFilterSnapshot(records: records)
        let expandedRecord = records.first { $0.id == "typed-chain" } ?? records[0]
        let collapsedRow = AuditHistoryScenarioRowSnapshot(AuditRowPresentation.make(expandedRecord, expanded: false))
        let expandedRow = AuditHistoryScenarioRowSnapshot(AuditRowPresentation.make(expandedRecord, expanded: true))
        let expandedDetail = AuditHistoryScenarioExpandedSnapshot(record: expandedRecord)
        let exportSnapshot = try makeExportSnapshot(records: records)
        let tamperSnapshot = makeTamperSnapshot()
        let redactionSnapshot = makeRedactionSnapshot(record: expandedRecord)
        let atomSnapshot = makeAtomSnapshot()

        let checks = [
            SettingsScenarioProbeCheck(name: "saved view chips filter rows", passed: filterSnapshot.overrideIds == ["override-1"] && filterSnapshot.silentIds == ["silent-1"] && filterSnapshot.failedIds == ["failed-1"]),
            SettingsScenarioProbeCheck(name: "search and dropdown clear saved view", passed: filterSnapshot.searchedSavedViewCleared && filterSnapshot.dropdownSavedViewCleared),
            SettingsScenarioProbeCheck(name: "clear filters resets search filters and saved view", passed: filterSnapshot.clearedSearch.isEmpty && filterSnapshot.clearedSavedViewIsNil && !filterSnapshot.clearedHasActiveFilters),
            SettingsScenarioProbeCheck(name: "row expansion presentation", passed: collapsedRow.disclosureSymbol == "›" && collapsedRow.accessibilityHint == "Expand details" && expandedRow.disclosureSymbol == "▾" && expandedRow.accessibilityHint == "Collapse details"),
            SettingsScenarioProbeCheck(name: "expanded detail metadata", passed: expandedDetail.requestID == "typed-chain" && expandedDetail.operationKindLabel == "Typed data" && expandedDetail.executionMode == RequestExecutionMode.approveAndSend.rawValue && expandedDetail.auditSignature.label == "Tamper-evident · verified" && expandedDetail.tamperedAuditSignature.label == "Tampered — verify install"),
            SettingsScenarioProbeCheck(name: "timeline transaction actions", passed: expandedDetail.timelineRows.count == 3 && expandedDetail.timelineRows.last?.transactionActionLabel == "View tx ↗" && expandedDetail.timelineRows.last?.transactionChainId == 8453),
            SettingsScenarioProbeCheck(name: "export sheet state", passed: exportSnapshot.optionLabels == ["Signed JSON bundle", "Plain JSON", "CSV"] && exportSnapshot.duplicateSaveBlocked && exportSnapshot.saveInFlightButtonTitle == "Saving…"),
            SettingsScenarioProbeCheck(name: "export renderers", passed: exportSnapshot.signedBundleRecordCount == records.count && exportSnapshot.plainJSONRecordCount == records.count && exportSnapshot.csvHeader == "timestamp,client,operation,result,reason,request_id" && exportSnapshot.csvContainsEscapedReason),
            SettingsScenarioProbeCheck(name: "tamper recovery banner states", passed: tamperSnapshot.brokenTone == "bad" && tamperSnapshot.recoverButtonTitle == "Archive and reset" && tamperSnapshot.recoveringDisablesActions && tamperSnapshot.recoveredDismissButtonTitle == "Dismiss"),
            SettingsScenarioProbeCheck(name: "audit redaction policy", passed: redactionSnapshot.payloadsRemoved && redactionSnapshot.clientAddress == "[REDACTED]" && redactionSnapshot.transactionHash == "[REDACTED]" && redactionSnapshot.digestHex == "[REDACTED]" && redactionSnapshot.redactAllSummary == "[REDACTED]"),
            SettingsScenarioProbeCheck(name: "shared atoms and tokens", passed: atomSnapshot.shortPrefixed == "0x123456…cdef" && atomSnapshot.staleCopyResetPrevented && atomSnapshot.chainBadges.contains("8453:Base:●") && atomSnapshot.statusDotLabels == ["Status: ok", "Status: warning", "Status: error", "Status: idle"] && atomSnapshot.approveAndSendChipLabel == "Approve + send" && atomSnapshot.radii["window"] == 14),
        ]

        return AuditHistoryScenarioProbeResponse(
            scenario: overviewScenario,
            passed: checks.allSatisfy { $0.passed },
            filters: filterSnapshot,
            collapsedRow: collapsedRow,
            expandedRow: expandedRow,
            expandedDetail: expandedDetail,
            export: exportSnapshot,
            tamperRecovery: tamperSnapshot,
            redaction: redactionSnapshot,
            atoms: atomSnapshot,
            checks: checks
        )
    }

    private static func makeFilterSnapshot(records: [AuditRequestRecord]) -> AuditHistoryScenarioFilterSnapshot {
        let state = AuditHistoryFilterState(records: records, search: "", filters: .default, savedView: nil)
        let overrides = state.applyingSavedView(.overrides)
        let searched = overrides.settingSearch(" treasury ")
        let clientFiltered = overrides.settingFilter(\.client, to: Optional("Treasury Bot"))
        let chainFiltered = state.settingFilter(\.chainId, to: Optional(8453))
        let cleared = searched.clearingFilters()

        return AuditHistoryScenarioFilterSnapshot(
            allIds: state.filteredRecords.map(\.id),
            overrideIds: overrides.filteredRecords.map(\.id),
            silentIds: state.applyingSavedView(.silent).filteredRecords.map(\.id),
            failedIds: state.applyingSavedView(.failed).filteredRecords.map(\.id),
            searchedSavedViewCleared: searched.savedView == nil,
            searchedIds: searched.filteredRecords.map(\.id),
            dropdownSavedViewCleared: clientFiltered.savedView == nil,
            clientFilteredIds: clientFiltered.filteredRecords.map(\.id),
            chainFilteredIds: chainFiltered.filteredRecords.map(\.id),
            clearedSearch: cleared.search,
            clearedSavedViewIsNil: cleared.savedView == nil,
            clearedHasActiveFilters: cleared.hasActiveFilters,
            normalizedIdentityStable: state.settingSearch(" treasury ").rowsContentIdentity == state.settingSearch("TREASURY").rowsContentIdentity
        )
    }

    private static func makeExportSnapshot(records: [AuditRequestRecord]) throws -> AuditHistoryScenarioExportSnapshot {
        var state = AuditExportSheetState()
        var presentation = AuditExportSheetPresentation.make(count: records.count, state: state)
        state.failSave("disk full")
        state.selectFormat(.csv)
        let afterFormatChange = AuditExportSheetPresentation.make(count: records.count, state: state)
        let firstBegin = state.beginSave()
        let secondBegin = state.beginSave()
        presentation = AuditExportSheetPresentation.make(count: records.count, state: state)

        let exporter = AuditExporter(
            installIdentifier: { "runtime-probe-install" },
            computeExportHMAC: { "runtime-probe-signature-\($0.count)" }
        )
        let signed = try exporter.render(records: records, format: .signedJSON)
        let plain = try exporter.render(records: records, format: .plainJSON)
        let csv = try exporter.render(records: records, format: .csv)
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        let signedBundle = try decoder.decode(AuditExportBundle.self, from: signed.data)
        let plainRecords = try decoder.decode([AuditRequestRecord].self, from: plain.data)
        let csvString = String(data: csv.data, encoding: .utf8) ?? ""

        return AuditHistoryScenarioExportSnapshot(
            title: afterFormatChange.title,
            subtitle: afterFormatChange.subtitle,
            optionLabels: afterFormatChange.options.map(\.label),
            selectedLabel: afterFormatChange.options.first(where: \.isSelected)?.label,
            saveButtonTitle: afterFormatChange.saveButtonTitle,
            saveInFlightButtonTitle: presentation.saveButtonTitle,
            duplicateSaveBlocked: firstBegin && !secondBegin,
            errorMessageAfterFormatChange: afterFormatChange.errorMessage,
            signedFilenameSuffix: signed.suggestedFilename.hasSuffix(".signed.json") ? ".signed.json" : signed.suggestedFilename,
            signedBundleRecordCount: signedBundle.recordCount,
            signedBundleInstallId: signedBundle.installId,
            signedBundleSignaturePrefix: signedBundle.signature.map { String($0.prefix("runtime-probe-signature-".count)) },
            plainJSONRecordCount: plainRecords.count,
            csvHeader: csvString.components(separatedBy: "\n").first ?? "",
            csvContainsEscapedReason: csvString.contains("\"Denied, \"\"needs review\"\"")
        )
    }

    private static func makeTamperSnapshot() -> AuditHistoryScenarioTamperSnapshot {
        let broken = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: false,
            recoveryMessage: nil,
            recoveryError: nil
        )
        let recovering = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: true,
            recoveryMessage: "stale success",
            recoveryError: nil
        )
        let failed = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: true,
            isRecovering: false,
            recoveryMessage: nil,
            recoveryError: "Recovery failed: owner authentication canceled"
        )
        let recovered = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: false,
            isRecovering: false,
            recoveryMessage: "Archived broken audit log to /tmp/audit-tampered.log",
            recoveryError: nil
        )

        return AuditHistoryScenarioTamperSnapshot(
            brokenTitle: broken.title,
            brokenMessage: broken.message,
            brokenTone: toneName(broken.tone),
            exportButtonTitle: broken.exportButtonTitle,
            recoverButtonTitle: broken.recoverButtonTitle,
            recoveringButtonTitle: recovering.recoverButtonTitle,
            recoveringDisablesActions: recovering.disablesActions,
            failedRecoveryError: failed.recoveryError,
            recoveredTitle: recovered.title,
            recoveredDismissButtonTitle: recovered.dismissButtonTitle,
            recoveredDetail: recovered.recoveryDetail
        )
    }

    private static func makeRedactionSnapshot(record: AuditRequestRecord) -> AuditHistoryScenarioRedactionSnapshot {
        let event = record.events.last ?? record.events[0]
        let payloadRedacted = event.applyingRedaction(.redactPayloads)
        let allRedacted = event.applyingRedaction(.redactAll)
        return AuditHistoryScenarioRedactionSnapshot(
            payloadsRemoved: payloadRedacted.request?.payloads == nil,
            clientAddress: payloadRedacted.client?.accountAddress,
            transactionHash: payloadRedacted.submission?.transactionHash,
            digestHex: allRedacted.request?.digestHex,
            redactAllSummary: allRedacted.request?.summary,
            redactAllDetails: allRedacted.request?.details
        )
    }

    private static func makeAtomSnapshot() -> AuditHistoryScenarioAtomSnapshot {
        let signOnly = RequestModeChipPresentation.make(mode: .signOnly)
        let approveAndSend = RequestModeChipPresentation.make(mode: .approveAndSend)
        let chainIds = [1, 11_155_111, 8453, 84_532, 42_161, 999_999]
        return AuditHistoryScenarioAtomSnapshot(
            shortPrefixed: BastionFormat.shortHex("0x1234567890abcdef", head: 6, tail: 4),
            shortBare: BastionFormat.shortHex("1234567890abcdef", head: 6, tail: 4),
            copyResetDelay: AddressCopyFeedback.resetDelay,
            staleCopyResetPrevented: !AddressCopyFeedback.shouldReset(scheduledGeneration: 1, currentGeneration: 2),
            chainBadges: chainIds.map {
                let badge = ChainBadgePresentation.make(chainId: $0)
                return "\(badge.chainId):\(badge.name):\(badge.glyph)"
            },
            statusDotLabels: [
                StatusDot.State.ok.accessibilityLabel,
                StatusDot.State.warn.accessibilityLabel,
                StatusDot.State.bad.accessibilityLabel,
                StatusDot.State.idle.accessibilityLabel,
            ],
            signOnlyChipLabel: signOnly.label,
            signOnlyChipStyle: chipStyleName(signOnly.style),
            approveAndSendChipLabel: approveAndSend.label,
            approveAndSendChipStyle: chipStyleName(approveAndSend.style),
            fontSizes: [
                "caption": Double(BastionFont.caption.size),
                "label": Double(BastionFont.label.size),
                "body": Double(BastionFont.body.size),
                "title": Double(BastionFont.title.size),
                "large": Double(BastionFont.large.size),
            ],
            spacingValues: [
                "xs": Double(BastionSpacing.xs.value),
                "s": Double(BastionSpacing.s.value),
                "m": Double(BastionSpacing.m.value),
                "l": Double(BastionSpacing.l.value),
                "xl": Double(BastionSpacing.xl.value),
            ],
            radii: [
                "small": Double(BastionTokens.radiusSmall),
                "medium": Double(BastionTokens.radiusMedium),
                "large": Double(BastionTokens.radiusLarge),
                "xl": Double(BastionTokens.radiusXL),
                "window": Double(BastionTokens.windowRadius),
            ]
        )
    }

    private static func makeRecords() -> [AuditRequestRecord] {
        let treasury = makeClientContext(bundleId: "com.example.treasury", profileLabel: "Treasury Bot")
        let agent = makeClientContext(bundleId: "com.example.agent", profileLabel: "Example Agent")
        let csvAgent = makeClientContext(bundleId: "com.example.csv", profileLabel: "Agent, \"Alpha\"")
        let typedRequest = makeTypedDataRequest(requestID: "typed-chain", chainId: 8453)
        let txHash = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd"
        return [
            AuditRequestRecord(events: [
                AuditEvent(
                    type: .signSuccess,
                    dataPrefix: "silent-1",
                    approvalMode: .auto,
                    request: makeMessageRequest(requestID: "silent-1", clientBundleId: "com.example.treasury"),
                    clientContext: treasury
                )
            ]),
            AuditRequestRecord(events: [
                AuditEvent(
                    type: .signSuccess,
                    dataPrefix: "override-1",
                    approvalMode: .ruleOverride,
                    request: makeMessageRequest(requestID: "override-1", clientBundleId: "com.example.treasury"),
                    clientContext: treasury
                )
            ]),
            AuditRequestRecord(events: [
                AuditEvent(
                    type: .signDenied,
                    dataPrefix: "failed-1",
                    reason: "Rule denied",
                    request: makeMessageRequest(requestID: "failed-1", clientBundleId: "com.example.agent"),
                    clientContext: agent
                )
            ]),
            AuditRequestRecord(events: [
                AuditEvent(
                    type: .signSuccess,
                    dataPrefix: "csv-1",
                    reason: "Denied, \"needs review\"\nRetry later",
                    approvalMode: .policyReview,
                    request: makeMessageRequest(requestID: "csv-1", clientBundleId: "com.example.csv"),
                    clientContext: csvAgent
                )
            ]),
            AuditRequestRecord(events: [
                AuditEvent(
                    type: .signSuccess,
                    dataPrefix: "typed-chain",
                    approvalMode: .ruleOverride,
                    request: typedRequest,
                    clientContext: agent
                ),
                AuditEvent(
                    type: .userOpSubmitted,
                    dataPrefix: "typed-chain",
                    request: typedRequest,
                    clientContext: agent,
                    submission: AuditSubmissionSnapshot(
                        provider: "ZeroDev",
                        status: "submitted",
                        userOpHash: "0x1234",
                        transactionHash: nil,
                        detail: "Submitted"
                    )
                ),
                AuditEvent(
                    type: .userOpReceiptSuccess,
                    dataPrefix: "typed-chain",
                    request: typedRequest,
                    clientContext: agent,
                    submission: AuditSubmissionSnapshot(
                        provider: "ZeroDev",
                        status: "receipt_success",
                        userOpHash: "0x1234",
                        transactionHash: txHash,
                        detail: "Confirmed"
                    )
                ),
            ]),
        ]
    }

    private static func makeMessageRequest(requestID: String, clientBundleId: String?) -> SignRequest {
        SignRequest(
            operation: .message("hello world"),
            requestID: requestID,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: clientBundleId
        )
    }

    private static func makeTypedDataRequest(requestID: String, chainId: Int) -> SignRequest {
        let typedData = EIP712TypedData(
            types: [
                "EIP712Domain": [
                    EIP712Field(name: "name", type: "string"),
                    EIP712Field(name: "version", type: "string"),
                    EIP712Field(name: "chainId", type: "uint256"),
                ],
                "Mail": [
                    EIP712Field(name: "from", type: "string"),
                    EIP712Field(name: "to", type: "string"),
                    EIP712Field(name: "contents", type: "string"),
                ],
            ],
            primaryType: "Mail",
            domain: EIP712Domain(
                name: "Test",
                version: "1",
                chainId: chainId,
                verifyingContract: nil,
                salt: nil
            ),
            message: [
                "from": AnyCodable("alice"),
                "to": AnyCodable("bob"),
                "contents": AnyCodable("Hello, Bob!"),
            ]
        )
        return SignRequest(
            operation: .typedData(typedData),
            requestID: requestID,
            timestamp: Date(timeIntervalSince1970: 1_710_000_000),
            clientBundleId: "com.example.agent",
            userOperationSubmission: UserOperationSubmissionRequest(
                provider: .zeroDev,
                projectId: "runtime-probe-project"
            )
        )
    }

    private static func makeClientContext(bundleId: String?, profileLabel: String?) -> ClientSigningContext {
        ClientSigningContext(
            bundleId: bundleId,
            profileId: bundleId,
            profileLabel: profileLabel,
            authPolicy: .biometricOrPasscode,
            keyTag: "com.bastion.signingkey.runtime-probe",
            accountAddress: "0x1234567890abcdef1234567890abcdef12345678",
            rules: .default
        )
    }

    static func toneName(_ tone: AuditPresentationTone) -> String {
        switch tone {
        case .neutral: return "neutral"
        case .ok: return "ok"
        case .warn: return "warn"
        case .bad: return "bad"
        case .accent: return "accent"
        case .outline: return "outline"
        }
    }

    static func toneName(_ tone: AuditTamperRecoveryBannerTone) -> String {
        switch tone {
        case .ok: return "ok"
        case .bad: return "bad"
        }
    }

    private static func chipStyleName(_ style: BastionChip.Style) -> String {
        switch style {
        case .neutral: return "neutral"
        case .ok: return "ok"
        case .warn: return "warn"
        case .bad: return "bad"
        case .accent: return "accent"
        case .outline: return "outline"
        }
    }
}

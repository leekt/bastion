import AppKit
import SwiftUI

// Audit history window — Bastion v2 redesign.
// Composable filter dropdowns (outcome × client × chain × range), saved views,
// expandable timeline rows, tx-hash deep links, signed-JSON export sheet.
// Mirrors audit-v2.jsx.

struct AuditHistoryView: View {
    @State private var records: [AuditRequestRecord] = AuditLog.shared.recentRequestRecords(limit: 200)
    @State private var search: String = ""
    @State private var filters: AuditFilters = .default
    @State private var savedView: SavedView? = nil
    @State private var expandedID: String? = nil
    @State private var showExport: Bool = false
    @State private var auditIntegrityBroken: Bool = AuditLog.shared.logTampered || AuditLog.shared.chainBroken
    @State private var isRecoveringAuditLog: Bool = false
    @State private var recoveryMessage: String? = nil
    @State private var recoveryError: String? = nil

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
                if auditIntegrityBroken || recoveryMessage != nil || recoveryError != nil {
                    tamperRecoveryBanner
                    BastionDivider()
                }
                savedViewsRow
                BastionDivider()
                filterRow
                BastionDivider()
                columnHeader
                rowsList
            }
            .background(Color.paper)

            if showExport {
                Color.black.opacity(0.32).ignoresSafeArea()
                    .onTapGesture { showExport = false }
                ExportSheet(count: filtered.count, onClose: { showExport = false }, records: filtered)
            }
        }
        .frame(minWidth: 1020, minHeight: 660)
        .onAppear { reload() }
    }

    private var tamperRecoveryBanner: some View {
        let presentation = AuditTamperRecoveryBannerPresentation.make(
            auditIntegrityBroken: auditIntegrityBroken,
            isRecovering: isRecoveringAuditLog,
            recoveryMessage: recoveryMessage,
            recoveryError: recoveryError
        )
        return HStack(alignment: .top, spacing: 12) {
            StatusDot(state: presentation.tone.statusDotState)
                .padding(.top, 2)
            VStack(alignment: .leading, spacing: 4) {
                Text(presentation.title)
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundStyle(presentation.tone == .bad ? Color.bastionBad : Color.bastionOk)
                Text(presentation.message)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.ink600)
                if let recoveryError = presentation.recoveryError {
                    Text(recoveryError)
                        .font(.system(size: 11.5, weight: .medium))
                        .foregroundStyle(Color.bastionBad)
                }
                if let recoveryMessage = presentation.recoveryDetail {
                    Text(recoveryMessage)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Color.ink500)
                        .lineLimit(2)
                }
            }
            Spacer(minLength: 12)
            if presentation.showsRecoveryActions {
                Button(presentation.exportButtonTitle ?? "Export…") { showExport = true }
                    .bastionButton(.default, size: .small)
                    .disabled(presentation.disablesActions)
                Button(presentation.recoverButtonTitle ?? "Archive and reset") {
                    Task { await recoverAuditLog() }
                }
                .bastionButton(.danger, size: .small)
                .disabled(presentation.disablesActions)
            } else {
                Button(presentation.dismissButtonTitle ?? "Dismiss") {
                    recoveryMessage = nil
                    recoveryError = nil
                }
                .bastionButton(.ghost, size: .small)
            }
        }
        .padding(EdgeInsets(top: 10, leading: 24, bottom: 10, trailing: 24))
        .background(presentation.tone == .bad ? Color.bastionBad.opacity(0.08) : Color.bastionOk.opacity(0.08))
    }

    // MARK: - Saved views + search

    /// PR fix: the v2 mock had a separate `titleBar` row that drew a fake
    /// "Bastion · Audit history" label, decorative traffic-light dots, the
    /// search box and the Export button. The SwiftUI `Settings`-style
    /// window already gives us a real macOS title bar with real traffic
    /// lights, so the fake header just stacked on top of the real one and
    /// made the chrome ~50pt taller than necessary. Search + Export move
    /// into this row alongside the saved-view chips.
    private var savedViewsRow: some View {
        HStack(spacing: 8) {
            BastionSectionLabel(text: "Views")
            ViewChip(label: "All", active: savedView == nil) {
                applyFilterState(filterState().applyingSavedView(nil))
            }
            ViewChip(label: "Overrides only", active: savedView == .overrides) {
                applyFilterState(filterState().applyingSavedView(.overrides))
            }
            ViewChip(label: "Silent signs", active: savedView == .silent) {
                applyFilterState(filterState().applyingSavedView(.silent))
            }
            ViewChip(label: "Failed", active: savedView == .failed) {
                applyFilterState(filterState().applyingSavedView(.failed))
            }
            Spacer()
            TextField("Search…", text: $search)
                .onChange(of: search) { _, newValue in
                    applyFilterState(filterState().settingSearch(newValue), preserveSearchBinding: true)
                }
                .textFieldStyle(.plain)
                .font(.system(size: 12))
                .padding(.horizontal, 10).padding(.vertical, 4)
                .frame(width: 200)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(Color.ink50)
                        .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Color.ink200, lineWidth: 1))
                )
            Button("Export…") { showExport = true }
                .bastionButton(.default, size: .small)
        }
        .padding(EdgeInsets(top: 6, leading: 24, bottom: 6, trailing: 24))
    }

    // MARK: - Filter row

    private var filterRow: some View {
        HStack(spacing: 10) {
            FilterDropdown(
                label: "Outcome",
                value: filters.outcome,
                options: AuditOutcomeFilter.allCases,
                onChange: { setFilter(\.outcome, to: $0) }
            )
            FilterDropdown(
                label: "Client",
                value: filters.client,
                options: clientOptions,
                onChange: { setFilter(\.client, to: $0) }
            )
            FilterDropdown(
                label: "Chain",
                value: filters.chainId,
                options: chainOptions,
                onChange: { setFilter(\.chainId, to: $0) }
            )
            FilterDropdown(
                label: "Range",
                value: filters.range,
                options: AuditRangeFilter.allCases,
                onChange: { setFilter(\.range, to: $0) }
            )
            Spacer()
            Button("Clear filters") { clearFilters() }
                .bastionButton(.ghost, size: .small)
                .opacity(hasActiveFilters ? 1 : 0)
                .allowsHitTesting(hasActiveFilters)
                .accessibilityHidden(!hasActiveFilters)
            Text("\(filtered.count) of \(records.count)")
                .font(.system(size: 11))
                .foregroundStyle(Color.ink500)
        }
        .padding(EdgeInsets(top: 6, leading: 24, bottom: 6, trailing: 24))
        .background(Color.ink50)
    }

    private var clientOptions: [FilterOption<String?>] {
        var opts: [FilterOption<String?>] = [.init(value: nil, label: "Any client")]
        let names = Set(records.map(\.clientDisplayName))
        for n in names.sorted() {
            opts.append(.init(value: n, label: n))
        }
        return opts
    }

    private var chainOptions: [FilterOption<Int?>] {
        var opts: [FilterOption<Int?>] = [.init(value: nil, label: "Any chain")]
        for chain in [1, 8453, 10, 42161] {
            opts.append(.init(value: chain, label: ChainConfig.name(for: chain)))
        }
        return opts
    }

    // MARK: - Column header
    //
    // No divider between `columnHeader` and `rowsList` on purpose — the
    // column header is part of the data table, not a separate section.

    private var columnHeader: some View {
        HStack(spacing: 12) {
            Text("Time").frame(width: 90, alignment: .leading)
            Text("Client").frame(width: 130, alignment: .leading)
            Text("Request").frame(maxWidth: .infinity, alignment: .leading)
            Text("Outcome").frame(width: 130, alignment: .leading)
            Text("Chain").frame(width: 100, alignment: .leading)
            // Width-only frame on a Color leaves the vertical dimension
            // flexible. With this trailing spacer flexible-vertical AND
            // `rowsList`'s ScrollView ALSO flexible-vertical, the body
            // VStack split its remaining height between them — giving
            // `columnHeader` ~half the window with the text centered, and
            // pushing the rows into the lower half. Pinning height to 1
            // makes the spacer a no-op vertically.
            Color.clear.frame(width: 14, height: 1)
        }
        .font(.system(size: 11, weight: .semibold))
        .foregroundStyle(Color.ink500)
        .padding(EdgeInsets(top: 4, leading: 24, bottom: 4, trailing: 24))
        // Belt-and-suspenders: even if some future modifier reintroduces
        // flexible vertical sizing, this clamps the header to natural
        // content height.
        .fixedSize(horizontal: false, vertical: true)
    }

    // MARK: - Rows

    private var rowsList: some View {
        // No `List` (its NSTableView phantom header insets rows down).
        // No `LazyVStack` (its lazy-content reservation centers short
        // datasets vertically on macOS).
        // No GeometryReader/ZStack overlay tricks.
        //
        // Plain ScrollView + VStack with **all three** anchors set
        // belt-and-suspenders: `.defaultScrollAnchor(.top)` on the
        // ScrollView so macOS NSScrollView pins documentView origin to
        // the top regardless of flipped-coordinate state, and
        // `.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)`
        // so the inner VStack fills the scroll container and aligns its
        // children top-leading. Once one of these is missing, the
        // container can position rows in the middle of empty space and
        // we get the giant empty band the user kept seeing.
        ScrollView {
            VStack(spacing: 0) {
                if filtered.isEmpty {
                    emptyState
                } else {
                    ForEach(filtered) { record in
                        AuditRow(
                            record: record,
                            expanded: expandedID == record.id,
                            onToggle: { expandedID = expandedID == record.id ? nil : record.id }
                        )
                        BastionDivider()
                    }
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .defaultScrollAnchor(.top)
        .id(rowsContentIdentity)
    }

    private var emptyState: some View {
        VStack(spacing: 4) {
            Text("No matching requests")
                .font(.system(size: 13, weight: .medium))
                .foregroundStyle(Color.ink700)
            Text("Try widening the time range or clearing a filter.")
                .font(.system(size: 12))
                .foregroundStyle(Color.ink500)
        }
        .padding(60)
        .frame(maxWidth: .infinity)
    }

    // MARK: - Filtering

    private var filtered: [AuditRequestRecord] {
        filterState().filteredRecords
    }

    private var rowsContentIdentity: String {
        filterState().rowsContentIdentity
    }

    private var hasActiveFilters: Bool {
        filterState().hasActiveFilters
    }

    private func setFilter<Value>(_ keyPath: WritableKeyPath<AuditFilters, Value>, to value: Value) {
        applyFilterState(filterState().settingFilter(keyPath, to: value))
    }

    private func clearFilters() {
        applyFilterState(filterState().clearingFilters())
    }

    private func reload() {
        let log = AuditLog.shared
        records = log.recentRequestRecords(limit: 200)
        auditIntegrityBroken = log.logTampered || log.chainBroken
    }

    private func filterState() -> AuditHistoryFilterState {
        AuditHistoryFilterState(
            records: records,
            search: search,
            filters: filters,
            savedView: savedView
        )
    }

    private func applyFilterState(_ state: AuditHistoryFilterState, preserveSearchBinding: Bool = false) {
        if !preserveSearchBinding {
            search = state.search
        }
        filters = state.filters
        savedView = state.savedView
    }

    @MainActor
    private func recoverAuditLog() async {
        guard !isRecoveringAuditLog else { return }
        isRecoveringAuditLog = true
        recoveryError = nil
        recoveryMessage = nil
        do {
            try await AuthManager.shared.authenticate(
                policy: .biometricOrPasscode,
                reason: "Authorize audit log recovery"
            )
            let result = try AuditLog.shared.archiveAndResetTamperedLog()
            if let archived = result.archivedLogPath {
                recoveryMessage = "Archived broken audit log to \(archived)"
            } else {
                recoveryMessage = result.recovered
                    ? "Cleared stale audit integrity state"
                    : "No audit integrity recovery was needed"
            }
            reload()
        } catch {
            recoveryError = "Recovery failed: \(error.localizedDescription)"
        }
        isRecoveringAuditLog = false
    }
}

// MARK: - Saved views

nonisolated enum SavedView: Hashable, Sendable { case overrides, silent, failed }

nonisolated enum AuditTamperRecoveryBannerTone: Equatable, Sendable {
    case ok
    case bad

    var statusDotState: StatusDot.State {
        switch self {
        case .ok: return .ok
        case .bad: return .bad
        }
    }
}

nonisolated struct AuditTamperRecoveryBannerPresentation: Equatable, Sendable {
    let tone: AuditTamperRecoveryBannerTone
    let title: String
    let message: String
    let recoveryError: String?
    let recoveryDetail: String?
    let showsRecoveryActions: Bool
    let exportButtonTitle: String?
    let recoverButtonTitle: String?
    let dismissButtonTitle: String?
    let disablesActions: Bool

    static func make(
        auditIntegrityBroken: Bool,
        isRecovering: Bool,
        recoveryMessage: String?,
        recoveryError: String?
    ) -> AuditTamperRecoveryBannerPresentation {
        if auditIntegrityBroken {
            return AuditTamperRecoveryBannerPresentation(
                tone: .bad,
                title: "Audit log integrity check failed",
                message: "Export the visible records if needed, then archive and reset the broken log to resume audit writes.",
                recoveryError: recoveryError,
                recoveryDetail: nil,
                showsRecoveryActions: true,
                exportButtonTitle: "Export…",
                recoverButtonTitle: isRecovering ? "Resetting…" : "Archive and reset",
                dismissButtonTitle: nil,
                disablesActions: isRecovering
            )
        }

        return AuditTamperRecoveryBannerPresentation(
            tone: .ok,
            title: "Audit log recovery complete",
            message: recoveryMessage ?? "Audit logging can resume with a fresh integrity chain.",
            recoveryError: recoveryError,
            recoveryDetail: recoveryMessage,
            showsRecoveryActions: false,
            exportButtonTitle: nil,
            recoverButtonTitle: nil,
            dismissButtonTitle: "Dismiss",
            disablesActions: false
        )
    }
}

// MARK: - Filters

struct AuditFilters: Equatable, Sendable {
    var outcome: AuditOutcomeFilter
    var client: String?
    var chainId: Int?
    var range: AuditRangeFilter

    static let `default` = AuditFilters(outcome: .all, client: nil, chainId: nil, range: .last24h)
}

nonisolated struct AuditHistoryFilterState: Sendable {
    var records: [AuditRequestRecord]
    var search: String
    var filters: AuditFilters
    var savedView: SavedView?

    var filteredRecords: [AuditRequestRecord] {
        let q = normalizedSearch
        return records.filter { record in
            if !q.isEmpty {
                let haystack = "\(record.clientDisplayName) \(record.operationTitle) \(record.summary) \(record.id)".lowercased()
                if !haystack.contains(q) { return false }
            }
            if let client = filters.client, record.clientDisplayName != client { return false }
            if let chain = filters.chainId, !Self.recordContainsChain(record, chainId: chain) { return false }
            if !filters.outcome.matches(record) { return false }
            if let cutoff = filters.range.cutoff, let ts = record.latestTimestamp, ts < cutoff { return false }
            return true
        }
    }

    var rowsContentIdentity: String {
        let filterKey = [
            normalizedSearch,
            filters.outcome.rawValue,
            filters.client ?? "",
            filters.chainId.map(String.init) ?? "",
            filters.range.rawValue
        ].joined(separator: "|")

        let recordKey = filteredRecords.map(\.id).joined(separator: "|")
        return "\(filterKey)#\(recordKey)"
    }

    var hasActiveFilters: Bool {
        filters != .default || savedView != nil || !normalizedSearch.isEmpty
    }

    func applyingSavedView(_ view: SavedView?) -> AuditHistoryFilterState {
        switch view {
        case .overrides:
            return AuditHistoryFilterState(
                records: records,
                search: "",
                filters: AuditFilters(outcome: .overrides, client: nil, chainId: nil, range: .last24h),
                savedView: .overrides
            )
        case .silent:
            return AuditHistoryFilterState(
                records: records,
                search: "",
                filters: AuditFilters(outcome: .silent, client: nil, chainId: nil, range: .last24h),
                savedView: .silent
            )
        case .failed:
            return AuditHistoryFilterState(
                records: records,
                search: "",
                filters: AuditFilters(outcome: .failed, client: nil, chainId: nil, range: .last24h),
                savedView: .failed
            )
        case .none:
            return clearingFilters()
        }
    }

    func settingSearch(_ value: String) -> AuditHistoryFilterState {
        AuditHistoryFilterState(
            records: records,
            search: value,
            filters: filters,
            savedView: value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? savedView : nil
        )
    }

    func settingFilter<Value>(_ keyPath: WritableKeyPath<AuditFilters, Value>, to value: Value) -> AuditHistoryFilterState {
        var nextFilters = filters
        nextFilters[keyPath: keyPath] = value
        return AuditHistoryFilterState(records: records, search: search, filters: nextFilters, savedView: nil)
    }

    func clearingFilters() -> AuditHistoryFilterState {
        AuditHistoryFilterState(records: records, search: "", filters: .default, savedView: nil)
    }

    private var normalizedSearch: String {
        search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    private static func recordContainsChain(_ record: AuditRequestRecord, chainId: Int) -> Bool {
        guard let request = record.request else { return false }
        return request.details.contains { $0.localizedCaseInsensitiveContains("\(chainId)") }
            || request.summary.localizedCaseInsensitiveContains("\(chainId)")
    }
}

enum AuditOutcomeFilter: String, CaseIterable, Hashable, FilterOptionEnum, Sendable {
    case all = "Any outcome"
    case silent = "Silent"
    case overrides = "Overrides"
    case failed = "Failed"

    var label: String { rawValue }

    func matches(_ r: AuditRequestRecord) -> Bool {
        let last = r.latestEvent
        switch self {
        case .all: return true
        case .silent: return last?.approvalMode == .auto
        case .overrides: return last?.approvalMode == .ruleOverride
        case .failed: return last?.type == .signDenied || last?.type == .ruleViolation || last?.type == .authFailed
        }
    }
}

enum AuditRangeFilter: String, CaseIterable, Hashable, FilterOptionEnum, Sendable {
    case last24h = "Last 24 hours"
    case last7d = "Last 7 days"
    case last30d = "Last 30 days"
    case allTime = "All time"

    var label: String { rawValue }
    var cutoff: Date? {
        let now = Date()
        switch self {
        case .last24h: return now.addingTimeInterval(-86_400)
        case .last7d:  return now.addingTimeInterval(-86_400 * 7)
        case .last30d: return now.addingTimeInterval(-86_400 * 30)
        case .allTime: return nil
        }
    }
}

// MARK: - Filter option / dropdown

protocol FilterOptionEnum: Hashable {
    var label: String { get }
}

struct FilterOption<Value: Hashable>: Identifiable, Hashable {
    let value: Value
    let label: String
    var id: Self { self }
}

private struct FilterDropdown<Value: Hashable, Option: Hashable>: View {
    let label: String
    let value: Value
    let options: [Option]
    let onChange: (Value) -> Void

    var body: some View {
        let isDefault = isDefaultValue
        Menu {
            ForEach(options, id: \.self) { opt in
                Button(action: { onChange(extractValue(opt)) }) {
                    HStack {
                        Text("\(label): \(extractLabel(opt))")
                        if extractValue(opt) == value { Image(systemName: "checkmark") }
                    }
                }
            }
        } label: {
            HStack(spacing: 5) {
                Text("\(label): \(currentLabel)")
                    .font(.system(size: 12, weight: .medium))
                Text("▾")
                    .font(.system(size: 9))
            }
            .padding(.horizontal, 10).padding(.vertical, 5)
            .foregroundStyle(isDefault ? Color.ink700 : Color.paper)
            .background(
                RoundedRectangle(cornerRadius: 6)
                    .fill(isDefault ? Color.paper : Color.ink900)
                    .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(isDefault ? Color.ink200 : Color.ink900, lineWidth: 1))
            )
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    private var isDefaultValue: Bool {
        if let first = options.first {
            return extractValue(first) == value
        }
        return true
    }

    private var currentLabel: String {
        if let opt = options.first(where: { extractValue($0) == value }) {
            return extractLabel(opt)
        }
        return ""
    }

    private func extractValue(_ option: Option) -> Value {
        if let typed = option as? FilterOption<Value> { return typed.value }
        if let value = option as? Value { return value }
        return self.value
    }

    private func extractLabel(_ option: Option) -> String {
        if let typed = option as? FilterOption<Value> { return typed.label }
        if let proto = option as? any FilterOptionEnum { return proto.label }
        return String(describing: option)
    }
}

// MARK: - Saved view chip

private struct ViewChip: View {
    let label: String
    let active: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(label)
                .font(.system(size: 12, weight: .medium))
                .padding(.horizontal, 10).padding(.vertical, 4)
                .foregroundStyle(active ? Color.paper : Color.ink700)
                .background(
                    RoundedRectangle(cornerRadius: 6)
                        .fill(active ? Color.ink900 : Color.paper)
                        .overlay(
                            RoundedRectangle(cornerRadius: 6)
                                .strokeBorder(active ? .clear : Color.ink150, lineWidth: 1)
                        )
                )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Audit row + expanded detail

nonisolated enum AuditPresentationTone: Equatable, Sendable {
    case neutral
    case ok
    case warn
    case bad
    case accent
    case outline
}

nonisolated struct AuditChipPresentation: Equatable, Sendable {
    let label: String
    let tone: AuditPresentationTone
}

nonisolated enum AuditTransactionAction: Equatable, Sendable {
    case openExplorer
    case copyHash

    var label: String {
        label(copied: false)
    }

    func label(copied: Bool) -> String {
        switch self {
        case .openExplorer: return "View tx ↗"
        case .copyHash: return copied ? "Copied" : "Copy tx"
        }
    }
}

nonisolated struct AuditRowPresentation: Equatable, Sendable {
    let id: String
    let clientDisplayName: String
    let operationTitle: String
    let executionMode: RequestExecutionMode
    let outcome: AuditChipPresentation
    let chainId: Int?
    let disclosureSymbol: String
    let accessibilityLabelResult: String
    let accessibilityHint: String
    let rowHelp: String

    static func make(_ record: AuditRequestRecord, expanded: Bool) -> AuditRowPresentation {
        let result = record.latestEvent?.resultLabel ?? "no outcome"
        return AuditRowPresentation(
            id: record.id,
            clientDisplayName: record.clientDisplayName,
            operationTitle: record.operationTitle,
            executionMode: record.executionMode,
            outcome: .makeOutcome(record),
            chainId: AuditExpandedDetailPresentation.guessChainId(record),
            disclosureSymbol: expanded ? "▾" : "›",
            accessibilityLabelResult: result,
            accessibilityHint: expanded ? "Collapse details" : "Expand details",
            rowHelp: "Client: \(record.clientDisplayName)\nOperation: \(record.operationTitle)\nOutcome: \(result)"
        )
    }
}

nonisolated struct AuditExpandedDetailPresentation: Equatable, Sendable {
    let requestID: String
    let operationKindLabel: String
    let executionMode: RequestExecutionMode
    let rulePath: AuditChipPresentation
    let transactionHash: String?
    let transactionChainId: Int?
    let auditSignature: AuditChipPresentation
    let timelineRows: [AuditTimelineEntryPresentation]

    static func make(
        _ record: AuditRequestRecord,
        auditIntegrityBroken: Bool = AuditLog.shared.logTampered || AuditLog.shared.chainBroken
    ) -> AuditExpandedDetailPresentation {
        let chainId = guessChainId(record)
        let tx = record.events.first { $0.submission?.transactionHash != nil }?.submission?.transactionHash
        return AuditExpandedDetailPresentation(
            requestID: record.requestID,
            operationKindLabel: record.operationKindLabel,
            executionMode: record.executionMode,
            rulePath: .makeRulePath(record.latestEvent?.approvalMode),
            transactionHash: tx,
            transactionChainId: tx == nil ? nil : chainId,
            auditSignature: auditIntegrityBroken
                ? AuditChipPresentation(label: "Tampered — verify install", tone: .bad)
                : AuditChipPresentation(label: "Tamper-evident · verified", tone: .ok),
            timelineRows: record.events.enumerated().map { index, event in
                AuditTimelineEntryPresentation.make(
                    event,
                    isLast: index == record.events.count - 1,
                    chainId: chainId
                )
            }
        )
    }

    static func guessChainId(_ record: AuditRequestRecord) -> Int? {
        guard let details = record.request?.details else { return nil }
        for line in details {
            if line.lowercased().contains("chain") {
                let nums = line.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
                if let n = nums.first { return n }
            }
        }
        return nil
    }
}

nonisolated struct AuditTimelineEntryPresentation: Equatable, Sendable {
    let resultLabel: String
    let isLast: Bool
    let isDenied: Bool
    let dotTone: AuditPresentationTone
    let transactionHash: String?
    let transactionChainId: Int?
    let transactionAction: AuditTransactionAction?
    let reason: String?

    var transactionActionLabel: String? {
        transactionAction?.label
    }

    static func make(_ event: AuditEvent, isLast: Bool, chainId: Int?) -> AuditTimelineEntryPresentation {
        let tx = event.submission?.transactionHash
        return AuditTimelineEntryPresentation(
            resultLabel: event.resultLabel,
            isLast: isLast,
            isDenied: denied(event.type),
            dotTone: dotTone(type: event.type, approvalMode: event.approvalMode),
            transactionHash: tx,
            transactionChainId: tx == nil ? nil : chainId,
            transactionAction: tx.map { transactionAction(txHash: $0, chainId: chainId) },
            reason: event.reason?.isEmpty == false ? event.reason : nil
        )
    }

    static func transactionAction(txHash: String, chainId: Int?) -> AuditTransactionAction {
        if let chainId, ChainConfig.explorerURL(chainId: chainId, txHash: txHash) != nil {
            return .openExplorer
        }
        return .copyHash
    }

    private static func denied(_ type: AuditEvent.EventType) -> Bool {
        switch type {
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            return true
        default:
            return false
        }
    }

    private static func dotTone(type: AuditEvent.EventType, approvalMode: AuditEvent.ApprovalMode?) -> AuditPresentationTone {
        switch type {
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            return .bad
        case .userOpReceiptTimeout:
            return .warn
        case .userOpReceiptSuccess:
            return .ok
        case .signSuccess, .userOpSubmitted, .preflightCompleted:
            return approvalMode == .ruleOverride ? .warn : .neutral
        default:
            return .neutral
        }
    }
}

extension AuditChipPresentation {
    static func makeOutcome(_ record: AuditRequestRecord) -> AuditChipPresentation {
        switch record.latestEvent?.type {
        case .userOpReceiptSuccess:
            return AuditChipPresentation(label: "Confirmed", tone: .ok)
        case .userOpSubmitted:
            return AuditChipPresentation(label: "Submitted", tone: .accent)
        case .signSuccess:
            return AuditChipPresentation(label: "Signed", tone: .ok)
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            return AuditChipPresentation(label: "Denied", tone: .bad)
        case .userOpReceiptTimeout:
            return AuditChipPresentation(label: "Pending", tone: .warn)
        default:
            return AuditChipPresentation(label: record.latestEvent?.resultLabel ?? "—", tone: .neutral)
        }
    }

    static func makeRulePath(_ approvalMode: AuditEvent.ApprovalMode?) -> AuditChipPresentation {
        switch approvalMode {
        case .auto:
            return AuditChipPresentation(label: "Silent · rules passed", tone: .outline)
        case .policyReview:
            return AuditChipPresentation(label: "Approved", tone: .accent)
        case .ruleOverride:
            return AuditChipPresentation(label: "Override · owner auth", tone: .warn)
        case .none:
            return AuditChipPresentation(label: "—", tone: .neutral)
        }
    }
}

private extension AuditPresentationTone {
    var chipStyle: BastionChip.Style {
        switch self {
        case .neutral: return .neutral
        case .ok: return .ok
        case .warn: return .warn
        case .bad: return .bad
        case .accent: return .accent
        case .outline: return .outline
        }
    }

    var statusDotState: StatusDot.State {
        switch self {
        case .ok:
            return .ok
        case .warn:
            return .warn
        case .bad:
            return .bad
        case .neutral, .accent, .outline:
            return .idle
        }
    }

    var timelineColor: Color {
        switch self {
        case .bad: return .bastionBad
        case .warn: return .bastionWarn
        case .ok: return .bastionOk
        case .neutral, .accent, .outline: return .ink700
        }
    }
}

private struct AuditRow: View {
    let record: AuditRequestRecord
    let expanded: Bool
    let onToggle: () -> Void

    var body: some View {
        let presentation = AuditRowPresentation.make(record, expanded: expanded)
        VStack(spacing: 0) {
            Button(action: onToggle) {
                HStack(spacing: 12) {
                    Text(BastionFormat.relative(record.latestTimestamp))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.ink700)
                        .frame(width: 90, alignment: .leading)
                    Text(presentation.clientDisplayName)
                        .font(.system(size: 12.5, weight: .medium))
                        .frame(width: 130, alignment: .leading)
                        .lineLimit(1)
                    Text(presentation.operationTitle)
                        .font(.system(size: 12.5))
                        .foregroundStyle(Color.ink700)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    RequestModeChip(mode: presentation.executionMode)
                        .frame(width: 112, alignment: .leading)
                    OutcomeBadge(presentation: presentation.outcome)
                        .frame(width: 130, alignment: .leading)
                    chainCell(chainId: presentation.chainId)
                        .frame(width: 100, alignment: .leading)
                    Text(presentation.disclosureSymbol)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.ink400)
                        .frame(width: 14, alignment: .center)
                }
                .padding(EdgeInsets(top: 6, leading: 24, bottom: 6, trailing: 24))
                .background(expanded ? Color.ink50 : Color.clear)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("\(presentation.operationTitle), from \(presentation.clientDisplayName), \(presentation.accessibilityLabelResult), \(BastionFormat.relative(record.latestTimestamp))")
            .accessibilityHint(presentation.accessibilityHint)
            .help(presentation.rowHelp)

            if expanded {
                ExpandedDetail(record: record)
                    .padding(EdgeInsets(top: 0, leading: 24, bottom: 18, trailing: 24))
                    .background(Color.ink50)
            }
        }
    }

    @ViewBuilder
    private func chainCell(chainId: Int?) -> some View {
        if let chainId {
            ChainBadge(chainId: chainId, size: .small)
        } else {
            Text("—").foregroundStyle(Color.ink300).font(.system(size: 12))
        }
    }
}

private struct OutcomeBadge: View {
    let presentation: AuditChipPresentation

    var body: some View {
        BastionChip(
            label: presentation.label,
            style: presentation.tone.chipStyle,
            leading: leading
        )
    }

    private var leading: AnyView? {
        switch presentation.tone {
        case .ok, .warn, .bad:
            return AnyView(StatusDot(state: presentation.tone.statusDotState))
        case .neutral, .accent, .outline:
            return nil
        }
    }
}

private struct ExpandedDetail: View {
    let record: AuditRequestRecord

    var body: some View {
        let presentation = AuditExpandedDetailPresentation.make(record)
        HStack(alignment: .top, spacing: 24) {
            metadata(presentation)
            timeline(presentation)
        }
        .padding(EdgeInsets(top: 14, leading: 18, bottom: 14, trailing: 18))
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.paper)
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.ink150, lineWidth: 1))
        )
    }

    private func metadata(_ presentation: AuditExpandedDetailPresentation) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            DetailRow(key: "Request ID", value: AnyView(
                Text(presentation.requestID).font(.system(size: 12, design: .monospaced))
            ))
            DetailRow(key: "Type", value: AnyView(
                BastionChip(label: presentation.operationKindLabel, style: .neutral)
            ))
            DetailRow(key: "Flow", value: AnyView(
                RequestModeChip(mode: presentation.executionMode)
            ))
            DetailRow(key: "Rule path", value: AnyView(
                BastionChip(label: presentation.rulePath.label, style: presentation.rulePath.tone.chipStyle)
            ))
            if let tx = presentation.transactionHash {
                DetailRow(key: "Tx hash", value: AnyView(
                    HStack {
                        AddressView(address: tx)
                        if let chainId = presentation.transactionChainId,
                           let url = ChainConfig.explorerURL(chainId: chainId, txHash: tx) {
                            Button {
                                NSWorkspace.shared.open(url)
                            } label: {
                                Text("Open in explorer ↗").font(.system(size: 10))
                            }
                            .bastionButton(.ghost, size: .small)
                        }
                    }
                ))
            }
            DetailRow(key: "Audit signature", value: AnyView(
                HStack(spacing: 6) {
                    StatusDot(state: presentation.auditSignature.tone.statusDotState)
                    Text(presentation.auditSignature.label)
                        .font(.system(size: 11.5))
                        .foregroundStyle(presentation.auditSignature.tone == .bad ? Color.bastionBad : Color.bastionOk)
                }
            ))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func timeline(_ presentation: AuditExpandedDetailPresentation) -> some View {
        return VStack(alignment: .leading, spacing: 0) {
            BastionSectionLabel(text: "Timeline").padding(.bottom, 10)
            ForEach(Array(record.events.enumerated()), id: \.offset) { index, event in
                TimelineEntry(event: event, presentation: presentation.timelineRows[index])
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

private struct DetailRow: View {
    let key: String
    let value: AnyView

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 12) {
            Text(key)
                .font(.system(size: 11))
                .foregroundStyle(Color.ink500)
                .frame(width: 110, alignment: .leading)
            value
            Spacer(minLength: 0)
        }
    }
}

private struct TimelineEntry: View {
    let event: AuditEvent
    let presentation: AuditTimelineEntryPresentation
    @State private var transactionCopied = false
    @State private var transactionCopyGeneration: UInt64 = 0

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Circle()
                    .fill(presentation.dotTone.timelineColor)
                    .frame(width: 8, height: 8)
                    .padding(.top, 4)
                if !presentation.isLast {
                    Rectangle()
                        .fill(Color.ink200)
                        .frame(width: 1)
                }
            }
            .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(presentation.resultLabel)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(presentation.isDenied ? Color.bastionBad : Color.ink900)
                    if let tx = presentation.transactionHash,
                       let action = presentation.transactionAction {
                        Button {
                            switch action {
                            case .openExplorer:
                                if let chainId = presentation.transactionChainId,
                                   let url = ChainConfig.explorerURL(chainId: chainId, txHash: tx) {
                                    NSWorkspace.shared.open(url)
                                }
                            case .copyHash:
                                copyTransactionHash(tx)
                            }
                        } label: {
                            Text(action.label(copied: transactionCopied)).font(.system(size: 10))
                        }
                        .bastionButton(.ghost, size: .small)
                    }
                }
                if let date = event.timestampDate {
                    Text(BastionFormat.timeOnly(date))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                }
                if let reason = presentation.reason {
                    Text(reason)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Color.ink600)
                }
            }
            .padding(.bottom, 14)
            Spacer(minLength: 0)
        }
    }

    private func copyTransactionHash(_ tx: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(tx, forType: .string)
        transactionCopyGeneration &+= 1
        let generation = transactionCopyGeneration
        transactionCopied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + AddressCopyFeedback.resetDelay) {
            if AddressCopyFeedback.shouldReset(
                scheduledGeneration: generation,
                currentGeneration: transactionCopyGeneration
            ) {
                transactionCopied = false
            }
        }
    }
}

// MARK: - Export sheet

nonisolated enum AuditExportSheetFormat: String, CaseIterable, Identifiable, Sendable {
    case signedJSON = "Signed JSON bundle"
    case plainJSON = "Plain JSON"
    case csv = "CSV"

    var id: Self { self }
    var hint: String {
        switch self {
        case .signedJSON: return "Tamper-evident · for compliance review"
        case .plainJSON: return "For your own scripts"
        case .csv: return "Spreadsheet-friendly · less detail"
        }
    }

    var auditFormat: AuditExportFormat {
        switch self {
        case .signedJSON: return .signedJSON
        case .plainJSON: return .plainJSON
        case .csv: return .csv
        }
    }
}

nonisolated struct AuditExportSheetOptionPresentation: Equatable, Sendable {
    let format: AuditExportSheetFormat
    let label: String
    let hint: String
    let isSelected: Bool
}

nonisolated struct AuditExportSheetPresentation: Equatable, Sendable {
    let title: String
    let subtitle: String
    let options: [AuditExportSheetOptionPresentation]
    let errorMessage: String?
    let cancelButtonTitle: String
    let saveButtonTitle: String
    let disablesFormatSelection: Bool
    let disablesCancel: Bool
    let disablesSave: Bool

    static func make(count: Int, state: AuditExportSheetState) -> AuditExportSheetPresentation {
        AuditExportSheetPresentation(
            title: "Export audit log",
            subtitle: "\(count) requests · signed by your Bastion installation",
            options: AuditExportSheetFormat.allCases.map { option in
                AuditExportSheetOptionPresentation(
                    format: option,
                    label: option.rawValue,
                    hint: option.hint,
                    isSelected: state.format == option
                )
            },
            errorMessage: state.errorMessage,
            cancelButtonTitle: "Cancel",
            saveButtonTitle: state.isSaving ? "Saving…" : "Save…",
            disablesFormatSelection: state.isSaving,
            disablesCancel: state.isSaving,
            disablesSave: state.isSaving
        )
    }
}

nonisolated struct AuditExportSheetState: Equatable, Sendable {
    var format: AuditExportSheetFormat = .signedJSON
    var errorMessage: String? = nil
    var isSaving = false

    mutating func selectFormat(_ option: AuditExportSheetFormat) {
        guard !isSaving else { return }
        format = option
        errorMessage = nil
    }

    mutating func beginSave() -> Bool {
        guard !isSaving else { return false }
        isSaving = true
        errorMessage = nil
        return true
    }

    mutating func cancelSave() {
        isSaving = false
    }

    mutating func failExport(_ message: String) {
        errorMessage = "Export failed: \(message)"
        isSaving = false
    }

    mutating func failSave(_ message: String) {
        errorMessage = "Save failed: \(message)"
        isSaving = false
    }
}

private struct ExportSheet: View {
    let count: Int
    let onClose: () -> Void
    let records: [AuditRequestRecord]
    @State private var state = AuditExportSheetState()

    private var presentation: AuditExportSheetPresentation {
        AuditExportSheetPresentation.make(count: count, state: state)
    }

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text(presentation.title)
                    .font(.system(size: 14, weight: .semibold))
                    .kerning(-0.14)
                Text(presentation.subtitle)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
            }
            .padding(EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18))
            .frame(maxWidth: .infinity, alignment: .leading)
            BastionDivider()
            VStack(spacing: 8) {
                ForEach(presentation.options, id: \.format) { option in
                    Button(action: {
                        state.selectFormat(option.format)
                    }) {
                        HStack(alignment: .top, spacing: 10) {
                            ZStack {
                                Circle()
                                    .strokeBorder(option.isSelected ? Color.ink900 : Color.ink300, lineWidth: 1.5)
                                    .frame(width: 14, height: 14)
                                if option.isSelected {
                                    Circle().fill(Color.ink900).frame(width: 7, height: 7)
                                }
                            }
                            .padding(.top, 2)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(option.label).font(.system(size: 13, weight: .medium))
                                Text(option.hint).font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                            }
                            Spacer()
                        }
                        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(option.isSelected ? Color.ink50 : Color.paper)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .strokeBorder(option.isSelected ? Color.ink700 : Color.ink150, lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)
                    .disabled(presentation.disablesFormatSelection)
                }
            }
            .padding(18)

            if let errorMessage = presentation.errorMessage {
                Text(errorMessage)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.bastionBad)
                    .padding(.horizontal, 18).padding(.bottom, 8)
            }
            BastionDivider()
            HStack {
                Spacer()
                Button(presentation.cancelButtonTitle, action: onClose).bastionButton(.default)
                    .disabled(presentation.disablesCancel)
                Button(presentation.saveButtonTitle) {
                    saveExport()
                }
                .bastionButton(.primary)
                .disabled(presentation.disablesSave)
            }
            .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
            .background(Color.ink50)
        }
        .frame(width: 440)
        .background(Color.paper)
        .clipShape(RoundedRectangle(cornerRadius: 12))
        .overlay(
            RoundedRectangle(cornerRadius: 12).strokeBorder(Color.ink150, lineWidth: 1)
        )
        .shadow(color: Color.black.opacity(0.3), radius: 30, y: 20)
    }

    private func saveExport() {
        guard state.beginSave() else { return }
        do {
            let result = try AuditExporter.shared.render(records: records, format: state.format.auditFormat)
            let savePanel = NSSavePanel()
            savePanel.nameFieldStringValue = result.suggestedFilename
            savePanel.canCreateDirectories = true
            savePanel.title = "Export audit log"
            savePanel.begin { response in
                guard response == .OK, let url = savePanel.url else {
                    DispatchQueue.main.async { state.cancelSave() }
                    return
                }
                do {
                    try result.data.write(to: url, options: .atomic)
                    DispatchQueue.main.async { onClose() }
                } catch {
                    DispatchQueue.main.async {
                        state.failSave(error.localizedDescription)
                    }
                }
            }
        } catch {
            state.failExport(error.localizedDescription)
        }
    }
}

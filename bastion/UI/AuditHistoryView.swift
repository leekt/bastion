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

    var body: some View {
        ZStack {
            VStack(spacing: 0) {
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
            LabelXS(text: "Views")
            ViewChip(label: "All", active: savedView == nil) {
                savedView = nil; filters = .default
            }
            ViewChip(label: "Overrides only", active: savedView == .overrides) {
                savedView = .overrides; filters = AuditFilters(outcome: .overrides, client: nil, chainId: nil, range: .last24h)
            }
            ViewChip(label: "Silent signs", active: savedView == .silent) {
                savedView = .silent; filters = AuditFilters(outcome: .silent, client: nil, chainId: nil, range: .last24h)
            }
            ViewChip(label: "Failed", active: savedView == .failed) {
                savedView = .failed; filters = AuditFilters(outcome: .failed, client: nil, chainId: nil, range: .last24h)
            }
            Spacer()
            TextField("Search…", text: $search)
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
                onChange: { filters.outcome = $0 }
            )
            FilterDropdown(
                label: "Client",
                value: filters.client,
                options: clientOptions,
                onChange: { filters.client = $0 }
            )
            FilterDropdown(
                label: "Chain",
                value: filters.chainId,
                options: chainOptions,
                onChange: { filters.chainId = $0 }
            )
            FilterDropdown(
                label: "Range",
                value: filters.range,
                options: AuditRangeFilter.allCases,
                onChange: { filters.range = $0 }
            )
            Spacer()
            Button("Clear filters") { filters = .default; savedView = nil }
                .bastionButton(.ghost, size: .small)
                .opacity(filters != .default ? 1 : 0)
                .allowsHitTesting(filters != .default)
                .accessibilityHidden(filters == .default)
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
        .font(.system(size: 10.5, weight: .semibold))
        .kerning(0.6)
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
        let q = search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        return records.filter { r in
            if !q.isEmpty {
                let haystack = "\(r.clientDisplayName) \(r.operationTitle) \(r.summary) \(r.id)".lowercased()
                if !haystack.contains(q) { return false }
            }
            if let client = filters.client, r.clientDisplayName != client { return false }
            if let chain = filters.chainId, !recordContainsChain(r, chainId: chain) { return false }
            if !filters.outcome.matches(r) { return false }
            if let cutoff = filters.range.cutoff, let ts = r.latestTimestamp, ts < cutoff { return false }
            return true
        }
    }

    private var rowsContentIdentity: String {
        let filterKey = [
            search.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
            filters.outcome.rawValue,
            filters.client ?? "",
            filters.chainId.map(String.init) ?? "",
            filters.range.rawValue
        ].joined(separator: "|")

        let recordKey = filtered.map(\.id).joined(separator: "|")
        return "\(filterKey)#\(recordKey)"
    }

    private func recordContainsChain(_ r: AuditRequestRecord, chainId: Int) -> Bool {
        guard let request = r.request else { return false }
        return request.details.contains { $0.localizedCaseInsensitiveContains("\(chainId)") }
            || request.summary.localizedCaseInsensitiveContains("\(chainId)")
    }

    private func reload() {
        records = AuditLog.shared.recentRequestRecords(limit: 200)
    }
}

// MARK: - Saved views

private enum SavedView: Hashable { case overrides, silent, failed }

// MARK: - Filters

struct AuditFilters: Equatable {
    var outcome: AuditOutcomeFilter
    var client: String?
    var chainId: Int?
    var range: AuditRangeFilter

    static let `default` = AuditFilters(outcome: .all, client: nil, chainId: nil, range: .last24h)
}

enum AuditOutcomeFilter: String, CaseIterable, Hashable, FilterOptionEnum {
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

enum AuditRangeFilter: String, CaseIterable, Hashable, FilterOptionEnum {
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

private struct AuditRow: View {
    let record: AuditRequestRecord
    let expanded: Bool
    let onToggle: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            Button(action: onToggle) {
                HStack(spacing: 12) {
                    Text(BastionFormat.relative(record.latestTimestamp))
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(Color.ink700)
                        .frame(width: 90, alignment: .leading)
                    Text(record.clientDisplayName)
                        .font(.system(size: 12.5, weight: .medium))
                        .frame(width: 130, alignment: .leading)
                        .lineLimit(1)
                    Text(record.operationTitle)
                        .font(.system(size: 12.5))
                        .foregroundStyle(Color.ink700)
                        .lineLimit(1)
                        .frame(maxWidth: .infinity, alignment: .leading)
                    OutcomeBadge(record: record)
                        .frame(width: 130, alignment: .leading)
                    chainCell
                        .frame(width: 100, alignment: .leading)
                    Text(expanded ? "▾" : "›")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.ink400)
                        .frame(width: 14, alignment: .center)
                }
                .padding(EdgeInsets(top: 6, leading: 24, bottom: 6, trailing: 24))
                .background(expanded ? Color.ink50 : Color.clear)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)

            if expanded {
                ExpandedDetail(record: record)
                    .padding(EdgeInsets(top: 0, leading: 24, bottom: 18, trailing: 24))
                    .background(Color.ink50)
            }
        }
    }

    @ViewBuilder
    private var chainCell: some View {
        if let chainId = guessChain(record) {
            ChainBadge(chainId: chainId, size: .small)
        } else {
            Text("—").foregroundStyle(Color.ink300).font(.system(size: 12))
        }
    }

    private func guessChain(_ r: AuditRequestRecord) -> Int? {
        guard let details = r.request?.details else { return nil }
        for line in details {
            if line.lowercased().contains("chain") {
                let nums = line.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
                if let n = nums.first { return n }
            }
        }
        return nil
    }
}

private struct OutcomeBadge: View {
    let record: AuditRequestRecord

    var body: some View {
        switch record.latestEvent?.type {
        case .userOpReceiptSuccess:
            BastionChip(label: "Confirmed", style: .ok, leading: AnyView(StatusDot(state: .ok, size: 5)))
        case .signSuccess, .userOpSubmitted:
            BastionChip(label: "Signed", style: .ok, leading: AnyView(StatusDot(state: .ok, size: 5)))
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            BastionChip(label: "Denied", style: .bad, leading: AnyView(StatusDot(state: .bad, size: 5)))
        case .userOpReceiptTimeout:
            BastionChip(label: "Pending", style: .warn, leading: AnyView(StatusDot(state: .warn, size: 5)))
        default:
            BastionChip(label: record.latestEvent?.resultLabel ?? "—", style: .neutral)
        }
    }
}

private func guessChainId(_ record: AuditRequestRecord) -> Int? {
    guard let details = record.request?.details else { return nil }
    for line in details {
        if line.lowercased().contains("chain") {
            let nums = line.split(whereSeparator: { !$0.isNumber }).compactMap { Int($0) }
            if let n = nums.first { return n }
        }
    }
    return nil
}

private struct ExpandedDetail: View {
    let record: AuditRequestRecord

    var body: some View {
        HStack(alignment: .top, spacing: 24) {
            metadata
            timeline
        }
        .padding(EdgeInsets(top: 14, leading: 18, bottom: 14, trailing: 18))
        .background(
            RoundedRectangle(cornerRadius: 10)
                .fill(Color.paper)
                .overlay(RoundedRectangle(cornerRadius: 10).strokeBorder(Color.ink150, lineWidth: 1))
        )
    }

    private var metadata: some View {
        VStack(alignment: .leading, spacing: 10) {
            DetailRow(key: "Request ID", value: AnyView(
                Text(record.requestID).font(.system(size: 12, design: .monospaced))
            ))
            DetailRow(key: "Type", value: AnyView(
                Text(record.request?.operationKind ?? "—").font(.system(size: 12))
            ))
            DetailRow(key: "Rule path", value: AnyView(rulePathChip))
            if let txEvent = record.events.first(where: { $0.submission?.transactionHash != nil }),
               let tx = txEvent.submission?.transactionHash {
                let chainId = guessChainId(record)
                DetailRow(key: "Tx hash", value: AnyView(
                    HStack {
                        AddressView(address: tx)
                        if let chainId,
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
                    StatusDot(state: AuditLog.shared.logTampered ? .bad : .ok, size: 5)
                    Text(AuditLog.shared.logTampered ? "Tampered — verify install" : "Tamper-evident · verified")
                        .font(.system(size: 11.5))
                        .foregroundStyle(AuditLog.shared.logTampered ? Color.bastionBad : Color.bastionOk)
                }
            ))
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var rulePathChip: some View {
        let mode = record.latestEvent?.approvalMode
        switch mode {
        case .auto:
            return AnyView(BastionChip(label: "Silent · rules passed", style: .outline))
        case .policyReview:
            return AnyView(BastionChip(label: "Approved", style: .accent))
        case .ruleOverride:
            return AnyView(BastionChip(label: "Override · owner auth", style: .warn))
        case .none:
            return AnyView(BastionChip(label: "—", style: .neutral))
        }
    }

    private var timeline: some View {
        let chainId = guessChainId(record)
        return VStack(alignment: .leading, spacing: 0) {
            LabelXS(text: "Timeline").padding(.bottom, 10)
            ForEach(Array(record.events.enumerated()), id: \.offset) { idx, event in
                TimelineEntry(event: event, isLast: idx == record.events.count - 1, chainId: chainId)
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
    let isLast: Bool
    var chainId: Int? = nil

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(spacing: 0) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 8, height: 8)
                    .padding(.top, 4)
                if !isLast {
                    Rectangle()
                        .fill(Color.ink200)
                        .frame(width: 1)
                }
            }
            .frame(width: 16)

            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(event.resultLabel)
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundStyle(isDenied ? Color.bastionBad : Color.ink900)
                    if let tx = event.submission?.transactionHash {
                        Button {
                            if let chainId, let url = ChainConfig.explorerURL(chainId: chainId, txHash: tx) {
                                NSWorkspace.shared.open(url)
                            } else {
                                NSPasteboard.general.clearContents()
                                NSPasteboard.general.setString(tx, forType: .string)
                            }
                        } label: {
                            Text("View tx ↗").font(.system(size: 10))
                        }
                        .bastionButton(.ghost, size: .small)
                    }
                }
                if let date = event.timestampDate {
                    Text(BastionFormat.timeOnly(date))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                }
                if let reason = event.reason, !reason.isEmpty {
                    Text(reason)
                        .font(.system(size: 11.5))
                        .foregroundStyle(Color.ink600)
                }
            }
            .padding(.bottom, 14)
            Spacer(minLength: 0)
        }
    }

    private var isDenied: Bool {
        switch event.type {
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            return true
        default:
            return false
        }
    }

    private var dotColor: Color {
        switch event.type {
        case .signDenied, .ruleViolation, .authFailed, .userOpSendFailed, .userOpReceiptFailed:
            return .bastionBad
        case .userOpReceiptTimeout:
            return .bastionWarn
        case .userOpReceiptSuccess:
            return .bastionOk
        case .signSuccess, .userOpSubmitted, .preflightCompleted:
            return event.approvalMode == .ruleOverride ? .bastionWarn : .ink700
        default:
            return .ink700
        }
    }
}

// MARK: - Export sheet

private struct ExportSheet: View {
    let count: Int
    let onClose: () -> Void
    let records: [AuditRequestRecord]
    @State private var format: ExportFormat = .signedJSON
    @State private var errorMessage: String? = nil

    enum ExportFormat: String, CaseIterable, Identifiable {
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

    var body: some View {
        VStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Export audit log")
                    .font(.system(size: 14, weight: .semibold))
                    .kerning(-0.14)
                Text("\(count) requests · signed by your Bastion installation")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
            }
            .padding(EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18))
            .frame(maxWidth: .infinity, alignment: .leading)
            BastionDivider()
            VStack(spacing: 8) {
                ForEach(ExportFormat.allCases) { option in
                    Button(action: { format = option }) {
                        HStack(alignment: .top, spacing: 10) {
                            ZStack {
                                Circle()
                                    .strokeBorder(format == option ? Color.ink900 : Color.ink300, lineWidth: 1.5)
                                    .frame(width: 14, height: 14)
                                if format == option {
                                    Circle().fill(Color.ink900).frame(width: 7, height: 7)
                                }
                            }
                            .padding(.top, 2)
                            VStack(alignment: .leading, spacing: 2) {
                                Text(option.rawValue).font(.system(size: 13, weight: .medium))
                                Text(option.hint).font(.system(size: 11.5)).foregroundStyle(Color.ink500)
                            }
                            Spacer()
                        }
                        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
                        .background(
                            RoundedRectangle(cornerRadius: 8)
                                .fill(format == option ? Color.ink50 : Color.paper)
                                .overlay(
                                    RoundedRectangle(cornerRadius: 8)
                                        .strokeBorder(format == option ? Color.ink700 : Color.ink150, lineWidth: 1)
                                )
                        )
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(18)

            if let errorMessage {
                Text(errorMessage)
                    .font(.system(size: 11.5))
                    .foregroundStyle(Color.bastionBad)
                    .padding(.horizontal, 18).padding(.bottom, 8)
            }
            BastionDivider()
            HStack {
                Spacer()
                Button("Cancel", action: onClose).bastionButton(.default)
                Button("Save…") {
                    saveExport()
                }
                .bastionButton(.primary)
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
        do {
            let result = try AuditExporter.shared.render(records: records, format: format.auditFormat)
            let savePanel = NSSavePanel()
            savePanel.nameFieldStringValue = result.suggestedFilename
            savePanel.canCreateDirectories = true
            savePanel.title = "Export audit log"
            savePanel.begin { response in
                guard response == .OK, let url = savePanel.url else { return }
                do {
                    try result.data.write(to: url, options: .atomic)
                    DispatchQueue.main.async { onClose() }
                } catch {
                    DispatchQueue.main.async {
                        errorMessage = "Save failed: \(error.localizedDescription)"
                    }
                }
            }
        } catch {
            errorMessage = "Export failed: \(error.localizedDescription)"
        }
    }
}

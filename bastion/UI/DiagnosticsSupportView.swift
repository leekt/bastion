import AppKit
import SwiftUI

struct DiagnosticsSupportView: View {
    @State private var snapshot: DiagnosticsSnapshot = .empty
    @State private var exportState = DiagnosticsSupportExportState()

    private var presentation: DiagnosticsDashboardPresentation {
        DiagnosticsDashboardPresentation.make(
            snapshot: snapshot,
            isExporting: exportState.isExporting,
            exportStatus: exportState.status,
            exportError: exportState.error
        )
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            BastionDivider()
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    statusGrid
                    serviceSection
                    crashSection
                    diagnosticsSection
                }
                .padding(18)
            }
        }
        .frame(minWidth: 760, minHeight: 520)
        .background(Color.paper)
        .task {
            refresh()
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 8)
                    .fill(snapshot.overallColor)
                Image(systemName: "stethoscope")
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundStyle(Color.paper)
            }
            .frame(width: 32, height: 32)

            VStack(alignment: .leading, spacing: 3) {
                Text(presentation.title)
                    .font(.system(size: 17, weight: .semibold))
                    .foregroundStyle(Color.ink900)
                HStack(spacing: 6) {
                    StatusDot(state: presentation.overallDot)
                    Text(presentation.subtitle)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                }
            }

            Spacer()

            if let exportStatus = presentation.exportStatus {
                Text(exportStatus)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.bastionOk)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            if let exportError = presentation.exportError {
                Text(exportError)
                    .font(.system(size: 11))
                    .foregroundStyle(Color.bastionBad)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Button {
                refresh()
            } label: {
                Label(presentation.refreshButtonTitle, systemImage: "arrow.clockwise")
            }
            .bastionButton(.default, size: .small)
            .disabled(presentation.disablesRefresh)

            Button {
                exportSupportBundle()
            } label: {
                Label(presentation.exportButtonTitle, systemImage: "square.and.arrow.down")
            }
            .bastionButton(.primary, size: .small)
            .disabled(presentation.disablesExport)
        }
        .padding(EdgeInsets(top: 14, leading: 18, bottom: 14, trailing: 18))
        .background(Color.ink50)
    }

    private var statusGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 150), spacing: 10)], spacing: 10) {
            ForEach(presentation.metricTiles) { tile in
                DiagnosticsMetricTile(
                    title: tile.title,
                    value: tile.value,
                    state: tile.state
                )
            }
        }
    }

    private var serviceSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionSectionHeader(
                title: presentation.serviceSectionTitle,
                subtitle: presentation.serviceSectionSubtitle
            )
            LazyVGrid(columns: [
                GridItem(.flexible(minimum: 240), spacing: 12),
                GridItem(.flexible(minimum: 240), spacing: 12)
            ], alignment: .leading, spacing: 8) {
                ForEach(presentation.serviceFields) { field in
                    DiagnosticsField(label: field.label, value: field.value)
                }
            }
        }
    }

    private var crashSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionSectionHeader(
                title: presentation.crashSectionTitle,
                subtitle: presentation.crashSectionSubtitle
            )
            if snapshot.crashReports.isEmpty {
                Text(presentation.emptyCrashMessage)
                    .font(.system(size: 13))
                    .foregroundStyle(Color.ink500)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(18)
                    .background(
                        RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                            .fill(Color.ink50)
                            .overlay(
                                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                    .strokeBorder(Color.ink150, lineWidth: 1)
                            )
                    )
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(snapshot.crashReports.enumerated()), id: \.offset) { index, report in
                        CrashReportRow(report: report)
                        if index < snapshot.crashReports.count - 1 {
                            BastionDivider()
                        }
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .fill(Color.bastionWarnSoft.opacity(0.6))
                        .overlay(
                            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                .strokeBorder(Color.bastionWarn.opacity(0.25), lineWidth: 1)
                        )
                )
            }
        }
    }

    private var diagnosticsSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            BastionSectionHeader(
                title: presentation.diagnosticsSectionTitle,
                subtitle: presentation.diagnosticsSectionSubtitle
            )
            if snapshot.diagnostics.isEmpty {
                Text(presentation.emptyDiagnosticsMessage)
                    .font(.system(size: 13))
                    .foregroundStyle(Color.ink500)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(18)
                    .background(
                        RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                            .fill(Color.ink50)
                            .overlay(
                                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                    .strokeBorder(Color.ink150, lineWidth: 1)
                            )
                    )
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(snapshot.diagnostics.enumerated()), id: \.offset) { index, entry in
                        DiagnosticEntryRow(entry: entry)
                        if index < snapshot.diagnostics.count - 1 {
                            BastionDivider()
                        }
                    }
                }
                .background(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .fill(Color.ink50)
                        .overlay(
                            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                                .strokeBorder(Color.ink150, lineWidth: 1)
                        )
                )
            }
        }
    }

    private func refresh() {
        RuleEngine.shared.ensureConfigLoadedIfNeeded()
        snapshot = DiagnosticsSnapshot.load()
        exportState.clearError()
    }

    private func exportSupportBundle() {
        guard exportState.beginExport() else { return }
        do {
            RuleEngine.shared.ensureConfigLoadedIfNeeded()
            let data = try SupportBundleExporter.makeBundleData(
                config: RuleEngine.shared.loadConfig(),
                service: SupportBundleExporter.currentServiceSnapshot(configCorrupted: RuleEngine.shared.configCorrupted),
                request: DiagnosticsSupportExportState.bundleRequest
            )
            let savePanel = NSSavePanel()
            savePanel.nameFieldStringValue = "bastion-support-\(Self.filenameTimestamp()).json"
            savePanel.canCreateDirectories = true
            savePanel.title = DiagnosticsSupportExportState.savePanelTitle
            savePanel.begin { response in
                guard response == .OK, let url = savePanel.url else {
                    DispatchQueue.main.async { exportState.cancelExport() }
                    return
                }
                do {
                    try data.write(to: url, options: .atomic)
                    let diagnostic = DiagnosticsSupportExportState.savedDiagnostic(filename: url.lastPathComponent)
                    DiagnosticLog.shared.record(
                        category: diagnostic.category,
                        event: diagnostic.event,
                        message: diagnostic.message,
                        context: diagnostic.context
                    )
                    DispatchQueue.main.async {
                        exportState.succeed(filename: url.lastPathComponent)
                        refresh()
                    }
                } catch {
                    DispatchQueue.main.async {
                        exportState.fail(error.localizedDescription)
                    }
                }
            }
        } catch {
            exportState.fail(error.localizedDescription)
        }
    }

    private static func filenameTimestamp() -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyyMMdd-HHmmss"
        return formatter.string(from: Date())
    }
}

nonisolated struct DiagnosticsSupportExportDiagnostic: Equatable, Sendable {
    let category: DiagnosticCategory
    let event: String
    let message: String
    let context: [String: String]
}

nonisolated struct DiagnosticsSupportExportState: Equatable, Sendable {
    var status: String?
    var error: String?
    var isExporting = false

    static let bundleRequest = SupportBundleRequest(
        maxAuditRecords: 100,
        maxDiagnosticEntries: 500,
        maxCrashReports: 20
    )
    static let savePanelTitle = "Export Bastion support bundle"

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

    mutating func succeed(filename: String) {
        status = filename
        error = nil
        isExporting = false
    }

    mutating func fail(_ message: String) {
        status = nil
        error = "Export failed: \(message)"
        isExporting = false
    }

    mutating func clearError() {
        error = nil
    }

    static func savedDiagnostic(filename: String) -> DiagnosticsSupportExportDiagnostic {
        DiagnosticsSupportExportDiagnostic(
            category: .support,
            event: "support_bundle_saved",
            message: "Support bundle saved from diagnostics panel",
            context: ["filename": filename]
        )
    }
}

struct DiagnosticsSnapshot {
    let service: SupportServiceSnapshot
    let auditTampered: Bool
    let auditChainBroken: Bool
    let diagnostics: [DiagnosticLogEntry]
    let crashReports: [CrashReportSummary]

    var warningCount: Int {
        diagnostics.filter { $0.level == .warning }.count
    }

    var errorCount: Int {
        diagnostics.filter { $0.level == .error }.count
    }

    var serviceState: StatusDot.State {
        service.serviceRegistrationStatus == "enabled" ? .ok : .warn
    }

    var auditState: StatusDot.State {
        auditTampered || auditChainBroken ? .bad : .ok
    }

    var auditStateLabel: String {
        if auditTampered { return "Tampered" }
        if auditChainBroken { return "Chain broken" }
        return "Healthy"
    }

    var diagnosticsState: StatusDot.State {
        if errorCount > 0 { return .bad }
        if warningCount > 0 { return .warn }
        return .ok
    }

    var crashState: StatusDot.State {
        crashReports.isEmpty ? .ok : .warn
    }

    var crashStateLabel: String {
        crashReports.isEmpty ? "None found" : "\(crashReports.count) found"
    }

    var overallDot: StatusDot.State {
        if service.configCorrupted || auditTampered || auditChainBroken || errorCount > 0 { return .bad }
        if warningCount > 0 || serviceState == .warn || !crashReports.isEmpty { return .warn }
        return .ok
    }

    var overallColor: Color {
        switch overallDot {
        case .ok: return .bastionOk
        case .warn: return .bastionWarn
        case .bad: return .bastionBad
        case .idle: return .ink500
        }
    }

    var subtitle: String {
        if service.configCorrupted {
            return "Config recovery required"
        }
        if auditTampered || auditChainBroken {
            return "Audit integrity needs recovery"
        }
        if errorCount > 0 {
            return "\(errorCount) recent diagnostic errors"
        }
        if serviceState == .warn {
            return "Service registration needs attention"
        }
        if !crashReports.isEmpty {
            return "\(crashReports.count) recent crash reports available"
        }
        if warningCount > 0 {
            return "\(warningCount) recent diagnostic warnings"
        }
        return "No recent support issues detected"
    }

    static let empty = DiagnosticsSnapshot(
        service: SupportBundleExporter.serviceSnapshot(
            version: "unknown",
            serviceRegistrationStatus: "unknown",
            configCorrupted: false,
            bundlePath: "",
            executablePath: "",
            bundleIdentifier: nil,
            processIdentifier: 0,
            launchMode: "unknown",
            machServiceName: xpcServiceName,
            launchAgentPlistName: ServiceRegistration.launchAgentPlistName
        ),
        auditTampered: false,
        auditChainBroken: false,
        diagnostics: [],
        crashReports: []
    )

    @MainActor
    static func load() -> DiagnosticsSnapshot {
        DiagnosticsSnapshot(
            service: SupportBundleExporter.currentServiceSnapshot(configCorrupted: RuleEngine.shared.configCorrupted),
            auditTampered: AuditLog.shared.logTampered,
            auditChainBroken: AuditLog.shared.chainBroken,
            diagnostics: Array(DiagnosticLog.shared.recentEntries(limit: 100).reversed()),
            crashReports: CrashReportCollector.shared.recentReports(limit: 10)
        )
    }
}

nonisolated struct DiagnosticsMetricTilePresentation: Identifiable, Equatable, Sendable {
    let title: String
    let value: String
    let state: StatusDot.State

    var id: String { title }
}

nonisolated struct DiagnosticsFieldPresentation: Identifiable, Equatable, Sendable {
    let label: String
    let value: String

    var id: String { label }
}

nonisolated struct DiagnosticsDashboardPresentation: Equatable, Sendable {
    let title: String
    let subtitle: String
    let overallDot: StatusDot.State
    let metricTiles: [DiagnosticsMetricTilePresentation]
    let serviceSectionTitle: String
    let serviceSectionSubtitle: String
    let serviceFields: [DiagnosticsFieldPresentation]
    let crashSectionTitle: String
    let crashSectionSubtitle: String
    let emptyCrashMessage: String
    let diagnosticsSectionTitle: String
    let diagnosticsSectionSubtitle: String
    let emptyDiagnosticsMessage: String
    let refreshButtonTitle: String
    let exportButtonTitle: String
    let disablesRefresh: Bool
    let disablesExport: Bool
    let exportStatus: String?
    let exportError: String?

    static func make(
        snapshot: DiagnosticsSnapshot,
        isExporting: Bool,
        exportStatus: String?,
        exportError: String?
    ) -> DiagnosticsDashboardPresentation {
        let service = snapshot.service
        return DiagnosticsDashboardPresentation(
            title: "Diagnostics",
            subtitle: snapshot.subtitle,
            overallDot: snapshot.overallDot,
            metricTiles: [
                DiagnosticsMetricTilePresentation(
                    title: "Service",
                    value: service.serviceRegistrationStatus,
                    state: snapshot.serviceState
                ),
                DiagnosticsMetricTilePresentation(
                    title: "Config",
                    value: service.configCorrupted ? "Corrupt" : "Healthy",
                    state: service.configCorrupted ? .bad : .ok
                ),
                DiagnosticsMetricTilePresentation(
                    title: "Audit",
                    value: snapshot.auditStateLabel,
                    state: snapshot.auditState
                ),
                DiagnosticsMetricTilePresentation(
                    title: "Diagnostics",
                    value: "\(snapshot.errorCount) errors · \(snapshot.warningCount) warnings",
                    state: snapshot.diagnosticsState
                ),
                DiagnosticsMetricTilePresentation(
                    title: "Crashes",
                    value: snapshot.crashStateLabel,
                    state: snapshot.crashState
                ),
            ],
            serviceSectionTitle: "Service Snapshot",
            serviceSectionSubtitle: "Current process and registration context included in support exports.",
            serviceFields: [
                DiagnosticsFieldPresentation(label: "Version", value: service.version),
                DiagnosticsFieldPresentation(label: "Launch mode", value: service.launchMode),
                DiagnosticsFieldPresentation(label: "Process ID", value: "\(service.processIdentifier)"),
                DiagnosticsFieldPresentation(label: "Bundle ID", value: service.bundleIdentifier ?? "unknown"),
                DiagnosticsFieldPresentation(label: "Mach service", value: service.machServiceName),
                DiagnosticsFieldPresentation(label: "LaunchAgent plist", value: service.launchAgentPlistName),
                DiagnosticsFieldPresentation(label: "Bundle path", value: service.bundlePath),
                DiagnosticsFieldPresentation(label: "Executable", value: service.executablePath),
            ],
            crashSectionTitle: "Crash Reports",
            crashSectionSubtitle: "Recent macOS DiagnosticReports for Bastion. Raw crash bodies are excluded from support bundles.",
            emptyCrashMessage: "No recent Bastion crash reports found.",
            diagnosticsSectionTitle: "Recent Diagnostics",
            diagnosticsSectionSubtitle: "\(snapshot.diagnostics.count) newest lifecycle, XPC, approval, submission, notification, support, and update events.",
            emptyDiagnosticsMessage: "No diagnostic events recorded yet.",
            refreshButtonTitle: "Refresh",
            exportButtonTitle: isExporting ? "Exporting…" : "Export Bundle",
            disablesRefresh: isExporting,
            disablesExport: isExporting,
            exportStatus: exportStatus,
            exportError: exportError
        )
    }
}

private struct DiagnosticsMetricTile: View {
    let title: String
    let value: String
    let state: StatusDot.State

    var body: some View {
        VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 6) {
                StatusDot(state: state)
                Text(title)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(Color.ink500)
            }
            Text(value)
                .font(.system(size: 13, weight: .semibold))
                .foregroundStyle(Color.ink900)
                .lineLimit(1)
                .truncationMode(.middle)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(EdgeInsets(top: 11, leading: 12, bottom: 11, trailing: 12))
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                .fill(Color.ink50)
                .overlay(
                    RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                        .strokeBorder(Color.ink150, lineWidth: 1)
                )
        )
    }
}

private struct DiagnosticsField: View {
    let label: String
    let value: String

    var body: some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Color.ink500)
            Text(value.isEmpty ? "unknown" : value)
                .font(.system(size: 12, design: .monospaced))
                .foregroundStyle(Color.ink800)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(value)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(EdgeInsets(top: 9, leading: 10, bottom: 9, trailing: 10))
        .background(
            RoundedRectangle(cornerRadius: BastionTokens.radiusSmall)
                .fill(Color.ink50)
        )
    }
}

private struct DiagnosticEntryRow: View {
    let entry: DiagnosticLogEntry

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusDot(state: entry.dotState)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text(entry.event)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    Text(entry.category.rawValue)
                        .font(.system(size: 11))
                        .foregroundStyle(entry.categoryColor)
                    Spacer(minLength: 8)
                    Text(entry.relativeTimestamp)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink400)
                }
                Text(entry.message)
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink700)
                    .fixedSize(horizontal: false, vertical: true)
                if !entry.context.isEmpty {
                    Text(entry.contextSummary)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }
            }
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
    }
}

private struct CrashReportRow: View {
    let report: CrashReportSummary

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            StatusDot(state: .warn)
                .padding(.top, 5)
            VStack(alignment: .leading, spacing: 5) {
                HStack(spacing: 8) {
                    Text(report.process ?? report.filename)
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(Color.ink900)
                        .lineLimit(1)
                    Text(report.reportType)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.bastionWarn)
                    Spacer(minLength: 8)
                    Text(BastionFormat.relative(report.modifiedDate))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Color.ink500)
                }
                if let exception = report.exceptionType ?? report.terminationReason {
                    Text(exception)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink700)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text(report.filename)
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.ink500)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }
        }
        .padding(EdgeInsets(top: 10, leading: 12, bottom: 10, trailing: 12))
    }
}

private extension CrashReportSummary {
    var modifiedDate: Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: modifiedAt)
    }
}

private extension DiagnosticLogEntry {
    var dotState: StatusDot.State {
        switch level {
        case .info: return .ok
        case .warning: return .warn
        case .error: return .bad
        }
    }

    var categoryColor: Color {
        switch category {
        case .lifecycle: return .bastionAccentDeep
        case .xpc: return .ink700
        case .approval: return .bastionWarn
        case .submission: return .bastionAccent
        case .notification: return .bastionOk
        case .support: return .ink500
        case .update: return .bastionAccentDeep
        case .policy: return .bastionWarn
        }
    }

    var timestampDate: Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter.date(from: timestamp)
    }

    var relativeTimestamp: String {
        BastionFormat.relative(timestampDate)
    }

    var contextSummary: String {
        context
            .sorted { $0.key < $1.key }
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: " · ")
    }
}

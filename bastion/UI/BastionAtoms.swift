import AppKit
import SwiftUI

// Shared atoms — small reusable pieces used across all Bastion surfaces.
// Mirrors atoms.jsx from the design bundle.

// MARK: - Hex helpers

enum BastionFormat {
    static func shortHex(_ s: String, head: Int = 6, tail: Int = 4) -> String {
        guard !s.isEmpty else { return "" }
        if s.count <= head + tail + 2 { return s }
        let prefixLen = s.hasPrefix("0x") ? head + 2 : head
        let prefix = s.prefix(prefixLen)
        let suffix = s.suffix(tail)
        return "\(prefix)…\(suffix)"
    }

    static func relative(_ date: Date?) -> String {
        guard let date else { return "never" }
        let diff = Date().timeIntervalSince(date)
        if diff < 60 { return "just now" }
        if diff < 3600 { return "\(Int(diff / 60))m ago" }
        if diff < 86400 { return "\(Int(diff / 3600))h ago" }
        return "\(Int(diff / 86400))d ago"
    }

    static func timeOnly(_ date: Date) -> String {
        let f = DateFormatter()
        f.dateFormat = "HH:mm"
        return f.string(from: date)
    }
}

// MARK: - Address pill

struct AddressView: View {
    let address: String
    var full: Bool = false
    var muted: Bool = false
    var prefix: String = ""

    @State private var copied: Bool = false
    @State private var copyGeneration: UInt64 = 0

    var body: some View {
        Button(action: copy) {
            HStack(spacing: 6) {
                if !prefix.isEmpty {
                    Text(prefix).foregroundStyle(.secondary)
                }
                Text(full ? address : BastionFormat.shortHex(address))
                    .font(.system(size: 12, design: .monospaced))
                    .foregroundStyle(muted ? Color.ink500 : Color.ink800)
                    .kerning(-0.12)
                Text(copied ? "✓ copied" : "⎘")
                    .font(.system(size: 10))
                    .foregroundStyle(copied ? Color.bastionOk : Color.ink400)
                    .opacity(copied ? 1.0 : 0.55)
            }
        }
        .buttonStyle(.plain)
        .help(address)
    }

    private func copy() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(address, forType: .string)
        copyGeneration &+= 1
        let generation = copyGeneration
        copied = true
        DispatchQueue.main.asyncAfter(deadline: .now() + AddressCopyFeedback.resetDelay) {
            if AddressCopyFeedback.shouldReset(scheduledGeneration: generation, currentGeneration: copyGeneration) {
                copied = false
            }
        }
    }
}

nonisolated enum AddressCopyFeedback {
    static let resetDelay: TimeInterval = 0.9

    static func shouldReset(scheduledGeneration: UInt64, currentGeneration: UInt64) -> Bool {
        scheduledGeneration == currentGeneration
    }
}

// MARK: - Chain badge

nonisolated struct ChainBadgePresentation: Equatable, Sendable {
    let chainId: Int
    let name: String
    let glyph: String

    static func make(chainId: Int) -> ChainBadgePresentation {
        switch chainId {
        case 1:
            return ChainBadgePresentation(chainId: chainId, name: "Ethereum", glyph: "◆")
        case 11_155_111:
            return ChainBadgePresentation(chainId: chainId, name: "Sepolia", glyph: "◆")
        case 8453:
            return ChainBadgePresentation(chainId: chainId, name: "Base", glyph: "●")
        case 84_532:
            return ChainBadgePresentation(chainId: chainId, name: "Base Sepolia", glyph: "●")
        case 10:
            return ChainBadgePresentation(chainId: chainId, name: "Optimism", glyph: "○")
        case 42_161:
            return ChainBadgePresentation(chainId: chainId, name: "Arbitrum", glyph: "◇")
        default:
            return ChainBadgePresentation(chainId: chainId, name: "Chain \(chainId)", glyph: "◇")
        }
    }
}

struct ChainBadge: View {
    let chainId: Int
    var size: BadgeSize = .medium

    enum BadgeSize { case small, medium }

    private var presentation: ChainBadgePresentation {
        ChainBadgePresentation.make(chainId: chainId)
    }

    private var color: Color {
        switch chainId {
        case 1:          return Color(red: 0.384, green: 0.494, blue: 0.918)
        case 11_155_111: return Color(red: 0.654, green: 0.545, blue: 0.980)
        case 8453:       return Color(red: 0.000, green: 0.322, blue: 1.000)
        case 84_532:     return Color(red: 0.478, green: 0.651, blue: 1.000)
        case 10:         return Color(red: 1.000, green: 0.016, blue: 0.125)
        case 42_161:     return Color(red: 0.157, green: 0.627, blue: 0.941)
        default:         return .ink500
        }
    }

    var body: some View {
        let small = size == .small
        let dim: CGFloat = small ? 14 : 16
        HStack(spacing: 6) {
            ZStack {
                RoundedRectangle(cornerRadius: 4)
                    .fill(color.opacity(0.10))
                Text(presentation.glyph)
                    .font(.system(size: small ? 10 : 11, weight: .bold))
                    .foregroundStyle(color)
            }
            .frame(width: dim, height: dim)
            Text(presentation.name)
                .font(.system(size: small ? 11 : 12, weight: .medium))
                .foregroundStyle(Color.ink700)
        }
    }
}

// MARK: - Section header

struct BastionSectionHeader<Trailing: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let trailing: () -> Trailing

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Color.ink900)
                    .kerning(-0.13)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                }
            }
            Spacer()
            trailing()
        }
        .padding(.bottom, 12)
    }
}

extension BastionSectionHeader where Trailing == EmptyView {
    init(title: String, subtitle: String? = nil) {
        self.init(title: title, subtitle: subtitle, trailing: { EmptyView() })
    }
}

// MARK: - Toggle row

struct BastionToggleRow: View {
    let label: String
    var hint: String? = nil
    @Binding var isOn: Bool

    var body: some View {
        HStack(alignment: .top) {
            VStack(alignment: .leading, spacing: 2) {
                if !label.isEmpty {
                    Text(label).font(.system(size: 13)).foregroundStyle(Color.ink900)
                }
                if let hint {
                    Text(hint).font(.system(size: 12)).foregroundStyle(Color.ink500)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer()
            Toggle("", isOn: $isOn)
                .toggleStyle(.switch)
                .labelsHidden()
                .controlSize(.small)
        }
        .padding(.vertical, 10)
    }
}

// MARK: - Tabs

struct BastionTab<T: Hashable>: Identifiable {
    let id: T
    let label: String
}

struct BastionTabs<T: Hashable>: View {
    let tabs: [BastionTab<T>]
    @Binding var selection: T

    var body: some View {
        HStack(spacing: 2) {
            ForEach(tabs) { tab in
                let isSelected = tab.id == selection
                Button {
                    selection = tab.id
                } label: {
                    Text(tab.label)
                        .font(.system(size: 12, weight: .medium))
                        .foregroundStyle(isSelected ? Color.ink900 : Color.ink500)
                        .padding(.horizontal, 12)
                        .padding(.vertical, 5)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .fill(isSelected ? Color.paper : .clear)
                                .shadow(color: isSelected ? Color.black.opacity(0.05) : .clear, radius: 1, y: 1)
                        )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(Color.ink100)
                .overlay(RoundedRectangle(cornerRadius: 8).strokeBorder(Color.ink150, lineWidth: 1))
        )
        .fixedSize()
    }
}

// MARK: - Quota bar

struct BastionQuota: View {
    let used: Double
    let total: Double
    let label: String
    var unit: String = ""

    private var pct: Double { min(100, total > 0 ? (used / total) * 100 : 0) }
    private var color: Color {
        pct < 60 ? .bastionOk : pct < 90 ? .bastionWarn : .bastionBad
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(label).font(.system(size: 12)).foregroundStyle(Color.ink700)
                Spacer()
                Text("\(formatted(used))\(unit) / \(formatted(total))\(unit)")
                    .font(.system(size: 11, design: .monospaced))
                    .foregroundStyle(Color.ink500)
            }
            GeometryReader { geo in
                ZStack(alignment: .leading) {
                    RoundedRectangle(cornerRadius: 2).fill(Color.ink150)
                    RoundedRectangle(cornerRadius: 2)
                        .fill(color)
                        .frame(width: geo.size.width * (pct / 100))
                }
            }
            .frame(height: 4)
        }
    }

    private func formatted(_ v: Double) -> String {
        if v == v.rounded() && abs(v) >= 1 { return String(Int(v)) }
        return String(format: v < 1 ? "%.4g" : "%.2f", v)
    }
}

// MARK: - Chip

struct BastionChip: View {
    enum Style: Equatable, Sendable { case neutral, ok, warn, bad, accent, outline }

    let label: String
    var style: Style = .neutral
    var leading: AnyView? = nil

    var body: some View {
        HStack(spacing: 5) {
            if let leading { leading }
            Text(label)
                .font(.system(size: 11.5, weight: .medium))
        }
        .foregroundStyle(textColor)
        .padding(.horizontal, 8)
        .frame(height: 22)
        .background(background)
        .overlay(border)
        .clipShape(Capsule())
    }

    private var textColor: Color {
        switch style {
        case .neutral: return .ink700
        case .ok:      return .bastionOk
        case .warn:    return .bastionWarn
        case .bad:     return .bastionBad
        case .accent:  return .bastionAccentDeep
        case .outline: return .ink700
        }
    }

    @ViewBuilder
    private var background: some View {
        switch style {
        case .neutral: Capsule().fill(Color.ink100)
        case .ok:      Capsule().fill(Color.bastionOkSoft)
        case .warn:    Capsule().fill(Color.bastionWarnSoft)
        case .bad:     Capsule().fill(Color.bastionBadSoft)
        case .accent:  Capsule().fill(Color.bastionAccentSoft)
        case .outline: Capsule().fill(Color.clear)
        }
    }

    @ViewBuilder
    private var border: some View {
        if style == .outline {
            Capsule().strokeBorder(Color.ink200, lineWidth: 1)
        }
    }
}

nonisolated struct RequestModeChipPresentation: Equatable, Sendable {
    let label: String
    let style: BastionChip.Style
    let statusDot: StatusDot.State
    let help: String

    static func make(mode: RequestExecutionMode) -> RequestModeChipPresentation {
        RequestModeChipPresentation(
            label: mode.label,
            style: mode == .approveAndSend ? .accent : .outline,
            statusDot: mode == .approveAndSend ? .warn : .idle,
            help: mode.detail
        )
    }
}

struct RequestModeChip: View {
    let mode: RequestExecutionMode

    var body: some View {
        let presentation = RequestModeChipPresentation.make(mode: mode)
        BastionChip(
            label: presentation.label,
            style: presentation.style,
            leading: AnyView(StatusDot(state: presentation.statusDot, size: 8))
        )
        .help(presentation.help)
    }
}

// MARK: - Status dot

struct StatusDot: View {
    enum State: Equatable, Sendable {
        case ok, warn, bad, idle

        var symbolName: String? {
            switch self {
            case .ok:   return "checkmark"
            case .warn: return "exclamationmark"
            case .bad:  return "xmark"
            case .idle: return nil
            }
        }

        var accessibilityLabel: String {
            switch self {
            case .ok:   return "Status: ok"
            case .warn: return "Status: warning"
            case .bad:  return "Status: error"
            case .idle: return "Status: idle"
            }
        }
    }

    let state: State
    /// Requested diameter. Floored at 8pt — a 5–7pt dot is below the
    /// click-target minimum and indistinguishable for color-blind users
    /// without the inset glyph.
    var size: CGFloat = 8

    private var resolvedSize: CGFloat { max(size, 8) }

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: resolvedSize, height: resolvedSize)
            .overlay(
                Circle()
                    .stroke(softColor, lineWidth: 3)
            )
            .overlay(glyph)
            .accessibilityLabel(Text(stateLabel))
    }

    @ViewBuilder
    private var glyph: some View {
        // Shape redundancy with color: SF Symbol on top of the dot fill.
        // Skipped for `idle` (no useful shape) and for very small dots
        // where the symbol would not render legibly.
        if let symbol = state.symbolName, resolvedSize >= 8 {
            Image(systemName: symbol)
                .font(.system(size: resolvedSize * 0.7, weight: .bold))
                .foregroundStyle(Color.paper)
        }
    }

    private var color: Color {
        switch state {
        case .ok:   return .bastionOk
        case .warn: return .bastionWarn
        case .bad:  return .bastionBad
        case .idle: return .ink300
        }
    }

    private var softColor: Color {
        switch state {
        case .ok:   return .bastionOkSoft
        case .warn: return .bastionWarnSoft
        case .bad:  return .bastionBadSoft
        case .idle: return .clear
        }
    }

    private var stateLabel: String { state.accessibilityLabel }
}

// MARK: - Pulse dot

struct PulseDot: View {
    var color: Color = .bastionOk
    @State private var scale: CGFloat = 1.0
    @State private var opacity: Double = 0.45

    var body: some View {
        ZStack {
            Circle()
                .fill(color)
                .opacity(opacity)
                .scaleEffect(scale)
            Circle()
                .fill(color)
                .frame(width: 4, height: 4)
        }
        .frame(width: 8, height: 8)
        .onAppear {
            withAnimation(.easeOut(duration: 1.6).repeatForever(autoreverses: false)) {
                scale = 2.6
                opacity = 0
            }
        }
    }
}

// MARK: - Icons (no SF symbols dependency where the design specifies a custom glyph)

struct ShieldGlyph: View {
    var size: CGFloat = 16
    var color: Color = .ink900
    var filled: Bool = false

    var body: some View {
        ShieldShape()
            .stroke(color, style: StrokeStyle(lineWidth: 1.4, lineJoin: .round))
            .background(
                filled ? AnyView(ShieldShape().fill(color)) : AnyView(EmptyView())
            )
            .frame(width: size, height: size)
    }
}

private struct ShieldShape: Shape {
    func path(in rect: CGRect) -> Path {
        var p = Path()
        let s = rect.width / 16
        p.move(to: CGPoint(x: 8 * s, y: 1.5 * s))
        p.addLine(to: CGPoint(x: 13.5 * s, y: 3.5 * s))
        p.addLine(to: CGPoint(x: 13.5 * s, y: 8 * s))
        p.addCurve(to: CGPoint(x: 8 * s, y: 14.5 * s),
                   control1: CGPoint(x: 13.5 * s, y: 11.5 * s),
                   control2: CGPoint(x: 8 * s, y: 14.5 * s))
        p.addCurve(to: CGPoint(x: 2.5 * s, y: 8 * s),
                   control1: CGPoint(x: 8 * s, y: 14.5 * s),
                   control2: CGPoint(x: 2.5 * s, y: 11.5 * s))
        p.addLine(to: CGPoint(x: 2.5 * s, y: 3.5 * s))
        p.closeSubpath()
        return p
    }
}

struct LockGlyph: View {
    var size: CGFloat = 14
    var color: Color = .ink500

    var body: some View {
        Canvas { ctx, _ in
            let s = size / 14
            let body = Path(roundedRect: CGRect(x: 2.5 * s, y: 6.5 * s, width: 9 * s, height: 6.5 * s), cornerRadius: 1.5 * s)
            ctx.stroke(body, with: .color(color), lineWidth: 1.3)
            var arch = Path()
            arch.move(to: CGPoint(x: 4.5 * s, y: 6.5 * s))
            arch.addLine(to: CGPoint(x: 4.5 * s, y: 4.5 * s))
            arch.addQuadCurve(to: CGPoint(x: 9.5 * s, y: 4.5 * s), control: CGPoint(x: 7.0 * s, y: 1.5 * s))
            arch.addLine(to: CGPoint(x: 9.5 * s, y: 6.5 * s))
            ctx.stroke(arch, with: .color(color), style: StrokeStyle(lineWidth: 1.3, lineCap: .round))
        }
        .frame(width: size, height: size)
    }
}

struct ChevronRightGlyph: View {
    var size: CGFloat = 12
    var color: Color = .ink400

    var body: some View {
        Canvas { ctx, _ in
            var p = Path()
            let s = size / 12
            p.move(to: CGPoint(x: 4.5 * s, y: 3 * s))
            p.addLine(to: CGPoint(x: 7.5 * s, y: 6 * s))
            p.addLine(to: CGPoint(x: 4.5 * s, y: 9 * s))
            ctx.stroke(p, with: .color(color), style: StrokeStyle(lineWidth: 1.4, lineCap: .round, lineJoin: .round))
        }
        .frame(width: size, height: size)
    }
}

struct CheckGlyph: View {
    var size: CGFloat = 12
    var color: Color = .bastionOk

    var body: some View {
        Canvas { ctx, _ in
            var p = Path()
            let s = size / 12
            p.move(to: CGPoint(x: 2.5 * s, y: 6.5 * s))
            p.addLine(to: CGPoint(x: 5 * s, y: 9 * s))
            p.addLine(to: CGPoint(x: 9.5 * s, y: 3.5 * s))
            ctx.stroke(p, with: .color(color), style: StrokeStyle(lineWidth: 1.6, lineCap: .round, lineJoin: .round))
        }
        .frame(width: size, height: size)
    }
}

struct CloseGlyph: View {
    var size: CGFloat = 12
    var color: Color = .ink500

    var body: some View {
        Canvas { ctx, _ in
            let s = size / 12
            var p = Path()
            p.move(to: CGPoint(x: 3 * s, y: 3 * s))
            p.addLine(to: CGPoint(x: 9 * s, y: 9 * s))
            p.move(to: CGPoint(x: 9 * s, y: 3 * s))
            p.addLine(to: CGPoint(x: 3 * s, y: 9 * s))
            ctx.stroke(p, with: .color(color), style: StrokeStyle(lineWidth: 1.5, lineCap: .round))
        }
        .frame(width: size, height: size)
    }
}

// MARK: - TouchID glyph

struct TouchIDGlyph: View {
    var size: CGFloat = 32
    var pulsing: Bool = false
    @State private var scale: CGFloat = 1.0

    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 7)
                .fill(Color.ink900)
            Canvas { ctx, _ in
                let s = (size * 0.55) / 16
                let cx = size / 2 - (size * 0.55) / 2
                let cy = size / 2 - (size * 0.55) / 2
                func arc(_ from: CGPoint, _ control: CGPoint, _ to: CGPoint) -> Path {
                    var p = Path()
                    p.move(to: CGPoint(x: from.x * s + cx, y: from.y * s + cy))
                    p.addQuadCurve(to: CGPoint(x: to.x * s + cx, y: to.y * s + cy),
                                   control: CGPoint(x: control.x * s + cx, y: control.y * s + cy))
                    return p
                }
                let strokeStyle = StrokeStyle(lineWidth: 1.2, lineCap: .round)
                ctx.stroke(arc(.init(x: 2, y: 8), .init(x: 8, y: 2), .init(x: 14, y: 8)),
                           with: .color(.paper), style: strokeStyle)
                ctx.stroke(arc(.init(x: 3.5, y: 9.5), .init(x: 8, y: 4), .init(x: 12.5, y: 9.5)),
                           with: .color(.paper), style: strokeStyle)
                ctx.stroke(arc(.init(x: 5.5, y: 11), .init(x: 8, y: 6.5), .init(x: 10.5, y: 11)),
                           with: .color(.paper), style: strokeStyle)
                ctx.stroke(arc(.init(x: 7, y: 12.5), .init(x: 8, y: 10), .init(x: 9, y: 12.5)),
                           with: .color(.paper), style: strokeStyle)
            }
        }
        .frame(width: size, height: size)
        .scaleEffect(scale)
        .shadow(color: pulsing ? Color.bastionAccent.opacity(0.18) : .clear,
                radius: pulsing ? 8 * scale : 0)
        .onAppear {
            guard pulsing else { return }
            withAnimation(.easeInOut(duration: 0.7).repeatForever(autoreverses: true)) {
                scale = 1.03
            }
        }
    }
}

// MARK: - Card container

struct BastionCard<Content: View>: View {
    var padding: CGFloat = 18
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                RoundedRectangle(cornerRadius: BastionTokens.radiusLarge)
                    .fill(Color.paper)
                    .overlay(
                        RoundedRectangle(cornerRadius: BastionTokens.radiusLarge)
                            .strokeBorder(Color.ink150, lineWidth: 1)
                    )
            )
    }
}

// MARK: - Key/Value row

struct KVRow<Value: View>: View {
    let key: String
    var keyWidth: CGFloat = 100
    @ViewBuilder let value: () -> Value

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(key)
                .font(.system(size: 12))
                .foregroundStyle(Color.ink500)
                .frame(width: keyWidth, alignment: .leading)
            value()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }
}

// MARK: - Bastion-styled buttons

enum BastionButtonStyleKind: Equatable, Sendable { case `default`, primary, danger, ghost }

struct BastionButtonStyle: ButtonStyle {
    var kind: BastionButtonStyleKind = .default
    var size: ControlSize = .regular

    func makeBody(configuration: Configuration) -> some View {
        let small = size == .small
        configuration.label
            .font(.system(size: small ? 12 : 13, weight: .medium))
            .padding(.horizontal, small ? 10 : 14)
            .padding(.vertical, small ? 4 : 7)
            .foregroundStyle(foreground)
            .background(
                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                    .fill(background(pressed: configuration.isPressed))
            )
            .overlay(
                RoundedRectangle(cornerRadius: BastionTokens.radiusMedium)
                    .strokeBorder(borderColor, lineWidth: kind == .ghost ? 0 : 1)
            )
            .scaleEffect(configuration.isPressed ? 0.99 : 1.0)
            .animation(.easeOut(duration: 0.06), value: configuration.isPressed)
    }

    private var foreground: Color {
        switch kind {
        case .default: return .ink900
        case .primary: return .paper
        case .danger:  return .paper
        case .ghost:   return .ink600
        }
    }

    private func background(pressed: Bool) -> Color {
        switch kind {
        case .default: return pressed ? .ink100 : .paper
        case .primary: return pressed ? .ink800 : .ink900
        case .danger:  return pressed ? .bastionBad.opacity(0.85) : .bastionBad
        case .ghost:   return pressed ? .ink100 : .clear
        }
    }

    private var borderColor: Color {
        switch kind {
        case .default: return .ink200
        case .primary: return .ink900
        case .danger:  return .bastionBad
        case .ghost:   return .clear
        }
    }
}

extension View {
    func bastionButton(_ kind: BastionButtonStyleKind = .default, size: ControlSize = .regular) -> some View {
        self.buttonStyle(BastionButtonStyle(kind: kind, size: size))
    }
}

// MARK: - Section divider

struct BastionDivider: View {
    var body: some View {
        Rectangle()
            .fill(Color.ink150)
            .frame(height: 1)
    }
}

// MARK: - Panel header

/// Shared 18pt title + 12pt subtitle pattern used at the top of every Settings
/// panel. Standardises padding (top:18 leading:28 bottom:14 trailing:28) and
/// ensures consistent typography. Optional trailing slot for an action button.
struct BastionPanelHeader<Trailing: View>: View {
    let title: String
    var subtitle: String? = nil
    @ViewBuilder let trailing: () -> Trailing

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            VStack(alignment: .leading, spacing: 4) {
                Text(title)
                    .font(.system(size: 18, weight: .semibold))
                    .kerning(-0.36)
                if let subtitle, !subtitle.isEmpty {
                    Text(subtitle)
                        .font(.system(size: 12))
                        .foregroundStyle(Color.ink500)
                }
            }
            Spacer()
            trailing()
        }
        .padding(EdgeInsets(top: 18, leading: 28, bottom: 14, trailing: 28))
    }
}

extension BastionPanelHeader where Trailing == EmptyView {
    init(title: String, subtitle: String? = nil) {
        self.init(title: title, subtitle: subtitle, trailing: { EmptyView() })
    }
}

/// Standard panel content padding (matches the panel header so cards align
/// with the title's leading edge). Use when wrapping a panel body in a
/// ScrollView so all panels share whitespace rules.
extension EdgeInsets {
    static let bastionPanelContent = EdgeInsets(top: 18, leading: 28, bottom: 28, trailing: 28)
}

// MARK: - Section label
//
// Used everywhere a small "section header" caption was needed — sidebar section
// titles, audit column headers, "Views" / "Code" / "Risk signals" labels, etc.
// The previous 10.5pt + uppercase + kerning(0.6) treatment was stylized below
// macOS comfortable read size; bumped to 11pt regular case to match Finder/Mail.

struct BastionSectionLabel: View {
    let text: String
    var body: some View {
        Text(text)
            .font(.system(size: 11, weight: .semibold))
            .foregroundStyle(Color.ink500)
    }
}

import SwiftUI

// Bastion design tokens — calm, technical, native-mac feel.
// Mirrors tokens.css from the design bundle. All colors track system appearance.

enum BastionTokens {
    // Window / surface radii
    static let radiusSmall: CGFloat = 6
    static let radiusMedium: CGFloat = 8
    static let radiusLarge: CGFloat = 12
    static let radiusXL: CGFloat = 16
    static let windowRadius: CGFloat = 14

    static let monoFont = Font.system(.body, design: .monospaced)
}

// MARK: - Font scale
//
// Previously the codebase used 9 distinct font sizes (10.5 / 11 / 11.5 / 12 /
// 12.5 / 13 / 14 / 17 / 18). macOS conventionally uses 4–5 (mini=10, secondary
// =11, body=13, title=15-17). Half-point variants are indistinguishable to
// readers and create accidental visual noise. New sites should use a token.

enum BastionFont {
    /// 11pt — secondary captions, "X of Y" counts, hint lines.
    case caption
    /// 12pt — body labels and form field labels.
    case label
    /// 13pt — primary body text.
    case body
    /// 17pt — panel and window titles.
    case title
    /// 24pt — dashboard hero numerals.
    case large

    var size: CGFloat {
        switch self {
        case .caption: return 11
        case .label:   return 12
        case .body:    return 13
        case .title:   return 17
        case .large:   return 24
        }
    }

    func font(weight: Font.Weight = .regular, design: Font.Design = .default) -> Font {
        .system(size: size, weight: weight, design: design)
    }
}

extension Text {
    /// Apply a Bastion font token. Equivalent to `.font(.system(size: token.size, weight: weight, design: design))`.
    func bastionFont(_ token: BastionFont, weight: Font.Weight = .regular, design: Font.Design = .default) -> Text {
        font(token.font(weight: weight, design: design))
    }
}

// MARK: - Spacing scale
//
// The codebase had ~130 hardcoded padding values clustered around 4/6/8/10/12
// /14/16/18/22/24/28 — every fix-the-spacing PR picked new arbitrary numbers.
// This is the canonical 5-step scale; new sites should use a token instead of
// a literal so the spacing rhythm stays consistent across screens.

enum BastionSpacing: CGFloat {
    case xs = 4
    case s = 8
    case m = 12
    case l = 16
    case xl = 24

    var value: CGFloat { rawValue }
}

extension View {
    /// Apply token-scaled padding. Prefer this over `.padding(<literal>)`.
    func padding(_ token: BastionSpacing, _ edges: Edge.Set = .all) -> some View {
        padding(edges, token.value)
    }

    /// Apply token-scaled padding with separate vertical and horizontal values.
    /// Common pattern: `.padding(vertical: .s, horizontal: .m)`.
    func padding(vertical: BastionSpacing, horizontal: BastionSpacing) -> some View {
        padding(.vertical, vertical.value)
            .padding(.horizontal, horizontal.value)
    }
}

// MARK: - Adaptive color helpers

private func adaptive(_ light: Color, _ dark: Color) -> Color {
    Color(NSColor(name: nil) { appearance in
        let isDark = appearance.bestMatch(from: [.darkAqua, .vibrantDark, .accessibilityHighContrastDarkAqua]) != nil
        return NSColor(isDark ? dark : light)
    })
}

private func hex(_ rgb: UInt32, alpha: Double = 1.0) -> Color {
    let r = Double((rgb >> 16) & 0xff) / 255
    let g = Double((rgb >> 8) & 0xff) / 255
    let b = Double(rgb & 0xff) / 255
    return Color(red: r, green: g, blue: b, opacity: alpha)
}

extension Color {
    // Ink scale — body text → backgrounds. Inverts for dark mode.
    static let ink900 = adaptive(hex(0x0b0d10), hex(0xf4f5f7))
    static let ink800 = adaptive(hex(0x16191e), hex(0xe4e6ea))
    static let ink700 = adaptive(hex(0x22262d), hex(0xc8ccd2))
    static let ink600 = adaptive(hex(0x353a43), hex(0x9aa0aa))
    static let ink500 = adaptive(hex(0x555b65), hex(0x777e88))
    static let ink400 = adaptive(hex(0x7a818c), hex(0x565c66))
    static let ink300 = adaptive(hex(0xa3a9b3), hex(0x3c424b))
    static let ink200 = adaptive(hex(0xcdd1d8), hex(0x2a2f37))
    static let ink150 = adaptive(hex(0xe2e5ea), hex(0x20242b))
    static let ink100 = adaptive(hex(0xeef0f3), hex(0x181b21))
    static let ink50  = adaptive(hex(0xf6f7f9), hex(0x14171c))
    static let paper  = adaptive(hex(0xffffff), hex(0x1c1f25))

    // Single accent — quiet indigo for "armed/active"
    static let bastionAccent     = adaptive(hex(0x4d6bff), hex(0x4d6bff))
    static let bastionAccentSoft = adaptive(hex(0xe7ecff), hex(0x1e2547))
    static let bastionAccentDeep = adaptive(hex(0x2c46d6), hex(0x9bb0ff))

    // Status — restrained, not saturated
    static let bastionOk        = adaptive(hex(0x2c8a5a), hex(0x4cb37e))
    static let bastionOkSoft    = adaptive(hex(0xe3f3eb), hex(0x163525))
    static let bastionWarn      = adaptive(hex(0xb06a00), hex(0xd99a3d))
    static let bastionWarnSoft  = adaptive(hex(0xfbeed3), hex(0x3a2a0c))
    static let bastionBad       = adaptive(hex(0xb03a2e), hex(0xe07065))
    static let bastionBadSoft   = adaptive(hex(0xf7e3df), hex(0x3a1e1a))

    // Desktop / window background gradient
    static let bastionDesktopTop    = adaptive(hex(0xe8edf4), hex(0x14181f))
    static let bastionDesktopBottom = adaptive(hex(0xd6dde7), hex(0x20252e))
}

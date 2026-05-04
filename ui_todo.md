# UI TODO — audit findings

_Last reviewed: 2026-05-04. Captured after the audit-history header investigation; this is the working list of what's wrong with the current UI in priority order._

## Legend

- **P0** — actively broken or misleading; users will hit it.
- **P1** — same family of bugs as one we've already fixed; deferred fix risks future regression.
- **P2** — feels "off" because we're reimplementing native macOS primitives.
- **P3** — typography / spacing sprawl; cumulative quality drag.
- **P4** — dead code, orphans, low-cost cleanup.
- **P5** — accessibility long-tail.

---

## P0 · actively broken / misleading

### "+ Save" / "+ Save current" button in audit history is bait
- `AuditHistoryView.swift:82` — comment literally reads `// backend gap — saved views persistence not implemented`.
- Clicking does nothing — no toast, no error, no feedback.
- **Fix**: remove the button entirely until we implement `SavedView` persistence. Keep the `SavedView` enum + the four built-in chips.

### "Test approval" / "Test violation" buttons ship in release builds
- `RulesSettingsView.swift:634-636`. Pure dev surface (`SigningRequestPreviewFactory.policyReview()` / `.ruleOverride()`).
- No `#if DEBUG` gate. Real users see two prominent buttons in their settings header that summon fake approval popups.
- **Fix**: wrap the buttons + the supporting state in `#if DEBUG`. Move the preview factory to a debug-only target if possible.

### "Wallet Groups…" footer item in the menu bar is a fake link
- `MenuBarPanelView.swift:428` — calls `openSettings()` with no destination. Same handler as the "Settings…" item right above it.
- **Fix**: deep-link to the wallet-groups section by setting `selection` on RulesSettingsView, OR remove the entry until deep-link plumbing exists.

---

## P1 · layout fragility (same family as the audit-history fix we just shipped)

The `LazyVStack` swap landed for one site. Same `ScrollView { … }` pattern with potentially-short content exists in seven other places. Three of them use `LazyVGrid` with `adaptive(.minimum:)` which has its own quirks on macOS.

- `RulesSettingsView.swift:758, 797, 1288, 1314` — `LazyVGrid` for cap tiles and template grids
- `SigningRequestView.swift:632` — `LazyVGrid` for risk-signal chips ("poor man's wrapping flow")
- `AgentSessionView.swift:362` — Grant Session sheet ScrollView
- `PolicySimulatorView.swift:21` — main scroll area
- `RulesSettingsView.swift:1192, 1287, 1401, 1501, 1562` — sub-panel scroll areas

The centering pathology only triggers when content is shorter than the scroll area, i.e. exactly what happens on a fresh install (empty address book, no rate limits, blank policy simulator).

**Fix**: defensive `.frame(maxWidth: .infinity, alignment: .topLeading)` on each inner stack inside a `ScrollView`. Alternative: write a `BastionScrollColumn` wrapper view that bakes this in.

---

## P2 · native macOS divergence

The redesign reimplements primitives macOS already provides. Cumulatively this reads as "off" even when each individual divergence is small.

| Custom thing | macOS-native equivalent | What we lose |
|---|---|---|
| `FilterDropdown` | `Picker(.menu)` | Native popover style + keyboard nav |
| `BastionCard` | `GroupBox` | Adaptive bg + a11y |
| Sidebar `VStack` of buttons | `NavigationSplitView` + `Section { Button }` with `.listStyle(.sidebar)` | Hover, selection, drag-reorder, keyboard up/down |
| `bastionButton(.primary, .danger, .ghost, .default)` | `.borderedProminent`, `.bordered`, `.borderless` | Focus rings, HIG conformance |
| Audit-history view chips | `Picker(.segmented)` | Keyboard nav |

Not advocating a wholesale redo. But sidebar → `NavigationSplitView`, `BastionCard` → `GroupBox`, button styles → bordered/borderless would carry a lot of weight.

---

## P3 · typography and spacing sprawl

### Font size proliferation
9 distinct font sizes in active use: **10.5, 11, 11.5, 12, 12.5, 13, 14, 17, 18**. macOS conventionally uses 4–5 (mini=10, secondary=11, body=13, title=15-17). 11 vs 11.5 vs 12 vs 12.5 are all "small label, slightly different" — readers can't tell them apart anyway.

**Fix**: lock down a `BastionFont` enum with `.caption (11)`, `.body (13)`, `.label (12)`, `.title (17)`, `.large (24)`. Migrate call sites incrementally.

### Padding sprawl
133 padding sites with hardcoded numbers (53 `EdgeInsets(...)` + 80 `.padding(...)`). Values cluster at 4, 6, 8, 10, 12, 14, 16, 18, 22, 24, 28 — at least 10 different units, no scale token. Every fix-the-padding round has been picking new arbitrary numbers.

**Fix**: `BastionSpacing.xs (4)`, `.s (8)`, `.m (12)`, `.l (16)`, `.xl (24)`. Replace `.padding(EdgeInsets(top: 8, leading: 12, bottom: 8, trailing: 12))` with `.padding(.s)`.

### Stylized small caps everywhere
Sidebar section headers + audit column headers both use `10.5pt + uppercase + tracking 0.6`. Below comfortable read size. Real Finder / Mail use 11pt regular case for column headers.

**Fix**: extract a single `BastionSectionLabel` atom and bump to 11pt regular case.

### Status dots are too small
5–7pt circles carrying ok/warn/bad/idle meaning. Below click-target minimum and indistinguishable for color-blind users (no shape variation).

**Fix**: bump to 8pt minimum, add shape glyphs (✓ / ! / × / ·) inside for redundancy with color.

---

## P4 · dead code and orphans

- **`MacTrafficLights`** (`BastionAtoms.swift:631`) — defined but no longer called anywhere. Pure cruft after the title-bar cleanup.
- **`SigningRequestPreviewFactory`** ships in release builds even though only Test approval/Test violation buttons (which are themselves dev-only) ever invoke it. Move behind `#if DEBUG`.
- **`kerning(0.6) + uppercase + 10.5pt`** style appears in two places — collapse into a single `BastionSectionLabel` atom.

---

## P5 · accessibility

Zero `accessibilityLabel`, `accessibilityHint`, or `accessibilityValue` modifiers in the entire UI directory. VoiceOver users get raw view-tree readings — chains rendered as "diamond" / "circle" symbols, status carried solely by color. The signing approval popup (the most critical surface) has no a11y annotations at all.

**Fix**: pass over each surface and label every actionable element. The signing popup, settings sidebar, and audit row are the highest-impact starting points.

---

## Audit-history header investigation log

Multiple PRs targeted the perceived header height, none of them landed:
- **#38** — removed fake `MacTrafficLights` title row + duplicate "Bastion · Audit history" label.
- **#42** — column header padding 8→4, filter row 12→6, saved-views 8→6.
- **#43** — `AuditRow` padding 14→8, removed divider between `columnHeader` and `rowsList`.
- **#44** — defensive top-anchor (`.frame(maxHeight: .infinity, alignment: .top)`) on the ScrollView.
- **#45** — `LazyVStack` → plain `VStack`; suppressed bogus `signSuccess` audit entry; humanized sparse-record fallbacks.

Local-only edits (uncommitted) further switched `ScrollView+VStack` to `List(.plain)`, swapped `NSHostingView` → `NSHostingController`, added defensive `.frame(maxHeight: .infinity, alignment: .top)` everywhere, killed `listRowInsets`/`listRowSeparator`/`scrollContentBackground`, lowered `defaultMinListRowHeight` to 1. **Still tall.**

Every padding/spacing change, every container-swap, every alignment hint — none of them moved the visual gap. Because none of them were the cause.

## Root cause (after ultrathink)

**It's `.fullSizeContentView` in the window's style mask.** The header isn't tall — empty space at the top of the scroll content is being inserted at the AppKit layer, not the SwiftUI layer. Every padding number we've changed is downstream of the actual bug.

Layout chain:

1. **`AuditHistoryWindowManager.swift:24`** — `styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView]`.
   `.fullSizeContentView` makes the window's `contentView` fill the entire window, **including the area under the title bar**. The title bar then overlays the contentView at the top.
2. **`NSHostingController` lays out SwiftUI inside that full-size content view.** SwiftUI sees a 1180×760 frame.
3. **SwiftUI applies a safe-area inset matching the title bar.** Because the contentView extends under the title bar, AppKit reports the title bar's intrusion as a safe-area inset (~28pt top). SwiftUI views that don't `.ignoresSafeArea()` are inset by 28pt. → `savedViewsRow` correctly renders at `y ≈ 28pt`, flush against the title bar bottom. **This part is fine.**
4. **Inside the `List` (and prior `ScrollView`), the wrapped `NSScrollView` applies its OWN content inset.** When a `NSScrollView` lives in a window with `.fullSizeContentView`, `automaticallyAdjustsScrollerInsets` adds an inset matching the window's title bar to prevent rows scrolling under it.
5. **Double-inset.** The List's NSScrollView is already nested inside the SwiftUI VStack that's been pushed down 28pt by safe area. The title bar isn't anywhere near the List's frame. But the NSScrollView doesn't know that — it sees `.fullSizeContentView` on the window and adds its own ~28pt inset at the top of its scroll content.

That 28pt is the empty band above the column header. Sometimes it stacks higher (filter row gray block ends, then 28pt safe-area inset on the inner table area, then List's own 28pt insetting its rows further down) — which is why the screenshot looks like ~60-80pt of nothing.

Same pathology applies to the bottom: NSScrollView adds matching inset there, leaving empty space below the rows.

**Why padding tweaks didn't help.** Every one of #42 / #43 / #44 / #45 was adjusting SwiftUI-layer values (`.padding(...)`, `LazyVStack` vs `VStack`, `.frame(alignment:)`). The empty band lives below the SwiftUI layer — it's `NSScrollView.contentInsets`. SwiftUI primitives don't see it, can't shrink it.

## Fix

**Drop `.fullSizeContentView` from the window's style mask.**

```diff
 styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
+styleMask: [.titled, .closable, .miniaturizable, .resizable],
```

This is the right call regardless of the bug:

- The v2 mock specified `.fullSizeContentView` because it drew a custom in-content title bar (`MacTrafficLights` + "Bastion · Audit history" label). PR #38 removed that fake title bar entirely. The reason the flag was set no longer exists.
- The opaque OS title bar above separated content is the macOS-native arrangement (Finder, Mail, Audit history in Console.app, etc.).
- It removes the safe-area double-counting at the AppKit layer. SwiftUI sees a clean rectangular frame with no title-bar safe area to negotiate.
- All the defensive `.frame(maxHeight: .infinity, alignment: .top)` annotations the user added locally become unnecessary — they were patching for the AppKit inset, but now there's no AppKit inset to patch.

Settings is unaffected — SwiftUI's `Settings { ... }` scene already uses a standard window (no full-size content view).

## Cleanup once `.fullSizeContentView` is dropped

The local edits in `AuditHistoryView.swift` were patching around the AppKit issue, not the actual layout. They can be reverted to a simpler shape:

- Drop `Color.paper.ignoresSafeArea()` background — no safe area to ignore.
- Drop the multiple `.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)` defensive wraps.
- Drop the `tableArea` indirection.
- Keep `List(.plain)` if we want the macOS-native list behavior, OR revert to `ScrollView+VStack` if we want the simpler hand-rolled rows. Either works once the inset bug is gone.

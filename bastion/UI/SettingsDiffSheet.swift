import SwiftUI

// "Review changes before saving" sheet — shown when the operator clicks
// Review diff in the unsaved-changes save bar. Pure presentation; the diff
// computation lives in SettingsDiffPresentation.

nonisolated struct DiffLine: Identifiable, Hashable, Sendable {
    let id = UUID()
    let removed: String
    let added: String
}

struct DiffSheet: View {
    let diffLines: [DiffLine]
    var isSaving: Bool = false
    let onCancel: () -> Void
    let onSave: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            heading
            BastionDivider()
            content
            BastionDivider()
            actions
        }
        .frame(width: 520)
        .background(Color.paper)
    }

    private var heading: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("Review changes before saving")
                .font(.system(size: 14, weight: .semibold))
            Text("Active agents will see these changes on their next request.")
                .font(.system(size: 12))
                .foregroundStyle(Color.ink500)
        }
        .padding(EdgeInsets(top: 16, leading: 18, bottom: 16, trailing: 18))
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    @ViewBuilder
    private var content: some View {
        VStack(spacing: 2) {
            if diffLines.isEmpty {
                Text("No semantic changes detected.")
                    .font(.system(size: 12))
                    .foregroundStyle(Color.ink500)
                    .padding(.vertical, 14)
            }
            ForEach(diffLines) { line in
                diffRow(sign: "-", text: line.removed, isAdd: false)
                diffRow(sign: "+", text: line.added, isAdd: true)
            }
        }
        .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
    }

    private var actions: some View {
        HStack {
            Spacer()
            Button("Cancel", action: onCancel)
                .bastionButton(.default)
                .disabled(isSaving)
            Button(isSaving ? "Saving…" : "Save changes", action: onSave)
                .bastionButton(.primary)
                .disabled(isSaving)
        }
        .padding(EdgeInsets(top: 12, leading: 18, bottom: 12, trailing: 18))
        .background(Color.ink50)
    }

    private func diffRow(sign: String, text: String, isAdd: Bool) -> some View {
        HStack {
            Text(sign).font(.system(size: 12, weight: .bold, design: .monospaced))
            Text(text).font(.system(size: 12, design: .monospaced))
            Spacer(minLength: 0)
        }
        .foregroundStyle(isAdd ? Color.bastionOk : Color.bastionBad)
        .padding(.horizontal, 10).padding(.vertical, 6)
        .background(
            RoundedRectangle(cornerRadius: 4)
                .fill((isAdd ? Color.bastionOkSoft : Color.bastionBadSoft).opacity(0.7))
        )
    }
}

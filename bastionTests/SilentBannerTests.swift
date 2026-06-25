import AppKit
import Testing
@testable import bastion

@Suite("Silent Banner")
struct SilentBannerTests {
    @Test("silent receipt banner uses non-activating top-right presentation")
    func presentationContract() {
        #expect(SilentBannerPresentation.panelWidth(fittingWidth: 280) == 320)
        #expect(SilentBannerPresentation.panelWidth(fittingWidth: 360) == 360)

        #expect(SilentBannerPresentation.styleMask.contains(.borderless))
        #expect(SilentBannerPresentation.styleMask.contains(.nonactivatingPanel))
        #expect(SilentBannerPresentation.styleMask.contains(.fullSizeContentView))
        #expect(SilentBannerPresentation.level == .statusBar)
        #expect(SilentBannerPresentation.collectionBehavior.contains(.moveToActiveSpace))
        #expect(SilentBannerPresentation.collectionBehavior.contains(.fullScreenAuxiliary))

        let origin = SilentBannerPresentation.panelOrigin(
            visibleFrame: NSRect(x: 100, y: 50, width: 1_200, height: 800),
            panelSize: NSSize(width: 320, height: 72)
        )

        #expect(origin.x == 964)
        #expect(origin.y == 766)
    }

    @Test("silent receipt banner auto-dismiss waits and honors cancellation")
    func autoDismissDelayDecision() async {
        let successRecorder = SilentBannerDelayRecorder()
        let shouldDismiss = await SilentBannerPresentation.shouldAutoDismissAfterDelay(
            duration: 4,
            sleep: { duration in
                await successRecorder.record(duration)
            }
        )

        #expect(shouldDismiss == true)
        #expect(await successRecorder.snapshot() == [4])

        let cancelledRecorder = SilentBannerDelayRecorder()
        let cancelledDismiss = await SilentBannerPresentation.shouldAutoDismissAfterDelay(
            duration: 2,
            sleep: { duration in
                await cancelledRecorder.record(duration)
                throw CancellationError()
            }
        )

        #expect(cancelledDismiss == false)
        #expect(await cancelledRecorder.snapshot() == [2])
    }
}

private actor SilentBannerDelayRecorder {
    private var durations: [TimeInterval] = []

    func record(_ duration: TimeInterval) {
        durations.append(duration)
    }

    func snapshot() -> [TimeInterval] {
        durations
    }
}

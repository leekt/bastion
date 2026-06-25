import Testing
@testable import bastion
import Foundation

// PR1 regression tests: every signing/submission path resolves the
// ZeroDev project ID through BundlerTrustResolver with the same precedence
// rule. App-config wins. Wire-supplied is fallback only when no config.
//
// Pinning this prevents the class of bug where one path trusts the agent's
// wire-supplied projectId (letting an agent redirect a sponsored UserOp
// through an attacker-controlled bundler) while another correctly picks
// the app-configured ID.

@Suite("Bundler trust resolver — precedence")
struct BundlerTrustResolverPrecedenceTests {

    private func makeConfig(projectId: String?) -> BastionConfig {
        var config = BastionConfig.default
        config.bundlerPreferences.zeroDevProjectId = projectId
        return config
    }

    @Test("Settings project ID input trims and clears blank values")
    func settingsProjectIdInputNormalization() {
        #expect(ZeroDevProjectIdInput.normalized(" zd_project_owner ") == "zd_project_owner")
        #expect(ZeroDevProjectIdInput.normalized("\nzd_project_owner\t") == "zd_project_owner")
        #expect(ZeroDevProjectIdInput.normalized("") == nil)
        #expect(ZeroDevProjectIdInput.normalized("   ") == nil)
    }

    @Test("Settings RPC chain draft validates and upserts endpoints")
    func settingsRPCChainDraftValidationAndUpsert() throws {
        let draft = ChainRPCPreferenceDraft(
            chainId: " 8453 ",
            rpcURL: " https://base.example.com/rpc?token=abc "
        )

        #expect(draft.validationMessage == nil)
        let preference = try #require(draft.makePreference())
        #expect(preference.chainId == 8453)
        #expect(preference.rpcURL == "https://base.example.com/rpc?token=abc")

        let seeded = BundlerPreferences(
            zeroDevProjectId: nil,
            chainRPCs: [ChainRPCPreference(chainId: 10, rpcURL: "https://optimism.example.com")]
        )
        var updated = ChainRPCPreferenceDraft.upsert(preference, into: seeded)
        #expect(updated.chainRPCs.map(\.chainId) == [10, 8453])

        let replacement = try #require(ChainRPCPreferenceDraft(
            chainId: "10",
            rpcURL: "http://localhost:8545"
        ).makePreference())
        updated = ChainRPCPreferenceDraft.upsert(replacement, into: updated)
        #expect(updated.chainRPCs.map(\.chainId) == [10, 8453])
        #expect(updated.chainRPCs.first?.rpcURL == "http://localhost:8545")

        let invalidChain = ChainRPCPreferenceDraft(chainId: "0", rpcURL: "https://rpc.example.com")
        #expect(invalidChain.validationMessage == ChainRPCPreferenceDraft.chainIdError)
        #expect(invalidChain.makePreference() == nil)

        let invalidScheme = ChainRPCPreferenceDraft(chainId: "1", rpcURL: "ftp://rpc.example.com")
        #expect(invalidScheme.validationMessage == ChainRPCPreferenceDraft.rpcURLError)
        #expect(invalidScheme.makePreference() == nil)

        let missingHost = ChainRPCPreferenceDraft(chainId: "1", rpcURL: "https://")
        #expect(missingHost.validationMessage == ChainRPCPreferenceDraft.rpcURLError)
        #expect(missingHost.makePreference() == nil)
    }

    @Test("RPC probe presentation labels state and guards duplicate probes")
    func rpcProbePresentationStateAndLabels() {
        let empty = RPCProbePresentation.make(isProbing: false, endpointCount: 0)
        #expect(empty.buttonTitle == "Probe now")
        #expect(empty.isButtonDisabled == true)

        let ready = RPCProbePresentation.make(isProbing: false, endpointCount: 2)
        #expect(ready.buttonTitle == "Probe now")
        #expect(ready.isButtonDisabled == false)

        let probing = RPCProbePresentation.make(isProbing: true, endpointCount: 2)
        #expect(probing.buttonTitle == "Probing…")
        #expect(probing.isButtonDisabled == true)

        #expect(RPCProbePresentation.status(for: nil) == .unknown)
        #expect(RPCProbePresentation.latencyLabel(nil) == "not probed")

        let latencySample = RPCHealthSample(
            chainId: 8453,
            status: .ok,
            latencyMs: 321,
            error: nil,
            probedAt: Date(timeIntervalSince1970: 0)
        )
        #expect(RPCProbePresentation.status(for: latencySample) == .ok)
        #expect(RPCProbePresentation.latencyLabel(latencySample) == "321ms")

        let errorSample = RPCHealthSample(
            chainId: 1,
            status: .bad,
            latencyMs: 42,
            error: "HTTP 500",
            probedAt: Date(timeIntervalSince1970: 0)
        )
        #expect(RPCProbePresentation.latencyLabel(errorSample) == "HTTP 500")

        let timeoutSample = RPCHealthSample(
            chainId: 10,
            status: .bad,
            latencyMs: nil,
            error: nil,
            probedAt: Date(timeIntervalSince1970: 0)
        )
        #expect(RPCProbePresentation.latencyLabel(timeoutSample) == "timeout")
    }

    @Test("RPC health monitor schedule does not probe again when sleep is cancelled")
    func rpcHealthMonitorScheduleStopsWhenSleepIsCancelled() async {
        let recorder = RPCProbeScheduleRecorder(cancelOnSleepAttempt: 1)

        await RPCHealthMonitor.runScheduledProbes(
            interval: RPCHealthMonitor.monitoringInterval,
            sleep: { interval in
                try await recorder.sleep(interval)
            },
            probe: {
                await recorder.probe()
            }
        )

        #expect(await recorder.probeCount == 1)
        #expect(await recorder.intervals == [RPCHealthMonitor.monitoringInterval])
    }

    @Test("App config wins over wire-supplied project ID")
    func configOverridesWire() throws {
        let config = makeConfig(projectId: "zd_project_owner")
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "zd_project_attacker",
            config: config
        )
        #expect(resolved.projectId == "zd_project_owner")
        #expect(resolved.source == .configOverrodeRequest)
    }

    @Test("Wire-supplied matches config — flagged as match, not override")
    func configMatchesWire() throws {
        let config = makeConfig(projectId: "zd_project_owner")
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "zd_project_owner",
            config: config
        )
        #expect(resolved.projectId == "zd_project_owner")
        #expect(resolved.source == .configMatchedRequest)
    }

    @Test("No config configured — wire-supplied is the fallback")
    func wireFallbackWhenConfigEmpty() throws {
        let config = makeConfig(projectId: nil)
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "zd_project_wire",
            config: config
        )
        #expect(resolved.projectId == "zd_project_wire")
        #expect(resolved.source == .requestFallback)
    }

    @Test("Whitespace-only config behaves as if unset")
    func whitespaceConfigTreatedAsUnset() throws {
        let config = makeConfig(projectId: "   ")
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "zd_project_wire",
            config: config
        )
        #expect(resolved.projectId == "zd_project_wire")
        #expect(resolved.source == .requestFallback)
    }

    @Test("Whitespace-only wire fallthrough still respects config")
    func whitespaceWireFallthroughUsesConfig() throws {
        let config = makeConfig(projectId: "zd_project_owner")
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "   ",
            config: config
        )
        #expect(resolved.projectId == "zd_project_owner")
        // Whitespace wire is treated as nil — config didn't override
        // anything; it was just used.
        #expect(resolved.source == .configOverrodeRequest)
    }

    @Test("Neither side configured — throws")
    func nothingConfiguredThrows() {
        let config = makeConfig(projectId: nil)
        #expect(throws: BastionError.self) {
            _ = try BundlerTrustResolver.resolveZeroDevProjectId(
                wireSupplied: nil,
                config: config
            )
        }
    }

    @Test("Both empty — throws")
    func bothEmptyThrows() {
        let config = makeConfig(projectId: "")
        #expect(throws: BastionError.self) {
            _ = try BundlerTrustResolver.resolveZeroDevProjectId(
                wireSupplied: "",
                config: config
            )
        }
    }

    // MARK: - Convenience overload (BundlerPreferences only)

    @Test("BundlerPreferences overload follows the same precedence")
    func preferencesOverloadMatches() throws {
        let prefs = BundlerPreferences(zeroDevProjectId: "zd_owner", chainRPCs: [])
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "zd_attacker",
            preferences: prefs
        )
        #expect(resolved.projectId == "zd_owner")
        #expect(resolved.source == .configOverrodeRequest)
    }

    @Test("BundlerPreferences overload — wire fallback")
    func preferencesOverloadWireFallback() throws {
        let prefs = BundlerPreferences(zeroDevProjectId: nil, chainRPCs: [])
        let resolved = try BundlerTrustResolver.resolveZeroDevProjectId(
            wireSupplied: "zd_wire",
            preferences: prefs
        )
        #expect(resolved.projectId == "zd_wire")
        #expect(resolved.source == .requestFallback)
    }
}

private actor RPCProbeScheduleRecorder {
    private let cancelOnSleepAttempt: Int
    private(set) var probeCount = 0
    private(set) var intervals: [Duration] = []

    init(cancelOnSleepAttempt: Int) {
        self.cancelOnSleepAttempt = cancelOnSleepAttempt
    }

    func probe() {
        probeCount += 1
    }

    func sleep(_ interval: Duration) throws {
        intervals.append(interval)
        if intervals.count >= cancelOnSleepAttempt {
            throw CancellationError()
        }
    }
}

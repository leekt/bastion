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

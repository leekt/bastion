import Foundation
import Security
import Testing
@testable import bastion

@Suite("XPC security")
struct XPCSecurityTests {
    @Test("Code-signing identifier wins over plist bundle identifier")
    func codeSigningIdentifierWinsOverPlistBundleIdentifier() {
        let signingInfo: [String: Any] = [
            kSecCodeInfoIdentifier as String: "com.example.signed-id",
            kSecCodeInfoPList as String: [
                "CFBundleIdentifier": "com.example.plist-id"
            ]
        ]

        #expect(XPCServer.bundleIdentifier(from: signingInfo) == "com.example.signed-id")
    }

    @Test("Plist bundle identifier is fallback only")
    func plistBundleIdentifierIsFallbackOnly() {
        let signingInfo: [String: Any] = [
            kSecCodeInfoPList as String: [
                "CFBundleIdentifier": "com.example.plist-id"
            ]
        ]

        #expect(XPCServer.bundleIdentifier(from: signingInfo) == "com.example.plist-id")
        #expect(XPCServer.bundleIdentifier(from: [:]) == nil)
    }

    @Test("Only Bastion team identifier is accepted")
    func onlyBastionTeamIdentifierIsAccepted() {
        #expect(XPCServer.isAllowedTeamIdentifier("926A27BQ7W") == true)
        #expect(XPCServer.isAllowedTeamIdentifier("OTHERTEAMID") == false)
        #expect(XPCServer.isAllowedTeamIdentifier(nil) == false)
    }

    @Test("Missing profile read message is actionable")
    func missingProfileReadMessageIsActionable() {
        #expect(XPCServer.missingClientProfileReadMessage == "Pair this client with Bastion before reading pubkey, rules, or state.")
        #expect(XPCServer.missingClientProfileReadMessage.contains("Pair this client"))
        #expect(XPCServer.missingClientProfileReadMessage.contains("pubkey, rules, or state"))
    }

    @Test("Pairing display inputs are trimmed and non-empty")
    func pairingDisplayInputsAreTrimmedAndNonEmpty() throws {
        let normalized = try #require(XPCServer.normalizedPairingDisplayInputs(
            bundleId: "  com.example.agent  ",
            processName: "  Example Agent  "
        ))
        #expect(normalized.bundleId == "com.example.agent")
        #expect(normalized.processName == "Example Agent")

        #expect(XPCServer.normalizedPairingDisplayInputs(
            bundleId: "  ",
            processName: "Example Agent"
        ) == nil)
        #expect(XPCServer.normalizedPairingDisplayInputs(
            bundleId: "com.example.agent",
            processName: "  "
        ) == nil)
        #expect(XPCServer.normalizedPairingDisplayInputs(
            bundleId: String(repeating: "a", count: 257),
            processName: "Example Agent"
        ) == nil)
        #expect(XPCServer.normalizedPairingDisplayInputs(
            bundleId: "com.example.agent",
            processName: String(repeating: "a", count: 257)
        ) == nil)
    }

    @Test("Client signing decision requires valid signature and Bastion team")
    func clientSigningDecisionRequiresValidSignatureAndBastionTeam() {
        let validBastionClient: [String: Any] = [
            kSecCodeInfoTeamIdentifier as String: "926A27BQ7W",
            kSecCodeInfoIdentifier as String: "com.example.client"
        ]
        let wrongTeamClient: [String: Any] = [
            kSecCodeInfoTeamIdentifier as String: "OTHERTEAMID",
            kSecCodeInfoIdentifier as String: "bastion-cli"
        ]

        #expect(XPCServer.isClientSigningInfoAllowed(
            validBastionClient,
            validityStatus: errSecSuccess,
            executablePath: nil,
            allowUntrustedDevSignature: false
        ) == true)
        #expect(XPCServer.isClientSigningInfoAllowed(
            validBastionClient,
            validityStatus: errSecInternalComponent,
            executablePath: nil,
            allowUntrustedDevSignature: false
        ) == false)
        #expect(XPCServer.isClientSigningInfoAllowed(
            wrongTeamClient,
            validityStatus: errSecSuccess,
            executablePath: "/Applications/bastion.app/Contents/MacOS/bastion-cli",
            allowUntrustedDevSignature: true
        ) == false)
    }

    @Test("Debug sidecar fallback requires untrusted dev allowance, CLI identity, and bundled path")
    func debugSidecarFallbackRequiresAllowanceIdentityAndPath() {
        let hostBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion Dev.app", isDirectory: true)
        let bundledCLIPath = hostBundleURL
            .appendingPathComponent("Contents/MacOS/bastion-cli")
            .path
        let sidecar: [String: Any] = [
            kSecCodeInfoIdentifier as String: "bastion-cli-arm64"
        ]

        #expect(XPCServer.isClientSigningInfoAllowed(
            sidecar,
            validityStatus: errSecSuccess,
            executablePath: bundledCLIPath,
            allowUntrustedDevSignature: false,
            hostBundleURL: hostBundleURL
        ) == false)
        #expect(XPCServer.isClientSigningInfoAllowed(
            sidecar,
            validityStatus: OSStatus(CSSMERR_TP_NOT_TRUSTED),
            executablePath: bundledCLIPath,
            allowUntrustedDevSignature: true,
            hostBundleURL: hostBundleURL
        ) == true)
        #expect(XPCServer.isClientSigningInfoAllowed(
            [kSecCodeInfoIdentifier as String: "other-tool"],
            validityStatus: OSStatus(CSSMERR_TP_NOT_TRUSTED),
            executablePath: bundledCLIPath,
            allowUntrustedDevSignature: true,
            hostBundleURL: hostBundleURL
        ) == false)
        #expect(XPCServer.isClientSigningInfoAllowed(
            sidecar,
            validityStatus: OSStatus(CSSMERR_TP_NOT_TRUSTED),
            executablePath: "/tmp/bastion-cli",
            allowUntrustedDevSignature: true,
            hostBundleURL: hostBundleURL
        ) == false)
        #expect(XPCServer.isClientSigningInfoAllowed(
            sidecar,
            validityStatus: OSStatus(CSSMERR_TP_NOT_TRUSTED),
            executablePath: "/tmp/bastion.app/Contents/MacOS/bastion-cli",
            allowUntrustedDevSignature: true,
            hostBundleURL: hostBundleURL
        ) == false)
    }

    @Test("Debug sidecar requires CLI identity and bundled CLI path")
    func debugSidecarRequiresCLIIdentityAndBundledPath() {
        let devHostBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion Dev.app", isDirectory: true)
        let devCLIPath = devHostBundleURL
            .appendingPathComponent("Contents/MacOS/bastion-cli")
            .path
        let buildHostBundleURL = URL(fileURLWithPath: "/Users/test/Library/Developer/Xcode/DerivedData/bastion-dev-signed/Build/Products/Debug/bastion.app", isDirectory: true)
        let buildCLIPath = buildHostBundleURL
            .appendingPathComponent("Contents/MacOS/bastion-cli")
            .path

        #expect(XPCServer.isAllowedDebugSidecar(
            identifier: "bastion-cli",
            executablePath: devCLIPath,
            hostBundleURL: devHostBundleURL
        ) == true)
        #expect(XPCServer.isAllowedDebugSidecar(
            identifier: "bastion-cli-arm64",
            executablePath: buildCLIPath,
            hostBundleURL: buildHostBundleURL
        ) == true)
        #expect(XPCServer.isAllowedDebugSidecar(
            identifier: "other-tool",
            executablePath: devCLIPath,
            hostBundleURL: devHostBundleURL
        ) == false)
        #expect(XPCServer.isAllowedDebugSidecar(
            identifier: "bastion-cli",
            executablePath: "/tmp/bastion-cli",
            hostBundleURL: devHostBundleURL
        ) == false)
        #expect(XPCServer.isAllowedDebugSidecar(
            identifier: "bastion-cli",
            executablePath: "/Applications/bastion.app/Contents/MacOS/bastion-cli",
            hostBundleURL: devHostBundleURL
        ) == false)
    }
}

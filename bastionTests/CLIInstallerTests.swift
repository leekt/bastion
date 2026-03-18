import Foundation
import Testing
@testable import bastion

@Suite("CLI Installer")
struct CLIInstallerTests {

    @Test("App bundle resolves bundled CLI path")
    func appBundleCLIPath() throws {
        let appBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion.app")

        let cliURL = try #require(CLIInstaller.bundledCLIExecutableURL(for: appBundleURL))

        #expect(cliURL.path == "/Users/test/Applications/Bastion.app/Contents/MacOS/bastion-cli")
    }

    @Test("Helper bundle resolves parent app CLI path")
    func helperBundleCLIPath() throws {
        let helperBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion.app/Contents/Helpers/bastion-helper.app")

        let cliURL = try #require(CLIInstaller.bundledCLIExecutableURL(for: helperBundleURL))
        let hostAppURL = try #require(CLIInstaller.hostAppBundleURL(forHelperBundle: helperBundleURL))

        #expect(hostAppURL.path == "/Users/test/Applications/Bastion.app")
        #expect(cliURL.path == "/Users/test/Applications/Bastion.app/Contents/MacOS/bastion-cli")
    }

    @Test("Non-helper nested bundle does not resolve host app")
    func nestedNonHelperBundleDoesNotResolve() {
        let nestedBundleURL = URL(fileURLWithPath: "/Users/test/Applications/Bastion.app/Contents/Helpers/not-bastion-helper.app")

        #expect(CLIInstaller.hostAppBundleURL(forHelperBundle: nestedBundleURL) == nil)
    }
}

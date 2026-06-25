import Darwin
import Foundation
import Testing

@main
struct Runner {
    static func main() async {
        var args = Testing.__CommandLineArguments_v0()
        args.parallel = false
        args.filter = ProcessInfo.processInfo.environment["BASTION_TEST_FILTER"]?
            .split(separator: "|")
            .map(String.init)
        let code: CInt = await Testing.__swiftPMEntryPoint(passing: args)
        exit(code)
    }
}

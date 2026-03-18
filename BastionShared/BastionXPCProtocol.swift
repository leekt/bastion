import Foundation

// Shared XPC surface for app/CLI integration.
// Runtime models currently live in the app target and CLI target until this file is wired into both.
@objc protocol BastionXPCProtocol {
    func sign(data: Data, requestID: String, withReply reply: @escaping (Data?, Error?) -> Void)
    func getPublicKey(withReply reply: @escaping (Data?, Error?) -> Void)
    func ping(withReply reply: @escaping (Bool) -> Void)
    func openUI(target: String, withReply reply: @escaping (Bool, Error?) -> Void)
    func getRules(withReply reply: @escaping (Data?, Error?) -> Void)
    func getState(withReply reply: @escaping (Data?, Error?) -> Void)
    func getServiceInfo(withReply reply: @escaping (Data?, Error?) -> Void)
    func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )
}

let xpcServiceName = "com.bastion.xpc"

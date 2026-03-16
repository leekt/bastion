import Foundation

@objc protocol BastionXPCProtocol {
    func sign(
        data: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getPublicKey(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func ping(
        withReply reply: @escaping (Bool) -> Void
    )

    func getRules(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    func getState(
        withReply reply: @escaping (Data?, Error?) -> Void
    )

    /// Structured signing: accepts a JSON-encoded signing operation.
    /// operationType: "message" | "typedData" | "userOperation"
    /// operationData: JSON payload specific to the operation type
    func signStructured(
        operationType: String,
        operationData: Data,
        requestID: String,
        withReply reply: @escaping (Data?, Error?) -> Void
    )
}

let xpcServiceName = "com.bastion.xpc"

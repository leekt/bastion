import Foundation

nonisolated enum RequestExecutionMode: String, Codable, Sendable, Equatable {
    case signOnly = "sign_only"
    case approveAndSend = "approve_and_send"

    var label: String {
        switch self {
        case .signOnly: return "Sign only"
        case .approveAndSend: return "Approve + send"
        }
    }

    var detail: String {
        switch self {
        case .signOnly:
            return "Bastion returns a signature to the requesting client."
        case .approveAndSend:
            return "Bastion signs and submits the UserOperation after approval."
        }
    }

    var compactDetail: String {
        switch self {
        case .signOnly:
            return "Signature returned to client"
        case .approveAndSend:
            return "Sign, then submit via provider"
        }
    }

    var actionLabel: String {
        switch self {
        case .signOnly: return "Sign"
        case .approveAndSend: return "Approve + send"
        }
    }

    var completedNotificationTitle: String {
        switch self {
        case .signOnly: return "Sign only complete"
        case .approveAndSend: return "Approve + send submitted"
        }
    }

    var confirmedNotificationTitle: String {
        switch self {
        case .signOnly: return "Sign only confirmed"
        case .approveAndSend: return "Approve + send confirmed"
        }
    }

    var failedNotificationTitle: String {
        switch self {
        case .signOnly: return "Sign only failed"
        case .approveAndSend: return "Approve + send failed"
        }
    }

    var pendingNotificationTitle: String {
        switch self {
        case .signOnly: return "Sign only pending"
        case .approveAndSend: return "Approve + send pending"
        }
    }

    static func resolve(request: SignRequest) -> RequestExecutionMode {
        request.requiresUserOperationSubmission ? .approveAndSend : .signOnly
    }

    static func resolve(record: AuditRequestRecord) -> RequestExecutionMode {
        if record.events.contains(where: { $0.submission != nil }) {
            return .approveAndSend
        }
        if record.request?.details.contains(where: { line in
            line.lowercased().hasPrefix("post-approval action:")
        }) == true {
            return .approveAndSend
        }
        return .signOnly
    }
}

extension SignRequest {
    nonisolated var executionMode: RequestExecutionMode {
        RequestExecutionMode.resolve(request: self)
    }

    nonisolated var operationKindLabel: String {
        switch operation {
        case .message:
            return "Message"
        case .rawBytes:
            return "Raw bytes"
        case .typedData:
            return "Typed data"
        case .userOperation:
            return "UserOp"
        }
    }
}

extension AuditRequestRecord {
    nonisolated var executionMode: RequestExecutionMode {
        RequestExecutionMode.resolve(record: self)
    }

    nonisolated var operationKindLabel: String {
        switch request?.operationKind {
        case "raw_message":
            return "Message"
        case "raw_bytes":
            return "Raw bytes"
        case "typed_data":
            return "Typed data"
        case "user_operation":
            return "UserOp"
        case let kind?:
            return kind
        case nil:
            return "Request"
        }
    }
}

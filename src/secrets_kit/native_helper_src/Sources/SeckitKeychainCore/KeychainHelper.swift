import Foundation
import Security

public let helperVersion = "1.0.0"

public enum BackendKind: String, Codable {
    case local
    case icloud
}

public enum CommandKind: String, Codable {
    case set
    case get
    case delete
    case exists
    case metadata
}

public struct HelperRequest: Codable {
    public let command: CommandKind
    public let backend: BackendKind
    public let service: String
    public let account: String
    public let name: String
    public let value: String?
    public let label: String?
    public let comment: String?
}

public struct KeychainMetadata: Codable {
    public let account: String
    public let service_name: String
    public let label: String
    public let comment: String
    public let created_at_raw: String
    public let modified_at_raw: String
    public let raw: String
}

public struct HelperResponse: Codable {
    public let ok: Bool
    public let value: String?
    public let exists: Bool?
    public let metadata: KeychainMetadata?
    public let error: String?

    public init(ok: Bool, value: String? = nil, exists: Bool? = nil, metadata: KeychainMetadata? = nil, error: String? = nil) {
        self.ok = ok
        self.value = value
        self.exists = exists
        self.metadata = metadata
        self.error = error
    }
}

public struct KeychainHelper {
    public static func process(_ request: HelperRequest) throws -> HelperResponse {
        switch request.command {
        case .set:
            try set(request)
            return HelperResponse(ok: true)
        case .get:
            return HelperResponse(ok: true, value: try get(request))
        case .delete:
            try delete(request)
            return HelperResponse(ok: true)
        case .exists:
            return HelperResponse(ok: true, exists: exists(request))
        case .metadata:
            return HelperResponse(ok: true, metadata: try metadata(request))
        }
    }

    static func set(_ request: HelperRequest) throws {
        guard let value = request.value else {
            throw HelperError.message("value is required for set")
        }
        guard let valueData = value.data(using: .utf8) else {
            throw HelperError.message("value encoding failed")
        }
        var addQuery = baseQuery(for: request)
        addQuery[kSecValueData] = valueData
        addQuery[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlocked
        if let label = request.label {
            addQuery[kSecAttrLabel] = label
        }
        if let comment = request.comment {
            addQuery[kSecAttrComment] = comment
        }
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        if status == errSecSuccess {
            return
        }
        if status != errSecDuplicateItem {
            throw HelperError.status(status)
        }
        var updateAttrs: [CFString: Any] = [
            kSecValueData: valueData,
            kSecAttrAccessible: kSecAttrAccessibleWhenUnlocked,
        ]
        if let label = request.label {
            updateAttrs[kSecAttrLabel] = label
        }
        if let comment = request.comment {
            updateAttrs[kSecAttrComment] = comment
        }
        let updateStatus = SecItemUpdate(baseQuery(for: request) as CFDictionary, updateAttrs as CFDictionary)
        if updateStatus != errSecSuccess {
            throw HelperError.status(updateStatus)
        }
    }

    static func get(_ request: HelperRequest) throws -> String {
        var query = baseQuery(for: request)
        if request.backend == .icloud {
            query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
        }
        query[kSecReturnData] = kCFBooleanTrue
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status != errSecSuccess {
            throw HelperError.status(status)
        }
        guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
            throw HelperError.message("failed to decode secret value")
        }
        return value
    }

    static func delete(_ request: HelperRequest) throws {
        var query = baseQuery(for: request)
        if request.backend == .icloud {
            query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
        }
        let status = SecItemDelete(query as CFDictionary)
        if status != errSecSuccess {
            throw HelperError.status(status)
        }
    }

    static func exists(_ request: HelperRequest) -> Bool {
        do {
            _ = try metadata(request)
            return true
        } catch let error as HelperError {
            if case .status(let code) = error, code == errSecItemNotFound {
                return false
            }
            return false
        } catch {
            return false
        }
    }

    static func metadata(_ request: HelperRequest) throws -> KeychainMetadata {
        var query = baseQuery(for: request)
        if request.backend == .icloud {
            query[kSecAttrSynchronizable] = kSecAttrSynchronizableAny
        }
        query[kSecReturnAttributes] = kCFBooleanTrue
        query[kSecMatchLimit] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status != errSecSuccess {
            throw HelperError.status(status)
        }
        guard let attrs = result as? [String: Any] else {
            throw HelperError.message("failed to decode keychain metadata")
        }
        return KeychainMetadata(
            account: stringValue(attrs[kSecAttrAccount as String]),
            service_name: stringValue(attrs[kSecAttrService as String]),
            label: stringValue(attrs[kSecAttrLabel as String]),
            comment: stringValue(attrs[kSecAttrComment as String]),
            created_at_raw: dateString(attrs[kSecAttrCreationDate as String]),
            modified_at_raw: dateString(attrs[kSecAttrModificationDate as String]),
            raw: ""
        )
    }

    static func baseQuery(for request: HelperRequest) -> [CFString: Any] {
        var query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrAccount: request.account,
            kSecAttrService: serviceName(service: request.service, name: request.name),
        ]
        if request.backend == .icloud {
            query[kSecAttrSynchronizable] = kCFBooleanTrue
        }
        return query
    }

    static func serviceName(service: String, name: String) -> String {
        "\(service):\(name)"
    }

    static func stringValue(_ value: Any?) -> String {
        if let string = value as? String {
            return string
        }
        return ""
    }

    static func dateString(_ value: Any?) -> String {
        guard let date = value as? Date else {
            return ""
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: date)
    }
}

public enum HelperError: Error {
    case status(OSStatus)
    case message(String)

    public var description: String {
        switch self {
        case .status(let status):
            if let message = SecCopyErrorMessageString(status, nil) as String? {
                return message
            }
            return "Keychain error code: \(status)"
        case .message(let message):
            return message
        }
    }
}

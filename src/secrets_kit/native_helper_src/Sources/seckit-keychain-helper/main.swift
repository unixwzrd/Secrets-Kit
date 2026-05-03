import Foundation
import Security

struct HelperError: Error, CustomStringConvertible {
    let description: String
}

func fail(_ message: String) -> Never {
    let payload: [String: Any] = ["ok": false, "error": message]
    emit(payload)
}

func emit(_ payload: [String: Any]) -> Never {
    do {
        let data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data("\n".utf8))
    } catch {
        FileHandle.standardError.write(Data("failed to encode response: \(error)\n".utf8))
        exit(1)
    }
    exit(payload["ok"] as? Bool == false ? 1 : 0)
}

func readPayload() throws -> [String: Any] {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    guard !data.isEmpty else {
        throw HelperError(description: "missing helper request payload")
    }
    let decoded = try JSONSerialization.jsonObject(with: data)
    guard let payload = decoded as? [String: Any] else {
        throw HelperError(description: "helper request must be a JSON object")
    }
    return payload
}

func requiredString(_ payload: [String: Any], _ key: String) throws -> String {
    guard let value = payload[key] as? String, !value.isEmpty else {
        throw HelperError(description: "missing required field: \(key)")
    }
    return value
}

func serviceName(_ payload: [String: Any]) throws -> String {
    let service = try requiredString(payload, "service")
    let name = try requiredString(payload, "name")
    return "\(service):\(name)"
}

/// First Keychain access group from this binary's code signature (matches embedded entitlements).
func keychainAccessGroupFromSelf() -> String? {
    guard let task = SecTaskCreateFromSelf(nil) else {
        return nil
    }
    guard let raw = SecTaskCopyValueForEntitlement(task, "keychain-access-groups" as CFString, nil) else {
        return nil
    }
    if let arr = raw as? [Any], let first = arr.first as? String, !first.isEmpty {
        return first
    }
    if let single = raw as? String, !single.isEmpty {
        return single
    }
    return nil
}

func baseQuery(_ payload: [String: Any]) throws -> [String: Any] {
    let backend = (payload["backend"] as? String) ?? "local"
    var query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: try serviceName(payload),
        kSecAttrAccount as String: try requiredString(payload, "account")
    ]
    if backend == "icloud" || backend == "icloud-helper" {
        query[kSecAttrSynchronizable as String] = kCFBooleanTrue
        if let group = keychainAccessGroupFromSelf() {
            query[kSecAttrAccessGroup as String] = group
        }
    }
    return query
}

func statusMessage(_ status: OSStatus, _ action: String) -> String {
    if let text = SecCopyErrorMessageString(status, nil) as String? {
        return "\(action) failed: \(text) (\(status))"
    }
    return "\(action) failed with OSStatus \(status)"
}

func setSecret(_ payload: [String: Any]) throws -> [String: Any] {
    let value = try requiredString(payload, "value")
    var query = try baseQuery(payload)
    SecItemDelete(query as CFDictionary)

    query[kSecValueData as String] = Data(value.utf8)
    query[kSecAttrLabel as String] = (payload["label"] as? String) ?? (payload["name"] as? String) ?? "seckit"
    if let comment = payload["comment"] as? String {
        query[kSecAttrComment as String] = comment
    }
    let status = SecItemAdd(query as CFDictionary, nil)
    guard status == errSecSuccess else {
        throw HelperError(description: statusMessage(status, "set"))
    }
    return ["ok": true]
}

func getSecret(_ payload: [String: Any]) throws -> [String: Any] {
    var query = try baseQuery(payload)
    query[kSecReturnData as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
        throw HelperError(description: statusMessage(status, "get"))
    }
    guard let data = result as? Data, let value = String(data: data, encoding: .utf8) else {
        throw HelperError(description: "secret value is not valid utf-8")
    }
    return ["ok": true, "value": value]
}

func existsSecret(_ payload: [String: Any]) throws -> [String: Any] {
    var query = try baseQuery(payload)
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    let status = SecItemCopyMatching(query as CFDictionary, nil)
    if status == errSecSuccess {
        return ["ok": true, "exists": true]
    }
    if status == errSecItemNotFound {
        return ["ok": true, "exists": false]
    }
    throw HelperError(description: statusMessage(status, "exists"))
}

func metadataSecret(_ payload: [String: Any]) throws -> [String: Any] {
    var query = try baseQuery(payload)
    query[kSecReturnAttributes as String] = kCFBooleanTrue
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    guard status == errSecSuccess else {
        throw HelperError(description: statusMessage(status, "metadata"))
    }
    guard let attrs = result as? [String: Any] else {
        throw HelperError(description: "metadata result was not an attribute dictionary")
    }
    let metadata: [String: Any] = [
        "account": attrs[kSecAttrAccount as String] as? String ?? "",
        "service_name": attrs[kSecAttrService as String] as? String ?? "",
        "label": attrs[kSecAttrLabel as String] as? String ?? "",
        "comment": attrs[kSecAttrComment as String] as? String ?? ""
    ]
    return ["ok": true, "metadata": metadata]
}

func deleteSecret(_ payload: [String: Any]) throws -> [String: Any] {
    let query = try baseQuery(payload)
    let status = SecItemDelete(query as CFDictionary)
    guard status == errSecSuccess || status == errSecItemNotFound else {
        throw HelperError(description: statusMessage(status, "delete"))
    }
    return ["ok": true]
}

/// No Keychain I/O: process runs and reads signing entitlements only (diagnostics / AMFI).
func selftestEntitlements() -> [String: Any] {
    var payload: [String: Any] = [
        "ok": true,
        "selftest": true,
    ]
    if let group = keychainAccessGroupFromSelf() {
        payload["keychain_access_group"] = group
    } else {
        payload["keychain_access_group"] = NSNull()
    }
    return payload
}

do {
    let payload = try readPayload()
    let command = try requiredString(payload, "command")
    switch command {
    case "selftest":
        emit(selftestEntitlements())
    case "set":
        emit(try setSecret(payload))
    case "get":
        emit(try getSecret(payload))
    case "exists":
        emit(try existsSecret(payload))
    case "metadata":
        emit(try metadataSecret(payload))
    case "delete":
        emit(try deleteSecret(payload))
    default:
        throw HelperError(description: "unsupported command: \(command)")
    }
} catch {
    fail(String(describing: error))
}

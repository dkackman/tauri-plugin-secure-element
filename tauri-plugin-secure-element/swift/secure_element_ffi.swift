import Foundation
import Security

// MARK: - FFI Helper Functions

/// Convert a Result to JSON string
private func resultToJson<T>(_ result: Result<T, SecureEnclaveError>, encoder: (T) -> [String: Any]) -> String {
    switch result {
    case let .success(value):
        return dictionaryToJson(encoder(value))
    case let .failure(error):
        return "{\"error\":\"\(escapeJsonString(error.localizedDescription))\"}"
    }
}

/// Convert dictionary to JSON string
private func dictionaryToJson(_ dict: [String: Any]) -> String {
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: dict, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8), !jsonString.isEmpty {
            return jsonString
        }
        return "{\"error\":\"Failed to serialize response\"}"
    } catch {
        return "{\"error\":\"Failed to serialize: \(escapeJsonString(error.localizedDescription))\"}"
    }
}

/// Escape special characters in JSON string
private func escapeJsonString(_ string: String) -> String {
    return string
        .replacingOccurrences(of: "\\", with: "\\\\")
        .replacingOccurrences(of: "\"", with: "\\\"")
        .replacingOccurrences(of: "\n", with: "\\n")
        .replacingOccurrences(of: "\r", with: "\\r")
        .replacingOccurrences(of: "\t", with: "\\t")
}

/// Allocate and return a C string from Swift string
private func toCString(_ string: String) -> UnsafeMutablePointer<CChar> {
    guard !string.isEmpty else {
        return strdup("{\"error\":\"Empty result\"}")!
    }

    let utf8Bytes = string.utf8CString
    let count = utf8Bytes.count

    guard let ptr = malloc(count)?.bindMemory(to: CChar.self, capacity: count) else {
        return strdup("{\"error\":\"malloc failed\"}")!
    }

    for i in 0 ..< count {
        ptr[i] = utf8Bytes[i]
    }

    return ptr
}

/// Convert C string to optional Swift string
private func fromCString(_ ptr: UnsafePointer<CChar>?) -> String? {
    guard let ptr = ptr else { return nil }
    let str = String(cString: ptr)
    return str.isEmpty ? nil : str
}

// MARK: - FFI Functions

@_cdecl("secure_element_generate_secure_key")
public func secureElementGenerateSecureKey(
    keyName: UnsafePointer<CChar>?,
    authMode: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar> {
    guard let keyNameStr = fromCString(keyName), !keyNameStr.isEmpty else {
        return strdup("{\"error\":\"keyName is required\"}")!
    }

    let authModeStr = fromCString(authMode)

    let result = SecureEnclaveCore.generateSecureKey(keyName: keyNameStr, authMode: authModeStr)
    let json = resultToJson(result) { response in
        ["publicKey": response.publicKey, "keyName": response.keyName, "hardwareBacking": response.hardwareBacking]
    }

    return toCString(json)
}

@_cdecl("secure_element_list_keys")
public func secureElementListKeys(
    keyName: UnsafePointer<CChar>?,
    publicKey: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar> {
    let keyNameStr = fromCString(keyName)
    let publicKeyStr = fromCString(publicKey)

    let result = SecureEnclaveCore.listKeys(keyName: keyNameStr, publicKey: publicKeyStr)
    let json = resultToJson(result) { response in
        let keys: [[String: Any]] = response.keys.map { keyInfo in
            var info: [String: Any] = [
                "keyName": keyInfo.keyName,
                "publicKey": keyInfo.publicKey,
            ]
            return info
        }
        return ["keys": keys]
    }

    return toCString(json)
}

@_cdecl("secure_element_sign_with_key")
public func secureElementSignWithKey(
    keyName: UnsafePointer<CChar>?,
    dataBase64: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar> {
    guard let keyNameStr = fromCString(keyName), !keyNameStr.isEmpty else {
        return strdup("{\"error\":\"keyName is required\"}")!
    }

    guard let dataBase64Str = fromCString(dataBase64), !dataBase64Str.isEmpty else {
        return strdup("{\"error\":\"data is required\"}")!
    }

    guard let data = Data(base64Encoded: dataBase64Str) else {
        return strdup("{\"error\":\"Failed to decode base64 data\"}")!
    }

    let result = SecureEnclaveCore.signWithKey(keyName: keyNameStr, data: data)
    let json = resultToJson(result) { response in
        ["signature": response.signature.base64EncodedString()]
    }

    return toCString(json)
}

@_cdecl("secure_element_delete_key")
public func secureElementDeleteKey(
    keyName: UnsafePointer<CChar>?,
    publicKey: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar> {
    let keyNameStr = fromCString(keyName)
    let publicKeyStr = fromCString(publicKey)

    if keyNameStr == nil, publicKeyStr == nil {
        return strdup("{\"error\":\"Either keyName or publicKey must be provided\"}")!
    }

    let result = SecureEnclaveCore.deleteKey(keyName: keyNameStr, publicKey: publicKeyStr)
    let json = resultToJson(result) { _ in
        ["success": true]
    }

    return toCString(json)
}

@_cdecl("secure_element_check_support")
public func secureElementCheckSupport() -> UnsafeMutablePointer<CChar> {
    let response = SecureEnclaveCore.checkSupport()
    let json = dictionaryToJson([
        "secureElementSupported": response.secureElementSupported,
        "teeSupported": response.teeSupported,
        "canEnforceBiometricOnly": response.canEnforceBiometricOnly,
    ])

    return toCString(json)
}

import Foundation
import Security

// MARK: - FFI Helper Functions

/// Convert a Result to JSON string
private func resultToJson<T>(_ result: Result<T, SecureEnclaveError>, encoder: (T) -> [String: Any]) -> String {
    switch result {
    case let .success(value):
        return dictionaryToJson(encoder(value))
    case let .failure(error):
        return errorJson(error)
    }
}

/// Renders a `SecureEnclaveError` as the `{"error": ..., "code": ...}` shape
/// `desktop.rs` parses.
///
/// The `code` is what the caller branches on and is identical in debug and
/// release builds; `error` is prose that is deliberately generic in release.
/// Both travel together so the Rust side never has to infer one from the other.
private func errorJson(_ error: SecureEnclaveError) -> String {
    let message = escapeJsonString(error.localizedDescription)
    return "{\"error\":\"\(message)\",\"code\":\"\(error.code)\"}"
}

/// Renders an FFI-boundary failure — bad arguments that never reached
/// `SecureEnclaveCore` — with the same shape as `errorJson`.
private func argumentErrorJson(_ message: String) -> String {
    "{\"error\":\"\(escapeJsonString(message))\",\"code\":\"validation\"}"
}

/// Convert dictionary to JSON string
private func dictionaryToJson(_ dict: [String: Any]) -> String {
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: dict, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8), !jsonString.isEmpty {
            return jsonString
        }
        return "{\"error\":\"Failed to serialize response\",\"code\":\"internal\"}"
    } catch {
        return "{\"error\":\"Failed to serialize: \(escapeJsonString(error.localizedDescription))\",\"code\":\"internal\"}"
    }
}

/// Escape special characters in JSON string.
/// Uses JSONSerialization to properly escape all control characters (U+0000-U+001F)
/// as required by the JSON specification.
private func escapeJsonString(_ string: String) -> String {
    // Use JSONSerialization to properly escape all special characters including
    // control characters that the simple replacingOccurrences approach misses
    guard let data = try? JSONSerialization.data(
        withJSONObject: string,
        options: .fragmentsAllowed
    ),
        let escaped = String(data: data, encoding: .utf8),
        escaped.count >= 2
    else {
        // Fallback: filter out control characters we can't escape
        return string.unicodeScalars
            .filter { $0.value >= 0x20 || $0 == "\t" || $0 == "\n" || $0 == "\r" }
            .map { String($0) }
            .joined()
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\r", with: "\\r")
            .replacingOccurrences(of: "\t", with: "\\t")
    }
    // JSONSerialization wraps the string in quotes, strip them
    return String(escaped.dropFirst().dropLast())
}

/// Allocate and return a C string from Swift string
private func toCString(_ string: String) -> UnsafeMutablePointer<CChar> {
    guard !string.isEmpty else {
        return strdup("{\"error\":\"Empty result\",\"code\":\"internal\"}")!
    }

    let utf8Bytes = string.utf8CString
    let count = utf8Bytes.count

    guard let ptr = malloc(count)?.bindMemory(to: CChar.self, capacity: count) else {
        return strdup("{\"error\":\"malloc failed\",\"code\":\"internal\"}")!
    }

    for index in 0 ..< count {
        ptr[index] = utf8Bytes[index]
    }

    return ptr
}

/// Convert C string to optional Swift string
private func fromCString(_ ptr: UnsafePointer<CChar>?) -> String? {
    guard let ptr else { return nil }
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
        return strdup(argumentErrorJson("keyName is required"))!
    }

    let authModeStr = fromCString(authMode)

    let result = SecureEnclaveCore.generateSecureKey(keyName: keyNameStr, authMode: authModeStr)
    let json = resultToJson(result) { response in
        // The key was just created in the Secure Enclave, so availability is
        // already proven — derive the backing tier from platform detection
        // rather than calling checkSupport(), which would create an extra
        // ephemeral SE test key on every key generation.
        let backing = SecureEnclaveCore.strongestBacking().rawValue
        return ["publicKey": response.publicKey, "keyName": response.keyName, "backing": backing]
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
            let info: [String: Any] = [
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
    dataBase64: UnsafePointer<CChar>?,
    reason: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar> {
    guard let keyNameStr = fromCString(keyName), !keyNameStr.isEmpty else {
        return strdup(argumentErrorJson("keyName is required"))!
    }

    guard let dataBase64Str = fromCString(dataBase64), !dataBase64Str.isEmpty else {
        return strdup(argumentErrorJson("data is required"))!
    }

    guard let data = Data(base64Encoded: dataBase64Str) else {
        return strdup(argumentErrorJson("Failed to decode base64 data"))!
    }

    // nil reason falls back to the platform default prompt.
    let result = SecureEnclaveCore.signWithKey(
        keyName: keyNameStr,
        data: data,
        reason: fromCString(reason)
    )
    let json = resultToJson(result) { response in
        ["signature": response.signature.base64EncodedString()]
    }

    return toCString(json)
}

@_cdecl("secure_element_delete_key")
public func secureElementDeleteKey(
    keyName: UnsafePointer<CChar>?,
    publicKey: UnsafePointer<CChar>?,
    authReason: UnsafePointer<CChar>?
) -> UnsafeMutablePointer<CChar> {
    let keyNameStr = fromCString(keyName)
    let publicKeyStr = fromCString(publicKey)

    if keyNameStr == nil, publicKeyStr == nil {
        return strdup(argumentErrorJson("Either keyName or publicKey must be provided"))!
    }

    // A non-nil reason means the caller asked for authentication before deletion.
    let result = SecureEnclaveCore.deleteKey(
        keyName: keyNameStr,
        publicKey: publicKeyStr,
        authReason: fromCString(authReason)
    )
    let json = resultToJson(result) { _ in
        ["success": true]
    }

    return toCString(json)
}

@_cdecl("secure_element_check_support")
public func secureElementCheckSupport() -> UnsafeMutablePointer<CChar> {
    let response = SecureEnclaveCore.checkSupport()
    let json = dictionaryToJson([
        "discrete": response.discrete,
        "integrated": response.integrated,
        "firmware": response.firmware,
        "emulated": response.emulated,
        "strongest": response.strongest.rawValue,
        "canEnforceBiometricOnly": response.canEnforceBiometricOnly,
    ])

    return toCString(json)
}

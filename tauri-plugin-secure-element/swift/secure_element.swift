import Foundation
import Security
import CryptoKit

// Direct list keys implementation for FFI (without Invoke dependency)
func listKeysDirect(keyName: String?, publicKey: String?) -> String {
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnAttributes as String: true,
        kSecReturnRef as String: true,
        kSecReturnData as String: false,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    var keys: [[String: Any]] = []
    
    if status == errSecSuccess, let items = result as? [[String: Any]] {
        for item in items {
            guard let keyRef = item[kSecValueRef as String] as? CFTypeRef else {
                continue
            }
            let privateKey = keyRef as! SecKey
            
            let keyNameLabel = (item[kSecAttrLabel as String] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
            let foundKeyName = keyNameLabel?.isEmpty == false ? keyNameLabel! : "<unnamed>"
            
            // Apply filters
            if let filterName = keyName, filterName != foundKeyName {
                continue
            }
            
            // Export public key
            guard let publicKeyObj = SecKeyCopyPublicKey(privateKey) else {
                continue
            }
            
            var exportError: Unmanaged<CFError>?
            guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKeyObj, &exportError) as Data? else {
                continue
            }
            
            let publicKeyBase64 = publicKeyData.base64EncodedString()
            
            if let filterPublicKey = publicKey, filterPublicKey != publicKeyBase64 {
                continue
            }
            
            // Extract auth mode
            var requiresAuthentication: Bool? = nil
            if let authModeData = item[kSecAttrApplicationTag as String] as? Data,
               let authModeString = String(data: authModeData, encoding: .utf8) {
                switch authModeString {
                case "none":
                    requiresAuthentication = false
                case "pinOrBiometric", "biometricOnly":
                    requiresAuthentication = true
                default:
                    requiresAuthentication = nil
                }
            }
            
            var keyInfo: [String: Any] = [
                "keyName": foundKeyName,
                "publicKey": publicKeyBase64,
            ]
            if let requiresAuthentication = requiresAuthentication {
                keyInfo["requiresAuthentication"] = requiresAuthentication
            }
            keys.append(keyInfo)
        }
    } else if status != errSecItemNotFound {
        // Return error as JSON
        return "{\"error\":\"Failed to query keys: \(status)\"}"
    }
    
    // Serialize to JSON - always return valid JSON
    do {
        let response = ["keys": keys]
        let jsonData = try JSONSerialization.data(withJSONObject: response, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8), !jsonString.isEmpty {
            return jsonString
        } else {
            return "{\"error\":\"Failed to serialize response: encoding failed\"}"
        }
    } catch {
        return "{\"error\":\"Failed to serialize: \(error.localizedDescription)\"}"
    }
}

// FFI function for direct C linking
@_cdecl("secure_element_list_keys")
public func secureElementListKeys(keyName: UnsafePointer<CChar>?, publicKey: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar> {
    // Convert C strings to Swift strings, treating null/empty as nil
    let keyNameStr: String?
    if let keyName = keyName {
        let str = String(cString: keyName)
        keyNameStr = str.isEmpty ? nil : str
    } else {
        keyNameStr = nil
    }
    
    let publicKeyStr: String?
    if let publicKey = publicKey {
        let str = String(cString: publicKey)
        publicKeyStr = str.isEmpty ? nil : str
    } else {
        publicKeyStr = nil
    }
    
    // Call the actual implementation
    let result = listKeysDirect(keyName: keyNameStr, publicKey: publicKeyStr)
    
    // Ensure result is not empty
    guard !result.isEmpty else {
        let errorMsg = "{\"error\":\"Swift function returned empty result\"}"
        return strdup(errorMsg)!
    }
    
    // Convert to UTF-8 C string array (includes null terminator)
    let utf8Bytes = result.utf8CString
    
    // Allocate memory with malloc (compatible with libc::free)
    let byteCount = utf8Bytes.count
    guard let mallocPtr = malloc(byteCount)?.bindMemory(to: CChar.self, capacity: byteCount) else {
        return strdup("{\"error\":\"malloc failed\"}")!
    }
    
    // Copy the bytes
    for i in 0..<byteCount {
        mallocPtr[i] = utf8Bytes[i]
    }
    
    return mallocPtr
}

// Direct check secure element support implementation for FFI
func checkSecureElementSupportDirect() -> String {
    // On macOS, Secure Enclave is available on Apple Silicon Macs (M1+)
    // Try to create access control first
    var accessError: Unmanaged<CFError>?
    let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]
    guard SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &accessError
    ) != nil else {
        // Can't create access control, Secure Enclave not available
        return "{\"secureElementSupported\":false,\"teeSupported\":false,\"canEnforceBiometricOnly\":false}"
    }
    
    // Try to create a test key with Secure Enclave token ID
    let testTag = Data("secure_element_test_\(UUID().uuidString)".utf8)
    let testAttributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrIsPermanent as String: false, // Temporary key for testing
        kSecAttrApplicationTag as String: testTag,
    ]
    
    var testError: Unmanaged<CFError>?
    let testKey = SecKeyCreateRandomKey(testAttributes as CFDictionary, &testError)
    
    // Clean up the test key
    defer {
        if testKey != nil {
            let deleteQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: testTag,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            ]
            SecItemDelete(deleteQuery as CFDictionary)
        }
    }
    
    let secureElementSupported: Bool
    let teeSupported: Bool
    let canEnforceBiometricOnly: Bool
    
    if testKey != nil {
        // Successfully created a key, Secure Enclave is available
        // On macOS, Secure Enclave IS the TEE, so both are true
        secureElementSupported = true
        teeSupported = true
        canEnforceBiometricOnly = true
    } else {
        // Failed to create key, Secure Enclave/TEE is not available
        secureElementSupported = false
        teeSupported = false
        canEnforceBiometricOnly = false
    }
    
    // Serialize to JSON
    do {
        let response: [String: Any] = [
            "secureElementSupported": secureElementSupported,
            "teeSupported": teeSupported,
            "canEnforceBiometricOnly": canEnforceBiometricOnly,
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: response, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8), !jsonString.isEmpty {
            return jsonString
        } else {
            return "{\"error\":\"Failed to serialize response: encoding failed\"}"
        }
    } catch {
        return "{\"error\":\"Failed to serialize: \(error.localizedDescription)\"}"
    }
}

// FFI function for check secure element support
@_cdecl("secure_element_check_support")
public func secureElementCheckSupport() -> UnsafeMutablePointer<CChar> {
    let result = checkSecureElementSupportDirect()
    
    // Ensure result is not empty
    guard !result.isEmpty else {
        let errorMsg = "{\"error\":\"Swift function returned empty result\"}"
        return strdup(errorMsg)!
    }
    
    // Convert to UTF-8 C string array (includes null terminator)
    let utf8Bytes = result.utf8CString
    let count = utf8Bytes.count
    
    // Allocate memory with malloc (compatible with libc::free)
    guard let mallocPtr = malloc(count)?.bindMemory(to: CChar.self, capacity: count) else {
        return strdup("{\"error\":\"malloc failed\"}")!
    }
    
    // Copy the bytes
    for i in 0..<count {
        mallocPtr[i] = utf8Bytes[i]
    }
    
    return mallocPtr
}

// Direct generate secure key implementation for FFI
func generateSecureKeyDirect(keyName: String, authMode: String?) -> String {
    // Check if a key with this name already exists
    let checkQuery: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrLabel as String: keyName,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnRef as String: false,
    ]
    
    var checkResult: CFTypeRef?
    let checkStatus = SecItemCopyMatching(checkQuery as CFDictionary, &checkResult)
    
    if checkStatus == errSecSuccess {
        // Key already exists
        return "{\"error\":\"Key already exists\"}"
    } else if checkStatus != errSecItemNotFound {
        // Unexpected error while checking
        return "{\"error\":\"Failed to check for existing key: \(checkStatus)\"}"
    }
    
    // Create access control
    let mode = authMode ?? "pinOrBiometric"
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    
    switch mode {
    case "none":
        // No authentication required, only .privateKeyUsage
        break
    case "biometricOnly":
        // Require biometric authentication only
        flags.insert(.biometryCurrentSet)
    case "pinOrBiometric", _:
        // Allow PIN or biometric (default)
        flags.insert(.userPresence)
    }
    
    var accessError: Unmanaged<CFError>?
    guard let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        flags,
        &accessError
    ) else {
        if let error = accessError {
            let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
            return "{\"error\":\"Failed to create access control: \(errorDescription)\"}"
        }
        return "{\"error\":\"Failed to create access control\"}"
    }
    
    // Store auth mode in kSecAttrApplicationTag as Data
    guard let authModeData = mode.data(using: .utf8) else {
        return "{\"error\":\"Invalid auth mode\"}"
    }
    
    // Create the Secure Enclave key
    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrIsPermanent as String: true,
        kSecAttrLabel as String: keyName,
        kSecAttrApplicationTag as String: authModeData,
        kSecPrivateKeyAttrs as String: [
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: accessControl,
        ],
    ]
    
    var keyError: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
        if let error = keyError {
            let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
            return "{\"error\":\"Failed to create key: \(errorDescription)\"}"
        }
        return "{\"error\":\"Failed to create key\"}"
    }
    
    // Extract and export public key
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        return "{\"error\":\"Failed to extract public key\"}"
    }
    
    var exportError: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
        if let error = exportError {
            let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
            return "{\"error\":\"Failed to export public key: \(errorDescription)\"}"
        }
        return "{\"error\":\"Failed to export public key\"}"
    }
    
    let publicKeyBase64 = publicKeyData.base64EncodedString()
    
    // Serialize to JSON
    do {
        let response: [String: Any] = [
            "publicKey": publicKeyBase64,
            "keyName": keyName,
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: response, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8), !jsonString.isEmpty {
            return jsonString
        } else {
            return "{\"error\":\"Failed to serialize response: encoding failed\"}"
        }
    } catch {
        return "{\"error\":\"Failed to serialize: \(error.localizedDescription)\"}"
    }
}

// FFI function for generate secure key
@_cdecl("secure_element_generate_secure_key")
public func secureElementGenerateSecureKey(keyName: UnsafePointer<CChar>?, authMode: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar> {
    // Convert C strings to Swift strings
    guard let keyName = keyName else {
        return strdup("{\"error\":\"keyName is required\"}")!
    }
    
    let keyNameStr = String(cString: keyName)
    guard !keyNameStr.isEmpty else {
        return strdup("{\"error\":\"keyName cannot be empty\"}")!
    }
    
    let authModeStr: String?
    if let authMode = authMode {
        let str = String(cString: authMode)
        authModeStr = str.isEmpty ? nil : str
    } else {
        authModeStr = nil
    }
    
    // Call the actual implementation
    let result = generateSecureKeyDirect(keyName: keyNameStr, authMode: authModeStr)
    
    // Ensure result is not empty
    guard !result.isEmpty else {
        let errorMsg = "{\"error\":\"Swift function returned empty result\"}"
        return strdup(errorMsg)!
    }
    
    // Convert to UTF-8 C string array (includes null terminator)
    let utf8Bytes = result.utf8CString
    let count = utf8Bytes.count
    
    // Allocate memory with malloc (compatible with libc::free)
    guard let mallocPtr = malloc(count)?.bindMemory(to: CChar.self, capacity: count) else {
        return strdup("{\"error\":\"malloc failed\"}")!
    }
    
    // Copy the bytes
    for i in 0..<count {
        mallocPtr[i] = utf8Bytes[i]
    }
    
    return mallocPtr
}

// Helper function to create key query
func createKeyQuery(keyName: String, returnRef: Bool = true) -> [String: Any] {
    var query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrLabel as String: keyName,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ]
    if returnRef {
        query[kSecReturnRef as String] = true
    }
    return query
}

// Helper function to export public key as base64
func exportPublicKeyBase64Silent(privateKey: SecKey) -> String? {
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        return nil
    }
    
    var exportError: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
        return nil
    }
    
    return publicKeyData.base64EncodedString()
}

// Direct sign with key implementation for FFI
func signWithKeyDirect(keyName: String, dataBase64: String) -> String {
    // Look up the key by name
    let query = createKeyQuery(keyName: keyName, returnRef: true)
    var keyRef: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
    
    // Accept both errSecSuccess and errSecInteractionNotAllowed
    // errSecInteractionNotAllowed can occur for auth-required keys, but authentication
    // will be enforced later when the key is actually used
    guard status == errSecSuccess || status == errSecInteractionNotAllowed, let keyRef = keyRef else {
        return "{\"error\":\"Key not found: \(keyName), status: \(status)\"}"
    }
    
    // keyRef is already SecKey (typealias for CFTypeRef)
    let privateKey = keyRef as! SecKey
    
    // Decode base64 data
    guard let dataToSign = Data(base64Encoded: dataBase64) else {
        return "{\"error\":\"Failed to decode base64 data\"}"
    }
    
    // Create SHA256 digest using CryptoKit
    let digest = SHA256.hash(data: dataToSign)
    let digestData = Data(digest)
    
    // Sign the digest using ECDSA
    // Secure Enclave will automatically prompt for authentication if the key requires it
    var signError: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureDigestX962SHA256,
        digestData as CFData,
        &signError
    ) as Data? else {
        if let error = signError {
            let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
            return "{\"error\":\"Failed to sign: \(errorDescription)\"}"
        }
        return "{\"error\":\"Failed to sign\"}"
    }
    
    // Convert signature to base64 for JSON
    let signatureBase64 = signature.base64EncodedString()
    
    // Serialize to JSON
    do {
        let response: [String: Any] = [
            "signature": signatureBase64,
        ]
        let jsonData = try JSONSerialization.data(withJSONObject: response, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8), !jsonString.isEmpty {
            return jsonString
        } else {
            return "{\"error\":\"Failed to serialize response: encoding failed\"}"
        }
    } catch {
        return "{\"error\":\"Failed to serialize: \(error.localizedDescription)\"}"
    }
}

// FFI function for sign with key
@_cdecl("secure_element_sign_with_key")
public func secureElementSignWithKey(keyName: UnsafePointer<CChar>?, dataBase64: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar> {
    // Convert C strings to Swift strings
    guard let keyName = keyName else {
        return strdup("{\"error\":\"keyName is required\"}")!
    }
    
    let keyNameStr = String(cString: keyName)
    guard !keyNameStr.isEmpty else {
        return strdup("{\"error\":\"keyName cannot be empty\"}")!
    }
    
    guard let dataBase64 = dataBase64 else {
        return strdup("{\"error\":\"data is required\"}")!
    }
    
    let dataBase64Str = String(cString: dataBase64)
    guard !dataBase64Str.isEmpty else {
        return strdup("{\"error\":\"data cannot be empty\"}")!
    }
    
    // Call the actual implementation
    let result = signWithKeyDirect(keyName: keyNameStr, dataBase64: dataBase64Str)
    
    // Ensure result is not empty
    guard !result.isEmpty else {
        let errorMsg = "{\"error\":\"Swift function returned empty result\"}"
        return strdup(errorMsg)!
    }
    
    // Convert to UTF-8 C string array (includes null terminator)
    let utf8Bytes = result.utf8CString
    let count = utf8Bytes.count
    
    // Allocate memory with malloc (compatible with libc::free)
    guard let mallocPtr = malloc(count)?.bindMemory(to: CChar.self, capacity: count) else {
        return strdup("{\"error\":\"malloc failed\"}")!
    }
    
    // Copy the bytes
    for i in 0..<count {
        mallocPtr[i] = utf8Bytes[i]
    }
    
    return mallocPtr
}

// Direct delete key implementation for FFI
func deleteKeyDirect(keyName: String?, publicKey: String?) -> String {
    // If keyName is provided, delete by name (fast path)
    if let keyName = keyName {
        let query = createKeyQuery(keyName: keyName, returnRef: false)
        let status = SecItemDelete(query as CFDictionary)
        
        if status == errSecSuccess || status == errSecItemNotFound {
            return "{\"success\":true}"
        } else {
            return "{\"error\":\"Failed to delete key: \(status)\"}"
        }
    }
    
    // If publicKey is provided, find the key by public key and delete it
    guard let targetPublicKey = publicKey else {
        return "{\"error\":\"Either keyName or publicKey must be provided\"}"
    }
    
    // Query for all keys in Secure Enclave
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnAttributes as String: true,
        kSecReturnRef as String: true,
        kSecReturnData as String: false,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]
    
    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)
    
    if status == errSecSuccess, let items = result as? [[String: Any]] {
        // Find the key matching the public key
        for item in items {
            guard let keyRef = item[kSecValueRef as String] as? CFTypeRef else {
                continue
            }
            let privateKey = keyRef as! SecKey
            
            // Get the public key for this private key
            if let publicKeyBase64 = exportPublicKeyBase64Silent(privateKey: privateKey),
               publicKeyBase64 == targetPublicKey
            {
                // Extract key name from kSecAttrLabel for deletion
                let keyNameLabel = (item[kSecAttrLabel as String] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
                let keyName = keyNameLabel?.isEmpty == false ? keyNameLabel! : "<unnamed>"
                
                // Found the matching key, delete it
                let deleteQuery = createKeyQuery(keyName: keyName, returnRef: false)
                let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)
                
                if deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound {
                    return "{\"success\":true}"
                } else {
                    return "{\"error\":\"Failed to delete key: \(deleteStatus)\"}"
                }
            }
        }
        
        // Key not found by public key, return success (idempotent)
        return "{\"success\":true}"
    } else if status == errSecItemNotFound {
        // No keys found, return success (idempotent)
        return "{\"success\":true}"
    } else {
        return "{\"error\":\"Failed to query keys for deletion: \(status)\"}"
    }
}

// FFI function for delete key
@_cdecl("secure_element_delete_key")
public func secureElementDeleteKey(keyName: UnsafePointer<CChar>?, publicKey: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar> {
    // Convert C strings to Swift strings, treating null/empty as nil
    let keyNameStr: String?
    if let keyName = keyName {
        let str = String(cString: keyName)
        keyNameStr = str.isEmpty ? nil : str
    } else {
        keyNameStr = nil
    }
    
    let publicKeyStr: String?
    if let publicKey = publicKey {
        let str = String(cString: publicKey)
        publicKeyStr = str.isEmpty ? nil : str
    } else {
        publicKeyStr = nil
    }
    
    // Call the actual implementation
    let result = deleteKeyDirect(keyName: keyNameStr, publicKey: publicKeyStr)
    
    // Ensure result is not empty
    guard !result.isEmpty else {
        let errorMsg = "{\"error\":\"Swift function returned empty result\"}"
        return strdup(errorMsg)!
    }
    
    // Convert to UTF-8 C string array (includes null terminator)
    let utf8Bytes = result.utf8CString
    let count = utf8Bytes.count
    
    // Allocate memory with malloc (compatible with libc::free)
    guard let mallocPtr = malloc(count)?.bindMemory(to: CChar.self, capacity: count) else {
        return strdup("{\"error\":\"malloc failed\"}")!
    }
    
    // Copy the bytes
    for i in 0..<count {
        mallocPtr[i] = utf8Bytes[i]
    }
    
    return mallocPtr
}


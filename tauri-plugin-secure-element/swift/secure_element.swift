import Foundation
import Security

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


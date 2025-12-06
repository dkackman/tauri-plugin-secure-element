// FFI Bridge for Rust ↔ Swift Communication
//
// This file provides C-compatible functions that can be called from Rust.
// It wraps the Security Framework APIs for Secure Enclave operations.

import CryptoKit
import Foundation
import Security

// MARK: - C-Compatible Result Types

/// Result structure for operations that return a string
@_cdecl("ffi_string_result_free")
func ffi_string_result_free(_ ptr: UnsafeMutablePointer<CChar>?) {
    ptr?.deallocate()
}

/// Convert Swift String to C string (caller must free)
private func toCString(_ string: String) -> UnsafeMutablePointer<CChar>? {
    return strdup(string)
}

// MARK: - Capability Detection

@_cdecl("secure_element_check_support")
func secure_element_check_support(
    _ supported: UnsafeMutablePointer<Bool>,
    _ tee_supported: UnsafeMutablePointer<Bool>
) -> Int32 {
    // Try to create a test key to check if Secure Enclave is available
    let testTag = "__ffi_test_key__".data(using: .utf8)!

    let attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrIsPermanent as String: false, // Ephemeral test key
    ]

    var error: Unmanaged<CFError>?
    let testKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error)

    let isAvailable = (testKey != nil)

    supported.pointee = isAvailable
    tee_supported.pointee = isAvailable

    return 0 // Success
}

// MARK: - Key Generation

@_cdecl("secure_element_generate_key")
func secure_element_generate_key(
    _ key_name: UnsafePointer<CChar>,
    _ public_key_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
    _ error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    let keyName = String(cString: key_name)

    // Delete existing key if present
    let deleteQuery: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyName.data(using: .utf8)!,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ]
    SecItemDelete(deleteQuery as CFDictionary)

    // Try to create access control with proper flags for Secure Enclave
    // First attempt: Full access control (works in production with proper entitlements)
    var accessError: Unmanaged<CFError>?
    let accessControl = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        .privateKeyUsage,
        &accessError
    )

    // Create key attributes with access control if available, otherwise without
    var attributes: [String: Any] = [
        kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeySizeInBits as String: 256,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecAttrIsPermanent as String: true,
        kSecAttrApplicationTag as String: keyName.data(using: .utf8)!,
    ]

    // Add access control only if successfully created
    // This allows keys to work in dev environments without full entitlements
    if let accessControl = accessControl {
        attributes[kSecPrivateKeyAttrs as String] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessControl as String: accessControl,
        ]
    } else {
        // Development fallback: simpler attributes without access control
        attributes[kSecPrivateKeyAttrs as String] = [
            kSecAttrIsPermanent as String: true,
        ]
    }

    var error: Unmanaged<CFError>?
    guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
        let errorMsg = error.map { CFErrorCopyDescription($0.takeRetainedValue()) as String? }
            ?? "Failed to create key"
        error_out.pointee = toCString(errorMsg ?? "Unknown error")
        return -1
    }

    // Extract public key
    guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
        error_out.pointee = toCString("Failed to extract public key")
        return -1
    }

    // Export public key
    var exportError: Unmanaged<CFError>?
    guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
        let errorMsg = exportError.map { CFErrorCopyDescription($0.takeRetainedValue()) as String? }
            ?? "Failed to export public key"
        error_out.pointee = toCString(errorMsg ?? "Unknown error")
        return -1
    }

    // Convert to base64
    let publicKeyBase64 = publicKeyData.base64EncodedString()
    public_key_out.pointee = toCString(publicKeyBase64)

    return 0 // Success
}

// MARK: - Key Signing

@_cdecl("secure_element_sign_data")
func secure_element_sign_data(
    _ key_name: UnsafePointer<CChar>,
    _ data_ptr: UnsafePointer<UInt8>,
    _ data_len: Int,
    _ signature_out: UnsafeMutablePointer<UnsafeMutablePointer<UInt8>?>,
    _ signature_len_out: UnsafeMutablePointer<Int>,
    _ error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    let keyName = String(cString: key_name)
    let data = Data(bytes: data_ptr, count: data_len)

    // Find the key
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyName.data(using: .utf8)!,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnRef as String: true,
    ]

    var keyRef: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &keyRef)

    guard status == errSecSuccess, let privateKey = keyRef as! SecKey? else {
        error_out.pointee = toCString("Key not found: \(keyName)")
        return -1
    }

    // Hash the data
    let digest = SHA256.hash(data: data)
    let digestData = Data(digest)

    // Sign
    var signError: Unmanaged<CFError>?
    guard let signature = SecKeyCreateSignature(
        privateKey,
        .ecdsaSignatureDigestX962SHA256,
        digestData as CFData,
        &signError
    ) as Data? else {
        let errorMsg = signError.map { CFErrorCopyDescription($0.takeRetainedValue()) as String? }
            ?? "Failed to sign"
        error_out.pointee = toCString(errorMsg ?? "Unknown error")
        return -1
    }

    // Allocate and copy signature data
    let signaturePtr = UnsafeMutablePointer<UInt8>.allocate(capacity: signature.count)
    signature.copyBytes(to: signaturePtr, count: signature.count)

    signature_out.pointee = signaturePtr
    signature_len_out.pointee = signature.count

    return 0 // Success
}

@_cdecl("ffi_signature_free")
func ffi_signature_free(_ ptr: UnsafeMutablePointer<UInt8>?, _ len: Int) {
    ptr?.deallocate()
}

// MARK: - Key Listing

@_cdecl("secure_element_list_keys")
func secure_element_list_keys(
    _ key_name_filter: UnsafePointer<CChar>?,
    _ public_key_filter: UnsafePointer<CChar>?,
    _ keys_json_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>,
    _ error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    let keyNameFilter = key_name_filter.map { String(cString: $0) }
    let publicKeyFilter = public_key_filter.map { String(cString: $0) }

    // Query for all Secure Enclave keys
    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        kSecReturnAttributes as String: true,
        kSecReturnData as String: false,
        kSecMatchLimit as String: kSecMatchLimitAll,
    ]

    var result: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &result)

    var keys: [[String: String]] = []

    if status == errSecSuccess, let items = result as? [[String: Any]] {
        for item in items {
            guard let keyNameData = item[kSecAttrApplicationTag as String] as? Data,
                  let keyName = String(data: keyNameData, encoding: .utf8)
            else {
                continue
            }

            // Apply key name filter
            if let filter = keyNameFilter, filter != keyName {
                continue
            }

            // Get public key
            let keyQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: keyNameData,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecReturnRef as String: true,
            ]

            var keyRef: CFTypeRef?
            let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyRef)

            if keyStatus == errSecSuccess, let privateKey = keyRef as! SecKey? {
                if let publicKey = SecKeyCopyPublicKey(privateKey) {
                    var exportError: Unmanaged<CFError>?
                    if let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? {
                        let publicKeyBase64 = publicKeyData.base64EncodedString()

                        // Apply public key filter
                        if let filter = publicKeyFilter, filter != publicKeyBase64 {
                            continue
                        }

                        keys.append([
                            "keyName": keyName,
                            "publicKey": publicKeyBase64,
                        ])
                    }
                }
            }
        }
    } else if status != errSecItemNotFound {
        error_out.pointee = toCString("Failed to query keys: \(status)")
        return -1
    }

    // Convert to JSON
    do {
        let jsonData = try JSONSerialization.data(withJSONObject: keys, options: [])
        if let jsonString = String(data: jsonData, encoding: .utf8) {
            keys_json_out.pointee = toCString(jsonString)
            return 0
        } else {
            error_out.pointee = toCString("Failed to encode JSON")
            return -1
        }
    } catch {
        error_out.pointee = toCString("Failed to serialize JSON: \(error)")
        return -1
    }
}

// MARK: - Key Deletion

@_cdecl("secure_element_delete_key")
func secure_element_delete_key(
    _ key_name: UnsafePointer<CChar>,
    _ error_out: UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>
) -> Int32 {
    let keyName = String(cString: key_name)

    let query: [String: Any] = [
        kSecClass as String: kSecClassKey,
        kSecAttrApplicationTag as String: keyName.data(using: .utf8)!,
        kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
    ]

    let status = SecItemDelete(query as CFDictionary)

    // Success if deleted or didn't exist (idempotent)
    if status == errSecSuccess || status == errSecItemNotFound {
        return 0
    } else {
        error_out.pointee = toCString("Failed to delete key: \(status)")
        return -1
    }
}

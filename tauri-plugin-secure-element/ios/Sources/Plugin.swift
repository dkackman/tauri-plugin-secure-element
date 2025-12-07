import CryptoKit
import Foundation
import LocalAuthentication
import os.log
import Security
import SwiftRs
import Tauri
import UIKit
import WebKit

// MARK: - Request Models

class PingArgs: Decodable {
    let value: String?
}

class GenerateSecureKeyArgs: Decodable {
    let keyName: String
    let authMode: String? // "none", "pinOrBiometric", or "biometricOnly"
}

class ListKeysArgs: Decodable {
    let keyName: String?
    let publicKey: String?
}

class SignWithKeyArgs: Decodable {
    let keyName: String
    let data: [UInt8]
    // Note: Authentication is enforced automatically by Secure Enclave based on the key's access control
}

class DeleteKeyArgs: Decodable {
    let keyName: String
    // Note: Authentication requirements are determined by the key's own attributes
}

// MARK: - SecureEnclavePlugin

class SecureEnclavePlugin: Plugin {
    /// Logger for error tracking (consistent with Android's Log.e pattern)
    private static let logger = OSLog(subsystem: "app.tauri.plugin.secureelement", category: "SecureEnclave")
    
    /// Returns a detailed error message in debug builds, generic message in release builds
    /// This prevents information disclosure in production while helping developers debug
    private func sanitizeError(_ detailedMessage: String, genericMessage: String) -> String {
        #if DEBUG
        return detailedMessage
        #else
        return genericMessage
        #endif
    }
    
    /// Returns error message with key name in debug builds only
    private func sanitizeErrorWithKeyName(_ keyName: String, operation: String) -> String {
        #if DEBUG
        return "\(operation): \(keyName)"
        #else
        return operation
        #endif
    }
    
    /// Logs an error consistently (matches Android's Log.e pattern)
    /// Always logs detailed error for debugging, but only returns sanitized message to client
    private func logError(_ operation: String, error: String, detailedError: String? = nil) {
        let logMessage = detailedError ?? error
        os_log("%{public}@: %{private}@", log: Self.logger, type: .error, operation, logMessage)
    }
    
    /// Converts authentication mode string to SecAccessControlCreateFlags
    private func getAccessControlFlags(authMode: String?) -> SecAccessControlCreateFlags {
        let mode = authMode ?? "pinOrBiometric"

        // .privateKeyUsage is REQUIRED for Secure Enclave keys
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

        return flags
    }

    // MARK: - Key Operations Helpers
    
    /// Converts key name string to Data, handling errors consistently
    private func keyNameToData(_ keyName: String, operation: String, invoke: Invoke) -> Data? {
        guard let keyNameData = keyName.data(using: .utf8) else {
            let message = "Invalid key name"
            logError(operation, error: message)
            invoke.reject(message)
            return nil
        }
        return keyNameData
    }
    
    /// Creates a base query dictionary for Secure Enclave key operations
    private func createKeyQuery(keyNameData: Data, returnRef: Bool = true) -> [String: Any] {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyNameData,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ]
        if returnRef {
            query[kSecReturnRef as String] = true
        }
        return query
    }
    
    /// Looks up a key by name and returns the SecKey, handling errors
    private func lookupKey(keyName: String, keyNameData: Data, operation: String, invoke: Invoke) -> SecKey? {
        let query = createKeyQuery(keyNameData: keyNameData, returnRef: true)
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)

        // Accept both errSecSuccess and errSecInteractionNotAllowed
        // errSecInteractionNotAllowed can occur for auth-required keys, but authentication
        // will be enforced later when the key is actually used (e.g., during SecKeyCreateSignature)
        guard (status == errSecSuccess || status == errSecInteractionNotAllowed), let keyRef = keyRef else {
            let message = sanitizeErrorWithKeyName(keyName, operation: "Key not found")
            logError(operation, error: message, detailedError: "Key not found: \(keyName), status: \(status)")
            invoke.reject(message)
            return nil
        }

        // keyRef is already SecKey (typealias for CFTypeRef) when errSecSuccess or errSecInteractionNotAllowed
        // SecKey is a typealias for CFTypeRef, so we can use it directly
        // swiftlint:disable:next force_cast
        return keyRef as! SecKey // Safe: SecKey is typealias for CFTypeRef
    }
    
    /// Extracts and exports a public key from a private key as base64
    private func exportPublicKeyBase64(privateKey: SecKey, operation: String, invoke: Invoke) -> String? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            let message = "Failed to extract public key"
            logError(operation, error: message)
            invoke.reject(message)
            return nil
        }
        
        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            if let error = exportError {
                let errorDescription = extractCFErrorDescription(error)
                let detailedMessage = "Failed to export public key: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to export public key")
                logError(operation, error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return nil
            }
            let message = "Failed to export public key"
            logError(operation, error: message)
            invoke.reject(message)
            return nil
        }
        
        return publicKeyData.base64EncodedString()
    }
    
    /// Extracts and exports a public key from a private key as base64 (non-rejecting version for loops)
    private func exportPublicKeyBase64Silent(privateKey: SecKey) -> String? {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return nil
        }
        
        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            return nil
        }
        
        return publicKeyData.base64EncodedString()
    }
    
    /// Looks up a key by name and returns the SecKey (non-rejecting version for loops)
    private func lookupKeySilent(keyNameData: Data) -> SecKey? {
        let query = createKeyQuery(keyNameData: keyNameData, returnRef: true)
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)
        
        guard status == errSecSuccess, let keyRef = keyRef else {
            return nil
        }
        
        // swiftlint:disable:next force_cast
        return keyRef as! SecKey // Safe: SecKey is typealias for CFTypeRef
    }
    
    /// Extracts error description from CFError
    private func extractCFErrorDescription(_ error: Unmanaged<CFError>) -> String {
        return CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
    }
    
    /// Checks if running on simulator and rejects if so
    private func checkSimulator(operation: String, invoke: Invoke) -> Bool {
        #if targetEnvironment(simulator)
        let message = "Secure Enclave is not available on iOS Simulator. Please test on a physical device."
        logError(operation, error: message)
        invoke.reject(message)
        return true
        #else
        return false
        #endif
    }
    
    /// Creates access control for Secure Enclave keys
    private func createAccessControl(authMode: String?, operation: String, invoke: Invoke) -> SecAccessControl? {
        let flags = getAccessControlFlags(authMode: authMode)
        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            if let error = accessError {
                let errorDescription = extractCFErrorDescription(error)
                let detailedMessage = "Failed to create access control: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to create access control")
                logError(operation, error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return nil
            }
            let message = "Failed to create access control"
            logError(operation, error: message)
            invoke.reject(message)
            return nil
        }
        return accessControl
    }
    
    /// Determines if a key requires authentication by checking its access control attributes
    /// Returns true if authentication is required, false if not, or nil if it cannot be determined
    ///
    /// Note: This is a best-effort attempt. The Secure Enclave enforces access control during
    /// key usage (e.g., SecKeyCreateSignature), so this method is for informational purposes only.
    private func keyRequiresAuthentication(keyNameData: Data) -> Bool? {
        // Query for the key's attributes including access control
        var query = createKeyQuery(keyNameData: keyNameData, returnRef: true)
        query[kSecReturnAttributes as String] = true

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        // If we can't get the key at all, return nil
        guard status == errSecSuccess || status == errSecInteractionNotAllowed else {
            return nil
        }

        // Try to extract access control information from attributes
        if let attributes = result as? [String: Any],
           let accessControl = attributes[kSecAttrAccessControl as String] as CFTypeRef? {
            // If the key has access control set, check the flags
            let flags = SecAccessControlGetConstraints(accessControl as! SecAccessControl)

            // If access control exists with constraints, authentication is likely required
            // Keys with only .privateKeyUsage don't require user authentication
            // Keys with .userPresence or .biometryCurrentSet do require authentication
            if flags != nil {
                return true
            }
        }

        // If we successfully retrieved the key without any access control constraints,
        // it likely doesn't require authentication
        if status == errSecSuccess {
            return false
        }

        // Default: can't determine
        return nil
    }
    
    /// Checks if a key with the given name already exists
    private func checkKeyExists(keyName: String, keyNameData: Data, operation: String, invoke: Invoke) -> Bool {
        let checkQuery = createKeyQuery(keyNameData: keyNameData, returnRef: false)
        var checkResult: CFTypeRef?
        let checkStatus = SecItemCopyMatching(checkQuery as CFDictionary, &checkResult)
        
        if checkStatus == errSecSuccess {
            // Key already exists
            let message = sanitizeErrorWithKeyName(keyName, operation: "Key already exists")
            logError(operation, error: message, detailedError: "Key already exists: \(keyName)")
            invoke.reject(message)
            return true
        } else if checkStatus != errSecItemNotFound {
            // Unexpected error while checking
            let detailedMessage = "Failed to check for existing key: \(checkStatus)"
            let message = sanitizeError(detailedMessage, genericMessage: "Failed to check for existing key")
            logError(operation, error: message, detailedError: detailedMessage)
            invoke.reject(message)
            return true
        }
        return false // Key doesn't exist, which is what we want
    }
    
    /// Creates a Secure Enclave key with the given attributes
    private func createSecureEnclaveKey(keyNameData: Data, accessControl: SecAccessControl, operation: String, invoke: Invoke) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: keyNameData,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error = error {
                let errorDescription = extractCFErrorDescription(error)
                let detailedMessage = "Failed to create key: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to create key")
                logError(operation, error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return nil
            }
            let message = "Failed to create key"
            logError(operation, error: message)
            invoke.reject(message)
            return nil
        }
        return privateKey
    }
}

@_cdecl("init_plugin_secure_element")
func initPlugin() -> Plugin {
    return SecureEnclavePlugin()
}

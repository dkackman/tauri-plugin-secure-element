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
    let authMode: String? // "none", "pinOrBiometric", or "biometricOnly"
}

class DeleteKeyArgs: Decodable {
    let keyName: String
    let authMode: String? // "none", "pinOrBiometric", or "biometricOnly"
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
    
    /// Authenticates the user using LocalAuthentication based on auth mode
    private func authenticateUser(authMode: String?, reason: String, completion: @escaping (Bool, String?) -> Void) {
        let mode = authMode ?? "pinOrBiometric"
        
        // For "none" mode, skip authentication
        if mode == "none" {
            completion(true, nil)
            return
        }
        
        let context = LAContext()
        var error: NSError?
        var policy: LAPolicy = .deviceOwnerAuthentication
        
        // For biometric-only, use biometric policy
        if mode == "biometricOnly" {
            if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
                policy = .deviceOwnerAuthenticationWithBiometrics
            } else {
                completion(false, "Biometric authentication is not available")
                return
            }
        }
        
        context.evaluatePolicy(policy, localizedReason: reason) { success, error in
            DispatchQueue.main.async {
                if success {
                    completion(true, nil)
                } else {
                    let errorMessage = error?.localizedDescription ?? "Authentication failed"
                    completion(false, errorMessage)
                }
            }
        }
    }
    // MARK: - Ping (for testing)

    @objc func ping(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PingArgs.self)
        invoke.resolve(["value": args.value ?? ""])
    }

    // MARK: - Generate Secure Key

    @objc func generateSecureKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(GenerateSecureKeyArgs.self)

        // Check if we're running on a simulator
        #if targetEnvironment(simulator)
            // iOS Simulator does not have Secure Enclave hardware
            let message = "Secure Enclave is not available on iOS Simulator. Please test on a physical device."
            logError("generateSecureKey", error: message)
            invoke.reject(message)
            return
        #endif

        // Create access control - keys are only accessible when device is unlocked
        // .privateKeyUsage flag is REQUIRED for Secure Enclave keys
        let flags = getAccessControlFlags(authMode: args.authMode)
        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            if let error = accessError {
                let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                let detailedMessage = "Failed to create access control: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to create access control")
                logError("generateSecureKey", error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return
            }
            let message = "Failed to create access control"
            logError("generateSecureKey", error: message)
            invoke.reject(message)
            return
        }

        // Create key attributes for Secure Enclave
        // Safely convert key name to data
        guard let keyNameData = args.keyName.data(using: .utf8) else {
            let message = "Invalid key name encoding"
            logError("generateSecureKey", error: message)
            invoke.reject(message)
            return
        }
        
        // Check if a key with this name already exists
        // This prevents accidental overwrites and ensures consistent behavior with Android
        let checkQuery: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyNameData,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: false, // We only need to know if it exists
        ]
        
        var checkResult: CFTypeRef?
        let checkStatus = SecItemCopyMatching(checkQuery as CFDictionary, &checkResult)
        
        if checkStatus == errSecSuccess {
            // Key already exists
            let message = sanitizeErrorWithKeyName(args.keyName, operation: "Key already exists")
            logError("generateSecureKey", error: message, detailedError: "Key already exists: \(args.keyName)")
            invoke.reject(message)
            return
        } else if checkStatus != errSecItemNotFound {
            // Unexpected error while checking
            let detailedMessage = "Failed to check for existing key: \(checkStatus)"
            let message = sanitizeError(detailedMessage, genericMessage: "Failed to check for existing key")
            logError("generateSecureKey", error: message, detailedError: detailedMessage)
            invoke.reject(message)
            return
        }
        // errSecItemNotFound means key doesn't exist, which is what we want - continue
        
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: true, // Non-ephemeral key
            kSecAttrApplicationTag as String: keyNameData,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error = error {
                let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                let detailedMessage = "Failed to create key: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to create key")
                logError("generateSecureKey", error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return
            }
            let message = "Failed to create key"
            logError("generateSecureKey", error: message)
            invoke.reject(message)
            return
        }

        // Extract the public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            let message = "Failed to extract public key"
            logError("generateSecureKey", error: message)
            invoke.reject(message)
            return
        }

        // Export public key as DER format
        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            if let error = exportError {
                let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                let detailedMessage = "Failed to export public key: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to export public key")
                logError("generateSecureKey", error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return
            }
            let message = "Failed to export public key"
            logError("generateSecureKey", error: message)
            invoke.reject(message)
            return
        }

        // Convert to base64
        let publicKeyBase64 = publicKeyData.base64EncodedString()

        invoke.resolve([
            "publicKey": publicKeyBase64,
            "keyName": args.keyName,
        ])
    }

    // MARK: - List Keys

    @objc func listKeys(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(ListKeysArgs.self)

        // Query for all keys in Secure Enclave
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: false,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        var keys: [[String: Any]] = []

        if status == errSecSuccess, let items = result as? [[String: Any]] {
            for item in items {
                guard let keyNameData = item[kSecAttrApplicationTag as String] as? Data,
                      let keyName = String(data: keyNameData, encoding: .utf8)
                else {
                    continue
                }

                // Apply filters if provided
                if let filterName = args.keyName, filterName != keyName {
                    continue
                }

                // Get the public key for this private key
                // We need to reconstruct the key reference to get the public key
                let keyQuery: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: keyNameData,
                    kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                    kSecReturnRef as String: true,
                ]

                var keyRef: CFTypeRef?
                let keyStatus = SecItemCopyMatching(keyQuery as CFDictionary, &keyRef)

                if keyStatus == errSecSuccess, let keyRef = keyRef {
                    // keyRef is already SecKey (typealias for CFTypeRef) when errSecSuccess
                    // SecKey is a typealias for CFTypeRef, so we can use it directly
                    // Suppress compiler warning: conditional downcast always succeeds for typealias
                    // swiftlint:disable:next force_cast
                    let privateKey = keyRef as! SecKey // Safe: SecKey is typealias for CFTypeRef
                    if let publicKey = SecKeyCopyPublicKey(privateKey) {
                        var exportError: Unmanaged<CFError>?
                        if let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? {
                            let publicKeyBase64 = publicKeyData.base64EncodedString()

                            // Apply public key filter if provided
                            if let filterPublicKey = args.publicKey, filterPublicKey != publicKeyBase64 {
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
            let detailedMessage = "Failed to query keys: \(status)"
            let message = sanitizeError(detailedMessage, genericMessage: "Failed to query keys")
            logError("listKeys", error: message, detailedError: detailedMessage)
            invoke.reject(message)
            return
        }

        invoke.resolve(["keys": keys])
    }

    // MARK: - Sign With Key

    @objc func signWithKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SignWithKeyArgs.self)

        // Find the key by name
        guard let keyNameData = args.keyName.data(using: .utf8) else {
            let message = "Invalid key name"
            logError("signWithKey", error: message)
            invoke.reject(message)
            return
        }

        // Require authentication before signing
        authenticateUser(authMode: args.authMode, reason: "Authenticate to sign with secure key") { success, errorMessage in
            if !success {
                let message = errorMessage ?? "Authentication failed"
                self.logError("signWithKey", error: message)
                invoke.reject(message)
                return
            }

            // Authentication successful, proceed with signing
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: keyNameData,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
                kSecReturnRef as String: true,
            ]

            var keyRef: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &keyRef)

            guard status == errSecSuccess, let keyRef = keyRef else {
                let message = self.sanitizeErrorWithKeyName(args.keyName, operation: "Key not found")
                self.logError("signWithKey", error: message, detailedError: "Key not found: \(args.keyName)")
                invoke.reject(message)
                return
            }

            // keyRef is already SecKey (typealias for CFTypeRef) when errSecSuccess
            // SecKey is a typealias for CFTypeRef, so we can use it directly
            // Suppress compiler warning: conditional downcast always succeeds for typealias
            // swiftlint:disable:next force_cast
            let privateKey = keyRef as! SecKey // Safe: SecKey is typealias for CFTypeRef

            // Convert data to Data type
            let dataToSign = Data(args.data)

            // Create SHA256 digest using CryptoKit
            let digest = SHA256.hash(data: dataToSign)
            let digestData = Data(digest)

            // Sign the digest using ECDSA
            var signError: Unmanaged<CFError>?
            guard let signature = SecKeyCreateSignature(
                privateKey,
                .ecdsaSignatureDigestX962SHA256,
                digestData as CFData,
                &signError
            ) as Data? else {
                if let error = signError {
                    let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                    let detailedMessage = "Failed to sign: \(errorDescription)"
                    let message = self.sanitizeError(detailedMessage, genericMessage: "Failed to sign")
                    self.logError("signWithKey", error: message, detailedError: detailedMessage)
                    invoke.reject(message)
                    return
                }
                let message = "Failed to sign"
                self.logError("signWithKey", error: message)
                invoke.reject(message)
                return
            }

            invoke.resolve(["signature": [UInt8](signature)])
        }
    }

    // MARK: - Delete Key

    @objc func deleteKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(DeleteKeyArgs.self)

        guard let keyNameData = args.keyName.data(using: .utf8) else {
            let message = "Invalid key name"
            logError("deleteKey", error: message)
            invoke.reject(message)
            return
        }

        // Require authentication before deletion
        authenticateUser(authMode: args.authMode, reason: "Authenticate to delete secure key") { success, errorMessage in
            if !success {
                let message = errorMessage ?? "Authentication failed"
                self.logError("deleteKey", error: message)
                invoke.reject(message)
                return
            }

            // Authentication successful, proceed with deletion
            let query: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrApplicationTag as String: keyNameData,
                kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            ]

            let status = SecItemDelete(query as CFDictionary)

            if status == errSecSuccess || status == errSecItemNotFound {
                invoke.resolve(["success": true])
            } else {
                let detailedMessage = "Failed to delete key: \(status)"
                let message = self.sanitizeError(detailedMessage, genericMessage: "Failed to delete key")
                self.logError("deleteKey", error: message, detailedError: detailedMessage)
                invoke.reject(message)
            }
        }
    }

    // MARK: - Check Secure Element Support

    @objc func checkSecureElementSupport(_ invoke: Invoke) throws {
        // Check if we're running on a simulator
        #if targetEnvironment(simulator)
            // iOS Simulator does not have Secure Enclave hardware
            // Secure Enclave IS the TEE on iOS, so both are false on simulator
            invoke.resolve([
                "secureElementSupported": false,
                "teeSupported": false,
            ])
            return
        #endif

        // On physical devices, check if Secure Enclave is available
        // by attempting to create a test key with Secure Enclave token ID
        // On iOS, Secure Enclave IS the TEE (Trusted Execution Environment)
        var accessError: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence] // Default auth mode for support check
        guard SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) != nil else {
            // If we can't create access control, Secure Enclave/TEE is not available
            invoke.resolve([
                "secureElementSupported": false,
                "teeSupported": false,
            ])
            return
        }

        // Try to create a test key with Secure Enclave token ID
        // Use a unique tag to identify our test key for cleanup
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

        // Always clean up the test key explicitly, even if ephemeral
        // This prevents resource leakage if the function is called repeatedly
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

        if testKey != nil {
            // Successfully created a key, Secure Enclave is available
            // On iOS, Secure Enclave IS the TEE, so both are true
            invoke.resolve([
                "secureElementSupported": true,
                "teeSupported": true, // Secure Enclave is iOS's TEE
            ])
        } else {
            // Failed to create key, Secure Enclave/TEE is not available
            invoke.resolve([
                "secureElementSupported": false,
                "teeSupported": false,
            ])
        }
    }
}

@_cdecl("init_plugin_secure_element")
func initPlugin() -> Plugin {
    return SecureEnclavePlugin()
}

import Foundation
import os.log
import Security
import Tauri
#if os(iOS)
    import UIKit
    import WebKit
#endif

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
}

class DeleteKeyArgs: Decodable {
    let keyName: String?
    let publicKey: String?
}

// MARK: - SecureEnclavePlugin

class SecureEnclavePlugin: Plugin {
    /// Logger for error tracking
    private static let logger = OSLog(subsystem: "net.kackman.secureelement", category: "SecureEnclave")

    /// Logs an error
    private func logError(_ operation: String, error: String) {
        os_log("%{public}@: %{private}@", log: Self.logger, type: .error, operation, error)
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

    /// Creates a base query dictionary for Secure Enclave key operations
    private func createKeyQuery(keyName: String, returnRef: Bool = true) -> [String: Any] {
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

    /// Looks up a key by name and returns the SecKey, handling errors
    private func lookupKey(keyName: String, operation: String, invoke: Invoke) -> SecKey? {
        let query = createKeyQuery(keyName: keyName, returnRef: true)
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)

        // Accept both errSecSuccess and errSecInteractionNotAllowed
        // errSecInteractionNotAllowed can occur for auth-required keys, but authentication
        // will be enforced later when the key is actually used (e.g., during SecKeyCreateSignature)
        guard status == errSecSuccess || status == errSecInteractionNotAllowed, let keyRef = keyRef else {
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

    /// Checks if a key with the given name already exists
    private func checkKeyExists(keyName: String, operation: String, invoke: Invoke) -> Bool {
        let checkQuery = createKeyQuery(keyName: keyName, returnRef: false)
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

        return false
    }

    /// Creates a Secure Enclave key with the given attributes
    private func createSecureEnclaveKey(keyName: String, accessControl: SecAccessControl, operation: String, invoke: Invoke) -> SecKey? {
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: true,
            kSecAttrLabel as String: keyName,
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

    // MARK: - Command Implementations

    // MARK: - Ping (for testing)

    @objc func ping(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PingArgs.self)
        invoke.resolve(["value": args.value ?? ""])
    }

    // MARK: - Generate Secure Key

    @objc func generateSecureKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(GenerateSecureKeyArgs.self)

        switch SecureEnclaveCore.generateSecureKey(keyName: args.keyName, authMode: args.authMode) {
        case let .success(response):
            invoke.resolve([
                "publicKey": response.publicKey,
                "keyName": response.keyName,
            ])
        case let .failure(error):
            logError("generateSecureKey", error: error.localizedDescription)
            invoke.reject(error.localizedDescription)
        }

        // Create access control - keys are only accessible when device is unlocked
        guard let accessControl = createAccessControl(authMode: args.authMode, operation: "generateSecureKey", invoke: invoke) else {
            return
        }

        // Check if a key with this name already exists
        if checkKeyExists(keyName: args.keyName, operation: "generateSecureKey", invoke: invoke) {
            return
        }

        // Create the Secure Enclave key
        guard let privateKey = createSecureEnclaveKey(keyName: args.keyName, accessControl: accessControl, operation: "generateSecureKey", invoke: invoke) else {
            return
        }

        // Extract and export public key
        guard let publicKeyBase64 = exportPublicKeyBase64(privateKey: privateKey, operation: "generateSecureKey", invoke: invoke) else {
            return
        }

        invoke.resolve([
            "publicKey": publicKeyBase64,
            "keyName": args.keyName,
            "hardwareBacking": "secureEnclave",
        ])
    }

    // MARK: - List Keys

    @objc func listKeys(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(ListKeysArgs.self)

        // Query for all keys in Secure Enclave
        // Request both attributes and key references to avoid a second lookup
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
                guard let keyRef = item[kSecValueRef as String] as? CFTypeRef
                else {
                    continue
                }
                // kSecValueRef returns a SecKey when kSecReturnRef is true
                // swiftlint:disable:next force_cast
                let privateKey = keyRef as! SecKey

                // Extract key name from kSecAttrLabel, default to "<unnamed>" if missing or empty
                let keyNameLabel = (item[kSecAttrLabel as String] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
                let keyName = keyNameLabel?.isEmpty == false ? keyNameLabel! : "<unnamed>"

                // Apply filters if provided
                if let filterName = args.keyName, filterName != keyName {
                    continue
                }

                // Get the public key for this private key
                // Use the key reference from the initial query
                if let publicKeyBase64 = exportPublicKeyBase64Silent(privateKey: privateKey) {
                    if let filterPublicKey = args.publicKey, filterPublicKey != publicKeyBase64 {
                        continue
                    }

                    let keyInfo: [String: Any] = [
                        "keyName": keyName,
                        "publicKey": publicKeyBase64,
                    ]
                    keys.append(keyInfo)
                }
                return info
            }
            invoke.resolve(["keys": keys])
        case let .failure(error):
            logError("listKeys", error: error.localizedDescription)
            invoke.reject(error.localizedDescription)
        }
    }

    // MARK: - Sign With Key

    @objc func signWithKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SignWithKeyArgs.self)
        let dataToSign = Data(args.data)

        switch SecureEnclaveCore.signWithKey(keyName: args.keyName, data: dataToSign) {
        case let .success(response):
            invoke.resolve(["signature": [UInt8](response.signature)])
        case let .failure(error):
            logError("signWithKey", error: error.localizedDescription)
            invoke.reject(error.localizedDescription)
        }
    }

    // MARK: - Delete Key

    @objc func deleteKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(DeleteKeyArgs.self)

        // If keyName is provided, delete by name (fast path)
        if let keyName = args.keyName {
            let query = createKeyQuery(keyName: keyName, returnRef: false)
            let status = SecItemDelete(query as CFDictionary)

            if status == errSecSuccess || status == errSecItemNotFound {
                invoke.resolve(["success": true])
            } else {
                let detailedMessage = "Failed to delete key: \(status)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to delete key")
                logError("deleteKey", error: message, detailedError: detailedMessage)
                invoke.reject(message)
            }
            return
        }

        // If publicKey is provided, find the key by public key and delete it
        guard let targetPublicKey = args.publicKey else {
            return
        }

        // Query for all keys in Secure Enclave
        // Request both attributes and key references to avoid a second lookup
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
                guard let keyRef = item[kSecValueRef as String] as? CFTypeRef
                else {
                    continue
                }
                // kSecValueRef returns a SecKey when kSecReturnRef is true
                // swiftlint:disable:next force_cast
                let privateKey = keyRef as! SecKey

                // Get the public key for this private key
                // Use the key reference from the initial query
                if let publicKeyBase64 = exportPublicKeyBase64Silent(privateKey: privateKey),
                   publicKeyBase64 == targetPublicKey
                // swiftlint:disable:next opening_brace
                {
                    // Extract key name from kSecAttrLabel for deletion
                    let keyNameLabel = (item[kSecAttrLabel as String] as? String)?.trimmingCharacters(in: .whitespacesAndNewlines)
                    let keyName = keyNameLabel?.isEmpty == false ? keyNameLabel! : "<unnamed>"

                    // Found the matching key, delete it
                    let deleteQuery = createKeyQuery(keyName: keyName, returnRef: false)
                    let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)

                    if deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound {
                        invoke.resolve(["success": true])
                    } else {
                        let detailedMessage = "Failed to delete key: \(deleteStatus)"
                        let message = sanitizeError(detailedMessage, genericMessage: "Failed to delete key")
                        logError("deleteKey", error: message, detailedError: detailedMessage)
                        invoke.reject(message)
                    }
                    return
                }
            }

            // Key not found by public key, return success (idempotent)
            invoke.resolve(["success": true])
        case let .failure(error):
            logError("deleteKey", error: error.localizedDescription)
            invoke.reject(error.localizedDescription)
        }
    }

    // MARK: - Check Secure Element Support

    @objc func checkSecureElementSupport(_ invoke: Invoke) throws {
        let response = SecureEnclaveCore.checkSupport()
        invoke.resolve([
            "secureElementSupported": response.secureElementSupported,
            "teeSupported": response.teeSupported,
            "canEnforceBiometricOnly": response.canEnforceBiometricOnly,
        ])
    }
}

@_cdecl("init_plugin_secure_element")
func initPlugin() -> Plugin {
    return SecureEnclavePlugin()
}

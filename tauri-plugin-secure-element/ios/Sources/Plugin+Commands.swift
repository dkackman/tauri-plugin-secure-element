import CryptoKit
import Foundation
import LocalAuthentication
import os.log
import Security
import SwiftRs
import Tauri

// MARK: - Command Implementations

extension SecureEnclavePlugin {
    // MARK: - Ping (for testing)

    @objc func ping(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PingArgs.self)
        invoke.resolve(["value": args.value ?? ""])
    }

    // MARK: - Generate Secure Key

    @objc func generateSecureKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(GenerateSecureKeyArgs.self)

        // Check if we're running on a simulator
        if checkSimulator(operation: "generateSecureKey", invoke: invoke) {
            return
        }

        // Create access control - keys are only accessible when device is unlocked
        guard let accessControl = createAccessControl(authMode: args.authMode, operation: "generateSecureKey", invoke: invoke) else {
            return
        }

        // Safely convert key name to data
        guard let keyNameData = keyNameToData(args.keyName, operation: "generateSecureKey", invoke: invoke) else {
            return
        }
        
        // Check if a key with this name already exists
        if checkKeyExists(keyName: args.keyName, keyNameData: keyNameData, operation: "generateSecureKey", invoke: invoke) {
            return
        }
        
        // Create the Secure Enclave key
        guard let privateKey = createSecureEnclaveKey(keyNameData: keyNameData, accessControl: accessControl, operation: "generateSecureKey", invoke: invoke) else {
            return
        }

        // Extract and export public key
        guard let publicKeyBase64 = exportPublicKeyBase64(privateKey: privateKey, operation: "generateSecureKey", invoke: invoke) else {
            return
        }

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
                if let privateKey = lookupKeySilent(keyNameData: keyNameData),
                    let publicKeyBase64 = exportPublicKeyBase64Silent(privateKey: privateKey) {
                    if let filterPublicKey = args.publicKey, filterPublicKey != publicKeyBase64 {
                        continue
                    }

                    let requiresAuth = keyRequiresAuthentication(keyNameData: keyNameData)

                    var keyInfo: [String: Any] = [
                        "keyName": keyName,
                        "publicKey": publicKeyBase64,
                    ]
                    if let requiresAuth = requiresAuth {
                        keyInfo["requiresAuthentication"] = requiresAuth
                    }
                    keys.append(keyInfo)
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
        guard let keyNameData = keyNameToData(args.keyName, operation: "signWithKey", invoke: invoke) else {
            return
        }

        // Secure Enclave automatically enforces the key's access control requirements
        // when using the key. No explicit authentication needed - the platform handles it.
        guard let privateKey = lookupKey(keyName: args.keyName, keyNameData: keyNameData, operation: "signWithKey", invoke: invoke) else {
            return
        }

        // Convert data to Data type
        let dataToSign = Data(args.data)

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
                let errorDescription = extractCFErrorDescription(error)
                let detailedMessage = "Failed to sign: \(errorDescription)"
                let message = sanitizeError(detailedMessage, genericMessage: "Failed to sign")
                logError("signWithKey", error: message, detailedError: detailedMessage)
                invoke.reject(message)
                return
            }
            let message = "Failed to sign"
            logError("signWithKey", error: message)
            invoke.reject(message)
            return
        }

        invoke.resolve(["signature": [UInt8](signature)])
    }

    // MARK: - Delete Key

    @objc func deleteKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(DeleteKeyArgs.self)

        guard let keyNameData = keyNameToData(args.keyName, operation: "deleteKey", invoke: invoke) else {
            return
        }

        let query = createKeyQuery(keyNameData: keyNameData, returnRef: false)
        let status = SecItemDelete(query as CFDictionary)

        if status == errSecSuccess || status == errSecItemNotFound {
            invoke.resolve(["success": true])
        } else {
            let detailedMessage = "Failed to delete key: \(status)"
            let message = sanitizeError(detailedMessage, genericMessage: "Failed to delete key")
            logError("deleteKey", error: message, detailedError: detailedMessage)
            invoke.reject(message)
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


import CryptoKit
import Foundation
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
    let keyName: String
}

// MARK: - SecureEnclavePlugin

class SecureEnclavePlugin: Plugin {
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
    // MARK: - Ping (for testing)

    @objc func ping(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(PingArgs.self)
        invoke.resolve(["value": args.value ?? ""])
    }

    // MARK: - Generate Secure Key

    @objc func generateSecureKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(GenerateSecureKeyArgs.self)

        // Create access control - keys are only accessible when device is unlocked
        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            &accessError
        ) else {
            if let error = accessError {
                let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                let message = sanitizeError(
                    "Failed to create access control: \(errorDescription)",
                    genericMessage: "Failed to create access control"
                )
                invoke.reject(message)
                return
            }
            invoke.reject("Failed to create access control")
            return
        }

        // Create key attributes for Secure Enclave
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: true, // Non-ephemeral key
            kSecAttrApplicationTag as String: args.keyName.data(using: .utf8)!,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrAccessControl as String: accessControl,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error = error {
                let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                let message = sanitizeError(
                    "Failed to create key: \(errorDescription)",
                    genericMessage: "Failed to create key"
                )
                invoke.reject(message)
                return
            }
            invoke.reject("Failed to create key")
            return
        }

        // Extract the public key
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            invoke.reject("Failed to extract public key")
            return
        }

        // Export public key as DER format
        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            if let error = exportError {
                let errorDescription = CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
                let message = sanitizeError(
                    "Failed to export public key: \(errorDescription)",
                    genericMessage: "Failed to export public key"
                )
                invoke.reject(message)
                return
            }
            invoke.reject("Failed to export public key")
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
                    // Force cast is safe here: we've verified errSecSuccess and the query returns SecKey
                    // swiftlint:disable:next force_cast
                    let privateKey = (keyRef as! SecKey) // swiftlint:disable:this force_cast
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
            let message = sanitizeError(
                "Failed to query keys: \(status)",
                genericMessage: "Failed to query keys"
            )
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
            invoke.reject("Invalid key name")
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyNameData,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecReturnRef as String: true,
        ]

        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)

        guard status == errSecSuccess, let keyRef = keyRef else {
            let message = sanitizeErrorWithKeyName(args.keyName, operation: "Key not found")
            invoke.reject(message)
            return
        }

        // Force cast is safe here: we've verified errSecSuccess and the query returns SecKey
        // swiftlint:disable:next force_cast
        let privateKey = (keyRef as! SecKey) // swiftlint:disable:this force_cast

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
                let message = sanitizeError(
                    "Failed to sign: \(errorDescription)",
                    genericMessage: "Failed to sign"
                )
                invoke.reject(message)
                return
            }
            invoke.reject("Failed to sign")
            return
        }

        invoke.resolve(["signature": [UInt8](signature)])
    }

    // MARK: - Delete Key

    @objc func deleteKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(DeleteKeyArgs.self)

        guard let keyNameData = args.keyName.data(using: .utf8) else {
            invoke.reject("Invalid key name")
            return
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: keyNameData,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
        ]

        let status = SecItemDelete(query as CFDictionary)

        if status == errSecSuccess || status == errSecItemNotFound {
            invoke.resolve(["success": true])
        } else {
            let message = sanitizeError(
                "Failed to delete key: \(status)",
                genericMessage: "Failed to delete key"
            )
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
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [],
            &accessError
        ) else {
            // If we can't create access control, Secure Enclave/TEE is not available
            invoke.resolve([
                "secureElementSupported": false,
                "teeSupported": false,
            ])
            return
        }

        // Try to create a test key with Secure Enclave token ID
        let testAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: false, // Temporary key for testing
        ]

        var testError: Unmanaged<CFError>?
        let testKey = SecKeyCreateRandomKey(testAttributes as CFDictionary, &testError)

        if testKey != nil {
            // Successfully created a key, Secure Enclave is available
            // On iOS, Secure Enclave IS the TEE, so both are true
            // Note: Since kSecAttrIsPermanent is false, the test key is ephemeral
            // and will be automatically cleaned up when the reference is released
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

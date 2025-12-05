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
                invoke.reject("Failed to create access control: \(errorDescription)")
                return
            }
            invoke.reject("Failed to create access control: Unknown error")
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
                invoke.reject("Failed to create key: \(errorDescription)")
                return
            }
            invoke.reject("Failed to create key: Unknown error")
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
                invoke.reject("Failed to export public key: \(errorDescription)")
                return
            }
            invoke.reject("Failed to export public key: Unknown error")
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

                if keyStatus == errSecSuccess, let privateKey = keyRef as! SecKey? {
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
            invoke.reject("Failed to query keys: \(status)")
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

        guard status == errSecSuccess, let privateKey = keyRef as! SecKey? else {
            invoke.reject("Key not found: \(args.keyName)")
            return
        }

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
                invoke.reject("Failed to sign: \(errorDescription)")
                return
            }
            invoke.reject("Failed to sign: Unknown error")
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
            invoke.reject("Failed to delete key: \(status)")
        }
    }
}

@_cdecl("init_plugin_secure_element")
func initPlugin() -> Plugin {
    return SecureEnclavePlugin()
}

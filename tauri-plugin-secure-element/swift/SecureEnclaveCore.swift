import CryptoKit
import Foundation
import LocalAuthentication
import Security

// this files is shared with symlink in the swift folder
// so any changes to this file will be reflected in the swift folder
// and vice versa
// this is to accommodate the two build modes (cargo for macos vs xcode for ios)
// yet share the implementation of the core logic

// MARK: - Response Types

/// Response from generating a secure key
public struct GenerateKeyResponse {
    public let publicKey: String
    public let keyName: String
    public let hardwareBacking: String
}

/// Information about a key in the Secure Enclave
public struct KeyInfo {
    public let keyName: String
    public let publicKey: String
}

/// Response from listing keys
public struct ListKeysResponse {
    public let keys: [KeyInfo]
}

/// Response from signing data
public struct SignResponse {
    public let signature: Data
}

/// Response from checking Secure Enclave support
public struct SupportResponse {
    public let secureElementSupported: Bool
    public let teeSupported: Bool
    public let canEnforceBiometricOnly: Bool
}

// MARK: - Error Types

/// Errors that can occur during Secure Enclave operations
public enum SecureEnclaveError: Error, LocalizedError {
    case simulatorNotSupported
    case keyAlreadyExists(String)
    case keyNotFound(String)
    case failedToCreateAccessControl(String)
    case failedToCreateKey(String)
    case failedToExtractPublicKey
    case failedToExportPublicKey(String)
    case failedToSign(String)
    case failedToDeleteKey(String)
    case failedToQueryKeys(Int32)
    case invalidAuthMode
    case invalidData(String)
    case biometricNotAvailable(String)

    public var errorDescription: String? {
        switch self {
        case .simulatorNotSupported:
            return "Secure Enclave is not available on iOS Simulator. Please test on a physical device."
        case let .keyAlreadyExists(name):
            #if DEBUG
                return "Key already exists: \(name)"
            #else
                return "Key already exists"
            #endif
        case let .keyNotFound(name):
            #if DEBUG
                return "Key not found: \(name)"
            #else
                return "Key not found"
            #endif
        case let .failedToCreateAccessControl(detail):
            #if DEBUG
                return "Failed to create access control: \(detail)"
            #else
                return "Failed to create access control"
            #endif
        case let .failedToCreateKey(detail):
            #if DEBUG
                return "Failed to create key: \(detail)"
            #else
                return "Failed to create key"
            #endif
        case .failedToExtractPublicKey:
            return "Failed to extract public key"
        case let .failedToExportPublicKey(detail):
            #if DEBUG
                return "Failed to export public key: \(detail)"
            #else
                return "Failed to export public key"
            #endif
        case let .failedToSign(detail):
            #if DEBUG
                return "Failed to sign: \(detail)"
            #else
                return "Failed to sign"
            #endif
        case let .failedToDeleteKey(detail):
            #if DEBUG
                return "Failed to delete key: \(detail)"
            #else
                return "Failed to delete key"
            #endif
        case let .failedToQueryKeys(status):
            #if DEBUG
                return "Failed to query keys: \(status)"
            #else
                return "Failed to query keys"
            #endif
        case .invalidAuthMode:
            return "Invalid auth mode"
        case let .invalidData(detail):
            return "Invalid data: \(detail)"
        case let .biometricNotAvailable(detail):
            return "biometricOnly authentication mode requires biometric authentication (Face ID/Touch ID) to be available and enrolled. \(detail)"
        }
    }
}

// MARK: - SecureEnclaveCore

/// Core implementation of Secure Enclave operations shared between iOS and macOS
public enum SecureEnclaveCore {
    // MARK: - Helper Functions

    /// Converts authentication mode string to SecAccessControlCreateFlags
    public static func getAccessControlFlags(authMode: String?) -> SecAccessControlCreateFlags {
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

    /// Creates a base query dictionary for Secure Enclave key operations
    public static func createKeyQuery(keyName: String, returnRef: Bool = true) -> [String: Any] {
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

    /// Extracts error description from CFError
    public static func extractCFErrorDescription(_ error: Unmanaged<CFError>) -> String {
        return CFErrorCopyDescription(error.takeRetainedValue()) as String? ?? "Unknown error"
    }

    /// Safely converts a CFTypeRef to SecKey.
    /// Uses unsafeBitCast (required for CF type bridging on iOS) with validation.
    /// Returns nil if the reference cannot be used as a valid SecKey.
    private static func cfTypeRefToSecKey(_ ref: CFTypeRef) -> SecKey? {
        // CFTypeRef is AnyObject in Swift. For CF types, as? may not work reliably
        // across all platforms (particularly iOS) due to type bridging differences.
        // unsafeBitCast is the correct way to bridge CF types.
        let key = unsafeBitCast(ref, to: SecKey.self)

        // Validate it's actually a usable key by attempting to get its public key.
        // This is a lightweight operation that will fail if ref wasn't a SecKey.
        guard SecKeyCopyPublicKey(key) != nil else {
            return nil
        }

        return key
    }

    /// Exports a public key from a private key as base64 string
    public static func exportPublicKeyBase64(privateKey: SecKey) -> Result<String, SecureEnclaveError> {
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            return .failure(.failedToExtractPublicKey)
        }

        var exportError: Unmanaged<CFError>?
        guard let publicKeyData = SecKeyCopyExternalRepresentation(publicKey, &exportError) as Data? else {
            if let error = exportError {
                return .failure(.failedToExportPublicKey(extractCFErrorDescription(error)))
            }
            return .failure(.failedToExportPublicKey("Unknown error"))
        }

        return .success(publicKeyData.base64EncodedString())
    }

    /// Checks if running on simulator
    public static var isSimulator: Bool {
        #if targetEnvironment(simulator)
            return true
        #else
            return false
        #endif
    }

    /// Checks if biometric authentication is available and enrolled on the device
    /// Returns nil if available, or an error message describing why it's not available
    public static func checkBiometricAvailability() -> String? {
        let context = LAContext()
        var error: NSError?

        if context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error) {
            return nil // Biometrics available
        }

        // Biometrics not available - determine why
        if let laError = error {
            switch laError.code {
            case LAError.biometryNotAvailable.rawValue:
                return "Biometric hardware is not available on this device."
            case LAError.biometryNotEnrolled.rawValue:
                return "No biometric authentication is enrolled. Please set up Face ID or Touch ID in Settings."
            case LAError.biometryLockout.rawValue:
                return "Biometric authentication is locked out due to too many failed attempts."
            default:
                return "Biometric authentication is not available: \(laError.localizedDescription)"
            }
        }

        return "Biometric authentication is not available on this device."
    }

    // MARK: - Core Operations

    /// Generate a new secure key in the Secure Enclave
    public static func generateSecureKey(keyName: String, authMode: String?) -> Result<GenerateKeyResponse, SecureEnclaveError> {
        // Check for simulator
        if isSimulator {
            return .failure(.simulatorNotSupported)
        }

        // Check biometric availability if biometricOnly mode is requested
        let mode = authMode ?? "pinOrBiometric"
        if mode == "biometricOnly" {
            if let biometricError = checkBiometricAvailability() {
                return .failure(.biometricNotAvailable(biometricError))
            }
        }

        // Check if key already exists
        let checkQuery = createKeyQuery(keyName: keyName, returnRef: false)
        var checkResult: CFTypeRef?
        let checkStatus = SecItemCopyMatching(checkQuery as CFDictionary, &checkResult)

        if checkStatus == errSecSuccess {
            return .failure(.keyAlreadyExists(keyName))
        } else if checkStatus != errSecItemNotFound {
            return .failure(.failedToQueryKeys(checkStatus))
        }

        // Create access control
        let flags = getAccessControlFlags(authMode: authMode)
        var accessError: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) else {
            if let error = accessError {
                return .failure(.failedToCreateAccessControl(extractCFErrorDescription(error)))
            }
            return .failure(.failedToCreateAccessControl("Unknown error"))
        }

        // Create the Secure Enclave key
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

        var keyError: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &keyError) else {
            if let error = keyError {
                return .failure(.failedToCreateKey(extractCFErrorDescription(error)))
            }
            return .failure(.failedToCreateKey("Unknown error"))
        }

        // Export public key
        switch exportPublicKeyBase64(privateKey: privateKey) {
        case let .success(publicKeyBase64):
            return .success(GenerateKeyResponse(publicKey: publicKeyBase64, keyName: keyName, hardwareBacking: "secureEnclave"))
        case let .failure(error):
            return .failure(error)
        }
    }

    /// List keys in the Secure Enclave, optionally filtered by name or public key
    public static func listKeys(keyName: String?, publicKey: String?) -> Result<ListKeysResponse, SecureEnclaveError> {
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

        var keys: [KeyInfo] = []

        if status == errSecSuccess, let items = result as? [[String: Any]] {
            for item in items {
                guard let keyRef = item[kSecValueRef as String] as CFTypeRef?,
                      let privateKey = cfTypeRefToSecKey(keyRef) else {
                    continue
                }

                // Extract key name from kSecAttrLabel
                let keyNameLabel = (item[kSecAttrLabel as String] as? String)?
                    .trimmingCharacters(in: .whitespacesAndNewlines)
                let foundKeyName = keyNameLabel?.isEmpty == false ? keyNameLabel! : "<unnamed>"

                // Apply name filter
                if let filterName = keyName, filterName != foundKeyName {
                    continue
                }

                // Export public key
                guard case let .success(publicKeyBase64) = exportPublicKeyBase64(privateKey: privateKey) else {
                    continue
                }

                // Apply public key filter
                if let filterPublicKey = publicKey, filterPublicKey != publicKeyBase64 {
                    continue
                }

                keys.append(KeyInfo(
                    keyName: foundKeyName,
                    publicKey: publicKeyBase64,
                ))
            }
        } else if status != errSecItemNotFound {
            return .failure(.failedToQueryKeys(status))
        }

        return .success(ListKeysResponse(keys: keys))
    }

    /// Sign data with a key from the Secure Enclave
    public static func signWithKey(keyName: String, data: Data) -> Result<SignResponse, SecureEnclaveError> {
        // Look up the key
        let query = createKeyQuery(keyName: keyName, returnRef: true)
        var keyRef: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &keyRef)

        guard status == errSecSuccess || status == errSecInteractionNotAllowed,
              let keyRef = keyRef,
              let privateKey = cfTypeRefToSecKey(keyRef)
        else {
            return .failure(.keyNotFound(keyName))
        }

        // Create SHA256 digest using CryptoKit
        let digest = SHA256.hash(data: data)
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
                return .failure(.failedToSign(extractCFErrorDescription(error)))
            }
            return .failure(.failedToSign("Unknown error"))
        }

        return .success(SignResponse(signature: signature))
    }

    /// Delete a key from the Secure Enclave by name or public key
    public static func deleteKey(keyName: String?, publicKey: String?) -> Result<Bool, SecureEnclaveError> {
        // If keyName is provided, delete by name (fast path)
        if let keyName = keyName {
            let query = createKeyQuery(keyName: keyName, returnRef: false)
            let status = SecItemDelete(query as CFDictionary)

            if status == errSecSuccess || status == errSecItemNotFound {
                return .success(true)
            } else {
                return .failure(.failedToDeleteKey("Status: \(status)"))
            }
        }

        // If publicKey is provided, find and delete by public key
        guard let targetPublicKey = publicKey else {
            return .failure(.invalidData("Either keyName or publicKey must be provided"))
        }

        // Query for all keys
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
            for item in items {
                guard let keyRef = item[kSecValueRef as String] as CFTypeRef?,
                      let privateKey = cfTypeRefToSecKey(keyRef) else {
                    continue
                }

                // Check if this key's public key matches
                if case let .success(publicKeyBase64) = exportPublicKeyBase64(privateKey: privateKey),
                   publicKeyBase64 == targetPublicKey {
                    // Extract key name for deletion
                    let keyNameLabel = (item[kSecAttrLabel as String] as? String)?
                        .trimmingCharacters(in: .whitespacesAndNewlines)
                    let foundKeyName = keyNameLabel?.isEmpty == false ? keyNameLabel! : "<unnamed>"

                    let deleteQuery = createKeyQuery(keyName: foundKeyName, returnRef: false)
                    let deleteStatus = SecItemDelete(deleteQuery as CFDictionary)

                    if deleteStatus == errSecSuccess || deleteStatus == errSecItemNotFound {
                        return .success(true)
                    } else {
                        return .failure(.failedToDeleteKey("Status: \(deleteStatus)"))
                    }
                }
            }

            // Key not found by public key - return success (idempotent)
            return .success(true)
        } else if status == errSecItemNotFound {
            // No keys found - return success (idempotent)
            return .success(true)
        } else {
            return .failure(.failedToQueryKeys(status))
        }
    }

    /// Check if Secure Enclave is supported on this device
    public static func checkSupport() -> SupportResponse {
        // Check for simulator
        if isSimulator {
            return SupportResponse(
                secureElementSupported: false,
                teeSupported: false,
                canEnforceBiometricOnly: false
            )
        }

        // Try to create access control with basic flags
        var accessError: Unmanaged<CFError>?
        let flags: SecAccessControlCreateFlags = [.privateKeyUsage, .userPresence]
        guard SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &accessError
        ) != nil else {
            return SupportResponse(
                secureElementSupported: false,
                teeSupported: false,
                canEnforceBiometricOnly: false
            )
        }

        // Try to create a test key to verify Secure Enclave availability
        let testTag = Data("secure_element_test_\(UUID().uuidString)".utf8)
        let testAttributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecAttrIsPermanent as String: false,
            kSecAttrApplicationTag as String: testTag,
        ]

        var testError: Unmanaged<CFError>?
        let testKey = SecKeyCreateRandomKey(testAttributes as CFDictionary, &testError)

        // Clean up test key
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

        guard testKey != nil else {
            return SupportResponse(
                secureElementSupported: false,
                teeSupported: false,
                canEnforceBiometricOnly: false
            )
        }

        // Check if biometric authentication is available and enrolled
        // This uses LAContext to verify both hardware availability AND enrollment
        let canEnforceBiometric = checkBiometricAvailability() == nil

        return SupportResponse(
            secureElementSupported: true,
            teeSupported: true,
            canEnforceBiometricOnly: canEnforceBiometric
        )
    }
}

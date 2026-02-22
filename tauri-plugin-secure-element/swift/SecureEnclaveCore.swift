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

/// Secure element hardware backing tiers
public enum SecureElementBacking: String, Codable {
    case none
    case firmware
    case integrated
    case discrete
}

/// Response from checking Secure Enclave support
public struct SupportResponse {
    /// A discrete physical security chip is available (e.g. T2 chip on Intel Macs)
    public let discrete: Bool
    /// An on-die isolated security core is available (e.g. Secure Enclave on Apple Silicon)
    public let integrated: Bool
    /// Firmware-backed security is available (not applicable on Apple platforms)
    public let firmware: Bool
    /// The security is emulated/virtual (e.g. iOS Simulator)
    public let emulated: Bool
    /// The strongest tier available on this device
    public let strongest: SecureElementBacking
    /// Whether biometric-only authentication can be enforced
    public let canEnforceBiometricOnly: Bool
}

// MARK: - Error Types

/// Errors that can occur during Secure Enclave operations
public enum SecureEnclaveError: Error, LocalizedError {
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
    case keyNotAccessible
    case invalidData(String)
    case biometricNotAvailable(String)

    public var errorDescription: String? {
        switch self {
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
        case .keyNotAccessible:
            return "Key is not accessible: the device may be locked"
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
        let cfError = error.takeRetainedValue()
        return CFErrorCopyDescription(cfError) as String? ?? "Unknown error"
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
                guard let keyRef = item[kSecValueRef as String] as? CFTypeRef else {
                    continue
                }
                // swiftlint:disable:next force_cast
                let privateKey = keyRef as! SecKey

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

        guard status == errSecSuccess, let keyRef = keyRef else {
            if status == errSecInteractionNotAllowed {
                return .failure(.keyNotAccessible)
            }
            return .failure(.keyNotFound(keyName))
        }

        // swiftlint:disable:next force_cast
        let privateKey = keyRef as! SecKey

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
                guard let keyRef = item[kSecValueRef as String] as? CFTypeRef else {
                    continue
                }
                // swiftlint:disable:next force_cast
                let privateKey = keyRef as! SecKey

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

    /// Detects the type of secure element on macOS (Apple Silicon vs T2 vs none)
    #if os(macOS)
        private static func detectMacSecureElementType() -> (discrete: Bool, integrated: Bool) {
            // Check if running on Apple Silicon (arm64)
            // Apple Silicon Macs have an integrated Secure Enclave on the SoC
            #if arch(arm64)
                return (discrete: false, integrated: true)
            #else
                // Intel Mac - check if T2 chip is present
                // T2 is a discrete security chip on Intel Macs
                // If Secure Enclave works on Intel Mac, it must be T2
                return (discrete: true, integrated: false)
            #endif
        }
    #endif

    /// Check if Secure Enclave is supported on this device
    public static func checkSupport() -> SupportResponse {
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
                discrete: false,
                integrated: false,
                firmware: false,
                emulated: isSimulator,
                strongest: .none,
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
                discrete: false,
                integrated: false,
                firmware: false,
                emulated: isSimulator,
                strongest: .none,
                canEnforceBiometricOnly: false
            )
        }

        // Check if biometric authentication is available and enrolled
        // This uses LAContext to verify both hardware availability AND enrollment
        let canEnforceBiometric = checkBiometricAvailability() == nil

        // Determine the type of secure element
        #if os(iOS) || os(watchOS) || os(tvOS)
            // iOS devices always have an integrated Secure Enclave on the SoC
            let discrete = false
            let integrated = true
        #elseif os(macOS)
            let (discrete, integrated) = detectMacSecureElementType()
        #else
            let discrete = false
            let integrated = false
        #endif

        // Determine strongest backing (discrete > integrated > firmware > none)
        let strongest: SecureElementBacking = discrete ? .discrete : (integrated ? .integrated : .none)

        return SupportResponse(
            discrete: discrete,
            integrated: integrated,
            firmware: false,        // Apple platforms don't have firmware-only TPM
            emulated: isSimulator,  // Real device or emulated
            strongest: strongest,
            canEnforceBiometricOnly: canEnforceBiometric
        )
    }
}

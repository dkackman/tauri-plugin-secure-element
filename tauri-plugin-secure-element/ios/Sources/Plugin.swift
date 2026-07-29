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
    /// `Data` decodes a base64 string by default (JSONDecoder.dataDecodingStrategy
    /// .base64), matching the wire format Rust's `SignWithKeyRequest` now uses —
    /// a JSON number array here costs ~4x the bytes over the IPC boundary.
    let data: Data
    /// Shown in the Face ID / Touch ID / passcode prompt so the user knows what
    /// they are approving. `nil` uses the system default.
    let reason: String?
}

class DeleteKeyArgs: Decodable {
    let keyName: String?
    let publicKey: String?
    /// Require device-owner authentication before the key is destroyed. The
    /// Keychain does not enforce this itself, even for auth-required keys.
    let requireAuth: Bool?
    /// Message shown in that prompt; ignored unless `requireAuth` is set.
    let reason: String?
}

// MARK: - SecureEnclavePlugin

class SecureEnclavePlugin: Plugin {
    /// Logger for error tracking
    private static let logger = OSLog(subsystem: "net.kackman.secureelement", category: "SecureEnclave")

    /// Logs an error
    private func logError(_ operation: String, error: String) {
        os_log("%{public}@: %{private}@", log: Self.logger, type: .error, operation, error)
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
            let backing = SecureEnclaveCore.checkSupport().strongest.rawValue
            invoke.resolve([
                "publicKey": response.publicKey,
                "keyName": response.keyName,
                "backing": backing,
            ])
        case let .failure(error):
            logError("generateSecureKey", error: error.localizedDescription)
            invoke.reject(error.localizedDescription, code: error.code)
        }
    }

    // MARK: - List Keys

    @objc func listKeys(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(ListKeysArgs.self)

        switch SecureEnclaveCore.listKeys(keyName: args.keyName, publicKey: args.publicKey) {
        case let .success(response):
            let keys: [[String: Any]] = response.keys.map { keyInfo in
                [
                    "keyName": keyInfo.keyName,
                    "publicKey": keyInfo.publicKey,
                ]
            }
            invoke.resolve(["keys": keys])
        case let .failure(error):
            logError("listKeys", error: error.localizedDescription)
            invoke.reject(error.localizedDescription, code: error.code)
        }
    }

    // MARK: - Sign With Key

    @objc func signWithKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(SignWithKeyArgs.self)

        switch SecureEnclaveCore.signWithKey(keyName: args.keyName, data: args.data, reason: args.reason) {
        case let .success(response):
            invoke.resolve(["signature": [UInt8](response.signature)])
        case let .failure(error):
            logError("signWithKey", error: error.localizedDescription)
            invoke.reject(error.localizedDescription, code: error.code)
        }
    }

    // MARK: - Delete Key

    @objc func deleteKey(_ invoke: Invoke) throws {
        let args = try invoke.parseArgs(DeleteKeyArgs.self)

        // A non-nil reason is what switches on the authentication check, so it
        // is only supplied when the caller actually asked for one.
        let authReason = (args.requireAuth ?? false)
            ? (args.reason ?? "Authenticate to delete a secure key")
            : nil

        switch SecureEnclaveCore.deleteKey(
            keyName: args.keyName,
            publicKey: args.publicKey,
            authReason: authReason
        ) {
        case .success:
            invoke.resolve(["success": true])
        case let .failure(error):
            logError("deleteKey", error: error.localizedDescription)
            invoke.reject(error.localizedDescription, code: error.code)
        }
    }

    // MARK: - Check Secure Element Support

    @objc func checkSecureElementSupport(_ invoke: Invoke) throws {
        let response = SecureEnclaveCore.checkSupport()
        invoke.resolve([
            "discrete": response.discrete,
            "integrated": response.integrated,
            "firmware": response.firmware,
            "emulated": response.emulated,
            "strongest": response.strongest.rawValue,
            "canEnforceBiometricOnly": response.canEnforceBiometricOnly,
        ])
    }
}

@_cdecl("init_plugin_secure_element")
func initPlugin() -> Plugin {
    SecureEnclavePlugin()
}

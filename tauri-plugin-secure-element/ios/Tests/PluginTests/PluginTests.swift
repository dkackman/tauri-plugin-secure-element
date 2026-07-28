import Foundation
@testable import tauri_plugin_secure_element
import XCTest

/// Tests for the key-namespacing helpers that scope every operation to keys this
/// plugin created. These are pure functions and run without a Secure Enclave.
final class KeyNamespacingTests: XCTestCase {
    func testTagRoundTripsToOriginalName() {
        for name in ["mykey", "my-key_1", "a", String(repeating: "z", count: 64)] {
            let tag = SecureEnclaveCore.applicationTag(for: name)
            XCTAssertEqual(SecureEnclaveCore.decodeKeyName(fromTag: tag), name)
        }
    }

    func testForeignTagsAreRejected() {
        // A bare name (no plugin prefix), as another library would store, is not ours.
        XCTAssertNil(SecureEnclaveCore.decodeKeyName(fromTag: Data("mykey".utf8)))
        XCTAssertNil(SecureEnclaveCore.decodeKeyName(fromTag: Data("com.other.app.key".utf8)))
        XCTAssertNil(SecureEnclaveCore.decodeKeyName(fromTag: Data()))
    }

    func testTagIsPrefixed() {
        let tag = SecureEnclaveCore.applicationTag(for: "k")
        XCTAssertEqual(String(data: tag, encoding: .utf8), "net.kackman.secureelement.k")
    }
}

/// Tests for `getAccessControlFlags`, a pure String -> SecAccessControlCreateFlags
/// mapping — no Keychain or Secure Enclave call involved.
final class AccessControlFlagsTests: XCTestCase {
    private func flags(for authMode: String?) throws -> SecAccessControlCreateFlags {
        try SecureEnclaveCore.getAccessControlFlags(authMode: authMode).get()
    }

    func testNoneRequiresOnlyPrivateKeyUsage() throws {
        let flags = try flags(for: "none")
        XCTAssertTrue(flags.contains(.privateKeyUsage))
        XCTAssertFalse(flags.contains(.biometryCurrentSet))
        XCTAssertFalse(flags.contains(.userPresence))
    }

    func testBiometricOnlyAddsBiometryCurrentSet() throws {
        let flags = try flags(for: "biometricOnly")
        XCTAssertTrue(flags.contains(.privateKeyUsage))
        XCTAssertTrue(flags.contains(.biometryCurrentSet))
        XCTAssertFalse(flags.contains(.userPresence))
    }

    func testPinOrBiometricAddsUserPresence() throws {
        let flags = try flags(for: "pinOrBiometric")
        XCTAssertTrue(flags.contains(.privateKeyUsage))
        XCTAssertTrue(flags.contains(.userPresence))
        XCTAssertFalse(flags.contains(.biometryCurrentSet))
    }

    func testNilDefaultsToPinOrBiometric() throws {
        let withNil = try flags(for: nil)
        let withExplicit = try flags(for: "pinOrBiometric")
        XCTAssertEqual(withNil, withExplicit)
    }

    func testUnrecognizedModeFailsClosed() {
        let result = SecureEnclaveCore.getAccessControlFlags(authMode: "bogus")
        switch result {
        case .success:
            XCTFail("expected .invalidAuthMode failure for an unrecognized auth mode")
        case let .failure(error):
            guard case .invalidAuthMode = error else {
                XCTFail("expected .invalidAuthMode, got \(error)")
                return
            }
        }
    }
}

/// `createKeyQuery` is pure dictionary construction from `applicationTag(for:)` — no
/// SecItemCopyMatching call involved.
final class CreateKeyQueryTests: XCTestCase {
    func testQueryIsScopedToTheNamespacedTag() {
        let query = SecureEnclaveCore.createKeyQuery(keyName: "my-key")
        XCTAssertEqual(query[kSecAttrApplicationTag as String] as? Data, SecureEnclaveCore.applicationTag(for: "my-key"))
        XCTAssertEqual(query[kSecClass as String] as? String, kSecClassKey as String)
        XCTAssertEqual(query[kSecAttrTokenID as String] as? String, kSecAttrTokenIDSecureEnclave as String)
    }

    func testReturnRefDefaultsToTrue() {
        let query = SecureEnclaveCore.createKeyQuery(keyName: "my-key")
        XCTAssertEqual(query[kSecReturnRef as String] as? Bool, true)
    }

    func testReturnRefFalseOmitsTheKey() {
        let query = SecureEnclaveCore.createKeyQuery(keyName: "my-key", returnRef: false)
        XCTAssertNil(query[kSecReturnRef as String])
    }
}

/// `detectSecureElementTiers`/`strongestBacking` are pure `#if os/arch` compile-time
/// branching — no Security or LocalAuthentication API call involved. These assert the
/// iOS Simulator's branch since that's what CI builds against; the values are fixed
/// per platform target, not runtime-probed.
final class SecureElementTierDetectionTests: XCTestCase {
    func testIOSAlwaysReportsIntegratedOnly() {
        #if os(iOS)
            let tiers = SecureEnclaveCore.detectSecureElementTiers()
            XCTAssertFalse(tiers.discrete)
            XCTAssertTrue(tiers.integrated)
        #endif
    }

    func testStrongestBackingMatchesDetectedTiers() {
        let tiers = SecureEnclaveCore.detectSecureElementTiers()
        let expected: SecureElementBacking = tiers.discrete ? .discrete : (tiers.integrated ? .integrated : .none)
        XCTAssertEqual(SecureEnclaveCore.strongestBacking(), expected)
    }
}

/// `SecureEnclaveError.errorDescription` is a pure switch producing message strings.
/// This test target builds in DEBUG configuration, so it exercises the detailed-message
/// branch — mirroring the accepted gap noted for `error_sanitize.rs`'s release path
/// (Rust) and closed for real in the Kotlin plugin's `sanitizeErrorMessage`.
final class SecureEnclaveErrorDescriptionTests: XCTestCase {
    func testKeyAlreadyExistsIncludesNameInDebug() {
        XCTAssertEqual(SecureEnclaveError.keyAlreadyExists("foo").errorDescription, "Key already exists: foo")
    }

    func testKeyNotFoundIncludesNameInDebug() {
        XCTAssertEqual(SecureEnclaveError.keyNotFound("foo").errorDescription, "Key not found: foo")
    }

    func testInvalidAuthModeHasAFixedMessage() {
        XCTAssertEqual(SecureEnclaveError.invalidAuthMode.errorDescription, "Invalid auth mode")
    }

    func testKeyNotAccessibleHasAFixedMessage() {
        XCTAssertEqual(
            SecureEnclaveError.keyNotAccessible.errorDescription,
            "Key is not accessible: the device may be locked"
        )
    }

    func testFailedToQueryKeysIncludesStatusInDebug() {
        XCTAssertEqual(SecureEnclaveError.failedToQueryKeys(-25300).errorDescription, "Failed to query keys: -25300")
    }
}

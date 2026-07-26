import Foundation
@testable import SecureKeysPlugin
import XCTest

final class ExamplePluginTests: XCTestCase {
    func testExample() {
        let plugin = SecureKeysPlugin()
    }
}

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

// SPDX-License-Identifier: BUSL-1.1

import Foundation
import XCTest
@testable import Kyntral

final class KyntralCoreTests: XCTestCase {
    func testCanonicalObjectOrdering() throws {
        let value: KCJValue = .object([
            "z": .integer(2),
            "a": .integer(1),
            "nested": .object([
                "b": .bool(true),
                "a": .null
            ])
        ])
        XCTAssertEqual(
            try KCJCanonicalizer.string(value),
            "{\"a\":1,\"nested\":{\"a\":null,\"b\":true},\"z\":2}"
        )
    }

    func testDeviceSigningAndAgreementKeysAreDistinct() async throws {
        let identity = try await DeviceKeyManager().identity()
        XCTAssertNotEqual(
            identity.signingPublicKey.kid,
            identity.keyAgreementPublicKey.kid
        )
        XCTAssertNotEqual(
            identity.signingPublicKey.x,
            identity.keyAgreementPublicKey.x
        )
    }

    func testURLFragmentsDoNotCreateDifferentDedupeIdentity() {
        let first = URL(string: "https://example.com/media?id=1#one")!
        let second = URL(string: "https://EXAMPLE.com/media?id=1#two")!
        XCTAssertEqual(
            DedupeLedger.sourceHash(first),
            DedupeLedger.sourceHash(second)
        )
    }

    func testOnlyAllowedPermitsExecution() {
        XCTAssertTrue(AuthorizationDecision.allowed.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.denied.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.unknown.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.expired.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.revoked.permitsExecution)
    }
}

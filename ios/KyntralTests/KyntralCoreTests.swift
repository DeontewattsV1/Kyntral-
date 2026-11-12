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
        let reloaded = try await DeviceKeyManager().identity()
        XCTAssertEqual(reloaded, identity)
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

    // The configured resolver host must not be a local network escape hatch.
    func testResolverRejectsLoopbackAndPrivateEndpointEvenWhenAllowlisted() {
        for hostname in ["127.0.0.1", "10.0.0.1", "192.168.1.2", "169.254.169.254", "localhost", "[::1]"] {
            let endpoint = URL(string: "https://" + hostname + "/api")!
            let host = endpoint.host!
            XCTAssertThrowsError(
                try CobaltCompatibleResolver(
                    endpoint: endpoint, allowedEndpointHosts: [host]
                ),
                "Unsafe resolver host should be denied: \(hostname)"
            )
        }
    }

    func testResolverRejectsCredentialsAndUnapprovedPort() {
        let hosts: Set<String> = ["resolver.example"]
        XCTAssertThrowsError(
            try CobaltCompatibleResolver(
                endpoint: URL(string: "https://user:pass@resolver.example/api")!,
                allowedEndpointHosts: hosts
            )
        )
        XCTAssertThrowsError(
            try CobaltCompatibleResolver(
                endpoint: URL(string: "https://resolver.example:8443/api")!,
                allowedEndpointHosts: hosts
            )
        )
    }


    func testResolverRejectsUnauthorizedMediaHostBeforeNetwork() async throws {
        let resolver = try CobaltCompatibleResolver(
            endpoint: URL(string: "https://resolver.example/api")!,
            allowedEndpointHosts: ["resolver.example"]
        )
        let media = ResolvedMedia(
            url: URL(string: "https://unapproved.invalid/media.mp4")!,
            filename: "media.mp4"
        )
        do {
            _ = try await resolver.download(media)
            XCTFail("Unapproved media host must be refused before any request")
        } catch CobaltResolverError.unapprovedEndpoint {
            // Expected exact policy denial, not a DNS/network error.
        } catch {
            XCTFail("Unexpected resolver error: \(error)")
        }
    }

    func testResolverRejectsLocalMediaSourceBeforeNetwork() async throws {
        let resolver = try CobaltCompatibleResolver(
            endpoint: URL(string: "https://resolver.example/api")!,
            allowedEndpointHosts: ["resolver.example"]
        )
        do {
            _ = try await resolver.resolve(source: URL(string: "https://127.0.0.1/private")!)
            XCTFail("Private source must be denied before contacting resolver")
        } catch CobaltResolverError.unapprovedSource {
            // Expected exact policy denial.
        } catch {
            XCTFail("Unexpected resolver error: \(error)")
        }
    }

}

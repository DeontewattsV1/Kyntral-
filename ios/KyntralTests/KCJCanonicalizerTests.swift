// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import XCTest
@testable import Kyntral

final class KCJCanonicalizerTests: XCTestCase {
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

    func testSignedActionHashMatchesFrozenProtocolVector() throws {
        let signedAction: KCJValue = .object([
            "version": .string("kyntral.action.v1"),
            "actionId": .string("act_vector_001"),
            "deviceId": .string("dev_vector_001"),
            "scopeId": .string("scope_vector_001"),
            "workflowId": .string("wf_media_intake"),
            "capability": .string("workflow.execute"),
            "risk": .string("K2"),
            "nonce": .string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "issuedAt": .string("2026-10-06T23:00:00.000Z"),
            "expiresAt": .string("2026-10-06T23:05:00.000Z"),
            "idempotencyKey": .string("idem_vector_0001"),
            "authorizationProof": .object([
                "keyId": .string("auth-test-01"),
                "algorithm": .string("ES256"),
                "signature": .string("MEUCIC2EfgP2sOmDKvZ0btRTQI1z7K3oDkom8Ci104W6oTFzAiEA-edHQ3uQngkSHlRhCVIw4vT64-b8hssmZhXNbU9UI20")
            ])
        ])

        let canonical = try KCJCanonicalizer.data(signedAction)
        let digest = SHA256.hash(data: canonical)
            .map { String(format: "%02x", $0) }
            .joined()

        XCTAssertEqual(
            "sha256:" + digest,
            "sha256:47a0b0c5f209dc6ccbab0f35588fe458c7b67b61b6f107b7785b93abc99c10de"
        )
    }

    func testActionAuthorizationPreimageMatchesFrozenVectorPrefix() throws {
        let unsignedAction: KCJValue = .object([
            "version": .string("kyntral.action.v1"),
            "actionId": .string("act_vector_001"),
            "deviceId": .string("dev_vector_001"),
            "scopeId": .string("scope_vector_001"),
            "workflowId": .string("wf_media_intake"),
            "capability": .string("workflow.execute"),
            "risk": .string("K2"),
            "nonce": .string("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
            "issuedAt": .string("2026-10-06T23:00:00.000Z"),
            "expiresAt": .string("2026-10-06T23:05:00.000Z"),
            "idempotencyKey": .string("idem_vector_0001")
        ])

        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "action-authorization",
            payload: unsignedAction
        )
        let prefix = Data("KYNTRAL\0action-authorization\0v1\0".utf8)

        XCTAssertTrue(preimage.starts(with: prefix))
        XCTAssertEqual(
            String(data: preimage.dropFirst(prefix.count), encoding: .utf8),
            "{\"actionId\":\"act_vector_001\",\"capability\":\"workflow.execute\",\"deviceId\":\"dev_vector_001\",\"expiresAt\":\"2026-10-06T23:05:00.000Z\",\"idempotencyKey\":\"idem_vector_0001\",\"issuedAt\":\"2026-10-06T23:00:00.000Z\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"risk\":\"K2\",\"scopeId\":\"scope_vector_001\",\"version\":\"kyntral.action.v1\",\"workflowId\":\"wf_media_intake\"}"
        )
    }
}

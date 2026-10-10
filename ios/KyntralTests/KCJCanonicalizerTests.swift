// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import XCTest
@testable import Kyntral

final class KCJCanonicalizerTests: XCTestCase {
    private let vectorAction = LocalActionEnvelope(
        actionId: "act_vector_001",
        deviceId: "dev_vector_001",
        scopeId: "scope_vector_001",
        workflowId: "wf_media_intake",
        capability: "workflow.execute",
        risk: .k2,
        nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        issuedAt: "2026-10-06T23:00:00.000Z",
        expiresAt: "2026-10-06T23:05:00.000Z",
        idempotencyKey: "idem_vector_0001",
        authorizationProof: ActionAuthorizationProof(
            keyId: "auth-test-01",
            algorithm: "ES256",
            signature: "MEUCIC2EfgP2sOmDKvZ0btRTQI1z7K3oDkom8Ci104W6oTFzAiEA-edHQ3uQngkSHlRhCVIw4vT64-b8hssmZhXNbU9UI20"
        )
    )

    private let authorizationKey = KyntralPublicJWK(
        kty: "EC",
        crv: "P-256",
        x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY",
        y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU",
        kid: "auth-test-01",
        use: "sig",
        alg: "ES256"
    )

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
        XCTAssertEqual(
            try vectorAction.actionHash(),
            "sha256:47a0b0c5f209dc6ccbab0f35588fe458c7b67b61b6f107b7785b93abc99c10de"
        )
    }

    func testActionAuthorizationPreimageMatchesFrozenVector() throws {
        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "action-authorization",
            payload: vectorAction.canonicalUnsignedValue
        )
        let prefix = Data("KYNTRAL\0action-authorization\0v1\0".utf8)

        XCTAssertTrue(preimage.starts(with: prefix))
        XCTAssertEqual(
            String(data: preimage.dropFirst(prefix.count), encoding: .utf8),
            "{\"actionId\":\"act_vector_001\",\"capability\":\"workflow.execute\",\"deviceId\":\"dev_vector_001\",\"expiresAt\":\"2026-10-06T23:05:00.000Z\",\"idempotencyKey\":\"idem_vector_0001\",\"issuedAt\":\"2026-10-06T23:00:00.000Z\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"risk\":\"K2\",\"scopeId\":\"scope_vector_001\",\"version\":\"kyntral.action.v1\",\"workflowId\":\"wf_media_intake\"}"
        )
    }

    func testActionAuthorizationSignatureMatchesFrozenProtocolVector() throws {
        XCTAssertTrue(
            try ActionVerifier.verifyAuthorizationSignature(
                action: vectorAction,
                trustedKey: authorizationKey
            )
        )
    }

    func testActionTimeWindowEnforcesFrozenSkewAndLifetime() throws {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let issuedAt = try XCTUnwrap(
            formatter.date(from: "2026-10-06T23:00:00.000Z")
        )
        XCTAssertNoThrow(
            try ActionVerifier.validateTimeWindow(
                vectorAction,
                now: issuedAt.addingTimeInterval(60)
            )
        )

        XCTAssertThrowsError(
            try ActionVerifier.validateTimeWindow(
                vectorAction,
                now: issuedAt.addingTimeInterval(361)
            )
        )
    }

    func testReplayLedgerConsumesActionNonceAndIdempotencyOnce() async throws {
        let stateURL = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".json")
        defer { try? FileManager.default.removeItem(at: stateURL) }

        let ledger = ActionReplayLedger(stateURL: stateURL)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let retainUntil = now.addingTimeInterval(360)

        let first = try await ledger.consume(
            actionId: "act_replay_001",
            nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            idempotencyKey: "idem_replay_0001",
            retainUntil: retainUntil,
            now: now
        )
        XCTAssertTrue(first)

        let replayedNonce = try await ledger.consume(
            actionId: "act_replay_002",
            nonce: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
            idempotencyKey: "idem_replay_0002",
            retainUntil: retainUntil,
            now: now
        )
        XCTAssertFalse(replayedNonce)

        let replayedIdempotencyKey = try await ledger.consume(
            actionId: "act_replay_003",
            nonce: "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC",
            idempotencyKey: "idem_replay_0001",
            retainUntil: retainUntil,
            now: now
        )
        XCTAssertFalse(replayedIdempotencyKey)
    }
}

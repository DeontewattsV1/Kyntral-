// SPDX-License-Identifier: BUSL-1.1

import Foundation
import XCTest
@testable import Kyntral

private final class PairingMockURLProtocol: URLProtocol {
    static var handler: ((URLRequest) throws -> (HTTPURLResponse, Data))?

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }

    override func startLoading() {
        guard let handler = Self.handler else {
            client?.urlProtocol(self, didFailWithError: URLError(.badServerResponse))
            return
        }
        do {
            let (response, data) = try handler(request)
            client?.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            client?.urlProtocol(self, didLoad: data)
            client?.urlProtocolDidFinishLoading(self)
        } catch {
            client?.urlProtocol(self, didFailWithError: error)
        }
    }

    override func stopLoading() {}
}

final class AuthorizationDecisionTests: XCTestCase {
    override func tearDown() {
        PairingMockURLProtocol.handler = nil
        super.tearDown()
    }

    func testOnlyAllowedPermitsExecution() {
        XCTAssertTrue(AuthorizationDecision.allowed.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.denied.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.unknown.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.expired.permitsExecution)
        XCTAssertFalse(AuthorizationDecision.revoked.permitsExecution)
    }

    func testPairingClientRejectsNonHTTPSService() {
        XCTAssertThrowsError(
            try KyntralPairingClient(
                serviceBaseURL: URL(string: "http://api.example.test")!
            )
        )
    }

    func testPairingClientPerformsChallengeThenSignedCompletion() async throws {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.protocolClasses = [PairingMockURLProtocol.self]
        let session = URLSession(configuration: configuration)
        let challengeNonce = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        var completedDeviceId: String?
        var requestCount = 0

        PairingMockURLProtocol.handler = { request in
            requestCount += 1
            XCTAssertEqual(
                request.value(forHTTPHeaderField: "Authorization"),
                "Bearer oauth-test-token"
            )

            if request.url?.path == "/v1/pairing/challenge" {
                XCTAssertEqual(request.httpMethod, "POST")
                let body: [String: Any] = [
                    "version": "kyntral.pairing-challenge.v1",
                    "challengeId": "pair_test_001",
                    "principalId": "usr_test_001",
                    "nonce": challengeNonce,
                    "issuedAt": "2026-10-07T01:00:00.000Z",
                    "expiresAt": "2026-10-07T01:05:00.000Z"
                ]
                let data = try JSONSerialization.data(withJSONObject: body)
                return (
                    HTTPURLResponse(
                        url: request.url!,
                        statusCode: 201,
                        httpVersion: nil,
                        headerFields: ["Content-Type": "application/json"]
                    )!,
                    data
                )
            }

            if request.url?.path == "/v1/pairing/complete" {
                XCTAssertEqual(request.httpMethod, "POST")
                let bodyData = try XCTUnwrap(request.httpBody)
                let body = try XCTUnwrap(
                    JSONSerialization.jsonObject(with: bodyData) as? [String: Any]
                )
                XCTAssertEqual(body["version"] as? String, "kyntral.pairing-proof.v1")
                XCTAssertEqual(body["challengeId"] as? String, "pair_test_001")
                XCTAssertEqual(body["nonce"] as? String, challengeNonce)

                let identity = try XCTUnwrap(
                    body["deviceIdentity"] as? [String: Any]
                )
                let signingKey = try XCTUnwrap(
                    identity["signingPublicKey"] as? [String: Any]
                )
                let agreementKey = try XCTUnwrap(
                    identity["keyAgreementPublicKey"] as? [String: Any]
                )
                let proof = try XCTUnwrap(body["proof"] as? [String: Any])
                let deviceId = try XCTUnwrap(identity["deviceId"] as? String)
                completedDeviceId = deviceId

                XCTAssertNotEqual(
                    signingKey["kid"] as? String,
                    agreementKey["kid"] as? String
                )
                XCTAssertEqual(
                    proof["keyId"] as? String,
                    signingKey["kid"] as? String
                )
                XCTAssertFalse((proof["signature"] as? String ?? "").isEmpty)

                let signingKeyId = try XCTUnwrap(signingKey["kid"] as? String)
                let agreementKeyId = try XCTUnwrap(
                    agreementKey["kid"] as? String
                )
                let response: [String: Any] = [
                    "deviceId": deviceId,
                    "state": "paired",
                    "signingKeyId": signingKeyId,
                    "keyAgreementKeyId": agreementKeyId,
                    "authorizationSigningKey": [
                        "kty": "EC",
                        "crv": "P-256",
                        "x": String(repeating: "A", count: 43),
                        "y": String(repeating: "B", count: 43),
                        "kid": "auth-test-01",
                        "use": "sig",
                        "alg": "ES256"
                    ]
                ]
                let data = try JSONSerialization.data(withJSONObject: response)
                return (
                    HTTPURLResponse(
                        url: request.url!,
                        statusCode: 200,
                        httpVersion: nil,
                        headerFields: ["Content-Type": "application/json"]
                    )!,
                    data
                )
            }

            throw URLError(.unsupportedURL)
        }

        let client = try KyntralPairingClient(
            serviceBaseURL: URL(string: "https://api.example.test/mcp")!,
            session: session
        )
        let completion = try await client.pair(accessToken: "oauth-test-token")

        XCTAssertEqual(requestCount, 2)
        XCTAssertEqual(completion.state, "paired")
        XCTAssertEqual(completion.deviceId, completedDeviceId)
    }
}

// SPDX-License-Identifier: BUSL-1.1

import Foundation

public struct PairingChallenge: Codable, Sendable {
    public let version: String
    public let challengeId: String
    public let principalId: String
    public let nonce: String
    public let issuedAt: String
    public let expiresAt: String
}

public struct PairingProofSignature: Codable, Sendable {
    public let keyId: String
    public let algorithm: String
    public let signature: String
}

public struct PairingProof: Codable, Sendable {
    public let version: String
    public let challengeId: String
    public let nonce: String
    public let deviceIdentity: KyntralDeviceIdentity
    public let proof: PairingProofSignature
}

public struct PairingProofBuilder {
    private let keyManager: DeviceKeyManager

    public init(keyManager: DeviceKeyManager = .shared) {
        self.keyManager = keyManager
    }

    public func build(challenge: PairingChallenge) async throws -> PairingProof {
        let identity = try await keyManager.identity()
        let unsigned = KCJValue.object([
            "version": .string("kyntral.pairing-proof.v1"),
            "challengeId": .string(challenge.challengeId),
            "nonce": .string(challenge.nonce),
            "deviceIdentity": identity.canonicalValue
        ])
        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "pairing-proof",
            payload: unsigned
        )
        let signature = try await keyManager.sign(preimage).base64URLString
        return PairingProof(
            version: "kyntral.pairing-proof.v1",
            challengeId: challenge.challengeId,
            nonce: challenge.nonce,
            deviceIdentity: identity,
            proof: PairingProofSignature(
                keyId: identity.signingPublicKey.kid,
                algorithm: "ES256",
                signature: signature
            )
        )
    }
}

public struct PairingCompletion: Codable, Sendable, Equatable {
    public let deviceId: String
    public let state: String
    public let signingKeyId: String
    public let keyAgreementKeyId: String
    public let authorizationSigningKey: KyntralPublicJWK
}

public struct PairedDeviceStatus: Codable, Sendable, Equatable {
    public let deviceId: String
    public let state: String
    public let executionAuthority: String
    public let contentLocation: String
}

public struct DeviceRevocationResult: Codable, Sendable, Equatable {
    public let deviceId: String
    public let state: String
    public let changed: Bool
}

public enum PairingClientError: Error {
    case invalidServiceURL
    case invalidAccessToken
    case invalidDeviceId
    case unexpectedResponse(Int)
    case responseMismatch
}

public struct KyntralPairingClient {
    private let serviceBaseURL: URL
    private let session: URLSession
    private let proofBuilder: PairingProofBuilder

    public init(
        serviceBaseURL: URL,
        session: URLSession? = nil,
        proofBuilder: PairingProofBuilder = PairingProofBuilder()
    ) throws {
        guard serviceBaseURL.scheme?.lowercased() == "https",
              serviceBaseURL.host != nil,
              serviceBaseURL.user == nil,
              serviceBaseURL.password == nil else {
            throw PairingClientError.invalidServiceURL
        }
        self.serviceBaseURL = serviceBaseURL
        self.proofBuilder = proofBuilder

        if let session {
            self.session = session
        } else {
            let configuration = URLSessionConfiguration.ephemeral
            configuration.httpCookieStorage = nil
            configuration.urlCache = nil
            configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
            self.session = URLSession(configuration: configuration)
        }
    }

    public func pair(accessToken: String) async throws -> PairingCompletion {
        let challenge: PairingChallenge = try await send(
            path: "/v1/pairing/challenge",
            method: "POST",
            accessToken: accessToken,
            body: Optional<Data>.none,
            expectedStatus: 201
        )
        let proof = try await proofBuilder.build(challenge: challenge)
        let proofData = try JSONEncoder().encode(proof)
        let completion: PairingCompletion = try await send(
            path: "/v1/pairing/complete",
            method: "POST",
            accessToken: accessToken,
            body: proofData,
            expectedStatus: 200
        )
        guard completion.deviceId == proof.deviceIdentity.deviceId,
              completion.signingKeyId == proof.deviceIdentity.signingPublicKey.kid,
              completion.keyAgreementKeyId == proof.deviceIdentity.keyAgreementPublicKey.kid,
              completion.authorizationSigningKey.kty == "EC",
              completion.authorizationSigningKey.crv == "P-256",
              completion.authorizationSigningKey.use == "sig",
              completion.authorizationSigningKey.alg == "ES256",
              !completion.authorizationSigningKey.kid.isEmpty,
              completion.state == "paired" else {
            throw PairingClientError.responseMismatch
        }
        return completion
    }

    public func status(
        deviceId: String,
        accessToken: String
    ) async throws -> PairedDeviceStatus {
        try validateDeviceId(deviceId)
        return try await send(
            path: "/v1/devices/" + deviceId,
            method: "GET",
            accessToken: accessToken,
            body: Optional<Data>.none,
            expectedStatus: 200
        )
    }

    public func revoke(
        deviceId: String,
        accessToken: String
    ) async throws -> DeviceRevocationResult {
        try validateDeviceId(deviceId)
        return try await send(
            path: "/v1/devices/" + deviceId + "/revoke",
            method: "POST",
            accessToken: accessToken,
            body: Optional<Data>.none,
            expectedStatus: 200
        )
    }

    private func send<T: Decodable>(
        path: String,
        method: String,
        accessToken: String,
        body: Data?,
        expectedStatus: Int
    ) async throws -> T {
        try validateAccessToken(accessToken)
        let endpoint = try endpointURL(path: path)
        var request = URLRequest(url: endpoint)
        request.httpMethod = method
        request.timeoutInterval = 30
        request.setValue("Bearer " + accessToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        if let body {
            request.httpBody = body
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == expectedStatus else {
            let status = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw PairingClientError.unexpectedResponse(status)
        }
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func endpointURL(path: String) throws -> URL {
        guard var components = URLComponents(
            url: serviceBaseURL,
            resolvingAgainstBaseURL: false
        ) else {
            throw PairingClientError.invalidServiceURL
        }
        components.path = path
        components.query = nil
        components.fragment = nil
        guard let url = components.url else {
            throw PairingClientError.invalidServiceURL
        }
        return url
    }

    private func validateAccessToken(_ token: String) throws {
        guard !token.isEmpty,
              token.count <= 16_384,
              token.rangeOfCharacter(from: .controlCharacters) == nil else {
            throw PairingClientError.invalidAccessToken
        }
    }

    private func validateDeviceId(_ deviceId: String) throws {
        guard deviceId.range(
            of: "^[A-Za-z][A-Za-z0-9_-]{2,127}$",
            options: .regularExpression
        ) != nil else {
            throw PairingClientError.invalidDeviceId
        }
    }
}

private extension KyntralPublicJWK {
    var canonicalValue: KCJValue {
        .object([
            "kty": .string(kty),
            "crv": .string(crv),
            "x": .string(x),
            "y": .string(y),
            "kid": .string(kid),
            "use": .string(use),
            "alg": .string(alg)
        ])
    }
}

private extension KyntralDeviceIdentity {
    var canonicalValue: KCJValue {
        .object([
            "version": .string(version),
            "deviceId": .string(deviceId),
            "platform": .string(platform),
            "signingPublicKey": signingPublicKey.canonicalValue,
            "keyAgreementPublicKey": keyAgreementPublicKey.canonicalValue,
            "createdAt": .string(createdAt)
        ])
    }
}

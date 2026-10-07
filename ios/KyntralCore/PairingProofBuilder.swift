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

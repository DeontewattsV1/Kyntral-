// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation
import Security

public struct KyntralPublicJWK: Codable, Sendable, Equatable {
    public let kty: String
    public let crv: String
    public let x: String
    public let y: String
    public let kid: String
    public let use: String
    public let alg: String
}

public struct KyntralDeviceIdentity: Codable, Sendable, Equatable {
    public let version: String
    public let deviceId: String
    public let platform: String
    public let signingPublicKey: KyntralPublicJWK
    public let keyAgreementPublicKey: KyntralPublicJWK
    public let createdAt: String
}

public struct KyntralPairingChallenge: Codable, Sendable, Equatable {
    public let version: String
    public let challengeId: String
    public let principalId: String
    public let nonce: String
    public let issuedAt: String
    public let expiresAt: String
}

public struct KyntralSignatureProof: Codable, Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let signature: String
}

public struct KyntralPairingProof: Codable, Sendable, Equatable {
    public let version: String
    public let challengeId: String
    public let nonce: String
    public let deviceIdentity: KyntralDeviceIdentity
    public let proof: KyntralSignatureProof
}

public enum KCJValue: Sendable, Equatable {
    case null
    case bool(Bool)
    case string(String)
    case integer(Int64)
    case array([KCJValue])
    case object([String: KCJValue])
}

public enum KCJError: Error {
    case duplicateNormalizedKey
}

public enum KCJCanonicalizer {
    public static func data(_ value: KCJValue) throws -> Data {
        Data(try string(value).utf8)
    }

    public static func string(_ value: KCJValue) throws -> String {
        switch value {
        case .null:
            return "null"
        case .bool(let value):
            return value ? "true" : "false"
        case .integer(let value):
            return String(value)
        case .string(let value):
            return quote(value.precomposedStringWithCanonicalMapping)
        case .array(let values):
            return "[" + try values.map(string).joined(separator: ",") + "]"
        case .object(let object):
            var normalized: [String: KCJValue] = [:]
            for (key, value) in object {
                let normalizedKey = key.precomposedStringWithCanonicalMapping
                guard normalized[normalizedKey] == nil else {
                    throw KCJError.duplicateNormalizedKey
                }
                normalized[normalizedKey] = value
            }
            let keys = normalized.keys.sorted { lhs, rhs in
                Array(lhs.utf8).lexicographicallyPrecedes(Array(rhs.utf8))
            }
            let fields = try keys.map { key in
                quote(key) + ":" + (try string(normalized[key]!))
            }
            return "{" + fields.joined(separator: ",") + "}"
        }
    }

    public static func signingPreimage(
        purpose: String,
        payload: KCJValue
    ) throws -> Data {
        var data = Data("KYNTRAL\0\(purpose)\0v1\0".utf8)
        data.append(try self.data(payload))
        return data
    }

    private static func quote(_ value: String) -> String {
        var result = "\""
        for scalar in value.unicodeScalars {
            switch scalar.value {
            case 0x22: result += "\\\""
            case 0x5C: result += "\\\\"
            case 0x08: result += "\\b"
            case 0x0C: result += "\\f"
            case 0x0A: result += "\\n"
            case 0x0D: result += "\\r"
            case 0x09: result += "\\t"
            case 0x00...0x1F:
                result += String(format: "\\u%04x", scalar.value)
            default:
                result.unicodeScalars.append(scalar)
            }
        }
        result += "\""
        return result
    }
}

public enum KyntralKeyError: Error {
    case keychain(OSStatus)
    case invalidPublicKey
}

private enum KyntralKeychain {
    static let service = "com.deontewatts.kyntral.device-keys"

    static func read(account: String) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw KyntralKeyError.keychain(status)
        }
        return result as? Data
    }

    static func write(_ data: Data, account: String) throws {
        let base: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
        let status = SecItemCopyMatching(base as CFDictionary, nil)
        if status == errSecSuccess {
            let update: [String: Any] = [kSecValueData as String: data]
            let updateStatus = SecItemUpdate(
                base as CFDictionary,
                update as CFDictionary
            )
            guard updateStatus == errSecSuccess else {
                throw KyntralKeyError.keychain(updateStatus)
            }
            return
        }

        var insert = base
        insert[kSecValueData as String] = data
        insert[kSecAttrAccessible as String] =
            kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(insert as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw KyntralKeyError.keychain(addStatus)
        }
    }
}

public actor DeviceKeyManager {
    public static let shared = DeviceKeyManager()

    private let defaults = UserDefaults.standard

    public init() {}

    public func identity() throws -> KyntralDeviceIdentity {
        let signing = try signingKey()
        let agreement = try agreementKey()
        return KyntralDeviceIdentity(
            version: "kyntral.device.v1",
            deviceId: deviceId(),
            platform: "ios",
            signingPublicKey: try jwk(
                representation: signing.publicKey.x963Representation,
                prefix: "devsig",
                use: "sig",
                alg: "ES256"
            ),
            keyAgreementPublicKey: try jwk(
                representation: agreement.publicKey.x963Representation,
                prefix: "devkex",
                use: "enc",
                alg: "ECDH-ES"
            ),
            createdAt: createdAt()
        )
    }

    public func sign(_ data: Data) throws -> Data {
        try signingKey().signature(for: data).derRepresentation
    }

    public func signingKeyID() throws -> String {
        try jwk(
            representation: signingKey().publicKey.x963Representation,
            prefix: "devsig",
            use: "sig",
            alg: "ES256"
        ).kid
    }

    public func makePairingProof(
        challenge: KyntralPairingChallenge
    ) throws -> KyntralPairingProof {
        let identity = try identity()
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
        let signature = try sign(preimage).base64URLString
        return KyntralPairingProof(
            version: "kyntral.pairing-proof.v1",
            challengeId: challenge.challengeId,
            nonce: challenge.nonce,
            deviceIdentity: identity,
            proof: KyntralSignatureProof(
                keyId: identity.signingPublicKey.kid,
                algorithm: "ES256",
                signature: signature
            )
        )
    }

    private func signingKey() throws -> P256.Signing.PrivateKey {
        if let raw = try KyntralKeychain.read(account: "signing") {
            return try P256.Signing.PrivateKey(rawRepresentation: raw)
        }
        let key = P256.Signing.PrivateKey()
        try KyntralKeychain.write(key.rawRepresentation, account: "signing")
        return key
    }

    private func agreementKey() throws -> P256.KeyAgreement.PrivateKey {
        if let raw = try KyntralKeychain.read(account: "key-agreement") {
            return try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
        }
        let key = P256.KeyAgreement.PrivateKey()
        try KyntralKeychain.write(
            key.rawRepresentation,
            account: "key-agreement"
        )
        return key
    }

    private func deviceId() -> String {
        if let existing = defaults.string(forKey: "kyntral.device.id") {
            return existing
        }
        let value = "dev_" + UUID().uuidString
            .replacingOccurrences(of: "-", with: "")
            .lowercased()
        defaults.set(value, forKey: "kyntral.device.id")
        return value
    }

    private func createdAt() -> String {
        if let existing = defaults.string(forKey: "kyntral.device.createdAt") {
            return existing
        }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let value = formatter.string(from: Date())
        defaults.set(value, forKey: "kyntral.device.createdAt")
        return value
    }

    private func jwk(
        representation: Data,
        prefix: String,
        use: String,
        alg: String
    ) throws -> KyntralPublicJWK {
        guard representation.count == 65, representation.first == 0x04 else {
            throw KyntralKeyError.invalidPublicKey
        }
        let x = representation.subdata(in: 1..<33)
        let y = representation.subdata(in: 33..<65)
        let digest = SHA256.hash(data: representation)
        let keyId = prefix + "_" + Data(digest.prefix(12)).base64URLString
        return KyntralPublicJWK(
            kty: "EC",
            crv: "P-256",
            x: x.base64URLString,
            y: y.base64URLString,
            kid: keyId,
            use: use,
            alg: alg
        )
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

public extension Data {
    var base64URLString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

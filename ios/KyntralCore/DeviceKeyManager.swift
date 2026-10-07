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

public enum KyntralKeyError: Error {
    case keychain(OSStatus)
    case keyCreation
    case publicKey
    case signature
}

public actor DeviceKeyManager {
    public static let shared = DeviceKeyManager()

    private let signingTag = Data("com.deontewatts.kyntral.signing".utf8)
    private let agreementTag = Data("com.deontewatts.kyntral.key-agreement".utf8)
    private let defaults = UserDefaults.standard

    public init() {}

    public func identity() throws -> KyntralDeviceIdentity {
        let signing = try loadOrCreate(tag: signingTag)
        let agreement = try loadOrCreate(tag: agreementTag)
        return KyntralDeviceIdentity(
            version: "kyntral.device.v1",
            deviceId: deviceId(),
            platform: "ios",
            signingPublicKey: try jwk(
                key: signing,
                prefix: "devsig",
                use: "sig",
                alg: "ES256"
            ),
            keyAgreementPublicKey: try jwk(
                key: agreement,
                prefix: "devkex",
                use: "enc",
                alg: "ECDH-ES"
            ),
            createdAt: createdAt()
        )
    }

    public func sign(_ data: Data) throws -> Data {
        let key = try loadOrCreate(tag: signingTag)
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            data as CFData,
            &error
        ) as Data? else {
            if let error = error?.takeRetainedValue() {
                throw error
            }
            throw KyntralKeyError.signature
        }
        return signature
    }

    public func signingKeyID() throws -> String {
        try jwk(
            key: loadOrCreate(tag: signingTag),
            prefix: "devsig",
            use: "sig",
            alg: "ES256"
        ).kid
    }

    private func loadOrCreate(tag: Data) throws -> SecKey {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true
        ]
        var existing: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &existing)
        if status == errSecSuccess, let key = existing as! SecKey? {
            return key
        }
        if status != errSecItemNotFound {
            throw KyntralKeyError.keychain(status)
        }

        if let secure = try? createKey(tag: tag, secureEnclave: true) {
            return secure
        }
        return try createKey(tag: tag, secureEnclave: false)
    }

    private func createKey(tag: Data, secureEnclave: Bool) throws -> SecKey {
        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
        ]
        if secureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            if let error = error?.takeRetainedValue() {
                throw error
            }
            throw KyntralKeyError.keyCreation
        }
        return key
    }

    private func jwk(
        key: SecKey,
        prefix: String,
        use: String,
        alg: String
    ) throws -> KyntralPublicJWK {
        guard let publicKey = SecKeyCopyPublicKey(key) else {
            throw KyntralKeyError.publicKey
        }
        var error: Unmanaged<CFError>?
        guard let raw = SecKeyCopyExternalRepresentation(publicKey, &error) as Data?,
              raw.count == 65,
              raw.first == 0x04 else {
            throw KyntralKeyError.publicKey
        }
        let x = raw.subdata(in: 1..<33)
        let y = raw.subdata(in: 33..<65)
        let digest = SHA256.hash(data: raw)
        let kid = prefix + "_" + Data(digest.prefix(12)).base64URLString
        return KyntralPublicJWK(
            kty: "EC",
            crv: "P-256",
            x: x.base64URLString,
            y: y.base64URLString,
            kid: kid,
            use: use,
            alg: alg
        )
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
}

public extension Data {
    var base64URLString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

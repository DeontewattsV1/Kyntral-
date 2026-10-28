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

public extension Data {
    var base64URLString: String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

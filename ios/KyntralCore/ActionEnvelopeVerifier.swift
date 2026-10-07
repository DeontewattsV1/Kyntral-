// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation
import Security

public struct RemoteAuthorizationProof: Codable, Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let signature: String
}

public struct RemoteActionEnvelope: Codable, Sendable, Equatable {
    public let version: String
    public let actionId: String
    public let deviceId: String
    public let scopeId: String
    public let workflowId: String
    public let capability: String
    public let risk: KyntralRiskClass
    public let nonce: String
    public let issuedAt: String
    public let expiresAt: String
    public let idempotencyKey: String
    public let authorizationProof: RemoteAuthorizationProof

    var canonicalUnsignedValue: KCJValue {
        .object([
            "version": .string(version),
            "actionId": .string(actionId),
            "deviceId": .string(deviceId),
            "scopeId": .string(scopeId),
            "workflowId": .string(workflowId),
            "capability": .string(capability),
            "risk": .string(risk.rawValue),
            "nonce": .string(nonce),
            "issuedAt": .string(issuedAt),
            "expiresAt": .string(expiresAt),
            "idempotencyKey": .string(idempotencyKey)
        ])
    }

    var canonicalSignedValue: KCJValue {
        .object([
            "version": .string(version),
            "actionId": .string(actionId),
            "deviceId": .string(deviceId),
            "scopeId": .string(scopeId),
            "workflowId": .string(workflowId),
            "capability": .string(capability),
            "risk": .string(risk.rawValue),
            "nonce": .string(nonce),
            "issuedAt": .string(issuedAt),
            "expiresAt": .string(expiresAt),
            "idempotencyKey": .string(idempotencyKey),
            "authorizationProof": .object([
                "keyId": .string(authorizationProof.keyId),
                "algorithm": .string(authorizationProof.algorithm),
                "signature": .string(authorizationProof.signature)
            ])
        ])
    }
}

public struct VerifiedRemoteAction: Sendable, Equatable {
    public let action: RemoteActionEnvelope
    public let actionHash: String
}

public enum ActionEnvelopeVerificationError: Error {
    case unsupportedVersion
    case invalidAuthorizationKey
    case authorizationKeyMismatch
    case invalidSignature
    case wrongDevice
    case wrongScope
    case invalidTime
    case invalidLifetime
    case workflowMismatch
    case authorizationRequired(AuthorizationDecision)
    case replayDetected
}

private struct ActionReplayState: Codable {
    var nonces: [String: Date] = [:]
    var idempotencyKeys: [String: Date] = [:]
}

public actor ActionReplayLedger {
    public static let shared = ActionReplayLedger()

    private let stateURL: URL
    private var state: ActionReplayState

    public init(stateURL: URL? = nil) {
        let root = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let directory = root.appendingPathComponent("Kyntral", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let resolvedURL = stateURL ?? directory.appendingPathComponent("action-replay-ledger.json")
        self.stateURL = resolvedURL
        if let data = try? Data(contentsOf: resolvedURL),
           let decoded = try? JSONDecoder().decode(ActionReplayState.self, from: data) {
            self.state = decoded
        } else {
            self.state = ActionReplayState()
        }
    }

    public func consume(
        nonce: String,
        idempotencyKey: String,
        expiresAt: Date,
        now: Date
    ) throws -> Bool {
        prune(now: now)
        guard state.nonces[nonce] == nil,
              state.idempotencyKeys[idempotencyKey] == nil else {
            return false
        }
        state.nonces[nonce] = expiresAt
        state.idempotencyKeys[idempotencyKey] = expiresAt
        try persist()
        return true
    }

    private func prune(now: Date) {
        let cutoff = now.addingTimeInterval(-60)
        state.nonces = state.nonces.filter { $0.value >= cutoff }
        state.idempotencyKeys = state.idempotencyKeys.filter { $0.value >= cutoff }
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

public struct ActionEnvelopeVerifier {
    public static let maximumLifetime: TimeInterval = 5 * 60
    public static let acceptedClockSkew: TimeInterval = 60

    private let registry: LocalWorkflowRegistry
    private let replayLedger: ActionReplayLedger

    public init(
        registry: LocalWorkflowRegistry = .shared,
        replayLedger: ActionReplayLedger = .shared
    ) {
        self.registry = registry
        self.replayLedger = replayLedger
    }

    public func verifyForLocalDevice(
        action: RemoteActionEnvelope,
        trustedAuthorizationKey: KyntralPublicJWK,
        expectedScopeId: String,
        now: Date = Date(),
        keyManager: DeviceKeyManager = .shared
    ) async throws -> VerifiedRemoteAction {
        let identity = try await keyManager.identity()
        return try await verifyAndConsume(
            action: action,
            trustedAuthorizationKey: trustedAuthorizationKey,
            expectedDeviceId: identity.deviceId,
            expectedScopeId: expectedScopeId,
            now: now
        )
    }

    public func verifyAndConsume(
        action: RemoteActionEnvelope,
        trustedAuthorizationKey: KyntralPublicJWK,
        expectedDeviceId: String,
        expectedScopeId: String,
        now: Date = Date()
    ) async throws -> VerifiedRemoteAction {
        guard action.version == "kyntral.action.v1" else {
            throw ActionEnvelopeVerificationError.unsupportedVersion
        }
        guard action.deviceId == expectedDeviceId else {
            throw ActionEnvelopeVerificationError.wrongDevice
        }
        guard action.scopeId == expectedScopeId else {
            throw ActionEnvelopeVerificationError.wrongScope
        }
        guard trustedAuthorizationKey.kty == "EC",
              trustedAuthorizationKey.crv == "P-256",
              trustedAuthorizationKey.use == "sig",
              trustedAuthorizationKey.alg == "ES256" else {
            throw ActionEnvelopeVerificationError.invalidAuthorizationKey
        }
        guard action.authorizationProof.algorithm == "ES256",
              action.authorizationProof.keyId == trustedAuthorizationKey.kid else {
            throw ActionEnvelopeVerificationError.authorizationKeyMismatch
        }

        let issuedAt = try parseDate(action.issuedAt)
        let expiresAt = try parseDate(action.expiresAt)
        guard expiresAt > issuedAt,
              expiresAt.timeIntervalSince(issuedAt) <= Self.maximumLifetime else {
            throw ActionEnvelopeVerificationError.invalidLifetime
        }
        guard issuedAt <= now.addingTimeInterval(Self.acceptedClockSkew),
              now <= expiresAt.addingTimeInterval(Self.acceptedClockSkew) else {
            throw ActionEnvelopeVerificationError.invalidTime
        }

        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "action-authorization",
            payload: action.canonicalUnsignedValue
        )
        guard verifyES256(
            key: trustedAuthorizationKey,
            message: preimage,
            signatureBase64URL: action.authorizationProof.signature
        ) else {
            throw ActionEnvelopeVerificationError.invalidSignature
        }

        guard let workflow = await registry.workflow(id: action.workflowId),
              workflow.capability == action.capability,
              workflow.risk == action.risk else {
            throw ActionEnvelopeVerificationError.workflowMismatch
        }
        let decision = await registry.decision(
            workflowId: action.workflowId,
            capability: action.capability,
            now: now
        )
        guard decision.permitsExecution else {
            throw ActionEnvelopeVerificationError.authorizationRequired(decision)
        }

        guard try await replayLedger.consume(
            nonce: action.nonce,
            idempotencyKey: action.idempotencyKey,
            expiresAt: expiresAt,
            now: now
        ) else {
            throw ActionEnvelopeVerificationError.replayDetected
        }

        let canonical = try KCJCanonicalizer.data(action.canonicalSignedValue)
        let digest = SHA256.hash(data: canonical)
            .map { String(format: "%02x", $0) }
            .joined()
        return VerifiedRemoteAction(
            action: action,
            actionHash: "sha256:" + digest
        )
    }

    private func parseDate(_ value: String) throws -> Date {
        let fractional = ISO8601DateFormatter()
        fractional.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = fractional.date(from: value) { return date }

        let wholeSeconds = ISO8601DateFormatter()
        wholeSeconds.formatOptions = [.withInternetDateTime]
        if let date = wholeSeconds.date(from: value) { return date }

        throw ActionEnvelopeVerificationError.invalidTime
    }

    private func verifyES256(
        key: KyntralPublicJWK,
        message: Data,
        signatureBase64URL: String
    ) -> Bool {
        guard let x = decodeBase64URL(key.x), x.count == 32,
              let y = decodeBase64URL(key.y), y.count == 32,
              let signature = decodeBase64URL(signatureBase64URL) else {
            return false
        }

        var raw = Data([0x04])
        raw.append(x)
        raw.append(y)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var creationError: Unmanaged<CFError>?
        guard let publicKey = SecKeyCreateWithData(
            raw as CFData,
            attributes as CFDictionary,
            &creationError
        ) else {
            return false
        }

        var verificationError: Unmanaged<CFError>?
        return SecKeyVerifySignature(
            publicKey,
            .ecdsaSignatureMessageX962SHA256,
            message as CFData,
            signature as CFData,
            &verificationError
        )
    }

    private func decodeBase64URL(_ value: String) -> Data? {
        guard !value.isEmpty,
              value.range(of: "^[A-Za-z0-9_-]+$", options: .regularExpression) != nil else {
            return nil
        }
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = (4 - base64.count % 4) % 4
        base64 += String(repeating: "=", count: padding)
        return Data(base64Encoded: base64)
    }
}

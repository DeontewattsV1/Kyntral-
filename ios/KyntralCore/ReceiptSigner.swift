// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation
import Security

public struct ActionAuthorizationProof: Codable, Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let signature: String
}

public struct LocalActionEnvelope: Codable, Sendable, Equatable {
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
    public let authorizationProof: ActionAuthorizationProof

    public init(
        version: String = "kyntral.action.v1",
        actionId: String,
        deviceId: String,
        scopeId: String,
        workflowId: String,
        capability: String,
        risk: KyntralRiskClass,
        nonce: String,
        issuedAt: String,
        expiresAt: String,
        idempotencyKey: String,
        authorizationProof: ActionAuthorizationProof
    ) {
        self.version = version
        self.actionId = actionId
        self.deviceId = deviceId
        self.scopeId = scopeId
        self.workflowId = workflowId
        self.capability = capability
        self.risk = risk
        self.nonce = nonce
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
        self.idempotencyKey = idempotencyKey
        self.authorizationProof = authorizationProof
    }

    public var canonicalUnsignedValue: KCJValue {
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

    public var canonicalSignedValue: KCJValue {
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

    public func actionHash() throws -> String {
        let data = try KCJCanonicalizer.data(canonicalSignedValue)
        return "sha256:" + SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

public struct ReceiptCounts: Codable, Sendable, Equatable {
    public let completed: Int
    public let failed: Int
}

public struct DeviceReceiptProof: Codable, Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let signature: String
}

public struct SignedExecutionReceipt: Codable, Sendable, Equatable {
    public let version: String
    public let receiptId: String
    public let actionId: String
    public let deviceId: String
    public let actionHash: String
    public let outcome: String
    public let startedAt: String
    public let completedAt: String
    public let counts: ReceiptCounts
    public let deviceProof: DeviceReceiptProof
}

public struct ReceiptSigner: Sendable {
    private let keyManager: DeviceKeyManager

    public init(keyManager: DeviceKeyManager = .shared) {
        self.keyManager = keyManager
    }

    public func sign(
        action: LocalActionEnvelope,
        outcome: String,
        completed: Int,
        failed: Int,
        startedAt: Date,
        completedAt: Date
    ) async throws -> SignedExecutionReceipt {
        let actionHash = try action.actionHash()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let receiptId = "rcpt_" + UUID().uuidString
            .replacingOccurrences(of: "-", with: "")
            .lowercased()
        let counts = ReceiptCounts(completed: completed, failed: failed)
        let started = formatter.string(from: startedAt)
        let completedTime = formatter.string(from: completedAt)
        let unsigned = KCJValue.object([
            "version": .string("kyntral.receipt.v1"),
            "receiptId": .string(receiptId),
            "actionId": .string(action.actionId),
            "deviceId": .string(action.deviceId),
            "actionHash": .string(actionHash),
            "outcome": .string(outcome),
            "startedAt": .string(started),
            "completedAt": .string(completedTime),
            "counts": .object([
                "completed": .integer(Int64(completed)),
                "failed": .integer(Int64(failed))
            ])
        ])
        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "execution-receipt",
            payload: unsigned
        )
        let signature = try await keyManager.sign(preimage).base64URLString
        let keyId = try await keyManager.signingKeyID()
        return SignedExecutionReceipt(
            version: "kyntral.receipt.v1",
            receiptId: receiptId,
            actionId: action.actionId,
            deviceId: action.deviceId,
            actionHash: actionHash,
            outcome: outcome,
            startedAt: started,
            completedAt: completedTime,
            counts: counts,
            deviceProof: DeviceReceiptProof(
                keyId: keyId,
                algorithm: "ES256",
                signature: signature
            )
        )
    }
}

public struct TrustedActionContext: Sendable, Equatable {
    public let scopeId: String
    public let authorizationKey: KyntralPublicJWK

    public init(scopeId: String, authorizationKey: KyntralPublicJWK) {
        self.scopeId = scopeId
        self.authorizationKey = authorizationKey
    }
}

public struct VerifiedAction: Sendable, Equatable {
    public let action: LocalActionEnvelope
    public let actionHash: String
}

public enum ActionVerificationError: Error {
    case invalidVersion
    case invalidShape
    case deviceMismatch
    case scopeMismatch
    case workflowMismatch
    case capabilityMismatch
    case riskMismatch
    case authorizationRequired(AuthorizationDecision)
    case invalidTime
    case expired
    case invalidAuthorizationKey
    case invalidSignature
    case replay
}

private struct ActionReplayState: Codable {
    var nonces: [String: Date] = [:]
    var idempotencyKeys: [String: Date] = [:]
    var actionIds: [String: Date] = [:]
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
        let resolvedURL = stateURL ??
            directory.appendingPathComponent("action-replay-ledger.json")
        self.stateURL = resolvedURL
        if let data = try? Data(contentsOf: resolvedURL),
           let decoded = try? JSONDecoder().decode(ActionReplayState.self, from: data) {
            self.state = decoded
        } else {
            self.state = ActionReplayState()
        }
    }

    public func consume(
        actionId: String,
        nonce: String,
        idempotencyKey: String,
        retainUntil: Date,
        now: Date = Date()
    ) throws -> Bool {
        prune(before: now)
        if state.actionIds[actionId] != nil ||
            state.nonces[nonce] != nil ||
            state.idempotencyKeys[idempotencyKey] != nil {
            return false
        }

        state.actionIds[actionId] = retainUntil
        state.nonces[nonce] = retainUntil
        state.idempotencyKeys[idempotencyKey] = retainUntil
        try persist()
        return true
    }

    private func prune(before now: Date) {
        state.actionIds = state.actionIds.filter { $0.value >= now }
        state.nonces = state.nonces.filter { $0.value >= now }
        state.idempotencyKeys = state.idempotencyKeys.filter { $0.value >= now }
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

public struct ActionVerifier: Sendable {
    public static let maximumLifetime: TimeInterval = 5 * 60
    public static let acceptedClockSkew: TimeInterval = 60

    private let keyManager: DeviceKeyManager
    private let registry: LocalWorkflowRegistry
    private let replayLedger: ActionReplayLedger

    public init(
        keyManager: DeviceKeyManager = .shared,
        registry: LocalWorkflowRegistry = .shared,
        replayLedger: ActionReplayLedger = .shared
    ) {
        self.keyManager = keyManager
        self.registry = registry
        self.replayLedger = replayLedger
    }

    public func verifyAndConsume(
        action: LocalActionEnvelope,
        context: TrustedActionContext,
        now: Date = Date()
    ) async throws -> VerifiedAction {
        guard action.version == "kyntral.action.v1" else {
            throw ActionVerificationError.invalidVersion
        }
        try Self.validateShape(action)
        let retainUntil = try Self.validateTimeWindow(action, now: now)

        guard try Self.verifyAuthorizationSignature(
            action: action,
            trustedKey: context.authorizationKey
        ) else {
            throw ActionVerificationError.invalidSignature
        }

        let identity = try await keyManager.identity()
        guard action.deviceId == identity.deviceId else {
            throw ActionVerificationError.deviceMismatch
        }
        guard action.scopeId == context.scopeId else {
            throw ActionVerificationError.scopeMismatch
        }
        guard let workflow = await registry.workflow(id: action.workflowId) else {
            throw ActionVerificationError.workflowMismatch
        }
        guard workflow.capability == action.capability else {
            throw ActionVerificationError.capabilityMismatch
        }
        guard workflow.risk == action.risk else {
            throw ActionVerificationError.riskMismatch
        }

        let decision = await registry.decision(
            workflowId: action.workflowId,
            capability: action.capability,
            risk: action.risk
        )
        guard decision.permitsExecution else {
            throw ActionVerificationError.authorizationRequired(decision)
        }

        guard try await replayLedger.consume(
            actionId: action.actionId,
            nonce: action.nonce,
            idempotencyKey: action.idempotencyKey,
            retainUntil: retainUntil,
            now: now
        ) else {
            throw ActionVerificationError.replay
        }

        return VerifiedAction(
            action: action,
            actionHash: try action.actionHash()
        )
    }

    static func validateShape(_ action: LocalActionEnvelope) throws {
        let idPattern = "^[A-Za-z][A-Za-z0-9_-]{2,127}$"
        let noncePattern = "^[A-Za-z0-9_-]{43}$"
        for value in [
            action.actionId,
            action.deviceId,
            action.scopeId,
            action.workflowId
        ] where value.range(of: idPattern, options: .regularExpression) == nil {
            throw ActionVerificationError.invalidShape
        }
        guard action.capability.count >= 3,
              action.capability.count <= 128,
              action.nonce.range(of: noncePattern, options: .regularExpression) != nil,
              action.idempotencyKey.count >= 16,
              action.idempotencyKey.count <= 128,
              action.authorizationProof.algorithm == "ES256" else {
            throw ActionVerificationError.invalidShape
        }
    }

    static func validateTimeWindow(
        _ action: LocalActionEnvelope,
        now: Date
    ) throws -> Date {
        guard let issuedAt = parseTimestamp(action.issuedAt),
              let expiresAt = parseTimestamp(action.expiresAt),
              expiresAt > issuedAt else {
            throw ActionVerificationError.invalidTime
        }
        let lifetime = expiresAt.timeIntervalSince(issuedAt)
        guard lifetime <= maximumLifetime else {
            throw ActionVerificationError.invalidTime
        }
        guard issuedAt.timeIntervalSince(now) <= acceptedClockSkew else {
            throw ActionVerificationError.invalidTime
        }
        guard now.timeIntervalSince(expiresAt) <= acceptedClockSkew else {
            throw ActionVerificationError.expired
        }
        return expiresAt.addingTimeInterval(acceptedClockSkew)
    }

    static func verifyAuthorizationSignature(
        action: LocalActionEnvelope,
        trustedKey: KyntralPublicJWK
    ) throws -> Bool {
        guard trustedKey.kty == "EC",
              trustedKey.crv == "P-256",
              trustedKey.use == "sig",
              trustedKey.alg == "ES256",
              action.authorizationProof.keyId == trustedKey.kid,
              action.authorizationProof.algorithm == "ES256" else {
            throw ActionVerificationError.invalidAuthorizationKey
        }
        guard let x = decodeBase64URL(trustedKey.x),
              let y = decodeBase64URL(trustedKey.y),
              x.count == 32,
              y.count == 32,
              let signature = decodeBase64URL(action.authorizationProof.signature) else {
            throw ActionVerificationError.invalidAuthorizationKey
        }

        var rawKey = Data([0x04])
        rawKey.append(x)
        rawKey.append(y)
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256
        ]
        var creationError: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(
            rawKey as CFData,
            attributes as CFDictionary,
            &creationError
        ) else {
            throw ActionVerificationError.invalidAuthorizationKey
        }

        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "action-authorization",
            payload: action.canonicalUnsignedValue
        )
        var verificationError: Unmanaged<CFError>?
        return SecKeyVerifySignature(
            key,
            .ecdsaSignatureMessageX962SHA256,
            preimage as CFData,
            signature as CFData,
            &verificationError
        )
    }

    private static func parseTimestamp(_ value: String) -> Date? {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: value) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: value)
    }

    private static func decodeBase64URL(_ value: String) -> Data? {
        guard value.range(
            of: "^[A-Za-z0-9_-]+$",
            options: .regularExpression
        ) != nil else {
            return nil
        }
        var base64 = value
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder != 0 {
            base64 += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: base64)
    }
}

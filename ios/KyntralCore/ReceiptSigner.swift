// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation

public struct LocalActionEnvelope: Sendable {
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
    public let authorizationKeyId: String
    public let authorizationSignature: String

    public var canonicalSignedValue: KCJValue {
        .object([
            "version": .string("kyntral.action.v1"),
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
                "keyId": .string(authorizationKeyId),
                "algorithm": .string("ES256"),
                "signature": .string(authorizationSignature)
            ])
        ])
    }
}

public struct ReceiptCounts: Codable, Sendable { public let completed: Int; public let failed: Int }
public struct DeviceReceiptProof: Codable, Sendable { public let keyId: String; public let algorithm: String; public let signature: String }

public struct SignedExecutionReceipt: Codable, Sendable {
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

public struct ReceiptSigner {
    private let keyManager: DeviceKeyManager
    public init(keyManager: DeviceKeyManager = .shared) { self.keyManager = keyManager }

    public func sign(
        action: LocalActionEnvelope,
        outcome: String,
        completed: Int,
        failed: Int,
        startedAt: Date,
        completedAt: Date
    ) async throws -> SignedExecutionReceipt {
        let actionData = try KCJCanonicalizer.data(action.canonicalSignedValue)
        let actionHash = "sha256:" + SHA256.hash(data: actionData).map { String(format: "%02x", $0) }.joined()
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        let receiptId = "rcpt_" + UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let counts = ReceiptCounts(completed: completed, failed: failed)
        let unsigned = KCJValue.object([
            "version": .string("kyntral.receipt.v1"),
            "receiptId": .string(receiptId),
            "actionId": .string(action.actionId),
            "deviceId": .string(action.deviceId),
            "actionHash": .string(actionHash),
            "outcome": .string(outcome),
            "startedAt": .string(formatter.string(from: startedAt)),
            "completedAt": .string(formatter.string(from: completedAt)),
            "counts": .object([
                "completed": .integer(Int64(completed)),
                "failed": .integer(Int64(failed))
            ])
        ])
        let preimage = try KCJCanonicalizer.signingPreimage(purpose: "execution-receipt", payload: unsigned)
        let signature = try await keyManager.sign(preimage).base64URLString
        let keyId = try await keyManager.signingKeyID()
        return SignedExecutionReceipt(
            version: "kyntral.receipt.v1",
            receiptId: receiptId,
            actionId: action.actionId,
            deviceId: action.deviceId,
            actionHash: actionHash,
            outcome: outcome,
            startedAt: formatter.string(from: startedAt),
            completedAt: formatter.string(from: completedAt),
            counts: counts,
            deviceProof: DeviceReceiptProof(keyId: keyId, algorithm: "ES256", signature: signature)
        )
    }
}

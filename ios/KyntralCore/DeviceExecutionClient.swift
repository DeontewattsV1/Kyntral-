// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation
import Security

public struct DeviceActionDelivery: Codable, Sendable {
    public let action: LocalActionEnvelope
}

public struct ReceiptAcceptance: Codable, Sendable {
    public let status: String
    public let verified: Bool
}

public struct DeviceRequestSignatureProof: Codable, Sendable, Equatable {
    public let keyId: String
    public let algorithm: String
    public let signature: String
}

public struct KyntralDeviceRequestProof: Codable, Sendable, Equatable {
    public let version: String
    public let deviceId: String
    public let method: String
    public let path: String
    public let bodyHash: String
    public let nonce: String
    public let issuedAt: String
    public let expiresAt: String
    public let proof: DeviceRequestSignatureProof

    var canonicalUnsignedValue: KCJValue {
        .object([
            "version": .string(version),
            "deviceId": .string(deviceId),
            "method": .string(method),
            "path": .string(path),
            "bodyHash": .string(bodyHash),
            "nonce": .string(nonce),
            "issuedAt": .string(issuedAt),
            "expiresAt": .string(expiresAt)
        ])
    }
}

public struct DeviceRequestSigner: Sendable {
    public static let headerName = "X-Kyntral-Device-Proof"
    public static let maximumLifetime: TimeInterval = 60

    private let keyManager: DeviceKeyManager

    public init(keyManager: DeviceKeyManager = .shared) {
        self.keyManager = keyManager
    }

    public func headerValue(
        deviceId: String,
        method: String,
        path: String,
        body: Data,
        now: Date = Date()
    ) async throws -> String {
        var nonce = Data(count: 32)
        let status = nonce.withUnsafeMutableBytes { buffer in
            SecRandomCopyBytes(
                kSecRandomDefault,
                buffer.count,
                buffer.baseAddress!
            )
        }
        guard status == errSecSuccess else {
            throw DeviceExecutionClientError.deviceProofCreation
        }

        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [
            .withInternetDateTime,
            .withFractionalSeconds
        ]
        let expiresAt = now.addingTimeInterval(Self.maximumLifetime)
        let unsigned = KyntralDeviceRequestProof(
            version: "kyntral.device-request.v1",
            deviceId: deviceId,
            method: method,
            path: path,
            bodyHash: Self.sha256(body),
            nonce: nonce.base64URLString,
            issuedAt: formatter.string(from: now),
            expiresAt: formatter.string(from: expiresAt),
            proof: DeviceRequestSignatureProof(
                keyId: try await keyManager.signingKeyID(),
                algorithm: "ES256",
                signature: ""
            )
        )
        let preimage = try KCJCanonicalizer.signingPreimage(
            purpose: "device-request",
            payload: unsigned.canonicalUnsignedValue
        )
        let signature = try await keyManager.sign(preimage).base64URLString
        let signed = KyntralDeviceRequestProof(
            version: unsigned.version,
            deviceId: unsigned.deviceId,
            method: unsigned.method,
            path: unsigned.path,
            bodyHash: unsigned.bodyHash,
            nonce: unsigned.nonce,
            issuedAt: unsigned.issuedAt,
            expiresAt: unsigned.expiresAt,
            proof: DeviceRequestSignatureProof(
                keyId: unsigned.proof.keyId,
                algorithm: "ES256",
                signature: signature
            )
        )
        return try JSONEncoder().encode(signed).base64URLString
    }

    public static func sha256(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }
}

public enum DeviceExecutionClientError: Error {
    case invalidServiceURL
    case invalidAccessToken
    case invalidDeviceId
    case noTrustedAuthorizationKey
    case deviceProofCreation
    case deviceMismatch
    case unexpectedResponse(Int)
    case receiptNotVerified
}

public enum DeviceExecutionCycleResult: Sendable, Equatable {
    case idle
    case receiptUploaded(actionId: String)
    case executed(actionId: String, outcome: String)
}

public struct DeviceExecutionClient: Sendable {
    private let serviceBaseURL: URL
    private let session: URLSession
    private let verifier: ActionVerifier
    private let runtime: KyntralRuntime
    private let receiptSigner: ReceiptSigner
    private let journal: ExecutionJournal
    private let keyManager: DeviceKeyManager
    private let trustStore: AuthorizationTrustStore
    private let requestSigner: DeviceRequestSigner

    public init(
        serviceBaseURL: URL,
        session: URLSession? = nil,
        verifier: ActionVerifier = ActionVerifier(),
        runtime: KyntralRuntime = .shared,
        receiptSigner: ReceiptSigner = ReceiptSigner(),
        journal: ExecutionJournal = .shared,
        keyManager: DeviceKeyManager = .shared,
        trustStore: AuthorizationTrustStore = .shared,
        requestSigner: DeviceRequestSigner = DeviceRequestSigner()
    ) throws {
        guard serviceBaseURL.scheme?.lowercased() == "https",
              serviceBaseURL.host != nil,
              serviceBaseURL.user == nil,
              serviceBaseURL.password == nil else {
            throw DeviceExecutionClientError.invalidServiceURL
        }
        self.serviceBaseURL = serviceBaseURL
        self.verifier = verifier
        self.runtime = runtime
        self.receiptSigner = receiptSigner
        self.journal = journal
        self.keyManager = keyManager
        self.trustStore = trustStore
        self.requestSigner = requestSigner

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

    public func processNext(
        accessToken: String
    ) async throws -> DeviceExecutionCycleResult {
        try validateAccessToken(accessToken)
        let identity = try await keyManager.identity()
        try validateOpaqueId(identity.deviceId)

        if let pending = await journal.firstPendingReceipt() {
            guard pending.deviceId == identity.deviceId else {
                throw DeviceExecutionClientError.deviceMismatch
            }
            try await submitAndAcknowledge(
                receipt: pending,
                deviceId: identity.deviceId,
                accessToken: accessToken
            )
            return .receiptUploaded(actionId: pending.actionId)
        }

        guard let authorizationKey = try await trustStore.current() else {
            throw DeviceExecutionClientError.noTrustedAuthorizationKey
        }

        let endpoint = try endpointURL(
            path: "/v1/devices/" + identity.deviceId + "/actions/next"
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        request.setValue(
            "Bearer " + accessToken,
            forHTTPHeaderField: "Authorization"
        )
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(
            try await requestSigner.headerValue(
                deviceId: identity.deviceId,
                method: "GET",
                path: endpoint.path,
                body: Data()
            ),
            forHTTPHeaderField: DeviceRequestSigner.headerName
        )
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw DeviceExecutionClientError.unexpectedResponse(-1)
        }
        if http.statusCode == 204 { return .idle }
        guard http.statusCode == 200 else {
            throw DeviceExecutionClientError.unexpectedResponse(http.statusCode)
        }

        let delivery = try JSONDecoder().decode(
            DeviceActionDelivery.self,
            from: data
        )
        guard delivery.action.deviceId == identity.deviceId else {
            throw DeviceExecutionClientError.deviceMismatch
        }

        if let existing = await journal.receipt(
            actionId: delivery.action.actionId
        ) {
            guard existing.actionHash == (try delivery.action.actionHash()) else {
                throw DeviceExecutionClientError.receiptNotVerified
            }
            try await submitAndAcknowledge(
                receipt: existing,
                deviceId: identity.deviceId,
                accessToken: accessToken
            )
            return .receiptUploaded(actionId: existing.actionId)
        }

        let verified = try await verifier.verifyAndConsume(
            action: delivery.action,
            context: TrustedActionContext(
                scopeId: delivery.action.scopeId,
                authorizationKey: authorizationKey
            )
        )

        let startedAt = Date()
        let result = await runtime.executeVerifiedAction(verified)
        let completedAt = Date()
        let outcome = result.failed == 0
            ? "completed"
            : (result.completed > 0 ? "partial" : "failed")
        let receipt = try await receiptSigner.sign(
            action: verified.action,
            outcome: outcome,
            completed: result.completed,
            failed: result.failed,
            startedAt: startedAt,
            completedAt: completedAt
        )

        // Durably persist proof of local execution before any network upload.
        try await journal.record(receipt)

        try await submitAndAcknowledge(
            receipt: receipt,
            deviceId: identity.deviceId,
            accessToken: accessToken
        )
        return .executed(
            actionId: receipt.actionId,
            outcome: receipt.outcome
        )
    }

    private func submitAndAcknowledge(
        receipt: SignedExecutionReceipt,
        deviceId: String,
        accessToken: String
    ) async throws {
        let acceptance = try await submit(
            receipt: receipt,
            deviceId: deviceId,
            accessToken: accessToken
        )
        guard acceptance.verified,
              acceptance.status == "accepted" ||
                acceptance.status == "duplicate" else {
            throw DeviceExecutionClientError.receiptNotVerified
        }
        try await journal.remove(actionId: receipt.actionId)
    }

    private func submit(
        receipt: SignedExecutionReceipt,
        deviceId: String,
        accessToken: String
    ) async throws -> ReceiptAcceptance {
        let endpoint = try endpointURL(
            path: "/v1/devices/" + deviceId + "/receipts"
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.timeoutInterval = 30
        request.setValue(
            "Bearer " + accessToken,
            forHTTPHeaderField: "Authorization"
        )
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        let body = try JSONEncoder().encode(receipt)
        request.httpBody = body
        request.setValue(
            try await requestSigner.headerValue(
                deviceId: deviceId,
                method: "POST",
                path: endpoint.path,
                body: body
            ),
            forHTTPHeaderField: DeviceRequestSigner.headerName
        )

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              http.statusCode == 200 || http.statusCode == 201 else {
            throw DeviceExecutionClientError.unexpectedResponse(
                (response as? HTTPURLResponse)?.statusCode ?? -1
            )
        }
        return try JSONDecoder().decode(ReceiptAcceptance.self, from: data)
    }

    private func endpointURL(path: String) throws -> URL {
        guard var components = URLComponents(
            url: serviceBaseURL,
            resolvingAgainstBaseURL: false
        ) else {
            throw DeviceExecutionClientError.invalidServiceURL
        }
        components.path = path
        components.query = nil
        components.fragment = nil
        guard let url = components.url else {
            throw DeviceExecutionClientError.invalidServiceURL
        }
        return url
    }

    private func validateAccessToken(_ token: String) throws {
        guard !token.isEmpty,
              token.count <= 16_384,
              token.rangeOfCharacter(from: .controlCharacters) == nil else {
            throw DeviceExecutionClientError.invalidAccessToken
        }
    }

    private func validateOpaqueId(_ value: String) throws {
        guard value.range(
            of: "^[A-Za-z][A-Za-z0-9_-]{2,127}$",
            options: .regularExpression
        ) != nil else {
            throw DeviceExecutionClientError.invalidDeviceId
        }
    }
}

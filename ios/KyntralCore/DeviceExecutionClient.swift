// SPDX-License-Identifier: BUSL-1.1

import Foundation

public struct DeviceActionDelivery: Codable, Sendable {
    public let action: LocalActionEnvelope
}

public struct ReceiptAcceptance: Codable, Sendable {
    public let status: String
    public let verified: Bool
}

public enum DeviceExecutionClientError: Error {
    case invalidServiceURL
    case invalidAccessToken
    case invalidDeviceId
    case noTrustedAuthorizationKey
    case unexpectedResponse(Int)
    case receiptNotVerified
}

public struct DeviceExecutionClient: Sendable {
    private let serviceBaseURL: URL
    private let session: URLSession
    private let verifier: ActionVerifier
    private let runtime: KyntralRuntime
    private let receiptSigner: ReceiptSigner

    public init(
        serviceBaseURL: URL,
        session: URLSession? = nil,
        verifier: ActionVerifier = ActionVerifier(),
        runtime: KyntralRuntime = .shared,
        receiptSigner: ReceiptSigner = ReceiptSigner()
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
        deviceId: String,
        scopeId: String,
        authorizationKey: KyntralPublicJWK,
        accessToken: String
    ) async throws -> SignedExecutionReceipt? {
        try validateAccessToken(accessToken)
        try validateOpaqueId(deviceId)

        let endpoint = try endpointURL(
            path: "/v1/devices/" + deviceId + "/actions/next"
        )
        var request = URLRequest(url: endpoint)
        request.httpMethod = "GET"
        request.timeoutInterval = 30
        request.setValue("Bearer " + accessToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.cachePolicy = .reloadIgnoringLocalCacheData

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse else {
            throw DeviceExecutionClientError.unexpectedResponse(-1)
        }
        if http.statusCode == 204 { return nil }
        guard http.statusCode == 200 else {
            throw DeviceExecutionClientError.unexpectedResponse(http.statusCode)
        }

        let delivery = try JSONDecoder().decode(DeviceActionDelivery.self, from: data)
        let verified = try await verifier.verifyAndConsume(
            action: delivery.action,
            context: TrustedActionContext(
                scopeId: scopeId,
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
        return receipt
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
        request.setValue("Bearer " + accessToken, forHTTPHeaderField: "Authorization")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(receipt)

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

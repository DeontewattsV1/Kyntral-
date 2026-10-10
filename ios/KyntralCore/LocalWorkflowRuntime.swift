// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation

public struct LocalWorkflowDefinition: Codable, Sendable, Equatable {
    public let id: String
    public let capability: String
    public let risk: KyntralRiskClass
    public let resolverEndpoint: URL?
    public let destinationBookmark: Data?
    public let allowedResolverHosts: [String]

    public init(
        id: String,
        capability: String,
        risk: KyntralRiskClass,
        resolverEndpoint: URL? = nil,
        destinationBookmark: Data? = nil,
        allowedResolverHosts: [String] = []
    ) {
        self.id = id
        self.capability = capability
        self.risk = risk
        self.resolverEndpoint = resolverEndpoint
        self.destinationBookmark = destinationBookmark
        self.allowedResolverHosts = allowedResolverHosts
    }
}

public struct LocalStandingGrant: Codable, Sendable, Equatable {
    public let workflowId: String
    public let capability: String
    public let risk: KyntralRiskClass
    public let allowed: Bool
    public let issuedAt: Date
    public let expiresAt: Date?
}

private struct LocalRegistryState: Codable {
    var workflows: [String: LocalWorkflowDefinition] = [:]
    var grants: [String: LocalStandingGrant] = [:]
}

public actor LocalWorkflowRegistry {
    public static let shared = LocalWorkflowRegistry()

    private let stateURL: URL
    private var state: LocalRegistryState

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
        self.stateURL = stateURL ??
            directory.appendingPathComponent("local-registry.json")

        if let data = try? Data(contentsOf: self.stateURL),
           let decoded = try? JSONDecoder().decode(
            LocalRegistryState.self,
            from: data
           ) {
            self.state = decoded
        } else {
            self.state = LocalRegistryState()
        }
    }

    public func putWorkflow(_ workflow: LocalWorkflowDefinition) throws {
        state.workflows[workflow.id] = workflow
        try persist()
    }

    public func workflow(id: String) -> LocalWorkflowDefinition? {
        state.workflows[id]
    }

    public func putStandingGrant(_ grant: LocalStandingGrant) throws {
        let key = grant.workflowId + "|" + grant.capability
        state.grants[key] = grant
        try persist()
    }

    public func decision(
        workflowId: String,
        capability: String,
        now: Date = Date()
    ) -> AuthorizationDecision {
        let key = workflowId + "|" + capability
        guard let grant = state.grants[key] else { return .unknown }
        guard grant.allowed else { return .denied }
        if let expiresAt = grant.expiresAt, expiresAt < now {
            return .expired
        }
        return .allowed
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

private struct DedupeState: Codable {
    var urlHashes: Set<String> = []
    var contentHashes: Set<String> = []
}

public actor DedupeLedger {
    public static let shared = DedupeLedger()

    private let stateURL: URL
    private var state: DedupeState

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
        self.stateURL = stateURL ??
            directory.appendingPathComponent("dedupe-ledger.json")

        if let data = try? Data(contentsOf: self.stateURL),
           let decoded = try? JSONDecoder().decode(DedupeState.self, from: data) {
            self.state = decoded
        } else {
            self.state = DedupeState()
        }
    }

    public func hasSource(_ url: URL) -> Bool {
        state.urlHashes.contains(Self.sourceHash(url))
    }

    public func recordSource(_ url: URL) throws {
        state.urlHashes.insert(Self.sourceHash(url))
        try persist()
    }

    public func hasContent(_ data: Data) -> Bool {
        state.contentHashes.contains(Self.contentHash(data))
    }

    public func recordContent(_ data: Data) throws {
        state.contentHashes.insert(Self.contentHash(data))
        try persist()
    }

    public static func sourceHash(_ url: URL) -> String {
        let normalized = canonicalURL(url)
        return "sha256:" + SHA256.hash(data: Data(normalized.utf8))
            .map { String(format: "%02x", $0) }
            .joined()
    }

    public static func contentHash(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private static func canonicalURL(_ url: URL) -> String {
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false)
        else { return url.absoluteString }
        parts.fragment = nil
        parts.scheme = parts.scheme?.lowercased()
        parts.host = parts.host?.lowercased()
        return parts.string ?? url.absoluteString
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

public enum KyntralRuntimeError: Error {
    case unknownWorkflow
    case authorizationRequired(AuthorizationDecision)
    case workflowNotConfigured
    case invalidDestinationBookmark
    case invalidResolverConfiguration
}

public actor KyntralRuntime {
    public static let shared = KyntralRuntime()

    private let registry: LocalWorkflowRegistry
    private let ledger: DedupeLedger

    public init(
        registry: LocalWorkflowRegistry = .shared,
        ledger: DedupeLedger = .shared
    ) {
        self.registry = registry
        self.ledger = ledger
    }

    public func configureMediaIntake(
        endpoint: URL,
        destinationBookmark: Data,
        standingGrantAllowed: Bool
    ) async throws {
        guard endpoint.scheme?.lowercased() == "https",
              let host = endpoint.host?.lowercased() else {
            throw KyntralRuntimeError.invalidResolverConfiguration
        }
        let workflow = LocalWorkflowDefinition(
            id: "wf_media_intake",
            capability: "workflow.execute",
            risk: .k2,
            resolverEndpoint: endpoint,
            destinationBookmark: destinationBookmark,
            allowedResolverHosts: [host]
        )
        try await registry.putWorkflow(workflow)
        try await registry.putStandingGrant(
            LocalStandingGrant(
                workflowId: workflow.id,
                capability: workflow.capability,
                risk: workflow.risk,
                allowed: standingGrantAllowed,
                issuedAt: Date(),
                expiresAt: nil
            )
        )
    }

    public func workflowState(
        id: String
    ) async -> (workflow: LocalWorkflowDefinition?, decision: AuthorizationDecision) {
        let workflow = await registry.workflow(id: id)
        guard let workflow else { return (nil, .unknown) }
        let decision = await registry.decision(
            workflowId: id,
            capability: workflow.capability
        )
        return (workflow, decision)
    }

    public func runMediaIntake(
        workflowId: String,
        urls: [URL]
    ) async throws -> MediaIntakeResult {
        guard let workflow = await registry.workflow(id: workflowId) else {
            throw KyntralRuntimeError.unknownWorkflow
        }

        let decision = await registry.decision(
            workflowId: workflowId,
            capability: workflow.capability
        )
        guard decision.permitsExecution else {
            throw KyntralRuntimeError.authorizationRequired(decision)
        }

        guard let endpoint = workflow.resolverEndpoint,
              let bookmark = workflow.destinationBookmark else {
            throw KyntralRuntimeError.workflowNotConfigured
        }
        guard let endpointHost = endpoint.host?.lowercased(),
              workflow.allowedResolverHosts.contains(endpointHost) else {
            throw KyntralRuntimeError.invalidResolverConfiguration
        }

        var stale = false
        let destination = try URL(
            resolvingBookmarkData: bookmark,
            options: [.withSecurityScope],
            relativeTo: nil,
            bookmarkDataIsStale: &stale
        )
        if stale {
            throw KyntralRuntimeError.invalidDestinationBookmark
        }

        let resolver = try CobaltCompatibleResolver(
            endpoint: endpoint,
            allowedEndpointHosts: Set(workflow.allowedResolverHosts)
        )
        return await MediaIntakeWorkflow(
            resolver: resolver,
            ledger: ledger
        ).run(
            sources: urls,
            destination: destination
        )
    }
}

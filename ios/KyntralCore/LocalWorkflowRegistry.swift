// SPDX-License-Identifier: BUSL-1.1

import Foundation

public struct LocalWorkflowDefinition: Codable, Sendable, Equatable {
    public let id: String
    public let capability: String
    public let risk: KyntralRiskClass
    public let scopeId: String?
    public let resolverEndpoint: URL?
    public let destinationBookmark: Data?
    public let allowedResolverHosts: [String]

    public init(
        id: String,
        capability: String,
        risk: KyntralRiskClass,
        scopeId: String? = nil,
        resolverEndpoint: URL?,
        destinationBookmark: Data?,
        allowedResolverHosts: [String]
    ) {
        self.id = id
        self.capability = capability
        self.risk = risk
        self.scopeId = scopeId
        self.resolverEndpoint = resolverEndpoint
        self.destinationBookmark = destinationBookmark
        self.allowedResolverHosts = allowedResolverHosts
    }
}

public struct LocalStandingGrant: Codable, Sendable, Equatable {
    public let scopeId: String?
    public let workflowId: String
    public let capability: String
    public let risk: KyntralRiskClass
    public let allowed: Bool
    public let issuedAt: Date
    public let expiresAt: Date?

    public init(
        scopeId: String? = nil,
        workflowId: String,
        capability: String,
        risk: KyntralRiskClass,
        allowed: Bool,
        issuedAt: Date,
        expiresAt: Date?
    ) {
        self.scopeId = scopeId
        self.workflowId = workflowId
        self.capability = capability
        self.risk = risk
        self.allowed = allowed
        self.issuedAt = issuedAt
        self.expiresAt = expiresAt
    }
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
        let resolvedURL = stateURL ?? directory.appendingPathComponent("local-registry.json")
        self.stateURL = resolvedURL
        if let data = try? Data(contentsOf: resolvedURL),
           let decoded = try? JSONDecoder().decode(LocalRegistryState.self, from: data) {
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
        state.grants[key(workflowId: grant.workflowId, capability: grant.capability)] = grant
        try persist()
    }

    public func decision(
        workflowId: String,
        capability: String,
        risk: KyntralRiskClass? = nil,
        scopeId: String? = nil,
        now: Date = Date()
    ) -> AuthorizationDecision {
        guard let grant = state.grants[key(workflowId: workflowId, capability: capability)] else {
            return .unknown
        }
        if let risk, grant.risk != risk {
            return .denied
        }
        if grant.scopeId != scopeId {
            return .denied
        }
        guard grant.allowed else { return .denied }
        if !now.timeIntervalSinceReferenceDate.isFinite ||
           !grant.issuedAt.timeIntervalSinceReferenceDate.isFinite {
            return .unknown
        }
        if now < grant.issuedAt {
            return .unknown
        }
        if let expiresAt = grant.expiresAt {
            guard expiresAt.timeIntervalSinceReferenceDate.isFinite,
                  expiresAt > grant.issuedAt else {
                return .unknown
            }
            if expiresAt < now {
                return .expired
            }
        }
        return .allowed
    }

    private func key(workflowId: String, capability: String) -> String {
        workflowId + "|" + capability
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

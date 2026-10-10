// SPDX-License-Identifier: BUSL-1.1

import Foundation

public enum KyntralRuntimeError: Error {
    case unknownWorkflow
    case authorizationRequired(AuthorizationDecision)
    case workflowNotConfigured
    case invalidDestinationBookmark
    case invalidResolverConfiguration
    case invalidScopeId
    case noLocalWorkflowInput
}

public actor KyntralRuntime {
    public static let shared = KyntralRuntime()
    private let registry: LocalWorkflowRegistry
    private let ledger: DedupeLedger
    private let inbox: LocalWorkflowInbox

    public init(
        registry: LocalWorkflowRegistry = .shared,
        ledger: DedupeLedger = .shared,
        inbox: LocalWorkflowInbox = .shared
    ) {
        self.registry = registry
        self.ledger = ledger
        self.inbox = inbox
    }

    public func stageMediaIntakeURLs(
        workflowId: String = "wf_media_intake",
        urls: [URL]
    ) async throws {
        try await inbox.replaceMediaIntakeURLs(
            workflowId: workflowId,
            urls: urls
        )
    }

    public func executeVerifiedAction(
        _ verified: VerifiedAction
    ) async -> MediaIntakeResult {
        let action = verified.action
        guard action.workflowId == "wf_media_intake",
              action.capability == "workflow.execute",
              action.risk == .k2 else {
            return MediaIntakeResult(completed: 0, duplicates: 0, failed: 1)
        }

        let urls = await inbox.mediaIntakeURLs(workflowId: action.workflowId)
        guard !urls.isEmpty else {
            return MediaIntakeResult(completed: 0, duplicates: 0, failed: 1)
        }

        do {
            let result = try await runMediaIntake(
                workflowId: action.workflowId,
                scopeId: action.scopeId,
                urls: urls
            )
            if result.failed == 0 {
                try await inbox.clear(workflowId: action.workflowId)
            }
            return result
        } catch {
            return MediaIntakeResult(completed: 0, duplicates: 0, failed: 1)
        }
    }

    public func configureMediaIntake(
        scopeId: String? = nil,
        endpoint: URL,
        destinationBookmark: Data,
        standingGrantAllowed: Bool
    ) async throws {
        if let scopeId {
            guard scopeId.range(
                of: "^[A-Za-z][A-Za-z0-9_-]{2,127}$",
                options: .regularExpression
            ) != nil else {
                throw KyntralRuntimeError.invalidScopeId
            }
        }

        guard endpoint.scheme?.lowercased() == "https",
              let host = endpoint.host?.lowercased(),
              !host.isEmpty else {
            throw KyntralRuntimeError.invalidResolverConfiguration
        }

        let workflow = LocalWorkflowDefinition(
            id: "wf_media_intake",
            capability: "workflow.execute",
            risk: .k2,
            scopeId: scopeId,
            resolverEndpoint: endpoint,
            destinationBookmark: destinationBookmark,
            allowedResolverHosts: [host]
        )
        try await registry.putWorkflow(workflow)
        try await registry.putStandingGrant(
            LocalStandingGrant(
                scopeId: scopeId,
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
        id: String,
        scopeId: String? = nil
    ) async -> (workflow: LocalWorkflowDefinition?, decision: AuthorizationDecision) {
        let workflow = await registry.workflow(id: id)
        guard let workflow else { return (nil, .unknown) }
        let decision = await registry.decision(
            workflowId: id,
            capability: workflow.capability,
            scopeId: scopeId
        )
        return (workflow, decision)
    }

    public func runMediaIntake(
        workflowId: String,
        scopeId: String? = nil,
        urls: [URL]
    ) async throws -> MediaIntakeResult {
        guard let workflow = await registry.workflow(id: workflowId) else {
            throw KyntralRuntimeError.unknownWorkflow
        }
        let decision = await registry.decision(
            workflowId: workflowId,
            capability: workflow.capability,
            scopeId: scopeId
        )
        guard decision.permitsExecution else {
            throw KyntralRuntimeError.authorizationRequired(decision)
        }
        guard let endpoint = workflow.resolverEndpoint,
              let bookmark = workflow.destinationBookmark,
              let endpointHost = endpoint.host?.lowercased(),
              workflow.allowedResolverHosts.contains(endpointHost) else {
            throw KyntralRuntimeError.workflowNotConfigured
        }
        var stale = false
        let destination = try URL(
            resolvingBookmarkData: bookmark,
            options: [],
            relativeTo: nil,
            bookmarkDataIsStale: &stale
        )
        if stale { throw KyntralRuntimeError.invalidDestinationBookmark }
        let resolver = try CobaltCompatibleResolver(
            endpoint: endpoint,
            allowedEndpointHosts: Set(workflow.allowedResolverHosts)
        )
        return await MediaIntakeWorkflow(resolver: resolver, ledger: ledger).run(
            sources: urls,
            destination: destination
        )
    }
}

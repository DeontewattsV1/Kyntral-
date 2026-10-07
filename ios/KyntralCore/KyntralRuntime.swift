// SPDX-License-Identifier: BUSL-1.1

import Foundation

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

    public init(registry: LocalWorkflowRegistry = .shared, ledger: DedupeLedger = .shared) {
        self.registry = registry
        self.ledger = ledger
    }

    public func runMediaIntake(workflowId: String, urls: [URL]) async throws -> MediaIntakeResult {
        guard let workflow = await registry.workflow(id: workflowId) else {
            throw KyntralRuntimeError.unknownWorkflow
        }
        let decision = await registry.decision(workflowId: workflowId, capability: workflow.capability)
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
            options: [.withSecurityScope],
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

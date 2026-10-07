// SPDX-License-Identifier: BUSL-1.1

import AppIntents
import Foundation

struct RunKyntralWorkflowIntent: AppIntent {
    static var title: LocalizedStringResource = "Run Kyntral Workflow"
    static var description = IntentDescription(
        "Validates an already-authorized Kyntral workflow under local device policy."
    )

    @Parameter(title: "Workflow ID")
    var workflowID: String

    func perform() async throws -> some IntentResult & ProvidesDialog {
        guard let workflow = await LocalWorkflowRegistry.shared.workflow(id: workflowID) else {
            return .result(dialog: "That Kyntral workflow is not configured on this device.")
        }
        let decision = await LocalWorkflowRegistry.shared.decision(
            workflowId: workflowID,
            capability: workflow.capability
        )
        guard decision.permitsExecution else {
            return .result(dialog: "Kyntral did not authorize this workflow. Current state: \(decision.rawValue).")
        }
        return .result(dialog: "Kyntral validated the local authorization for \(workflowID).")
    }
}

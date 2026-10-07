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
        let state = await KyntralRuntime.shared.workflowState(id: workflowID)
        guard let workflow = state.workflow else {
            return .result(
                dialog: "That Kyntral workflow is not configured on this device."
            )
        }
        guard state.decision.permitsExecution else {
            return .result(
                dialog: "Kyntral did not authorize \(workflow.id). Current state: \(state.decision.rawValue)."
            )
        }
        return .result(
            dialog: "Kyntral validated local authorization for \(workflow.id)."
        )
    }
}

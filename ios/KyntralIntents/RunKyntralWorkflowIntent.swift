// SPDX-License-Identifier: BUSL-1.1

import AppIntents
import Foundation

struct RunKyntralWorkflowIntent: AppIntent {
    static var title: LocalizedStringResource = "Run Kyntral Workflow"

    static var description = IntentDescription(
        "Runs an already-authorized Kyntral workflow using local device policy."
    )

    @Parameter(title: "Workflow ID")
    var workflowID: String

    func perform() async throws -> some IntentResult & ProvidesDialog {
        // Pre-alpha scaffold only. The production implementation must:
        // 1. resolve workflowID locally,
        // 2. verify standing/current authorization,
        // 3. enforce capability/risk policy,
        // 4. execute locally,
        // 5. sign an execution receipt.
        return .result(dialog: "Kyntral workflow request accepted for local validation.")
    }
}

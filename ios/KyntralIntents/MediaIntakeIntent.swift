// SPDX-License-Identifier: BUSL-1.1

import AppIntents
import Foundation

struct MediaIntakeIntent: AppIntent {
    static var title: LocalizedStringResource = "Run Kyntral Media Intake"
    static var description = IntentDescription(
        "Processes user-provided media URLs using an already-authorized local Kyntral workflow."
    )
    static var openAppWhenRun = false

    @Parameter(title: "URLs")
    var urls: [URL]

    @Parameter(title: "Workflow ID", default: "wf_media_intake")
    var workflowID: String

    func perform() async throws -> some IntentResult & ProvidesDialog {
        let result = try await KyntralRuntime.shared.runMediaIntake(
            workflowId: workflowID,
            urls: urls
        )
        return .result(
            dialog: "Kyntral completed \(result.completed), skipped \(result.duplicates) duplicates, and recorded \(result.failed) failures."
        )
    }
}

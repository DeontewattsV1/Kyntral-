// SPDX-License-Identifier: BUSL-1.1

import AppIntents
import Foundation

struct StageMediaIntakeIntent: AppIntent {
    static var title: LocalizedStringResource = "Stage Kyntral Media Intake"
    static var description = IntentDescription(
        "Stores user-provided media URLs locally for the next authorized Kyntral media-intake action."
    )
    static var openAppWhenRun = false

    @Parameter(title: "URLs")
    var urls: [URL]

    func perform() async throws -> some IntentResult & ProvidesDialog {
        try await KyntralRuntime.shared.stageMediaIntakeURLs(urls: urls)
        return .result(
            dialog: "Staged \(urls.count) media links locally for Kyntral."
        )
    }
}

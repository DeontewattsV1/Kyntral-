// SPDX-License-Identifier: BUSL-1.1

import AppIntents

struct KyntralAppShortcuts: AppShortcutsProvider {
    static var appShortcuts: [AppShortcut] {
        AppShortcut(
            intent: StageMediaIntakeIntent(),
            phrases: [
                "Stage media links with \(.applicationName)"
            ],
            shortTitle: "Stage Media",
            systemImageName: "tray.and.arrow.down"
        )

        AppShortcut(
            intent: MediaIntakeIntent(),
            phrases: [
                "Run media intake with \(.applicationName)",
                "Process media links with \(.applicationName)"
            ],
            shortTitle: "Media Intake",
            systemImageName: "link.badge.plus"
        )
        AppShortcut(
            intent: RunKyntralWorkflowIntent(),
            phrases: ["Run a workflow with \(.applicationName)"],
            shortTitle: "Run Workflow",
            systemImageName: "bolt.shield"
        )
    }
}

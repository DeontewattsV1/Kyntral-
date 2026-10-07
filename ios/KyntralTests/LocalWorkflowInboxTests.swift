// SPDX-License-Identifier: BUSL-1.1

import Foundation
import XCTest
@testable import Kyntral

final class LocalWorkflowInboxTests: XCTestCase {
    func testPrivateMediaURLsRemainInLocalInbox() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".json")
        let inbox = LocalWorkflowInbox(stateURL: url)
        let source = URL(string: "https://x.com/example/status/123")!

        try await inbox.replaceMediaIntakeURLs(
            workflowId: "wf_media_intake",
            urls: [source]
        )

        let stored = await inbox.mediaIntakeURLs(
            workflowId: "wf_media_intake"
        )
        XCTAssertEqual(stored, [source])
        XCTAssertTrue(FileManager.default.fileExists(atPath: url.path))
    }
}

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

    func testTwitterAndXVariantsCanonicalizeAndDeduplicateLocally() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".json")
        let inbox = LocalWorkflowInbox(stateURL: url)

        try await inbox.replaceMediaIntakeURLs(
            workflowId: "wf_media_intake",
            urls: [
                URL(string: "https://twitter.com/example/status/123")!,
                URL(string: "https://x.com/example/status/123")!
            ]
        )

        let stored = await inbox.mediaIntakeURLs(
            workflowId: "wf_media_intake"
        )
        XCTAssertEqual(
            stored,
            [URL(string: "https://x.com/example/status/123")!]
        )
    }

    func testNonXSourceIsRejectedFromKYNW01Inbox() async {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".json")
        let inbox = LocalWorkflowInbox(stateURL: url)

        do {
            try await inbox.replaceMediaIntakeURLs(
                workflowId: "wf_media_intake",
                urls: [URL(string: "https://example.com/video/123")!]
            )
            XCTFail("Expected invalidMediaSource")
        } catch LocalWorkflowInboxError.invalidMediaSource {
            // Expected.
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
}

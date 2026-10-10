// SPDX-License-Identifier: BUSL-1.1

import Foundation
import XCTest
@testable import Kyntral

private struct StubMediaResolver: MediaResolver {
    let payload: Data

    func resolve(source: URL) async throws -> [ResolvedMedia] {
        [
            ResolvedMedia(
                url: URL(string: "https://media.example.test/file.bin")!,
                filename: "file.bin"
            )
        ]
    }

    func download(_ media: ResolvedMedia) async throws -> Data {
        payload
    }
}

final class DedupeLedgerTests: XCTestCase {
    func testURLFragmentAndHostCaseDoNotChangeSourceIdentity() {
        let first = URL(string: "https://EXAMPLE.com/media?id=1#one")!
        let second = URL(string: "https://example.com/media?id=1#two")!

        XCTAssertEqual(
            DedupeLedger.sourceHash(first),
            DedupeLedger.sourceHash(second)
        )
    }

    func testDifferentGenericQueryProducesDifferentSourceIdentity() {
        let first = URL(string: "https://example.com/media?id=1")!
        let second = URL(string: "https://example.com/media?id=2")!

        XCTAssertNotEqual(
            DedupeLedger.sourceHash(first),
            DedupeLedger.sourceHash(second)
        )
    }

    func testKYNW01RetryWritesContentOnce() async throws {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString, isDirectory: true)
        try FileManager.default.createDirectory(
            at: root,
            withIntermediateDirectories: true
        )
        let ledger = DedupeLedger(
            stateURL: root.appendingPathComponent("dedupe.json")
        )
        let workflow = MediaIntakeWorkflow(
            resolver: StubMediaResolver(payload: Data("media".utf8)),
            ledger: ledger
        )
        let source = URL(
            string: "https://x.com/example/status/123?utm_source=copy"
        )!

        let first = await workflow.run(
            sources: [source],
            destination: root
        )
        XCTAssertEqual(first.completed, 1)
        XCTAssertEqual(first.failed, 0)

        let retry = await workflow.run(
            sources: [
                URL(string: "https://twitter.com/other/status/123?s=20")!
            ],
            destination: root
        )
        XCTAssertEqual(retry.completed, 0)
        XCTAssertEqual(retry.duplicates, 1)
        XCTAssertEqual(retry.failed, 0)

        let files = try FileManager.default.contentsOfDirectory(
            at: root,
            includingPropertiesForKeys: nil
        ).filter { $0.lastPathComponent.hasPrefix("file") }
        XCTAssertEqual(files.count, 1)
    }

    func testXTrackingQueriesAndLegacyHostCollapseToStatusIdentity() {
        let first = URL(
            string: "https://x.com/example/status/123?utm_source=copy"
        )!
        let second = URL(
            string: "https://twitter.com/other/status/123?s=20"
        )!

        XCTAssertEqual(
            DedupeLedger.canonicalSourceIdentity(first),
            "x:status:123"
        )
        XCTAssertEqual(
            DedupeLedger.sourceHash(first),
            DedupeLedger.sourceHash(second)
        )
    }
}

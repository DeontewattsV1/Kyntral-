// SPDX-License-Identifier: BUSL-1.1

import Foundation
import XCTest
@testable import Kyntral

final class ExecutionJournalTests: XCTestCase {
    func testReceiptSurvivesRetryBoundary() async throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".json")
        let journal = ExecutionJournal(stateURL: url)
        let receipt = SignedExecutionReceipt(
            version: "kyntral.receipt.v1",
            receiptId: "rcpt_test_001",
            actionId: "act_test_001",
            deviceId: "dev_test_001",
            actionHash: "sha256:" + String(repeating: "a", count: 64),
            outcome: "completed",
            startedAt: "2026-10-07T12:00:00.000Z",
            completedAt: "2026-10-07T12:00:01.000Z",
            counts: ReceiptCounts(completed: 1, failed: 0),
            deviceProof: DeviceReceiptProof(
                keyId: "devsig_test_001",
                algorithm: "ES256",
                signature: "MEUCIQexample"
            )
        )

        try await journal.record(receipt)
        let reloaded = ExecutionJournal(stateURL: url)
        let stored = await reloaded.receipt(actionId: receipt.actionId)
        XCTAssertEqual(stored, receipt)
        XCTAssertEqual(
            await journal.firstPendingReceipt(),
            receipt
        )

        try await journal.remove(actionId: receipt.actionId)
        XCTAssertNil(await journal.firstPendingReceipt())
        XCTAssertNil(await journal.receipt(actionId: receipt.actionId))
    }
}

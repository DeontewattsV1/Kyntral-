// SPDX-License-Identifier: BUSL-1.1

import Foundation

private struct ExecutionJournalState: Codable {
    var receipts: [String: SignedExecutionReceipt] = [:]
}

public actor ExecutionJournal {
    public static let shared = ExecutionJournal()

    private let stateURL: URL
    private var state: ExecutionJournalState

    public init(stateURL: URL? = nil) {
        let root = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        let directory = root.appendingPathComponent("Kyntral", isDirectory: true)
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        let resolved = stateURL ??
            directory.appendingPathComponent("execution-journal.json")
        self.stateURL = resolved
        if let data = try? Data(contentsOf: resolved),
           let decoded = try? JSONDecoder().decode(
            ExecutionJournalState.self,
            from: data
           ) {
            self.state = decoded
        } else {
            self.state = ExecutionJournalState()
        }
    }

    public func receipt(actionId: String) -> SignedExecutionReceipt? {
        state.receipts[actionId]
    }

    public func firstPendingReceipt() -> SignedExecutionReceipt? {
        state.receipts.values.sorted {
            if $0.completedAt == $1.completedAt {
                return $0.receiptId < $1.receiptId
            }
            return $0.completedAt < $1.completedAt
        }.first
    }

    public func remove(actionId: String) throws {
        state.receipts.removeValue(forKey: actionId)
        try persist()
    }

    public func record(_ receipt: SignedExecutionReceipt) throws {
        if let existing = state.receipts[receipt.actionId] {
            guard existing == receipt else {
                throw CocoaError(.fileWriteFileExists)
            }
            return
        }
        state.receipts[receipt.actionId] = receipt
        try persist()
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

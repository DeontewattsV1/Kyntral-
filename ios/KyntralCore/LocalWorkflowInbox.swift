// SPDX-License-Identifier: BUSL-1.1

import Foundation

private struct LocalWorkflowInboxState: Codable {
    var mediaIntakeURLs: [String: [String]] = [:]
}

public actor LocalWorkflowInbox {
    public static let shared = LocalWorkflowInbox()

    private let stateURL: URL
    private var state: LocalWorkflowInboxState

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
            directory.appendingPathComponent("workflow-inbox.json")
        self.stateURL = resolved
        if let data = try? Data(contentsOf: resolved),
           let decoded = try? JSONDecoder().decode(
            LocalWorkflowInboxState.self,
            from: data
           ) {
            self.state = decoded
        } else {
            self.state = LocalWorkflowInboxState()
        }
    }

    public func replaceMediaIntakeURLs(
        workflowId: String,
        urls: [URL]
    ) throws {
        state.mediaIntakeURLs[workflowId] = urls.map(\.absoluteString)
        try persist()
    }

    public func mediaIntakeURLs(workflowId: String) -> [URL] {
        (state.mediaIntakeURLs[workflowId] ?? []).compactMap(URL.init(string:))
    }

    public func clear(workflowId: String) throws {
        state.mediaIntakeURLs.removeValue(forKey: workflowId)
        try persist()
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

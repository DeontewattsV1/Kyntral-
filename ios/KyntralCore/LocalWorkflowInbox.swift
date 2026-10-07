// SPDX-License-Identifier: BUSL-1.1

import Foundation

private struct LocalWorkflowInboxState: Codable {
    var mediaIntakeURLs: [String: [String]] = [:]
}

public enum LocalWorkflowInboxError: Error {
    case invalidMediaSource
}

public actor LocalWorkflowInbox {
    public static let shared = LocalWorkflowInbox()

    private static let mediaHosts: Set<String> = [
        "x.com",
        "www.x.com",
        "twitter.com",
        "www.twitter.com",
        "mobile.twitter.com"
    ]

    private let stateURL: URL
    private var state: LocalWorkflowInboxState

    public init(stateURL: URL? = nil) {
        let root = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first!
        var directory = root.appendingPathComponent(
            "Kyntral",
            isDirectory: true
        )
        try? FileManager.default.createDirectory(
            at: directory,
            withIntermediateDirectories: true
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? directory.setResourceValues(values)

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
        var seen = Set<String>()
        var normalized: [String] = []

        for url in urls {
            guard url.scheme?.lowercased() == "https",
                  let host = url.host?.lowercased(),
                  Self.mediaHosts.contains(host),
                  url.path.range(
                    of: "^/[^/]+/status/[0-9]+(?:/.*)?$",
                    options: .regularExpression
                  ) != nil else {
                throw LocalWorkflowInboxError.invalidMediaSource
            }

            var parts = URLComponents(
                url: url,
                resolvingAgainstBaseURL: false
            )
            parts?.scheme = "https"
            parts?.host = host == "twitter.com" ||
                host == "www.twitter.com" ||
                host == "mobile.twitter.com"
                ? "x.com"
                : "x.com"
            parts?.fragment = nil
            parts?.query = nil
            let value = parts?.url?.absoluteString ?? url.absoluteString
            if seen.insert(value).inserted {
                normalized.append(value)
            }
        }

        state.mediaIntakeURLs[workflowId] = normalized
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

// SPDX-License-Identifier: BUSL-1.1

import CryptoKit
import Foundation

private struct DedupeState: Codable {
    var urlHashes: Set<String> = []
    var contentHashes: Set<String> = []
}

public actor DedupeLedger {
    public static let shared = DedupeLedger()

    private let stateURL: URL
    private var state: DedupeState

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
        let resolvedURL = stateURL ?? directory.appendingPathComponent("dedupe-ledger.json")
        self.stateURL = resolvedURL
        if let data = try? Data(contentsOf: resolvedURL),
           let decoded = try? JSONDecoder().decode(DedupeState.self, from: data) {
            self.state = decoded
        } else {
            self.state = DedupeState()
        }
    }

    public func hasSource(_ url: URL) -> Bool {
        state.urlHashes.contains(Self.sourceHash(url))
    }

    public func recordSource(_ url: URL) throws {
        state.urlHashes.insert(Self.sourceHash(url))
        try persist()
    }

    public func hasContent(_ data: Data) -> Bool {
        state.contentHashes.contains(Self.contentHash(data))
    }

    public func recordContent(_ data: Data) throws {
        state.contentHashes.insert(Self.contentHash(data))
        try persist()
    }

    public static func sourceHash(_ url: URL) -> String {
        contentHash(Data(canonicalSourceIdentity(url).utf8))
    }

    public static func canonicalSourceIdentity(_ url: URL) -> String {
        let host = url.host?.lowercased()
        let xHosts: Set<String> = [
            "x.com",
            "www.x.com",
            "twitter.com",
            "www.twitter.com",
            "mobile.twitter.com"
        ]
        if let host, xHosts.contains(host) {
            let components = url.path.split(separator: "/")
            if let statusIndex = components.firstIndex(of: "status"),
               components.indices.contains(statusIndex + 1) {
                let statusId = String(components[statusIndex + 1])
                if statusId.range(
                    of: "^[0-9]+$",
                    options: .regularExpression
                ) != nil {
                    return "x:status:" + statusId
                }
            }
        }

        guard var parts = URLComponents(
            url: url,
            resolvingAgainstBaseURL: false
        ) else {
            return url.absoluteString
        }
        parts.fragment = nil
        parts.scheme = parts.scheme?.lowercased()
        parts.host = parts.host?.lowercased()
        return parts.string ?? url.absoluteString
    }

    public static func contentHash(_ data: Data) -> String {
        "sha256:" + SHA256.hash(data: data)
            .map { String(format: "%02x", $0) }
            .joined()
    }

    private func persist() throws {
        let data = try JSONEncoder().encode(state)
        try data.write(to: stateURL, options: [.atomic])
    }
}

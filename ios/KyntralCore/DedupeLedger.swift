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
        guard var parts = URLComponents(url: url, resolvingAgainstBaseURL: false) else {
            return contentHash(Data(url.absoluteString.utf8))
        }
        parts.fragment = nil
        parts.scheme = parts.scheme?.lowercased()
        parts.host = parts.host?.lowercased()
        return contentHash(Data((parts.string ?? url.absoluteString).utf8))
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

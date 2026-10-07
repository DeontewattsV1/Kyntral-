// SPDX-License-Identifier: BUSL-1.1

import Foundation

public struct MediaIntakeResult: Sendable {
    public let completed: Int
    public let duplicates: Int
    public let failed: Int
}

public struct MediaIntakeWorkflow: Sendable {
    private let resolver: any MediaResolver
    private let ledger: DedupeLedger

    public init(resolver: any MediaResolver, ledger: DedupeLedger = .shared) {
        self.resolver = resolver
        self.ledger = ledger
    }

    public func run(sources: [URL], destination: URL) async -> MediaIntakeResult {
        var completed = 0
        var duplicates = 0
        var failed = 0
        let scoped = destination.startAccessingSecurityScopedResource()
        defer { if scoped { destination.stopAccessingSecurityScopedResource() } }

        for source in sources {
            do {
                if await ledger.hasSource(source) {
                    duplicates += 1
                    continue
                }
                let mediaItems = try await resolver.resolve(source: source)
                var sourceCompleted = false
                for media in mediaItems {
                    let data = try await resolver.download(media)
                    if await ledger.hasContent(data) {
                        duplicates += 1
                        continue
                    }
                    let output = uniqueDestination(directory: destination, preferredFilename: media.filename)
                    try data.write(to: output, options: [.atomic])
                    try await ledger.recordContent(data)
                    completed += 1
                    sourceCompleted = true
                }
                if sourceCompleted { try await ledger.recordSource(source) }
            } catch {
                failed += 1
            }
        }
        return MediaIntakeResult(completed: completed, duplicates: duplicates, failed: failed)
    }

    private func uniqueDestination(directory: URL, preferredFilename: String) -> URL {
        var candidate = directory.appendingPathComponent(preferredFilename)
        var index = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            let ext = candidate.pathExtension
            let stem = candidate.deletingPathExtension().lastPathComponent
            candidate = directory.appendingPathComponent(stem + "-\(index)" + (ext.isEmpty ? "" : "." + ext))
            index += 1
        }
        return candidate
    }
}

// SPDX-License-Identifier: BUSL-1.1

import Foundation

public struct ResolvedMedia: Sendable {
    public let url: URL
    public let filename: String
}

public protocol MediaResolver: Sendable {
    func resolve(source: URL) async throws -> [ResolvedMedia]
    func download(_ media: ResolvedMedia) async throws -> Data
}

public enum CobaltResolverError: Error {
    case endpointMustUseHTTPS
    case sourceMustUseHTTPS
    case unapprovedEndpoint
    case invalidResponse
    case remoteError(String)
    case localProcessingUnsupported
}

public struct CobaltCompatibleResolver: MediaResolver {
    private let endpoint: URL
    private let allowedEndpointHosts: Set<String>
    private let session: URLSession

    public init(
        endpoint: URL,
        allowedEndpointHosts: Set<String>
    ) throws {
        guard endpoint.scheme?.lowercased() == "https" else {
            throw CobaltResolverError.endpointMustUseHTTPS
        }
        guard let host = endpoint.host?.lowercased(),
              allowedEndpointHosts.contains(host) else {
            throw CobaltResolverError.unapprovedEndpoint
        }
        self.endpoint = endpoint
        self.allowedEndpointHosts = allowedEndpointHosts

        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCache = nil
        self.session = URLSession(configuration: configuration)
    }

    public func resolve(source: URL) async throws -> [ResolvedMedia] {
        guard source.scheme?.lowercased() == "https" else {
            throw CobaltResolverError.sourceMustUseHTTPS
        }

        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue(
            "application/json",
            forHTTPHeaderField: "Content-Type"
        )
        request.httpBody = try JSONEncoder().encode(
            CobaltRequest(url: source.absoluteString)
        )

        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse,
              200..<300 ~= http.statusCode else {
            throw CobaltResolverError.invalidResponse
        }

        let result = try JSONDecoder().decode(CobaltResponse.self, from: data)
        switch result.status {
        case "tunnel", "redirect":
            guard let rawURL = result.url,
                  let url = URL(string: rawURL) else {
                throw CobaltResolverError.invalidResponse
            }
            return [
                ResolvedMedia(
                    url: url,
                    filename: sanitize(
                        result.filename ?? "kyntral-media.bin"
                    )
                )
            ]
        case "picker":
            guard let picker = result.picker, !picker.isEmpty else {
                throw CobaltResolverError.invalidResponse
            }
            var result: [ResolvedMedia] = []
            for (index, item) in picker.enumerated() {
                guard let url = URL(string: item.url) else {
                    throw CobaltResolverError.invalidResponse
                }
                let ext: String
                switch item.type {
                case "photo": ext = "jpg"
                case "gif": ext = "gif"
                default: ext = "mp4"
                }
                result.append(
                    ResolvedMedia(
                        url: url,
                        filename: "kyntral-" + String(index + 1) + "." + ext
                    )
                )
            }
            return result
            throw CobaltResolverError.remoteError(
                result.error?.code ?? "unknown"
            )
        default:
            throw CobaltResolverError.invalidResponse
        }
    }

    public func download(_ media: ResolvedMedia) async throws -> Data {
        guard media.url.scheme?.lowercased() == "https" else {
            throw CobaltResolverError.sourceMustUseHTTPS
        }
        let (data, response) = try await session.data(from: media.url)
        guard let http = response as? HTTPURLResponse,
              200..<300 ~= http.statusCode else {
            throw CobaltResolverError.invalidResponse
        }
        return data
    }

    private func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: "._-")
        )
        let scalars = value.unicodeScalars.map {
            allowed.contains($0) ? Character(String($0)) : "_"
        }
        return String(scalars).prefix(160).description
    }
}

public struct MediaIntakeResult: Sendable, Equatable {
    public let completed: Int
    public let duplicates: Int
    public let failed: Int
}

public struct MediaIntakeWorkflow: Sendable {
    private let resolver: any MediaResolver
    private let ledger: DedupeLedger

    public init(
        resolver: any MediaResolver,
        ledger: DedupeLedger = .shared
    ) {
        self.resolver = resolver
        self.ledger = ledger
    }

    public func run(
        sources: [URL],
        destination: URL
    ) async -> MediaIntakeResult {
        var completed = 0
        var duplicates = 0
        var failed = 0

        let scoped = destination.startAccessingSecurityScopedResource()
        defer {
            if scoped {
                destination.stopAccessingSecurityScopedResource()
            }
        }

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

                    let output = uniqueDestination(
                        directory: destination,
                        preferredFilename: media.filename
                    )
                    try data.write(to: output, options: [.atomic])
                    try await ledger.recordContent(data)
                    completed += 1
                    sourceCompleted = true
                }

                if sourceCompleted {
                    try await ledger.recordSource(source)
                }
            } catch {
                failed += 1
            }
        }

        return MediaIntakeResult(
            completed: completed,
            duplicates: duplicates,
            failed: failed
        )
    }

    private func uniqueDestination(
        directory: URL,
        preferredFilename: String
    ) -> URL {
        var candidate = directory.appendingPathComponent(preferredFilename)
        var index = 2
        while FileManager.default.fileExists(atPath: candidate.path) {
            let ext = candidate.pathExtension
            let base = candidate.deletingPathExtension().lastPathComponent
            let nextName = base + "-" + String(index) +
                (ext.isEmpty ? "" : "." + ext)
            candidate = directory.appendingPathComponent(nextName)
            index += 1
        }
        return candidate
    }
}

private struct CobaltRequest: Encodable {
    let url: String
    let downloadMode = "auto"
    let filenameStyle = "basic"
}

private struct CobaltResponse: Decodable {
    struct PickerItem: Decodable {
        let type: String
        let url: String
    }

    struct RemoteError: Decodable {
        let code: String
    }

    let status: String
    let url: String?
    let filename: String?
    let picker: [PickerItem]?
    let error: RemoteError?
}

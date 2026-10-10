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
    private let session: URLSession

    public init(endpoint: URL, allowedEndpointHosts: Set<String>) throws {
        guard endpoint.scheme?.lowercased() == "https" else {
            throw CobaltResolverError.endpointMustUseHTTPS
        }
        guard let host = endpoint.host?.lowercased(),
              allowedEndpointHosts.contains(host) else {
            throw CobaltResolverError.unapprovedEndpoint
        }
        self.endpoint = endpoint
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
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(CobaltRequest(url: source.absoluteString))
        let (data, response) = try await session.data(for: request)
        guard let http = response as? HTTPURLResponse, 200..<300 ~= http.statusCode else {
            throw CobaltResolverError.invalidResponse
        }
        let result = try JSONDecoder().decode(CobaltResponse.self, from: data)
        switch result.status {
        case "tunnel", "redirect":
            guard let rawURL = result.url, let url = URL(string: rawURL) else {
                throw CobaltResolverError.invalidResponse
            }
            return [ResolvedMedia(url: url, filename: sanitize(result.filename ?? "kyntral-media.bin"))]
        case "picker":
            guard let picker = result.picker, !picker.isEmpty else {
                throw CobaltResolverError.invalidResponse
            }
            return picker.enumerated().compactMap { index, item in
                guard let url = URL(string: item.url) else { return nil }
                let ext = item.type == "photo" ? "jpg" : (item.type == "gif" ? "gif" : "mp4")
                return ResolvedMedia(url: url, filename: "kyntral-\(index + 1).\(ext)")
            }
        case "local-processing":
            throw CobaltResolverError.localProcessingUnsupported
        case "error":
            throw CobaltResolverError.remoteError(result.error?.code ?? "unknown")
        default:
            throw CobaltResolverError.invalidResponse
        }
    }

    public func download(_ media: ResolvedMedia) async throws -> Data {
        let (data, response) = try await session.data(from: media.url)
        guard let http = response as? HTTPURLResponse, 200..<300 ~= http.statusCode else {
            throw CobaltResolverError.invalidResponse
        }
        return data
    }

    private func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "._-"))
        let transformed = value.unicodeScalars.map { allowed.contains($0) ? String($0) : "_" }.joined()
        return String(transformed.prefix(160))
    }
}

private struct CobaltRequest: Encodable {
    let url: String
    let downloadMode = "auto"
    let filenameStyle = "basic"
}

private struct CobaltResponse: Decodable {
    struct PickerItem: Decodable { let type: String; let url: String }
    struct RemoteError: Decodable { let code: String }
    let status: String
    let url: String?
    let filename: String?
    let picker: [PickerItem]?
    let error: RemoteError?
}

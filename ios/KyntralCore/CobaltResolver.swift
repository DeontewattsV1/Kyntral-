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
    case unapprovedSource
    case responseTooLarge
    case unapprovedContentType
}

// A 3xx response must never move a resolver request to a new host or network.
private final class NoRedirectDelegate: NSObject, URLSessionTaskDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: @escaping (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

public struct CobaltCompatibleResolver: MediaResolver {
    private static let maxJSONBytes = 512 * 1024
    private static let maxMediaBytes = 64 * 1024 * 1024
    private static let sourceHosts: Set<String> = [
        "x.com", "www.x.com", "twitter.com", "www.twitter.com",
        "mobile.twitter.com"
    ]
    private static let mediaTypes: Set<String> = [
        "video/mp4", "video/quicktime", "image/jpeg", "image/png",
        "image/gif", "image/webp", "application/octet-stream"
    ]

    private let endpoint: URL
    private let allowedMediaHosts: Set<String>
    private let session: URLSession

    // Media hosts must be independently approved at configuration time.
    // The existing API defaults to same-host downloads, never arbitrary CDNs.
    public init(
        endpoint: URL,
        allowedEndpointHosts: Set<String>,
        allowedMediaHosts: Set<String>? = nil
    ) throws {
        guard endpoint.scheme?.lowercased() == "https" else {
            throw CobaltResolverError.endpointMustUseHTTPS
        }
        guard Self.isApprovedPublicURL(endpoint, hosts: allowedEndpointHosts) else {
            throw CobaltResolverError.unapprovedEndpoint
        }
        self.endpoint = endpoint
        self.allowedMediaHosts = allowedMediaHosts ?? allowedEndpointHosts

        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.urlCache = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 120
        self.session = URLSession(
            configuration: configuration,
            delegate: NoRedirectDelegate(),
            delegateQueue: nil
        )
    }

    public func resolve(source: URL) async throws -> [ResolvedMedia] {
        guard source.scheme?.lowercased() == "https" else {
            throw CobaltResolverError.sourceMustUseHTTPS
        }
        guard Self.isApprovedPublicURL(source, hosts: Self.sourceHosts) else {
            throw CobaltResolverError.unapprovedSource
        }
        var request = URLRequest(url: endpoint)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpBody = try JSONEncoder().encode(
            CobaltRequest(url: source.absoluteString)
        )
        let data = try await boundedResponse(
            for: request,
            maximum: Self.maxJSONBytes,
            permittedTypes: ["application/json"]
        )
        let result = try JSONDecoder().decode(CobaltResponse.self, from: data)
        switch result.status {
        case "tunnel", "redirect":
            guard let rawURL = result.url, let url = URL(string: rawURL) else {
                throw CobaltResolverError.invalidResponse
            }
            try verifyMediaURL(url)
            return [ResolvedMedia(
                url: url,
                filename: sanitize(result.filename ?? "kyntral-media.bin")
            )]
        case "picker":
            guard let picker = result.picker, !picker.isEmpty else {
                throw CobaltResolverError.invalidResponse
            }
            return try picker.enumerated().map { index, item in
                guard let url = URL(string: item.url) else {
                    throw CobaltResolverError.invalidResponse
                }
                try verifyMediaURL(url)
                let ext = item.type == "photo" ? "jpg" :
                    (item.type == "gif" ? "gif" : "mp4")
                return ResolvedMedia(
                    url: url, filename: "kyntral-\(index + 1).\(ext)"
                )
            }
        case "local-processing":
            throw CobaltResolverError.localProcessingUnsupported
        case "error":
            throw CobaltResolverError.remoteError(
                result.error?.code ?? "unknown"
            )
        default:
            throw CobaltResolverError.invalidResponse
        }
    }

    public func download(_ media: ResolvedMedia) async throws -> Data {
        try verifyMediaURL(media.url)
        var request = URLRequest(url: media.url)
        request.httpMethod = "GET"
        request.setValue(
            "video/mp4, video/quicktime, image/*, application/octet-stream",
            forHTTPHeaderField: "Accept"
        )
        return try await boundedResponse(
            for: request,
            maximum: Self.maxMediaBytes,
            permittedTypes: Self.mediaTypes
        )
    }

    private func verifyMediaURL(_ url: URL) throws {
        guard Self.isApprovedPublicURL(url, hosts: allowedMediaHosts) else {
            throw CobaltResolverError.unapprovedEndpoint
        }
    }

    private static func isApprovedPublicURL(
        _ url: URL, hosts: Set<String>
    ) -> Bool {
        guard url.scheme?.lowercased() == "https",
              url.user == nil, url.password == nil,
              url.port == nil || url.port == 443,
              let host = url.host?.lowercased(),
              !host.isEmpty, !host.hasSuffix("."),
              hosts.contains(host),
              host.contains("."),
              !host.contains(":"),
              !host.contains("%"),
              !host.hasPrefix("0x"),
              !host.allSatisfy({ $0.isNumber || $0 == "." }),
              !host.hasSuffix(".localhost"),
              !host.hasSuffix(".local"),
              !host.hasSuffix(".internal"),
              !host.hasSuffix(".lan"),
              !host.hasSuffix(".home.arpa") else {
            return false
        }
        // A hostname allowlist cannot establish the IP of the TLS peer.
        // DNS rebinding protection still requires connection-level controls.
        return true
    }

    private func boundedResponse(
        for request: URLRequest,
        maximum: Int,
        permittedTypes: Set<String>
    ) async throws -> Data {
        let (bytes, response) = try await session.bytes(for: request)
        guard let http = response as? HTTPURLResponse,
              200..<300 ~= http.statusCode,
              http.url?.host?.lowercased() == request.url?.host?.lowercased()
        else {
            throw CobaltResolverError.invalidResponse
        }

        let contentType = http.value(forHTTPHeaderField: "Content-Type")?
            .lowercased()
            .split(separator: ";", maxSplits: 1)
            .first
            .map { String($0).trimmingCharacters(in: .whitespaces) }
        guard let contentType, permittedTypes.contains(contentType) else {
            throw CobaltResolverError.unapprovedContentType
        }
        guard http.expectedContentLength <= Int64(maximum) else {
            throw CobaltResolverError.responseTooLarge
        }

        var data = Data()
        for try await byte in bytes {
            guard data.count < maximum else {
                throw CobaltResolverError.responseTooLarge
            }
            data.append(byte)
        }
        return data
    }

    private func sanitize(_ value: String) -> String {
        let allowed = CharacterSet.alphanumerics.union(
            CharacterSet(charactersIn: "._-")
        )
        let transformed = value.unicodeScalars
            .map { allowed.contains($0) ? String($0) : "_" }.joined()
        let safe = String(transformed.prefix(160))
        return safe.isEmpty || safe == "." || safe == ".."
            ? "kyntral-media.bin" : safe
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

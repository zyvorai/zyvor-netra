// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// A binary (or text) body fetched with GET, plus what the server said about it.
public struct DownloadedFile: Sendable, Equatable {
    public var data: Data
    public var filename: String?
    public var contentType: String?
    public var recordCount: Int?       // X-Netra-Export-Count on exports
    public init(data: Data, filename: String?, contentType: String?, recordCount: Int?) {
        self.data = data; self.filename = filename; self.contentType = contentType; self.recordCount = recordCount
    }
}

extension NetraClient {
    /// GET that keeps the raw body (PCAP, exports). Read-only; errors use the same envelope as `send`.
    public func download(_ path: String, query: [URLQueryItem] = []) async throws -> DownloadedFile {
        var req = request("GET", path, query: query)
        req.setValue("*/*", forHTTPHeaderField: "Accept")
        req.timeoutInterval = 120
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: req) }
        catch { throw NetraError.transport(error.localizedDescription) }
        guard let h = resp as? HTTPURLResponse else { throw NetraError.transport("non-HTTP response") }
        if h.statusCode == 401 { throw NetraError.unauthorized }
        guard (200..<300).contains(h.statusCode) else {
            throw NetraError.http(status: h.statusCode, message: errorMessage(from: data))
        }
        return DownloadedFile(data: data, filename: Self.dispositionFilename(h.value(forHTTPHeaderField: "Content-Disposition")),
                              contentType: h.value(forHTTPHeaderField: "Content-Type"),
                              recordCount: h.value(forHTTPHeaderField: "X-Netra-Export-Count").flatMap(Int.init))
    }

    static func dispositionFilename(_ header: String?) -> String? {
        guard let header, let r = header.range(of: "filename=") else { return nil }
        let name = header[r.upperBound...].trimmingCharacters(in: CharacterSet(charactersIn: "\" ;"))
        // Never let a server-supplied name carry a path.
        let base = (name as NSString).lastPathComponent
        return base.isEmpty ? nil : base
    }
}

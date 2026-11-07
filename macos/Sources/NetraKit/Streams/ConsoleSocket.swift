// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Async WebSocket transport for the console routes. Self-contained: builds the upgrade request with the
/// Bearer header (never in the URL) and runs on a caller-supplied URLSession, so passing the pinned session of
/// `NetraClient.pinned` reuses PinningDelegate. Contents of frames are passed to the caller and never logged.
public final class ConsoleSocket: NSObject, URLSessionWebSocketDelegate, @unchecked Sendable {
    public enum Event: Sendable, Equatable {
        case opened
        case text(String)
        case binary(Data)
        case closed(code: Int, reason: String)
        case failed(String)
    }

    private let task: URLSessionWebSocketTask
    private let continuation: AsyncStream<Event>.Continuation
    public let events: AsyncStream<Event>
    private var receiver: Task<Void, Never>?
    private let lock = NSLock()
    private var finished = false

    public init(client: NetraClient, path: String, query: [URLQueryItem] = []) {
        var req = client.request("GET", path, query: query)
        req.url = req.url.map(ConsoleData.webSocketURL)
        req.setValue(nil, forHTTPHeaderField: "Accept")
        req.timeoutInterval = 20
        (events, continuation) = AsyncStream<Event>.makeStream(bufferingPolicy: .unbounded)
        task = client.session.webSocketTask(with: req)
        task.maximumMessageSize = 4 * 1024 * 1024
        super.init()
        task.delegate = self
    }

    public func connect() {
        task.resume()
        receiver = Task { [weak self] in
            while let self, !Task.isCancelled {
                do {
                    switch try await self.task.receive() {
                    case .string(let s): self.continuation.yield(.text(s))
                    case .data(let d): self.continuation.yield(.binary(d))
                    @unknown default: break
                    }
                } catch {
                    self.finish(.failed(Self.describe(error, task: self.task)))
                    return
                }
            }
        }
    }

    public func send(text: String) async throws { try await task.send(.string(text)) }
    public func send(data: Data) async throws { try await task.send(.data(data)) }
    public func sendResize(cols: Int, rows: Int) async throws { try await send(text: ConsoleData.resizeMessage(cols: cols, rows: rows)) }

    public func close() {
        task.cancel(with: .normalClosure, reason: nil)
        receiver?.cancel()
        finish(nil)
    }

    private func finish(_ last: Event?) {
        lock.lock(); let already = finished; finished = true; lock.unlock()
        guard !already else { return }
        if let last { continuation.yield(last) }
        continuation.finish()
    }

    private static func describe(_ error: Error, task: URLSessionWebSocketTask) -> String {
        if let h = task.response as? HTTPURLResponse {
            if h.statusCode == 401 { return "Unauthorized" }
            if h.statusCode == 403 { return "Forbidden: consoles need the admin role" }
            if h.statusCode == 404 { return "Console disabled on the server (NETRA_WORKLOAD_CONSOLE)" }
            if h.statusCode != 101 { return "HTTP \(h.statusCode)" }
        }
        return error.localizedDescription
    }

    // MARK: URLSessionWebSocketDelegate
    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didOpenWithProtocol protocol: String?) {
        continuation.yield(.opened)
    }
    public func urlSession(_ session: URLSession, webSocketTask: URLSessionWebSocketTask, didCloseWith closeCode: URLSessionWebSocketTask.CloseCode, reason: Data?) {
        finish(.closed(code: closeCode.rawValue, reason: reason.map { String(decoding: $0, as: UTF8.self) } ?? ""))
    }
}

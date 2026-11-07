// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// One open socket. Text frames only (the metrics stream is JSON text).
public protocol WSTransport: Sendable {
    func send(_ text: String) async throws
    func receive() async throws -> Data
    func close()
}

/// Opens sockets. The URLSession implementation reuses the app's pinned session.
public protocol WSConnecting: Sendable {
    func open() async throws -> WSTransport
}

public enum WSState: Sendable, Equatable {
    case connecting
    case live
    case reconnecting(attempt: Int, in: TimeInterval, reason: String)
}

public enum WSUpdate<Message: Sendable>: Sendable {
    case state(WSState)
    case message(Message)
}
extension WSUpdate: Equatable where Message: Equatable {}

public enum WSClient {
    /// Auto-reconnecting stream. Sends `hello()` after each connect, then yields decoded messages.
    /// Finishes on cancellation, throws `NetraError.unauthorized` (terminal) on a 401 handshake.
    /// No frame for `idleTimeout` counts as a dead socket and triggers a reconnect.
    public static func stream<M: Sendable>(
        connector: WSConnecting,
        hello: @escaping @Sendable () -> String?,
        decode: @escaping @Sendable (Data) -> M?,
        backoff: SSEBackoff = SSEBackoff(),
        idleTimeout: TimeInterval = 15
    ) -> AsyncThrowingStream<WSUpdate<M>, Error> {
        AsyncThrowingStream { cont in
            let task = Task {
                var attempt = 0
                while !Task.isCancelled {
                    cont.yield(.state(.connecting))
                    var reason = "socket closed"
                    do {
                        let t = try await connector.open()
                        defer { t.close() }
                        if let h = hello() { try await t.send(h) }
                        var live = false
                        while !Task.isCancelled {
                            let data = try await receive(t, timeout: idleTimeout)
                            if !live { live = true; attempt = 0; cont.yield(.state(.live)) }
                            if let m = decode(data) { cont.yield(.message(m)) }
                        }
                    } catch is CancellationError {
                        break
                    } catch NetraError.unauthorized {
                        cont.finish(throwing: NetraError.unauthorized); return
                    } catch let NetraError.http(s, m) where (400..<500).contains(s) && s != 429 && s != 408 {
                        cont.finish(throwing: NetraError.http(status: s, message: m)); return
                    } catch {
                        if Task.isCancelled { break }
                        reason = (error as? NetraError).map { String(describing: $0) } ?? error.localizedDescription
                    }
                    if Task.isCancelled { break }
                    attempt += 1
                    let d = backoff.delay(attempt: attempt)
                    cont.yield(.state(.reconnecting(attempt: attempt, in: d, reason: reason)))
                    if (try? await Task.sleep(for: .seconds(d))) == nil { break }
                }
                cont.finish()
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }

    private struct IdleTimeout: Error, LocalizedError { var errorDescription: String? { "no data from server" } }

    private static func receive(_ t: WSTransport, timeout: TimeInterval) async throws -> Data {
        try await withThrowingTaskGroup(of: Data.self) { g in
            g.addTask { try await t.receive() }
            g.addTask { try await Task.sleep(for: .seconds(timeout)); throw IdleTimeout() }
            defer { g.cancelAll() }
            return try await g.next()!
        }
    }

    /// Live metrics stream against a controller, over the client's (pinned) session and Bearer token.
    public static func metrics(client: NetraClient, subscriptions: @escaping @Sendable () -> [LiveSubscription],
                               backoff: SSEBackoff = SSEBackoff()) -> AsyncThrowingStream<WSUpdate<LiveFrame>, Error> {
        stream(connector: URLSessionWSConnector(client: client),
               hello: { MetricsLive.subscribeMessage(subscriptions()) },
               decode: { MetricsLive.parseFrame($0) }, backoff: backoff)
    }
}

public struct URLSessionWSConnector: WSConnecting {
    let client: NetraClient
    public init(client: NetraClient) { self.client = client }

    public func open() async throws -> WSTransport {
        guard let url = MetricsLive.socketURL(base: client.profile.baseURL) else { throw NetraError.transport("bad controller URL") }
        var req = client.request("GET", "api/v1/metrics/stream")   // Bearer header, never the query string
        req.url = url
        let task = client.session.webSocketTask(with: req)
        task.resume()
        return URLSessionWSTransport(task: task)
    }
}

final class URLSessionWSTransport: WSTransport, @unchecked Sendable {
    let task: URLSessionWebSocketTask
    init(task: URLSessionWebSocketTask) { self.task = task }

    func send(_ text: String) async throws { try await wrap { try await self.task.send(.string(text)) } }
    func receive() async throws -> Data {
        try await wrap {
            switch try await self.task.receive() {
            case .string(let s): return Data(s.utf8)
            case .data(let d): return d
            @unknown default: return Data()
            }
        }
    }
    func close() { task.cancel(with: .normalClosure, reason: nil) }

    /// Maps a refused handshake (HTTP status on the task's response) to NetraError.
    private func wrap<T>(_ op: () async throws -> T) async throws -> T {
        do { return try await op() }
        catch {
            if Task.isCancelled { throw CancellationError() }
            if let h = task.response as? HTTPURLResponse {
                if h.statusCode == 401 { throw NetraError.unauthorized }
                if !(200..<300).contains(h.statusCode), h.statusCode != 101 { throw NetraError.http(status: h.statusCode, message: "") }
            }
            throw NetraError.transport(error.localizedDescription)
        }
    }
}

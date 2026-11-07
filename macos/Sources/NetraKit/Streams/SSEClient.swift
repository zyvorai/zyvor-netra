// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Splits raw stream bytes on newline boundaries so multi-byte UTF-8 is never cut, then feeds SSEParser.
public struct SSEByteFeeder: Sendable {
    private var pending = Data()
    private var parser = SSEParser()
    public init() {}

    public mutating func feed(_ chunk: Data) -> [SSEEvent] {
        pending.append(chunk)
        guard let last = pending.lastIndex(of: 0x0A) else { return [] }
        let complete = pending[pending.startIndex...last]
        let text = String(decoding: complete, as: UTF8.self)
        pending = Data(pending[pending.index(after: last)...])
        return parser.feed(text)
    }
}

public enum SSEConnectionState: Sendable, Equatable {
    case connecting
    case live
    case reconnecting(attempt: Int, in: TimeInterval, reason: String)
    case failed(String)   // terminal (auth / bad request)
}

public enum SSEUpdate: Sendable, Equatable {
    case state(SSEConnectionState)
    case event(SSEEvent)
}

/// Exponential backoff with a ceiling.
public struct SSEBackoff: Sendable, Equatable {
    public var base: TimeInterval
    public var maximum: TimeInterval
    public init(base: TimeInterval = 0.5, maximum: TimeInterval = 15) { self.base = base; self.maximum = maximum }
    public func delay(attempt: Int) -> TimeInterval {
        min(maximum, base * pow(2, Double(max(0, attempt - 1))))
    }
}

public enum SSEClient {
    /// One connection. Finishes when the server closes; throws on HTTP/transport errors.
    public static func events(for request: URLRequest, session: URLSession = .shared) -> AsyncThrowingStream<SSEEvent, Error> {
        AsyncThrowingStream { cont in
            let task = Task {
                do {
                    var req = request
                    req.setValue("text/event-stream", forHTTPHeaderField: "Accept")
                    req.timeoutInterval = 24 * 3600
                    let (bytes, resp) = try await session.bytes(for: req)
                    guard let h = resp as? HTTPURLResponse else { throw NetraError.transport("non-HTTP response") }
                    if h.statusCode == 401 { throw NetraError.unauthorized }
                    guard (200..<300).contains(h.statusCode) else {
                        var body = Data()
                        for try await b in bytes { body.append(b); if body.count > 4096 { break } }
                        throw NetraError.http(status: h.statusCode, message: errorMessage(from: body))
                    }
                    var feeder = SSEByteFeeder()
                    var buf = Data()
                    for try await b in bytes {
                        buf.append(b)
                        if b == 0x0A {
                            for e in feeder.feed(buf) { cont.yield(e) }
                            buf.removeAll(keepingCapacity: true)
                        }
                    }
                    cont.finish()
                } catch { cont.finish(throwing: error) }
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }

    /// Auto-reconnecting stream. Terminates only on cancellation or a non-retryable error (401, 4xx).
    public static func reconnecting(
        makeRequest: @escaping @Sendable () -> URLRequest,
        session: URLSession = .shared,
        backoff: SSEBackoff = SSEBackoff()
    ) -> AsyncStream<SSEUpdate> {
        AsyncStream { cont in
            let task = Task {
                var attempt = 0
                while !Task.isCancelled {
                    cont.yield(.state(.connecting))
                    do {
                        var gotLive = false
                        for try await e in events(for: makeRequest(), session: session) {
                            if !gotLive { gotLive = true; attempt = 0; cont.yield(.state(.live)) }
                            cont.yield(.event(e))
                        }
                        attempt += 1
                        let d = backoff.delay(attempt: attempt)
                        cont.yield(.state(.reconnecting(attempt: attempt, in: d, reason: "stream closed")))
                        try await Task.sleep(for: .seconds(d))
                    } catch is CancellationError {
                        break
                    } catch let e as NetraError {
                        switch e {
                        case .unauthorized:
                            cont.yield(.state(.failed("Unauthorized — check the API token"))); cont.finish(); return
                        case .http(let s, let m) where (400..<500).contains(s) && s != 429 && s != 408:
                            cont.yield(.state(.failed(m.isEmpty ? "HTTP \(s)" : m))); cont.finish(); return
                        default:
                            attempt += 1
                            let d = backoff.delay(attempt: attempt)
                            cont.yield(.state(.reconnecting(attempt: attempt, in: d, reason: String(describing: e))))
                            if (try? await Task.sleep(for: .seconds(d))) == nil { break }
                        }
                    } catch {
                        if Task.isCancelled { break }
                        attempt += 1
                        let d = backoff.delay(attempt: attempt)
                        cont.yield(.state(.reconnecting(attempt: attempt, in: d, reason: error.localizedDescription)))
                        if (try? await Task.sleep(for: .seconds(d))) == nil { break }
                    }
                }
                cont.finish()
            }
            cont.onTermination = { _ in task.cancel() }
        }
    }
}

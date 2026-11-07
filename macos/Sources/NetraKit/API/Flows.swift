// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Bounded FIFO: appending beyond capacity drops the oldest element.
public struct FlowRingBuffer<Element: Sendable>: Sendable {
    public let capacity: Int
    private var storage: [Element] = []
    private var head = 0
    public init(capacity: Int) { self.capacity = max(1, capacity) }
    public var count: Int { storage.count }
    public mutating func append(_ e: Element) {
        if storage.count < capacity { storage.append(e) }
        else { storage[head] = e; head = (head + 1) % capacity }
    }
    public mutating func removeAll() { storage.removeAll(); head = 0 }
    /// Oldest first.
    public var elements: [Element] { Array(storage[head...] + storage[..<head]) }
}

/// One live flow (Hubble-shaped JSON from /api/v1/flows/stream). Decoding is tolerant: every field optional.
public struct FlowRecord: Codable, Sendable, Identifiable, Hashable {
    public var id: Int = 0
    public let raw: JSONValue
    public let time: String
    public let timestamp: Date?
    public let verdict: String
    public let direction: String
    public let source: String
    public let destination: String
    public let sourceIP: String
    public let destinationIP: String
    public let sourcePort: Int
    public let destinationPort: Int
    public let proto: String
    public let dropReason: String

    public static func == (a: FlowRecord, b: FlowRecord) -> Bool { a.id == b.id }
    public func hash(into h: inout Hasher) { h.combine(id) }

    public init(raw: JSONValue, id: Int = 0) {
        self.id = id
        self.raw = raw
        time = raw["time"]?.string ?? ""
        timestamp = FlowRecord.parseDate(time)
        verdict = raw["verdict"]?.string ?? ""
        direction = raw["trafficDirection"]?.string ?? ""
        source = FlowRecord.endpointName(raw["source"])
        destination = FlowRecord.endpointName(raw["destination"])
        let ip = raw["IP"] ?? raw["ip"]
        sourceIP = ip?["source"]?.string ?? ""
        destinationIP = ip?["destination"]?.string ?? ""
        var p = "", sp = 0, dp = 0
        if case .object(let l4)? = raw["l4"] {
            for key in ["TCP", "tcp", "UDP", "udp", "SCTP", "sctp", "ICMPv4", "icmpv4", "ICMPv6", "icmpv6"] {
                if let v = l4[key] {
                    p = key.uppercased().replacingOccurrences(of: "ICMPV", with: "ICMPv")
                    sp = v["sourcePort"]?.controlInt ?? 0; dp = v["destinationPort"]?.controlInt ?? 0
                    break
                }
            }
        }
        proto = p; sourcePort = sp; destinationPort = dp
        dropReason = raw["dropReasonDesc"]?.string ?? ""
    }

    public init(from decoder: Decoder) throws { self.init(raw: try JSONValue(from: decoder)) }
    public func encode(to encoder: Encoder) throws { try raw.encode(to: encoder) }

    public static func endpointName(_ e: JSONValue?) -> String {
        guard let e else { return "world" }
        var pod = e["podName"]?.string ?? ""
        if pod.isEmpty, case .array(let ws)? = e["workloads"], let n = ws.first?["name"]?.string { pod = n }
        let name = [e["namespace"]?.string ?? "", pod].filter { !$0.isEmpty }.joined(separator: "/")
        if !name.isEmpty { return name }
        if let id = e["identity"], id != .null { return id.summary }
        return "world"
    }

    static func parseDate(_ s: String) -> Date? {
        NetraDate.parse(s)
    }

    public var sourceEndpoint: String { sourcePort > 0 ? "\(sourceIP):\(sourcePort)" : sourceIP }
    public var destinationEndpoint: String { destinationPort > 0 ? "\(destinationIP):\(destinationPort)" : destinationIP }

    public var prettyJSON: String {
        let e = JSONEncoder()
        e.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
        return (try? String(decoding: e.encode(raw), as: UTF8.self)) ?? "{}"
    }

    /// Lower-cased haystack for the filter field.
    public var searchText: String {
        [verdict, direction, source, destination, sourceIP, destinationIP, "\(sourcePort)", "\(destinationPort)", proto, dropReason]
            .joined(separator: " ").lowercased()
    }
}

/// Parses an SSE `flow` event payload; nil for non-flow events or malformed JSON.
public func decodeFlowEvent(_ e: SSEEvent) -> FlowRecord? {
    guard e.event == "flow", let d = e.data.data(using: .utf8),
          let v = try? JSONDecoder().decode(JSONValue.self, from: d), case .object = v else { return nil }
    return FlowRecord(raw: v)
}

/// Record of GET /api/v1/flows/history (internal/flowlog.Record).
public struct FlowHistoryRecord: Codable, Sendable, Identifiable, Hashable {
    public var id = UUID()
    public var observedAt: String
    public var node: String
    public var namespace: String
    public var pod: String
    public var workload: String
    public var peer: String
    public var port: Int
    public var proto: String
    public var direction: String
    public var appProtocol: String
    public var packets: Int
    public var bytes: Int
    public var blocked: Int
    public var retransmissions: Int
    public var rtos: Int
    public var srttUs: Int
    public var pid: Int
    public var comm: String
    public var dnsName: String
    public var tlsSni: String

    enum CodingKeys: String, CodingKey {
        case observedAt, node, namespace, pod, workloadKind, workloadName, peer, port, protocol_ = "protocol"
        case direction, appProtocol, packets, bytes, blocked, retransmissions, rtos, srttUs, pid, comm, dnsName, tlsSni
    }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        func s(_ k: CodingKeys) -> String { LenientDecode.string(c, k) ?? "" }
        func i(_ k: CodingKeys) -> Int { LenientDecode.double(c, k).flatMap(LenientDecode.int64).map { Int(clamping: $0) } ?? 0 }
        observedAt = s(.observedAt); node = s(.node); namespace = s(.namespace); pod = s(.pod)
        workload = [s(.workloadKind), s(.workloadName)].filter { !$0.isEmpty }.joined(separator: "/")
        peer = s(.peer); port = i(.port); proto = s(.protocol_); direction = s(.direction)
        appProtocol = s(.appProtocol); packets = i(.packets); bytes = i(.bytes); blocked = i(.blocked)
        retransmissions = i(.retransmissions); rtos = i(.rtos); srttUs = i(.srttUs); pid = i(.pid)
        comm = s(.comm); dnsName = s(.dnsName); tlsSni = s(.tlsSni)
    }
    public func encode(to e: Encoder) throws {
        var c = e.container(keyedBy: CodingKeys.self)
        try c.encode(observedAt, forKey: .observedAt); try c.encode(peer, forKey: .peer); try c.encode(port, forKey: .port)
        try c.encode(namespace, forKey: .namespace); try c.encode(pod, forKey: .pod)
        try c.encode(proto, forKey: .protocol_); try c.encode(direction, forKey: .direction)
        try c.encode(packets, forKey: .packets); try c.encode(bytes, forKey: .bytes)
    }
    public func hash(into h: inout Hasher) { h.combine(id) }
}

public struct FlowHistory: Codable, Sendable {
    public var records: [FlowHistoryRecord]
    public var matched: Int
    public var truncated: Bool
    public var limitations: [String]
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        records = (try? c.decodeIfPresent([FlowHistoryRecord].self, forKey: .records)) ?? []
        matched = LenientDecode.double(c, .matched).flatMap(LenientDecode.int64).map { Int(clamping: $0) } ?? records.count
        truncated = LenientDecode.bool(c, .truncated) ?? false
        limitations = (try? c.decodeIfPresent([String].self, forKey: .limitations)) ?? []
    }
    enum K: String, CodingKey { case records, matched, truncated, limitations }
}

public struct FlowNamedCount: Codable, Sendable, Hashable, Identifiable {
    public var name: String
    public var count: Int
    public var id: String { name }
    public init(name: String, count: Int) { self.name = name; self.count = count }
    enum K: String, CodingKey { case name, count }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        name = LenientDecode.string(c, .name) ?? ""
        count = LenientDecode.double(c, .count).flatMap(LenientDecode.int64).map { Int(clamping: $0) } ?? 0
    }
}

/// GET /api/v1/flows/summary (models.FlowsSummary).
public struct FlowsSummary: Codable, Sendable {
    public var total: Int
    public var verdicts: [String: Int]
    public var protocols: [String: Int]
    public var dropReasons: [FlowNamedCount]
    public var topDestinations: [FlowNamedCount]
    public var topWorkloads: [FlowNamedCount]
    public var topBlockedWorkloads: [FlowNamedCount]
    enum K: String, CodingKey { case total, verdicts, protocols, dropReasons, topDestinations, topWorkloads, topBlockedWorkloads }
    /// Go map[string]uint64 (nil map encodes as null); tolerates float-formatted counts.
    static func counts(_ c: KeyedDecodingContainer<K>, _ k: K) -> [String: Int] {
        if let m = try? c.decodeIfPresent([String: Int].self, forKey: k) { return m }
        guard let m = try? c.decodeIfPresent([String: Double].self, forKey: k) else { return [:] }
        return m.compactMapValues { LenientDecode.int64($0).map { Int(clamping: $0) } }
    }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: K.self)
        total = LenientDecode.double(c, .total).flatMap(LenientDecode.int64).map { Int(clamping: $0) } ?? 0
        verdicts = FlowsSummary.counts(c, .verdicts)
        protocols = FlowsSummary.counts(c, .protocols)
        dropReasons = (try? c.decodeIfPresent([FlowNamedCount].self, forKey: .dropReasons)) ?? []
        topDestinations = (try? c.decodeIfPresent([FlowNamedCount].self, forKey: .topDestinations)) ?? []
        topWorkloads = (try? c.decodeIfPresent([FlowNamedCount].self, forKey: .topWorkloads)) ?? []
        topBlockedWorkloads = (try? c.decodeIfPresent([FlowNamedCount].self, forKey: .topBlockedWorkloads)) ?? []
    }
}

public struct FlowFilterParams: Sendable, Equatable {
    public var direction = "", verdict = "", protocolName = "", namespace = "", pod = "", destination = ""
    public init() {}
    public var queryItems: [URLQueryItem] {
        [("direction", direction), ("verdict", verdict), ("protocol", protocolName),
         ("namespace", namespace), ("pod", pod), ("destination", destination)]
            .filter { !$0.1.isEmpty }.map { URLQueryItem(name: $0.0, value: $0.1) }
    }
}

public extension NetraClient {
    /// Bearer-authenticated request for the live SSE tail.
    func flowStreamRequest(number: Int = 100, filter: FlowFilterParams = .init()) -> URLRequest {
        request("GET", "api/v1/flows/stream", query: [URLQueryItem(name: "number", value: String(number))] + filter.queryItems)
    }
    func flowHistory(since: String = "1h", limit: Int = 200, namespace: String = "", pod: String = "",
                     peer: String = "", proto: String = "") async throws -> FlowHistory {
        var q = [URLQueryItem(name: "since", value: since), URLQueryItem(name: "limit", value: String(limit))]
        for (k, v) in [("namespace", namespace), ("pod", pod), ("peer", peer), ("protocol", proto)] where !v.isEmpty {
            q.append(URLQueryItem(name: k, value: v))
        }
        return try await get("api/v1/flows/history", query: q)
    }
    func flowSummary(number: Int = 500, filter: FlowFilterParams = .init()) async throws -> FlowsSummary {
        try await get("api/v1/flows/summary", query: [URLQueryItem(name: "number", value: String(number))] + filter.queryItems)
    }
}

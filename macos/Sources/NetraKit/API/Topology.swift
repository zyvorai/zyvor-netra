// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

// MARK: - Wire models (tolerant: every field optional, unknown keys ignored)

private struct Loose: Decodable {
    let c: KeyedDecodingContainer<AnyKey>
    init(from d: Decoder) throws { c = try d.container(keyedBy: AnyKey.self) }
    func str(_ k: String) -> String { (try? c.decodeIfPresent(String.self, forKey: AnyKey(k))) ?? "" }
    func num(_ k: String) -> Double {
        if let v = try? c.decodeIfPresent(Double.self, forKey: AnyKey(k)) { return v }
        if let s = try? c.decodeIfPresent(String.self, forKey: AnyKey(k)), let v = Double(s) { return v }
        return 0
    }
    func bool(_ k: String) -> Bool { (try? c.decodeIfPresent(Bool.self, forKey: AnyKey(k))) ?? false }
    func list<T: Decodable>(_ k: String, _ t: T.Type) -> [T] {
        guard let a = try? c.decodeIfPresent([Lossy<T>].self, forKey: AnyKey(k)) else { return [] }
        return a.compactMap(\.value)
    }
}
private struct AnyKey: CodingKey {
    var stringValue: String; var intValue: Int? { nil }
    init(_ s: String) { stringValue = s }
    init?(stringValue: String) { self.stringValue = stringValue }
    init?(intValue: Int) { nil }
}
private struct Lossy<T: Decodable>: Decodable {
    let value: T?
    init(from d: Decoder) throws { value = try? T(from: d) }
}

/// One row of GET /api/v1/ebpf/topology `items` (models.NetworkEdge).
public struct NetworkEdgeRow: Decodable, Sendable, Equatable {
    public var node, namespace, pod, workloadKind, workloadName, destination, proto: String
    public var packets, bytes, blocked: Double
    public init(from d: Decoder) throws {
        let l = try Loose(from: d)
        node = l.str("node"); namespace = l.str("namespace"); pod = l.str("pod")
        workloadKind = l.str("workloadKind"); workloadName = l.str("workloadName")
        destination = l.str("destination"); proto = l.str("protocol")
        packets = l.num("packets"); bytes = l.num("bytes"); blocked = l.num("blocked")
    }
    public init(node: String = "", namespace: String = "", pod: String = "", workloadKind: String = "",
                workloadName: String = "", destination: String, proto: String = "tcp",
                packets: Double = 0, bytes: Double = 0, blocked: Double = 0) {
        self.node = node; self.namespace = namespace; self.pod = pod; self.workloadKind = workloadKind
        self.workloadName = workloadName; self.destination = destination; self.proto = proto
        self.packets = packets; self.bytes = bytes; self.blocked = blocked
    }
}

public struct TopologyNode: Decodable, Sendable, Equatable, Identifiable {
    public var id: String
    public var kind: String
    public var namespace: String
    public var name: String
    public var ip: String
    public var workloadKind: String
    public init(from d: Decoder) throws {
        let l = try Loose(from: d)
        id = l.str("id"); kind = l.str("kind"); namespace = l.str("namespace"); name = l.str("name")
        ip = l.str("ip"); workloadKind = l.str("workloadKind")
    }
    public init(id: String, kind: String = "", namespace: String = "", name: String = "",
                ip: String = "", workloadKind: String = "") {
        self.id = id; self.kind = kind; self.namespace = namespace; self.name = name
        self.ip = ip; self.workloadKind = workloadKind
    }
    /// Mirrors web label(): external -> ip/name, otherwise namespace/name.
    public var label: String {
        if kind == "external" { return ip.isEmpty ? (name.isEmpty ? id : name) : ip }
        let s = namespace.isEmpty ? name : "\(namespace)/\(name)"
        return s.isEmpty ? id : s
    }
}

public struct TopologyEdge: Decodable, Sendable, Equatable, Identifiable {
    public var source, target, proto: String
    public var port: Int
    public var packets, bytes, blocked: Double
    public var external: Bool
    public var id: String { "\(source) \(target) \(proto) \(port)" }
    public init(from d: Decoder) throws {
        let l = try Loose(from: d)
        source = l.str("source"); target = l.str("target"); proto = l.str("protocol")
        port = Int(l.num("port")); packets = l.num("packets"); bytes = l.num("bytes")
        blocked = l.num("blocked"); external = l.bool("external")
    }
    public init(source: String, target: String, proto: String = "tcp", port: Int = 0,
                packets: Double = 0, bytes: Double = 0, blocked: Double = 0, external: Bool = false) {
        self.source = source; self.target = target; self.proto = proto; self.port = port
        self.packets = packets; self.bytes = bytes; self.blocked = blocked; self.external = external
    }
    public var label: String { port > 0 ? "\(proto)/\(port)" : proto }
}

/// Graph shape shared by /ebpf/topology (after conversion) and /insights/dependencies.
public struct TopologyGraph: Decodable, Sendable, Equatable {
    public var nodes: [TopologyNode]
    public var edges: [TopologyEdge]
    public init(nodes: [TopologyNode] = [], edges: [TopologyEdge] = []) { self.nodes = nodes; self.edges = edges }
    public init(from d: Decoder) throws {
        let l = try Loose(from: d)
        nodes = l.list("nodes", TopologyNode.self).filter { !$0.id.isEmpty }
        edges = l.list("edges", TopologyEdge.self)
    }

    /// Builds a graph from GET /api/v1/ebpf/topology `{items:[NetworkEdge]}`.
    public static func fromEdgeRows(_ rows: [NetworkEdgeRow]) -> TopologyGraph {
        var nodes: [String: TopologyNode] = [:]
        var edges: [String: TopologyEdge] = [:]
        for r in rows where !r.destination.isEmpty {
            let src: TopologyNode
            if !r.workloadName.isEmpty {
                src = TopologyNode(id: "\(r.namespace)/\(r.workloadKind.lowercased())/\(r.workloadName)", kind: "workload",
                                   namespace: r.namespace, name: r.workloadName, workloadKind: r.workloadKind)
            } else if !r.pod.isEmpty {
                src = TopologyNode(id: "\(r.namespace)/pod/\(r.pod)", kind: "pod", namespace: r.namespace, name: r.pod)
            } else {
                src = TopologyNode(id: "node/\(r.node)", kind: "node", name: r.node.isEmpty ? "host" : r.node)
            }
            nodes[src.id] = nodes[src.id] ?? src
            let dstID = "dest/\(r.destination)"
            nodes[dstID] = nodes[dstID] ?? TopologyNode(id: dstID, kind: "external", name: r.destination, ip: r.destination)
            var e = TopologyEdge(source: src.id, target: dstID, proto: r.proto,
                                 packets: r.packets, bytes: r.bytes, blocked: r.blocked)
            if let old = edges[e.id] { e.packets += old.packets; e.bytes += old.bytes; e.blocked += old.blocked }
            edges[e.id] = e
        }
        return TopologyGraph(nodes: nodes.values.sorted { $0.id < $1.id },
                             edges: edges.values.sorted { $0.id < $1.id })
    }

    public static func decodeEdgeRows(_ data: Data) throws -> TopologyGraph {
        struct Env: Decodable {
            var items: [NetworkEdgeRow]
            init(from d: Decoder) throws { items = try Loose(from: d).list("items", NetworkEdgeRow.self) }
        }
        return fromEdgeRows(try JSONDecoder().decode(Env.self, from: data).items)
    }

    /// Nodes adjacent to `id` (either direction).
    public func neighbors(of id: String) -> Set<String> {
        var s = Set<String>()
        for e in edges { if e.source == id { s.insert(e.target) } else if e.target == id { s.insert(e.source) } }
        return s
    }
}

public struct BlastRadius: Decodable, Sendable, Equatable {
    public var root: String
    public var maxHops: Int
    public var hops: [String: Int]
    public var truncated: Bool
    public var caveat: String
    public init(from d: Decoder) throws {
        let l = try Loose(from: d)
        root = l.str("root"); maxHops = Int(l.num("maxHops")); truncated = l.bool("truncated"); caveat = l.str("caveat")
        struct N: Decodable { var id: String; var hops: Int
            init(from d: Decoder) throws { let l = try Loose(from: d); id = l.str("id"); hops = Int(l.num("hops")) } }
        hops = Dictionary(l.list("nodes", N.self).map { ($0.id, $0.hops) }, uniquingKeysWith: min)
    }
}

public extension NetraClient {
    func topologyGraph(limit: Int = 500) async throws -> TopologyGraph {
        let data = try await send(request("GET", "api/v1/ebpf/topology", query: [.init(name: "limit", value: String(min(limit, 1000)))]))
        return try TopologyGraph.decodeEdgeRows(data)
    }
    func dependencyGraph(limit: Int = 500) async throws -> TopologyGraph {
        try await get("api/v1/insights/dependencies", query: [.init(name: "limit", value: String(limit))])
    }
    func blastRadius(root: String, hops: Int = 3) async throws -> BlastRadius {
        try await get("api/v1/insights/blast-radius",
                      query: [.init(name: "root", value: root), .init(name: "hops", value: String(hops))])
    }
}

// MARK: - Force layout (pure)

public struct Vec2: Sendable, Equatable { public var x: Double; public var y: Double
    public init(_ x: Double, _ y: Double) { self.x = x; self.y = y } }

/// Fruchterman-Reingold style simulation. Deterministic seeding so tests and refreshes are stable.
public struct ForceLayout: Sendable {
    public private(set) var positions: [String: Vec2] = [:]
    var velocity: [String: Vec2] = [:]
    public var pinned: Set<String> = []
    public var repulsion = 9000.0
    public var spring = 0.02
    public var restLength = 90.0
    public var gravity = 0.01
    public var damping = 0.85
    public var energy: Double = .infinity

    public init() {}

    /// Keeps existing positions for surviving nodes (so a refresh does not scramble the view);
    /// new nodes start near a neighbour if any, else on a deterministic spiral.
    public mutating func sync(nodes: [String], edges: [(String, String)]) {
        let keep = Set(nodes)
        positions = positions.filter { keep.contains($0.key) }
        velocity = velocity.filter { keep.contains($0.key) }
        pinned = pinned.filter { keep.contains($0) }
        for (i, id) in nodes.enumerated() where positions[id] == nil {
            var seed: Vec2?
            for (a, b) in edges {
                let other = a == id ? b : (b == id ? a : nil)
                if let o = other, let p = positions[o] { seed = Vec2(p.x + 20 * cos(Double(i)), p.y + 20 * sin(Double(i))); break }
            }
            let r = 40 + 18 * Double(i).squareRoot() * 3, th = Double(i) * 2.39996
            positions[id] = seed ?? Vec2(r * cos(th), r * sin(th))
            velocity[id] = Vec2(0, 0)
        }
        energy = .infinity
    }

    @discardableResult
    public mutating func step(edges: [(String, String)]) -> Double {
        let ids = Array(positions.keys).sorted()
        var force = [String: Vec2](uniqueKeysWithValues: ids.map { ($0, Vec2(0, 0)) })
        for i in 0..<ids.count {
            for j in (i + 1)..<max(ids.count, i + 1) {
                let a = positions[ids[i]]!, b = positions[ids[j]]!
                var dx = a.x - b.x, dy = a.y - b.y
                var d2 = dx * dx + dy * dy
                if d2 < 0.01 { dx = Double(i - j) * 0.1; dy = 0.1; d2 = dx * dx + dy * dy }
                let f = repulsion / d2, d = d2.squareRoot()
                let fx = f * dx / d, fy = f * dy / d
                force[ids[i]]!.x += fx; force[ids[i]]!.y += fy
                force[ids[j]]!.x -= fx; force[ids[j]]!.y -= fy
            }
        }
        for (s, t) in edges where s != t {
            guard let a = positions[s], let b = positions[t] else { continue }
            let dx = b.x - a.x, dy = b.y - a.y
            let d = max((dx * dx + dy * dy).squareRoot(), 0.01)
            let f = spring * (d - restLength)
            force[s]!.x += f * dx / d; force[s]!.y += f * dy / d
            force[t]!.x -= f * dx / d; force[t]!.y -= f * dy / d
        }
        var e = 0.0
        for id in ids where !pinned.contains(id) {
            let p = positions[id]!
            var v = velocity[id]!
            v.x = (v.x + force[id]!.x - gravity * p.x) * damping
            v.y = (v.y + force[id]!.y - gravity * p.y) * damping
            let sp = (v.x * v.x + v.y * v.y).squareRoot()
            if sp > 40 { v.x *= 40 / sp; v.y *= 40 / sp }
            velocity[id] = v
            positions[id] = Vec2(p.x + v.x, p.y + v.y)
            e += v.x * v.x + v.y * v.y
        }
        energy = e
        return e
    }

    public mutating func move(_ id: String, to p: Vec2) { if positions[id] != nil { positions[id] = p; velocity[id] = Vec2(0, 0); energy = .infinity } }
    public var settled: Bool { energy < 0.05 * Double(max(positions.count, 1)) }
}

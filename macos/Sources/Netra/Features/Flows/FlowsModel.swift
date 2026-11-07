// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

/// Live tail state: SSE -> bounded ring -> throttled snapshot for the Table.
@MainActor @Observable
final class FlowsModel {
    static let capacity = 5_000
    var rows: [FlowRecord] = []
    var state: SSEConnectionState = .connecting
    var paused = false { didSet { if !paused { publish() } } }
    var rate: Double = 0
    var total = 0
    var filter = FlowFilterParams()

    private var ring = FlowRingBuffer<FlowRecord>(capacity: FlowsModel.capacity)
    private var seq = 0
    private var arrivals: [Date] = []
    private var streamTask: Task<Void, Never>?
    private var tickTask: Task<Void, Never>?
    private var dirty = false

    func start(client: NetraClient?) {
        stop()
        guard let client else { state = .failed("No connection"); return }
        let f = filter
        let updates = SSEClient.reconnecting(makeRequest: { client.flowStreamRequest(number: 100, filter: f) })
        streamTask = Task { [weak self] in
            for await u in updates {
                guard let self else { return }
                switch u {
                case .state(let s): self.state = s
                case .event(let e): if let r = decodeFlowEvent(e) { self.ingest(r) }
                }
            }
        }
        tickTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(250))
                self?.tick()
            }
        }
    }

    func stop() { streamTask?.cancel(); tickTask?.cancel(); streamTask = nil; tickTask = nil }

    func clear() { ring.removeAll(); rows = []; total = 0; arrivals = [] }

    func ingest(_ r: FlowRecord) {
        var r = r; seq += 1; r.id = seq
        ring.append(r); total += 1; dirty = true
        arrivals.append(Date())
    }

    private func tick() {
        let cutoff = Date().addingTimeInterval(-5)
        arrivals.removeAll { $0 < cutoff }
        rate = Double(arrivals.count) / 5
        if dirty && !paused { publish() }
    }

    private func publish() { rows = ring.elements.reversed(); dirty = false }
}

enum FlowsTab: String, CaseIterable, Identifiable {
    case live = "Live", history = "History", summary = "Summary"
    var id: String { rawValue }
}

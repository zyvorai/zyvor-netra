// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Explain a drop (read-only). GET /api/v1/ebpf/explain?namespace=&pod=&limit=: {summary:{text,policyDropPackets,policyDropFlows,
/// conntrackEntries,exactFindings,probableFindings}, findings:[{source,confidence,node,namespace,pod,code,reason,direction,src,dst,
/// packets,explanation,suggestion}], sources}. (The "Explain in words" button separately POSTs /ai/explain and shows read-only text.)
struct MoreExplainPage: View {
    @Environment(AppModel.self) private var model
    @State private var namespace = ""
    @State private var pod = ""
    @State private var limit = 20
    @State private var result: JSONValue?
    @State private var failure: MoreFailure?
    @State private var running = false
    @State private var narrating = false
    @State private var narration: AskData.Brief?

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                VStack(spacing: 0) {
                    HStack {
                        TextField("Namespace (optional)", text: $namespace).frame(maxWidth: 200)
                        TextField("Pod (optional)", text: $pod).frame(maxWidth: 200)
                        Stepper("Limit \(limit)", value: $limit, in: 1...100, step: 10).fixedSize()
                        Button("Explain drops", systemImage: "questionmark.bubble") { Task { await run() } }
                            .keyboardShortcut(.defaultAction).disabled(running)
                        Button("Explain in words", systemImage: "text.bubble") { Task { await narrate() } }
                            .help("POST /api/v1/ai/explain: a read-only narration of these drops").disabled(running || narrating)
                        if running || narrating { ProgressView().controlSize(.small) }
                        Spacer()
                    }.padding()
                    Divider()
                    content
                }
            }
        }
        .navigationTitle("Explain").navigationSubtitle("api/v1/ebpf/explain")
        .task { await run() }
    }

    @ViewBuilder private var content: some View {
        if let result {
            VStack(spacing: 0) {
                if let failure { MoreBanner(text: "Showing the last result. Refresh failed: \(failure.text)") }
                if let narration {
                    GroupBox("AI explanation (read-only)") {
                        Text([narration.headline, narration.summary].filter { !$0.isEmpty }.joined(separator: "\n\n"))
                            .textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    }.padding([.horizontal, .top])
                }
                GroupBox {
                    Text(result.at("summary.text")?.string ?? "No summary.").textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }.padding([.horizontal, .top])
                StatRow(stats: [
                    .init(title: "Exact findings", symbol: "checkmark.seal", tint: .red) { CellFormat.text($0.at("summary.exactFindings") ?? .number(0), .int) },
                    .init(title: "Probable", symbol: "questionmark.circle", tint: .orange) { CellFormat.text($0.at("summary.probableFindings") ?? .number(0), .int) },
                    .init(title: "Policy-drop packets", symbol: "xmark.octagon") { TrafficData.compact($0.at("summary.policyDropPackets")?.asDouble ?? 0) },
                    .init(title: "Policy-drop flows", symbol: "arrow.triangle.branch") { TrafficData.compact($0.at("summary.policyDropFlows")?.asDouble ?? 0) },
                    .init(title: "Sources", symbol: "tray.2") { MoreData.strings($0, at: "sources").joined(separator: ", ") },
                ], value: result).padding(.horizontal)
                MoreRowsTable(rows: result.rows(at: "findings", idKeys: ["code", "src"]), columns: [
                    .init(title: "Confidence", path: "confidence", width: 80), .init(title: "Node", path: "node", width: 100),
                    .init(title: "Workload", path: "pod", width: 130), .init(title: "Direction", path: "direction", width: 70),
                    .init(title: "Source", path: "src", width: 120), .init(title: "Destination", path: "dst", width: 120),
                    .init(title: "Packets", path: "packets", kind: .int, width: 70), .init(title: "Code", path: "code", width: 140),
                    .init(title: "Explanation", path: "explanation", width: 300), .init(title: "Suggestion", path: "suggestion", width: 300),
                ], empty: "No drop findings match. Nothing is being dropped by Netra's datapath hooks, or no node has reported yet.")
            }
        } else if let failure {
            ContentUnavailableView(failure.featureOff ? "Explain is off" : "Couldn't explain drops",
                                   systemImage: "exclamationmark.triangle", description: Text(failure.text))
        } else { ProgressView().controlSize(.large).frame(maxHeight: .infinity) }
    }

    /// POST /api/v1/ai/explain (read-only narration of a finding). Never applies anything.
    private func narrate() async {
        guard let c = model.client else { return }
        narrating = true; defer { narrating = false }
        let subject = [namespace, pod].filter { !$0.isEmpty }.joined(separator: "/")
        let body = AskData.explainBody(kind: "drops", subject: subject, message: result?.at("summary.text")?.string ?? "", page: "explain")
        var req = c.request("POST", "api/v1/ai/explain", body: body); req.timeoutInterval = 60
        do { narration = AskData.brief(try JSONDecoder().decode(JSONValue.self, from: await c.send(req))) }
        catch { failure = MoreFailure(text: error.localizedDescription, featureOff: false) }
    }

    private func run() async {
        guard let c = model.client else { return }
        running = true; defer { running = false }
        switch await MoreFetch.get(c, "api/v1/ebpf/explain", query: MoreData.explainQuery(namespace: namespace, pod: pod, limit: limit), feature: "Explain") {
        case .success(let v): result = v; failure = nil
        case .failure(let f): failure = f
        }
    }
}

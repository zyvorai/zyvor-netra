// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
import SwiftUI
import NetraKit

/// Investigate a connection (read-only). GET /api/v1/investigate/connection?namespace=&pod=&peer=&port=&node=&window=
/// (the handler takes these, not a full 5-tuple): {request:{namespace,pod,peer,port,node,since,until},
/// events:[{ts,source,stage,summary,confidence,link}], gaps:[{stage,reason,link}],
/// confidence:{overall,sensorAvailability,samplingLoss,staleAttribution,retentionGaps,notes}, limitations:[]}.
struct MoreInvestigatePage: View {
    @Environment(AppModel.self) private var model
    @State private var namespace = ""
    @State private var pod = ""
    @State private var peer = ""
    @State private var port = ""
    @State private var node = ""
    @State private var window = "15m"
    @State private var result: JSONValue?
    @State private var failure: MoreFailure?
    @State private var inputError: String?
    @State private var running = false

    var body: some View {
        Group {
            if model.client == nil || model.whoami == nil {
                ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first."))
            } else {
                VStack(spacing: 0) {
                    HStack {
                        TextField("Namespace", text: $namespace).frame(maxWidth: 130)
                        TextField("Pod", text: $pod).frame(maxWidth: 150)
                        TextField("Peer IP", text: $peer).frame(maxWidth: 140)
                        TextField("Port", text: $port).frame(maxWidth: 70)
                        TextField("Node", text: $node).frame(maxWidth: 120)
                        TextField("Window", text: $window).frame(maxWidth: 70)
                        Button("Investigate", systemImage: "magnifyingglass") { Task { await run() } }
                            .keyboardShortcut(.defaultAction).disabled(running)
                        if running { ProgressView().controlSize(.small) }
                        Spacer()
                    }.padding()
                    if let inputError { MoreBanner(text: inputError) }
                    Divider()
                    content
                }
            }
        }
        .navigationTitle("Investigate").navigationSubtitle("api/v1/investigate/connection")
    }

    @ViewBuilder private var content: some View {
        if let result {
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if let failure { MoreBanner(text: "Showing the last result. Refresh failed: \(failure.text)") }
                    GroupBox("Confidence") {
                        HStack { MoreLevel(text: result.at("confidence.overall")?.string ?? ""); Spacer() }
                    }
                    GroupBox("Timeline") {
                        let events = MoreData.timeline(result)
                        if events.isEmpty { KernelEmpty(text: "No events matched this window and filter.") }
                        else {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(events) { e in
                                    HStack(alignment: .firstTextBaseline, spacing: 8) {
                                        Text(CellFormat.date(e.value["ts"]).map { $0.formatted(date: .omitted, time: .standard) } ?? "").monospacedDigit().foregroundStyle(.secondary)
                                        Text(e.value["stage"]?.string ?? "").font(.callout.weight(.medium)).frame(width: 100, alignment: .leading)
                                        Text(e.value["source"]?.string ?? "").font(.caption).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
                                        Text(e.value["summary"]?.string ?? "").textSelection(.enabled)
                                        Spacer(minLength: 8)
                                        Text(e.value["confidence"]?.string ?? "").font(.caption).foregroundStyle(.secondary)
                                    }
                                }
                            }.frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    MoreBullets(title: "Gaps", items: result.rows(at: "gaps", idKeys: ["stage"]).map { "\($0.value["stage"]?.string ?? ""): \($0.value["reason"]?.string ?? "")" }, symbol: "questionmark.circle")
                    MoreBullets(title: "Sensor availability", items: MoreData.strings(result, at: "confidence.sensorAvailability"))
                    MoreBullets(title: "Sampling loss", items: MoreData.strings(result, at: "confidence.samplingLoss"))
                    MoreBullets(title: "Stale attribution", items: MoreData.strings(result, at: "confidence.staleAttribution"))
                    MoreBullets(title: "Retention gaps", items: MoreData.strings(result, at: "confidence.retentionGaps"))
                    MoreBullets(title: "Notes", items: MoreData.strings(result, at: "confidence.notes"))
                    MoreBullets(title: "Limitations", items: MoreData.strings(result, at: "limitations"))
                }.padding()
            }
        } else if let failure {
            ContentUnavailableView(failure.featureOff ? "Investigation is off" : "Couldn't investigate", systemImage: "exclamationmark.triangle", description: Text(failure.text))
        } else {
            ContentUnavailableView("Describe a connection", systemImage: "magnifyingglass.circle",
                                   description: Text("Enter a namespace, pod, peer IP, port or node and choose Investigate. The timeline joins flow history, DNS, drops, path and captures."))
        }
    }

    private func run() async {
        guard let c = model.client else { return }
        let q = MoreData.investigateQuery(namespace: namespace, pod: pod, peer: peer, port: port, node: node, window: window)
        inputError = q.error
        guard q.error == nil else { return }
        running = true; defer { running = false }
        switch await MoreFetch.get(c, "api/v1/investigate/connection", query: q.items, feature: "Investigation") {
        case .success(let v): result = v; failure = nil
        case .failure(let f): failure = f
        }
    }
}

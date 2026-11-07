// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import NetraKit

struct OverviewView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        ScrollView {
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 260), spacing: 16)], spacing: 16) {
                ModeCard()
                Card(title: "Cluster health", symbol: "heart.text.square") {
                    if let h = model.healthScore {
                        Text("\(Int(h))").font(.system(size: 48, weight: .semibold, design: .rounded)).monospacedDigit()
                        Text("health score").foregroundStyle(.secondary)
                    } else { Text("—").font(.largeTitle).foregroundStyle(.secondary) }
                }
                Card(title: "Access", symbol: "person.badge.key") {
                    Text(model.whoami?.role.capitalized ?? "—").font(.title.weight(.semibold))
                    Text(model.gate.canMutate ? "Can change rules and captures" : "Read-only").foregroundStyle(.secondary)
                    if model.whoami?.isAdmin == true { Text("Admin: posture, policy, consoles").font(.caption).foregroundStyle(.secondary) }
                }
            }
            .padding(24)
        }
        .navigationTitle("Overview")
    }
}

struct Card<Content: View>: View {
    let title: String, symbol: String
    @ViewBuilder var content: Content
    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Label(title, systemImage: symbol).font(.headline).foregroundStyle(.secondary)
            content
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, minHeight: 140, alignment: .topLeading)
        .padding(16)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 14))
    }
}

struct ModeCard: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Card(title: "Datapath mode", symbol: "shield.lefthalf.filled") {
            let enforcing = model.effectiveMode == "enforce"
            Text(model.effectiveMode.capitalized)
                .font(.title.weight(.semibold)).foregroundStyle(enforcing ? .orange : .green)
            if let l = model.lease, enforcing || l.active { LeaseCountdown(lease: l, fetched: model.leaseFetchedAt) }
            else { Text("Observe-first: nothing is being enforced").foregroundStyle(.secondary) }
        }
    }
}

/// Counts down locally between polls; reaching zero means enforce has failed open to observe.
struct LeaseCountdown: View {
    let lease: LeaseStatus, fetched: Date
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { ctx in
            let left = max(0, Double(lease.remainingSeconds) - ctx.date.timeIntervalSince(fetched))
            VStack(alignment: .leading, spacing: 6) {
                Text(Duration.seconds(Int(left)).formatted(.time(pattern: .hourMinuteSecond))).font(.title2.monospacedDigit())
                if lease.leaseSeconds ?? 0 > 0 { ProgressView(value: left, total: Double(lease.leaseSeconds!)) }
                Text(left > 0 ? "until enforcement reverts to observe" : "lease expired — observing").font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct LeaseView: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                ModeCard().frame(maxWidth: 360)
                if let n = model.lease?.note, !n.isEmpty { Text(n).foregroundStyle(.secondary) }
                Text("Changing mode will go through preview and typed confirmation (coming with the Control phase).")
                    .font(.callout).foregroundStyle(.secondary)
            }.padding(24)
        }
        .navigationTitle("Lease")
    }
}

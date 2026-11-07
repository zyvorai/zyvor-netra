// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import SwiftUI
import AppKit
import NetraKit

/// Saves downloaded bytes through NSSavePanel (the user picks the destination; nothing is written silently).
@MainActor enum OpsSave {
    static func save(_ data: Data, suggestedName: String) -> String? {
        let p = NSSavePanel()
        p.nameFieldStringValue = suggestedName
        p.canCreateDirectories = true
        guard p.runModal() == .OK, let url = p.url else { return nil }
        do { try data.write(to: url, options: .atomic); return url.path } catch { return "Could not save: \(error.localizedDescription)" }
    }
}

func opsDescribe(_ e: Error) -> String {
    switch e as? NetraError {
    case .http(let s, let m): "HTTP \(s): \(m)"
    case .unauthorized: "unauthorized"
    case .transport(let m): m
    case nil: e.localizedDescription
    }
}

struct OpsNotConnected: View {
    var body: some View { ContentUnavailableView("Not connected", systemImage: "bolt.slash", description: Text("Connect to a Netra controller first.")) }
}

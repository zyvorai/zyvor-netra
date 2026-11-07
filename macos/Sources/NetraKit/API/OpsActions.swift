// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

import Foundation

/// Guarded control/ops mutations. Feature toggles live in `ControlMutations.featureSpec`
/// (POST /api/v1/features/{id}); GitOps resync is here.
public enum OpsAction {
    /// POST /api/v1/policies/gitops/resync with the manifest as the body. The server applies it through the
    /// normal policy pipeline regardless of drift, and is Cilium-gated (it refuses when Cilium is off).
    /// Never touches Cilium-owned BPF maps: it only submits a CiliumNetworkPolicy through the API.
    public static func gitopsResyncSpec(client c: NetraClient, manifest: Data, namespace: String, name: String) -> MutationSpec {
        MutationSpec(
            title: "GitOps resync \(namespace)/\(name)", risk: .high, expectedPhrase: "resync \(namespace)/\(name)", leaseBound: false,
            preview: { c.request("GET", "api/v1/policies/gitops/status") },
            summarize: { v in
                let d = GitOpsStatus(v)
                guard let m = d.manifests.first(where: { $0.namespace == namespace && $0.name == name }) else {
                    return "\(namespace)/\(name) is not among the \(d.manifests.count) manifest(s) GitOps tracks; the server will still apply the body you send."
                }
                var s = "Last pass: \(m.drifted ? "live policy has DRIFTED from Git" : "no drift"), risk \(m.risk ?? "unknown"), \(m.applied ? "applied" : "not applied")."
                if let e = m.error, !e.isEmpty { s += " Error: \(e)." }
                return s + " Resync overrides the unattended gating and requires explicit confirmation."
            },
            riskFromPreview: nil,
            execute: { _ in c.request("POST", "api/v1/policies/gitops/resync", body: manifest) })
    }

    /// Form-driven entry for the Enforcement catalog or any ActionFormSheet.
    public static let all: [ControlAction] = [
        ControlAction(
            id: "ops.gitops.resync", group: "GitOps", title: "GitOps resync",
            summary: "Force-apply a manifest through the GitOps pipeline (POST /policies/gitops/resync). Cilium must be enabled on the controller.",
            symbol: "arrow.triangle.2.circlepath", maxRisk: .high,
            fields: [.init("manifest", "Manifest (JSON or YAML)", .multiline, help: "A CiliumNetworkPolicy; namespace/name are read from metadata")],
            build: { c, v in
                let text = Form.str(v, "manifest")
                guard !text.isEmpty else { return .failure(.init("Paste a manifest")) }
                let data = Data(text.utf8)
                guard let id = ControlMutations.policyIdentity(data) else { return .failure(.init("The manifest needs metadata.name")) }
                return .success(gitopsResyncSpec(client: c, manifest: data, namespace: id.namespace, name: id.name))
            }),
    ]
}

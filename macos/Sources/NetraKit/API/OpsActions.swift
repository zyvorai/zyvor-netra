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
            // The server compares X-Netra-Confirm-Risk to the plan's own risk ("high" or "critical"), so the
            // preview is the read-only plan of this exact body (POST /policies/plan, viewer role, Cilium-gated
            // like the resync itself), and the risk it reports decides the header value.
            preview: { c.request("POST", "api/v1/policies/plan", body: manifest) },
            summarize: { v in
                let plan = v["plan"]
                let risk = plan?["risk"]?.string ?? "unknown"
                var s = "Plan risk: \(risk)."
                if case .bool(let b)? = v["dryRun"]?["passed"] { s += b ? " Kubernetes dry-run passed." : " Kubernetes dry-run FAILED\(v["dryRun"]?["error"]?.string.map { ": " + $0 } ?? "")." }
                if case .bool(false)? = plan?["specChanged"] { s += " The live policy already matches: nothing would change." }
                if case .array(let w)? = plan?["warnings"], !w.isEmpty { s += " Warnings: " + w.map(\.summary).joined(separator: "; ") + "." }
                return s + " Resync applies the body regardless of GitOps drift gating and needs GitOps enabled (NETRA_GITOPS_DIR) on the controller."
            },
            riskFromPreview: { Risk(serverValue: $0["plan"]?["risk"]?.string) },
            execute: { _ in c.request("POST", "api/v1/policies/gitops/resync", body: manifest) })
    }

    /// Form-driven entry for the Enforcement catalog or any ActionFormSheet.
    public static let all: [ControlAction] = [
        ControlAction(
            id: "ops.gitops.resync", group: "GitOps", title: "GitOps resync",
            summary: "Force-apply a manifest through the GitOps pipeline (POST /policies/gitops/resync). Cilium must be enabled on the controller.",
            symbol: "arrow.triangle.2.circlepath", maxRisk: .critical,
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

# Plain Kubernetes install

The base plain manifests are standalone and do **not** grant Cilium permissions. The controller receives read-only `get/list` access to Pods and Services for workload attribution and dependency resolution; the privileged agent remains tokenless.

**HTTPS is on by default** (self-signed P-256 via an openssl init container), matching the Helm chart. Open `https://…:30870` (browser warning expected). The agent sets `NETRA_TLS_INSECURE=true` for that generated cert. Operator CLI: `make install` then `netractl status` (see [`docs/netractl.md`](../docs/netractl.md) for `~/.netra/env` and TLS skip-verify).

Create controller/agent credentials first:

```bash
kubectl create namespace netra-system --dry-run=client -o yaml | kubectl apply -f -
kubectl -n netra-system create secret generic netra-auth \
  --from-literal=api-key="$(openssl rand -hex 32)" \
  --from-literal=agent-key="$(openssl rand -hex 32)"
kubectl apply -k deploy/
```

`deploy/kustomization.yaml` intentionally leaves the privileged `agent.yaml` disabled. Validate cgroup v2, bpffs and kernel BPF support, then enable standalone eBPF coverage:

```bash
kubectl apply -f deploy/agent.yaml
```

The default agent uses root-cgroup hooks and requires no CNI-specific interface. It rescans cgroup-v2 metadata every `NETRA_CGROUP_SCAN_INTERVAL` (default `10s`) so pod/container churn can be attributed without restarting the DaemonSet. TCX/XDP can be enabled by editing `NETRA_INTERFACES` / `NETRA_XDP_INTERFACES` in `agent.yaml`.

Cilium policy integration is optional. When needed, grant its RBAC separately:

```bash
kubectl apply -f deploy/rbac-cilium.yaml
kubectl -n netra-system set env deployment/netra NETRA_CILIUM_ENABLED=true
```

Hubble is disabled in the base controller manifest. Set `NETRA_HUBBLE_ENABLED=true` and configure `NETRA_HUBBLE_ADDR` only when Hubble Relay is available.

The plain deployment includes a PVC and remains a simple single-controller install. Use the Helm chart for the active/passive HA topology, which validates the shared RWX state assumptions and renders Lease election, anti-affinity and the PDB together.

## Install from a release

Only **tagged** releases have images in `ghcr.io`, and `0.28.0` was the first: the release workflow was
added after `v0.27.97` was tagged, so no earlier version has a published image. **Use `0.28.1` or later:**
the `0.28.0` images were built without the logo and favicon (the controller itself is unaffected). Each release is tagged
`X.Y.Z`, `sha-<commit>` and `latest`; pin `X.Y.Z`. The manifests here and the Helm chart pin the image tag
to the version of the checkout, so from `main` between releases they can name an image that does not exist
yet. Install from the tag, not from `main`:

```bash
git clone --branch v0.30.0 https://github.com/zyvorai/netra && cd netra
```

**Verify what you pull.** Both images are signed by the release workflow (keyless cosign), and the
signature names the workflow, the tag and the commit that built them:

```bash
cosign verify ghcr.io/zyvorai/netra:0.30.0 \
  --certificate-identity https://github.com/zyvorai/zyvor-netra/.github/workflows/release.yml@refs/tags/v0.30.0 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

The same command works for `netra-agent`. Compare the pulled images' digests with the
`imageID` of the running pods (`kubectl -n netra-system get pods -o jsonpath='{..imageID}'`)
&mdash; see `ghcr.io/zyvorai/netra` and `ghcr.io/zyvorai/netra-agent` for the `0.30.0` digests once
the release is verified.

**Plain manifests:** `kubectl apply -k deploy/` from the tag pulls the released images as written.

**Helm:** the chart in the tag defaults to the released images. To move an existing install without
losing its settings or keys, keep the values and change only the tags:

```bash
helm upgrade netra ./helm/netra -n netra-system --reset-then-reuse-values \
  --set image.tag=0.30.0 --set agentImage.tag=0.30.0
```

`--reset-then-reuse-values` (Helm 3.14+) takes the new chart's defaults for values you never set, which a
plain `--reuse-values` does not, so it survives a chart that gained new values. Keep
`image.pullPolicy=IfNotPresent` (or `Always`); `Never` only works for images you imported by hand.

## Tested in CI

`scripts/ci-manifests-kind.sh` (job `manifests-kind`) applies exactly these files on a real kind cluster
(`kubectl apply -k deploy/`, then `deploy/agent.yaml`) with only the image references pointed at locally
built images. It asserts: the manifests name the version the checkout builds; the controller and the agent
DaemonSet become ready; the API rejects an unauthenticated call and accepts the key from the Secret; the
controller reports the right version; a rule written before a pod restart is still there (the state volume is
in use); the agent reports and starts in `observe`. A kind node has no bpffs, so the script mounts it as a real
node image would.

# Envoy in front of Netra (Gateway API)

Netra can sit behind Envoy through the Kubernetes Gateway API. This works with
[Envoy Gateway](https://gateway.envoyproxy.io/) or any Gateway API
implementation. It is off by default and changes nothing about how Netra
authenticates: the API key, agent key and mTLS settings are the same with or
without the gateway. The gateway adds TLS termination, hostname routing and
edge policy (rate limits, IP allow lists) in front of the controller.

Node agents keep talking to the `netra` Service directly; only the API/UI
goes through Envoy.

## Enable

```bash
helm upgrade --install netra ./helm/netra -n netra-system \
  --set gateway.enabled=true \
  --set 'gateway.parentRefs[0].name=eg' \
  --set 'gateway.parentRefs[0].namespace=envoy-gateway-system' \
  --set 'gateway.hostnames[0]=netra.example.com'
```

`gateway.parentRefs` is required when the gateway is enabled; the chart fails
fast without it.

## Backend TLS

The controller serves HTTPS by default, so Envoy has to verify the pod
certificate. Use a stable certificate (`tls.existingSecret`) and give Envoy its
CA:

```yaml
gateway:
  enabled: true
  parentRefs: [{name: eg, namespace: envoy-gateway-system}]
  backendTLS:
    caCertificateRefs:
      - {group: "", kind: ConfigMap, name: netra-ca}
```

The chart renders a `BackendTLSPolicy` for the `netra` Service. If a trusted
gateway terminates TLS and the hop to the pod is plain HTTP, set
`tls.enabled=false` and `gateway.backendTLS.enabled=false` instead.

## WebSockets over backend TLS

With `gateway.backendTLS` on, Envoy negotiates HTTP/2 to the pod, and a
WebSocket upgrade (`/api/v1/metrics/stream`) cannot ride that hop: the client
sees `502` (`upstream_reset_before_response_started{protocol_error}`). On Envoy
Gateway, set `gateway.backendTrafficPolicy.enabled=true`; the chart renders a
`BackendTrafficPolicy` with `useClientProtocol: true`, which keeps the
upstream hop on the client's HTTP version so the upgrade returns `101`. It is
Envoy Gateway specific (it needs that project's CRDs), so it is off by default.

## Streams

Live flow and metric streams are long-lived. `gateway.requestTimeout` defaults
to `"0s"` so Envoy does not cut them at its default per-request timeout.

## Not covered

Envoy is a front door here. It is not a data-plane integration: Netra does not
read Envoy access logs or stats through this path.

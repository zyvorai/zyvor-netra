# Setura Gateway in front of Netra (Gateway API)

Netra can sit behind [Setura Gateway](https://github.com/zyvorai/zyvor-setura-gateway)
through the Kubernetes Gateway API. Any Gateway API implementation works the
same way. It is off by default and changes nothing about how Netra
authenticates: the API key, agent key and mTLS settings are the same with or
without the gateway. The gateway adds TLS termination, hostname routing and
edge policy in front of the controller.

Node agents keep talking to the `netra` Service directly; only the API/UI
goes through Setura.

## Install the gateway

The cluster needs the Gateway API CRDs and the Setura controller (GatewayClass
`setura`, controller `zyvor.dev/setura-gateway`):

```bash
setura gateway install --image ghcr.io/zyvorai/zyvor-setura-gateway:0.7.0 \
  --namespace setura-system | kubectl apply -f -
```

Then create a `Gateway` of class `setura` with an HTTPS listener (your TLS
Secret) for the hostname you want to serve. Add `--expose-gateway-ports` to the
install if the listener uses a port other than 80 or 443.

## Enable

```bash
helm upgrade --install netra ./helm/netra -n netra-system \
  --set gateway.enabled=true \
  --set 'gateway.parentRefs[0].name=setura' \
  --set 'gateway.parentRefs[0].namespace=default' \
  --set 'gateway.hostnames[0]=netra.example.com'
```

`gateway.parentRefs` is required when the gateway is enabled; the chart fails
fast without it.

## Backend TLS

The controller serves HTTPS by default, so the gateway has to verify the pod
certificate. Use a stable certificate (`tls.existingSecret`) and give the
gateway its CA:

```yaml
gateway:
  enabled: true
  parentRefs: [{name: setura, namespace: default}]
  backendTLS:
    caCertificateRefs:
      - {group: "", kind: ConfigMap, name: netra-ca}
```

The chart renders a `BackendTLSPolicy` for the `netra` Service. If a trusted
gateway terminates TLS and the hop to the pod is plain HTTP, set
`tls.enabled=false` and `gateway.backendTLS.enabled=false` instead.

## WebSockets over backend TLS

Setura handles WebSocket and other Upgrade requests itself, and Netra's live
metric stream (`/api/v1/metrics/stream`) has been run through it as the front
door. No extra policy object is needed, so the chart no longer renders the
`BackendTrafficPolicy` of Envoy Gateway (`gateway.backendTrafficPolicy` is
removed).

## Streams

Live flow and metric streams are long-lived. `gateway.requestTimeout` defaults
to `"0s"` so the gateway does not cut them at a per-request timeout.

## Metrics from Setura

Netra's application collector can scrape Setura's Prometheus endpoint with the
generic `prometheus` kind; the ready-made `apps.yaml` is in the Setura
repository (`docs/netra.md`).

## Not covered

Setura is a front door here. Edge policy that Envoy Gateway offered as separate
policy objects (rate limits, IP allow lists) is configured in Setura itself
(`--rate-limit`, auth blocks), not through this chart.

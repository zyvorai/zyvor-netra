# TLS client posture (`internal/tlsposture`)

Which TLS versions the clients on your nodes offer, per workload and SNI, from the JA4 ClientHello metadata Netra already samples. No decryption, no certificate, no payload. Read-only.

```bash
netractl insights tls-posture
```

`GET /api/v1/insights/tls-posture`. MCP: `netra_insights_tls_posture`. Console: **Network Risk**.

## What it reads

The first segment of the JA4 fingerprint (10 characters, `t13d1516h2`): the protocol (TCP, QUIC, DTLS), the **highest TLS version the client offers**, whether an SNI was sent, the cipher and extension counts and the first ALPN. See [`tls-fingerprints.md`](tls-fingerprints.md) for how Netra samples ClientHellos.

| Finding | Meaning | Severity |
|---|---|---|
| `ssl-max-version` | the client offers at most SSL 3.0 or SSL 2.0 | high |
| `legacy-max-version` | the client offers at most TLS 1.1 (or DTLS 1.0) and cannot negotiate TLS 1.2 | warning |
| `tls12-max` | the client offers TLS 1.2 and never 1.3 in the sample | info |
| `unparsed-fingerprint` | the JA4 could not be read | info |

The summary gives the version histogram, the share of hellos that offer TLS 1.3, ECH and QUIC counts and how many workloads were seen. Rows are per node, workload and SNI (lower-cased, at most 500 rows and 200 findings returned).

## What it is not

- It is the **offered** maximum, not the negotiated version. A client offering TLS 1.3 may be served 1.2 by an old server; that needs the ServerHello, which is not collected.
- No certificate (expiry, chain, self-signed, wildcard) and no cipher-suite list: Netra keeps the JA3 and JA4 hashes, the cipher and extension counts, the SNI and the ECH flag. TLS 1.3 encrypts the certificate, so a passive observer cannot read it. Products that report weak ciphers and expiring certificates (ExtraHop, Zeek, ntopng) see the server side; see [`RESEARCH-vendors-network.md`](RESEARCH-vendors-network.md).
- The fingerprints are rate-limited single-packet samples: counts are samples, and a quiet result is not proof a workload has no legacy client.
- A scoped principal sees only fingerprints from its own namespaces.

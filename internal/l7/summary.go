// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package l7

import (
	"fmt"
	"sort"

	"github.com/zyvorai/netra/internal/models"
)

// Build aggregates metadata-only L7 observations from the latest node reports.
// It never reconstructs payloads: TLS rows contain SNI only, HTTP rows contain
// method+Host only, and connection rows come from cgroup socket hooks.
func Build(agents []models.AgentStatus, limit int) models.L7ObservabilityResponse {
	if limit <= 0 {
		limit = 100
	}
	out := models.L7ObservabilityResponse{}
	sni := map[string]uint64{}
	hosts := map[string]uint64{}
	ports := map[string]uint64{}
	for _, a := range agents {
		for _, row := range a.TLSMetadata {
			out.TLS = append(out.TLS, row)
			out.Summary.TLSHandshakes += row.Handshakes
			out.Summary.TLSBlocked += row.Blocked
			sni[row.SNI] += row.Handshakes
		}
		for _, row := range a.HTTPMetadata {
			out.HTTP = append(out.HTTP, row)
			out.Summary.HTTPRequests += row.Requests
			hosts[row.Host] += row.Requests
		}
		for _, row := range a.HTTPStatus {
			out.HTTPStatus = append(out.HTTPStatus, row)
			if row.Status >= 500 {
				out.Summary.HTTP5xx += row.Count
			}
		}
		for _, row := range a.ConnectionAttempts {
			out.Connections = append(out.Connections, row)
			out.Summary.ConnectAttempts += row.Attempts
			out.Summary.ConnectBlocked += row.Blocked
			ports[fmt.Sprintf("%s/%d", row.Protocol, row.RemotePort)] += row.Attempts
		}
	}
	out.Summary.UniqueSNI = len(sni)
	out.Summary.UniqueHTTPHosts = len(hosts)
	out.Summary.TopSNI = top(sni, 15)
	out.Summary.TopHTTPHosts = top(hosts, 15)
	out.Summary.TopRemotePorts = top(ports, 15)
	sort.Slice(out.TLS, func(i, j int) bool { return out.TLS[i].Handshakes > out.TLS[j].Handshakes })
	sort.Slice(out.HTTP, func(i, j int) bool { return out.HTTP[i].Requests > out.HTTP[j].Requests })
	sort.Slice(out.HTTPStatus, func(i, j int) bool { return out.HTTPStatus[i].Count > out.HTTPStatus[j].Count })
	sort.Slice(out.Connections, func(i, j int) bool { return out.Connections[i].Attempts > out.Connections[j].Attempts })
	if len(out.TLS) > limit {
		out.TLS = out.TLS[:limit]
	}
	if len(out.HTTP) > limit {
		out.HTTP = out.HTTP[:limit]
	}
	if len(out.HTTPStatus) > limit {
		out.HTTPStatus = out.HTTPStatus[:limit]
	}
	if len(out.Connections) > limit {
		out.Connections = out.Connections[:limit]
	}
	return out
}

func top(in map[string]uint64, n int) []models.NamedCount {
	out := make([]models.NamedCount, 0, len(in))
	for k, v := range in {
		if k != "" {
			out = append(out, models.NamedCount{Name: k, Count: v})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Name < out[j].Name
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

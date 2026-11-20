// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package encdns

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestMatchDoTAndDoH(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			Stats: []models.DestinationStat{{
				DestinationIP: "1.1.1.1", Port: 853, Protocol: "TCP", Packets: 9, Namespace: "ns", Pod: "p",
			}},
			TLSMetadata: []models.TLSMetadataStat{{
				SNI: "cloudflare-dns.com", Handshakes: 2, Namespace: "ns", Pod: "p",
			}},
		},
	}}
	res := Match(agents, 50)
	if res.DoT < 1 || res.DoH < 1 {
		t.Fatalf("%+v", res)
	}
}

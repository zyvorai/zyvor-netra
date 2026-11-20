// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package appcat

import (
	"testing"

	"github.com/zyvorai/netra/internal/models"
)

func TestMatchCDN(t *testing.T) {
	agents := []models.AgentStatus{{
		AgentReport: models.AgentReport{
			Node: "n1",
			TLSMetadata: []models.TLSMetadataStat{{
				SNI: "d123.cloudfront.net", Handshakes: 4, Namespace: "ns", Pod: "p",
			}},
		},
	}}
	res := Match(agents, nil, 50)
	if res.Count != 1 || res.Hits[0].Category != CatCDN {
		t.Fatalf("%+v", res)
	}
}

func TestCatalogSuffixes(t *testing.T) {
	cases := []struct {
		host string
		cat  Category
	}{
		{"img.b-cdn.net", CatCDN},
		{"app.asana.com", CatSaaS},
		{"index.crates.io", CatDev},
		{"svc.run.app", CatCloud},
		{"api.wise.com", CatFinance},
		{"www.threads.net", CatSocial},
		{"api.linear.app", CatSaaS},
		{"xy123.snowflakecomputing.com", CatCloud},
		{"adb.databricks.com", CatCloud},
		{"app.calendly.com", CatSaaS},
		{"ghcr.io", CatDev},
		{"obj.r2.cloudflarestorage.com", CatCDN},
	}
	for _, c := range cases {
		e, ok := lookup(DefaultCatalog(), c.host)
		if !ok || e.Category != c.cat {
			t.Fatalf("%s: got %+v ok=%v want %s", c.host, e, ok, c.cat)
		}
	}
}

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package lateral

import (
	"testing"

	"github.com/zyvorai/netra/internal/scandetect"
)

func TestBuildPlaybooks(t *testing.T) {
	res := Build([]scandetect.Finding{{
		ID: "f1", Type: scandetect.FindingLateral, Severity: scandetect.SevWarning,
		Namespace: "prod", Pod: "api-1",
	}}, 10)
	if res.Count != 1 || len(res.Playbooks[0].LeaseDrafts) == 0 {
		t.Fatalf("%+v", res)
	}
}

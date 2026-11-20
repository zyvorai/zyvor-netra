// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/zyvorai/netra/internal/ebpfmaps"
)

func ebpfMapsCmd(args []string) error {
	asJSON := false
	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "-h", "--help":
			fmt.Println(`netractl ebpf maps [--json]
  Read-only inventory of datapath map contents (controller desired state).
  Human board by default; --json for the API payload.`)
			return nil
		default:
			return fmt.Errorf("unknown ebpf maps flag: %s", a)
		}
	}

	body, status, err := doRequest("GET", "/api/v1/ebpf/maps", nil, nil)
	if err != nil {
		return err
	}
	if status >= 300 {
		return fmt.Errorf("%s: %s", http.StatusText(status), string(body))
	}
	if asJSON {
		fmt.Print(string(body))
		if len(body) == 0 || body[len(body)-1] != '\n' {
			fmt.Println()
		}
		return nil
	}
	var rep ebpfmaps.Report
	if err := json.Unmarshal(body, &rep); err != nil {
		return err
	}
	maybeBanner()
	ebpfmaps.Format(os.Stdout, rep)
	return nil
}

// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0
package api

import (
	"net/http"
	"time"

	"github.com/zyvorai/netra/internal/denysim"
)

func (s *Server) ebpfDenyPreview(w http.ResponseWriter, r *http.Request) {
	var p denysim.Proposal
	if err := decodeJSON(r, &p, 1<<16); err != nil {
		errorJSON(w, 400, "invalid deny-preview body: "+err.Error())
		return
	}
	res, err := denysim.Preview(s.store.AgentStatuses(time.Now(), s.agentStaleAfter), p)
	if err != nil {
		errorJSON(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, res)
}

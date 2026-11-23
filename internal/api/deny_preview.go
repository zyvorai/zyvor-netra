// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package api

import (
	"net/http"
	"os"
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
	res.Lockout = s.denyLockout(p)
	writeJSON(w, 200, res)
}

// protectedDestinations is the controller's view of paths an operator must not
// cut: built-ins from its own environment plus NETRA_PROTECTED_DESTINATIONS.
// A malformed operator list is skipped (and reported in the lockout caveat
// by the preview) rather than failing the preview.
func protectedDestinations() ([]denysim.Protected, error) {
	conf, _ := os.ReadFile("/etc/resolv.conf")
	if len(conf) > 1<<16 {
		conf = conf[:1<<16]
	}
	out := denysim.BuiltinProtected(os.Getenv, string(conf), listenAddr())
	extra, err := denysim.ParseProtected(os.Getenv("NETRA_PROTECTED_DESTINATIONS"))
	return append(out, extra...), err
}

func (s *Server) denyLockout(p denysim.Proposal) *denysim.Lockout {
	prot, perr := protectedDestinations()
	lo, err := denysim.CheckLockout(p, prot)
	if err != nil {
		return nil
	}
	if perr != nil {
		lo.Caveat = "NETRA_PROTECTED_DESTINATIONS is invalid and was ignored (" + perr.Error() + "). " + lo.Caveat
	}
	return &lo
}

func listenAddr() string {
	if v := os.Getenv("NETRA_LISTEN"); v != "" {
		return v
	}
	return ":30870"
}

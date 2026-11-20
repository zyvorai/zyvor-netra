// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-1.0

package api

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/zyvorai/netra/internal/oidcauth"
)

// bcryptCost is the work factor for hashing service credential keys at load.
// Cost 10 keeps verify under a few ms on typical controller hardware while
// remaining expensive for offline guessing.
const bcryptCost = 10

// serviceCred is one scoped API credential loaded from
// NETRA_SERVICE_CREDENTIALS_FILE.
type serviceCred struct {
	ID         string
	Role       oidcauth.Role
	Hash       []byte // bcrypt hash
	Namespaces []string
	Clusters   []string
	Tenants    []string
}

type serviceCredFile struct {
	ID         string   `json:"id"`
	Key        string   `json:"key,omitempty"`     // plaintext; bcrypt-hashed at load
	KeyHash    string   `json:"keyHash,omitempty"` // bcrypt hash string
	Role       string   `json:"role"`
	Namespaces []string `json:"namespaces,omitempty"`
	Clusters   []string `json:"clusters,omitempty"`
	Tenants    []string `json:"tenants,omitempty"`
}

// loadServiceCreds reads a JSON array of scoped credentials. Empty path is OK.
func loadServiceCreds(path string) ([]serviceCred, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path) //nolint:gosec // operator-configured path
	if err != nil {
		return nil, err
	}
	var rows []serviceCredFile
	if err := json.Unmarshal(b, &rows); err != nil {
		return nil, fmt.Errorf("parse service credentials: %w", err)
	}
	out := make([]serviceCred, 0, len(rows))
	for i, row := range rows {
		id := strings.TrimSpace(row.ID)
		if id == "" {
			return nil, fmt.Errorf("service credentials[%d]: id is required", i)
		}
		role, err := oidcauth.ParseRole(row.Role)
		if err != nil || role == oidcauth.RoleNone {
			return nil, fmt.Errorf("service credentials[%d]: role: %w", i, err)
		}
		var hash []byte
		switch {
		case strings.TrimSpace(row.KeyHash) != "":
			hash = []byte(strings.TrimSpace(row.KeyHash))
			if _, err := bcrypt.Cost(hash); err != nil {
				return nil, fmt.Errorf("service credentials[%d]: keyHash must be a bcrypt hash: %w", i, err)
			}
		case row.Key != "":
			hash, err = bcrypt.GenerateFromPassword([]byte(row.Key), bcryptCost)
			if err != nil {
				return nil, fmt.Errorf("service credentials[%d]: hash key: %w", i, err)
			}
		default:
			return nil, fmt.Errorf("service credentials[%d]: key or keyHash is required", i)
		}
		out = append(out, serviceCred{
			ID: id, Role: role, Hash: hash,
			Namespaces: trimList(row.Namespaces),
			Clusters:   trimList(row.Clusters),
			Tenants:    trimList(row.Tenants),
		})
	}
	return out, nil
}

func trimList(in []string) []string {
	var out []string
	for _, s := range in {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) matchServiceCred(tok string) (principal, bool) {
	if s == nil || tok == "" || len(s.serviceCreds) == 0 {
		return principal{}, false
	}
	tokBytes := []byte(tok)
	for _, c := range s.serviceCreds {
		if bcrypt.CompareHashAndPassword(c.Hash, tokBytes) != nil {
			continue
		}
		return principal{
			kind:       "service",
			name:       "svc:" + c.ID,
			role:       c.Role,
			Namespaces: append([]string(nil), c.Namespaces...),
			Clusters:   append([]string(nil), c.Clusters...),
			Tenants:    append([]string(nil), c.Tenants...),
		}, true
	}
	return principal{}, false
}

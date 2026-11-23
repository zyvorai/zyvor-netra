// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: LicenseRef-Zyvor-Production-2.0
package api

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/zyvorai/netra/internal/denyset"
	"github.com/zyvorai/netra/internal/denysim"
	"github.com/zyvorai/netra/internal/leaserails"
	"github.com/zyvorai/netra/internal/store"
)

// Declarative leased-deny: plan, guarded apply, lease views and rails status.
// Plan and the lease views change nothing. Apply goes through the same
// plan-token + X-Netra-Confirm-Risk flow as the other high-blast-radius
// mutations, writes only leased rules through the store, never changes the
// mode, and is bounded by the operator's lease rails. See docs/denyset.md.

const (
	denysetBodyMax      = 128 << 10
	denysetPreviewLimit = 100
	leaseSoonWindow     = 15 * time.Minute
)

type denysetBody struct {
	File       string `json:"file"`
	PlanHash   string `json:"planHash,omitempty"`
	BreakGlass string `json:"breakGlass,omitempty"`
}

type denysetItem struct {
	denyset.Item
	Lockout *denysim.Lockout `json:"lockout,omitempty"`
	Preview *denysetPreview  `json:"preview,omitempty"`
}

type denysetPreview struct {
	HitCount     int    `json:"hitCount"`
	TotalPackets uint64 `json:"totalPackets"`
	TotalBytes   uint64 `json:"totalBytes"`
}

type denysetPlan struct {
	Name             string              `json:"name"`
	PlanHash         string              `json:"planHash"`
	Risk             string              `json:"risk"`
	Summary          map[string]int      `json:"summary"`
	Items            []denysetItem       `json:"items"`
	Rails            leaserails.Decision `json:"rails"`
	RailsEnabled     bool                `json:"railsEnabled"`
	Applicable       bool                `json:"applicable"`
	BreakGlassNeeded bool                `json:"breakGlassRequired"`
	PreviewSkipped   int                 `json:"previewSkipped,omitempty"`
	Caveat           string              `json:"caveat"`
	Receipt          any                 `json:"receipt,omitempty"`
	token            store.StateToken
	itemsRaw         []denyset.Item
	protected        map[string]bool
}

const denysetCaveat = "Plan only unless applied with a plan token: every rule is lease-bounded and removed by the controller when its lease ends; rules without a lease are never touched. Previews are observed-counter evidence (see deny-preview.md) and the lockout check is the controller's own view. Enforce stays leased and fails open; a denyset never changes the mode."

func codedError(w http.ResponseWriter, status int, code, msg string, extra map[string]any) {
	body := map[string]any{"error": msg, "code": code}
	for k, v := range extra {
		body[k] = v
	}
	writeJSON(w, status, body)
}

func denysetPlanBytes(hash string) []byte { return []byte("netra-denyset-plan:" + hash) }

func (s *Server) readDenysetBody(w http.ResponseWriter, r *http.Request) (denysetBody, *denyset.File, bool) {
	var b denysetBody
	if err := decodeJSON(r, &b, denysetBodyMax); err != nil {
		codedError(w, 400, "denyset_body_invalid", "invalid denyset body: "+err.Error(), nil)
		return b, nil, false
	}
	f, errs := denyset.Parse([]byte(b.File))
	if len(errs) > 0 {
		codedError(w, http.StatusUnprocessableEntity, "denyset_invalid", "denyset file is invalid: "+errs[0].Error(), map[string]any{"errors": errs})
		return b, nil, false
	}
	return b, f, true
}

func proposalFor(r denyset.Rule) denysim.Proposal {
	p := denysim.Proposal{Direction: r.Direction, Limit: 1}
	switch {
	case r.Type == "port":
		p.Kind, p.Value, p.Protocol = denysim.KindPort, strconv.Itoa(int(r.Port)), r.Protocol
	case r.Kind == "ip":
		p.Kind, p.Value = denysim.KindIP, strings.SplitN(r.CIDR, "/", 2)[0]
	default:
		p.Kind, p.Value = denysim.KindCIDR, r.CIDR
	}
	return p
}

// buildDenysetPlan diffs f against current leases and decorates each change
// with the self-lockout check and an observed-counter preview. It never
// mutates the store.
func (s *Server) buildDenysetPlan(f *denyset.File, who, breakGlass string) *denysetPlan {
	leases, present, tok := s.store.DenysetPlanState()
	items := denyset.Diff(f, leases, present)
	plan := &denysetPlan{Name: f.Name, PlanHash: denyset.Hash(f.Name, items), Summary: denyset.Counts(items), token: tok, itemsRaw: items, protected: map[string]bool{}, Caveat: denysetCaveat, Risk: "low"}
	prot, perr := protectedDestinations()
	agents := s.store.AgentStatuses(time.Now(), s.agentStaleAfter)
	previews := plan.Summary[denyset.ActionAdd]+plan.Summary[denyset.ActionExtend] <= denysetPreviewLimit
	for _, it := range items {
		di := denysetItem{Item: it}
		if it.Rule != nil && (it.Action == denyset.ActionAdd || it.Action == denyset.ActionExtend) {
			p := proposalFor(*it.Rule)
			if lo, err := denysim.CheckLockout(p, prot); err == nil {
				if perr != nil {
					lo.Caveat = "NETRA_PROTECTED_DESTINATIONS is invalid and was ignored. " + lo.Caveat
				}
				di.Lockout = &lo
				if lo.Risk != denysim.RiskNoneDetected {
					plan.protected[it.Type+"|"+it.Key] = true
				}
				if lo.Risk == denysim.RiskLikely {
					plan.Risk = "critical"
				}
			}
			if previews {
				if res, err := denysim.Preview(agents, p); err == nil {
					di.Preview = &denysetPreview{HitCount: res.HitCount, TotalPackets: res.TotalPackets, TotalBytes: res.TotalBytes}
				}
			} else {
				plan.PreviewSkipped++
			}
			if plan.Risk == "low" {
				plan.Risk = "high"
			}
		}
		plan.Items = append(plan.Items, di)
	}
	plan.Rails = s.store.EvaluateRails(f.Name, who, items, plan.protected, breakGlass)
	plan.RailsEnabled = s.store.LeaseRails().Enabled()
	plan.BreakGlassNeeded = plan.Rails.NeedsBreakGlass
	plan.Applicable = plan.Rails.Allowed()
	return plan
}

func (p *denysetPlan) hasChanges() bool {
	return p.Summary[denyset.ActionAdd]+p.Summary[denyset.ActionExtend]+p.Summary[denyset.ActionRemove] > 0
}

func railStatus(d leaserails.Decision) int {
	if len(d.Trips) > 0 && d.Trips[0].Code == leaserails.CodeActorRate {
		return http.StatusTooManyRequests
	}
	return http.StatusUnprocessableEntity
}

// ebpfDenysetPlan: POST /api/v1/ebpf/denysets/plan.
func (s *Server) ebpfDenysetPlan(w http.ResponseWriter, r *http.Request) {
	b, f, ok := s.readDenysetBody(w, r)
	if !ok {
		return
	}
	plan := s.buildDenysetPlan(f, actor(r), b.BreakGlass)
	s.metricsData.denysetPlans.Add(1)
	// A receipt only goes to a caller that can use it: nothing to apply, a hard
	// rail trip, or an explicit opt-out (the read-only MCP plan tool) gets none.
	if r.Header.Get("X-Netra-No-Receipt") == "" && plan.hasChanges() && (plan.Rails.Allowed() || plan.Rails.NeedsBreakGlass) {
		rcpt, err := s.store.IssuePreflight(denysetPlanBytes(plan.PlanHash), plan.Risk, actor(r), 5*time.Minute)
		if err != nil {
			if errors.Is(err, store.ErrPersistence) {
				s.metricsData.statePersistErrors.Add(1)
				errorJSON(w, http.StatusInsufficientStorage, err.Error())
			} else {
				errorJSON(w, 500, "could not issue preflight receipt")
			}
			return
		}
		plan.Receipt = rcpt
	}
	writeJSON(w, 200, plan)
}

// ebpfDenysetApply: POST /api/v1/ebpf/denysets/apply.
func (s *Server) ebpfDenysetApply(w http.ResponseWriter, r *http.Request) {
	b, f, ok := s.readDenysetBody(w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(b.PlanHash) == "" {
		codedError(w, 400, "plan_hash_required", "planHash is required; run denyset plan first", nil)
		return
	}
	who := actor(r)
	plan := s.buildDenysetPlan(f, who, b.BreakGlass)
	if b.PlanHash != plan.PlanHash {
		s.metricsData.preflightRejects.Add(1)
		codedError(w, http.StatusConflict, "plan_hash_mismatch", "the plan no longer matches the file or the current leases; plan again", map[string]any{"currentPlanHash": plan.PlanHash})
		return
	}
	if !plan.hasChanges() {
		writeJSON(w, 200, map[string]any{"name": f.Name, "planHash": plan.PlanHash, "noop": true, "added": 0, "extended": 0, "removed": 0})
		return
	}
	if !plan.Rails.Allowed() {
		s.rejectRails(w, who, f.Name, plan.Rails, true)
		return
	}
	token := strings.TrimSpace(r.Header.Get("X-Netra-Plan-Token"))
	if token == "" {
		s.metricsData.preflightRejects.Add(1)
		codedError(w, http.StatusPreconditionRequired, "plan_token_required", "a fresh preflight receipt is required; run /api/v1/ebpf/denysets/plan first", nil)
		return
	}
	risk, ok, err := s.store.ConsumePreflight(token, denysetPlanBytes(plan.PlanHash))
	if err != nil {
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, "could not persist preflight consumption: "+err.Error())
		return
	}
	if !ok {
		s.metricsData.preflightRejects.Add(1)
		codedError(w, http.StatusPreconditionFailed, "plan_token_invalid", "preflight receipt is expired, already used, or was issued for a different plan", nil)
		return
	}
	if (risk == "high" || risk == "critical") && !strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Netra-Confirm-Risk")), risk) {
		s.metricsData.preflightRejects.Add(1)
		codedError(w, 409, "risk_confirm_required", "plan risk is "+risk+"; plan again and apply with X-Netra-Confirm-Risk: "+risk, nil)
		return
	}
	res, err := s.store.ApplyDenyset(store.ApplyRequest{Owner: f.Name, Actor: who, Items: plan.itemsRaw, Protected: plan.protected, BreakGlass: b.BreakGlass, Token: plan.token})
	var re *store.RailsError
	switch {
	case errors.As(err, &re):
		s.rejectRails(w, who, f.Name, re.Decision, false)
		return
	case errors.Is(err, store.ErrStale):
		codedError(w, http.StatusConflict, "state_changed", "rules or leases changed while applying; plan again", nil)
		return
	case errors.Is(err, store.ErrPersistence):
		s.metricsData.statePersistErrors.Add(1)
		errorJSON(w, http.StatusInsufficientStorage, err.Error())
		return
	case err != nil:
		errorJSON(w, 400, err.Error())
		return
	}
	s.metricsData.denysetApplies.Add(1)
	writeJSON(w, 200, map[string]any{"name": f.Name, "planHash": plan.PlanHash, "added": res.Added, "extended": res.Extended, "removed": res.Removed, "revision": res.Revision, "breakGlass": res.Decision.BreakGlass, "caveat": denysetCaveat})
}

// rejectRails answers a rail refusal with a stable code. record is true when
// the refusal was caught before the store (so the timeline and audit log
// still get the attempt).
func (s *Server) rejectRails(w http.ResponseWriter, who, owner string, d leaserails.Decision, record bool) {
	s.metricsData.denysetRejects.Add(1)
	if record {
		if err := s.store.RecordRailReject(who, owner, d); err != nil {
			s.metricsData.statePersistErrors.Add(1)
		}
	}
	codedError(w, railStatus(d), d.Trips[0].Code, d.Trips[0].Message, map[string]any{"trips": d.Trips, "breakGlassRequired": d.NeedsBreakGlass})
}

type leaseView struct {
	Owner            string    `json:"owner"`
	Rule             string    `json:"rule"`
	Type             string    `json:"type"`
	LeaseSeconds     int64     `json:"leaseSeconds"`
	CreatedAt        time.Time `json:"createdAt"`
	CreatedBy        string    `json:"createdBy"`
	ExpiresAt        time.Time `json:"expiresAt"`
	RemainingSeconds int64     `json:"remainingSeconds"`
	Extensions       int       `json:"extensions,omitempty"`
	ExpiringSoon     bool      `json:"expiringSoon"`
}

// ebpfDenyLeases: GET /api/v1/ebpf/deny-leases?owner=&within=15m&expiring=true.
func (s *Server) ebpfDenyLeases(w http.ResponseWriter, r *http.Request) {
	within := leaseSoonWindow
	if v := r.URL.Query().Get("within"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d <= 0 || d > 24*time.Hour {
			errorJSON(w, 400, "within must be a duration between 1s and 24h")
			return
		}
		within = d
	}
	now := time.Now()
	owner := strings.TrimSpace(r.URL.Query().Get("owner"))
	onlySoon := r.URL.Query().Get("expiring") == "true"
	items := []leaseView{}
	for _, l := range s.store.DenyLeases(owner) {
		soon := l.ExpiresAt.Sub(now) <= within
		if onlySoon && !soon {
			continue
		}
		items = append(items, leaseView{Owner: l.Owner, Rule: l.Summary, Type: l.Type, LeaseSeconds: l.LeaseSeconds, CreatedAt: l.CreatedAt, CreatedBy: l.CreatedBy, ExpiresAt: l.ExpiresAt, RemainingSeconds: int64(l.ExpiresAt.Sub(now).Seconds()), Extensions: l.Extensions, ExpiringSoon: soon})
	}
	writeJSON(w, 200, map[string]any{"items": items, "now": now.UTC(), "expiringWithinSeconds": int64(within.Seconds()), "note": "Read-only. Leases belong to declarative denysets; the controller removes the rule when its lease ends."})
}

// ebpfDenyLeaseHistory: GET /api/v1/ebpf/deny-leases/history?owner=&limit=&since=.
func (s *Server) ebpfDenyLeaseHistory(w http.ResponseWriter, r *http.Request) {
	limit := 200
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			errorJSON(w, 400, "limit must be 1-1000")
			return
		}
		limit = n
	}
	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 && d <= 30*24*time.Hour {
			since = time.Now().Add(-d)
		} else if t, err := time.Parse(time.RFC3339, v); err == nil {
			since = t
		} else {
			errorJSON(w, 400, "since must be a duration up to 720h or an RFC3339 time")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"items": s.store.LeaseHistory(strings.TrimSpace(r.URL.Query().Get("owner")), since, limit), "note": "Read-only timeline of lease create, extend, expire, revoke and rail rejections, newest first. Keeps the last 1000 events and is persisted with controller state."})
}

// ebpfLeaseRails: GET /api/v1/ebpf/deny-leases/rails.
func (s *Server) ebpfLeaseRails(w http.ResponseWriter, _ *http.Request) {
	c := s.store.LeaseRails()
	out := map[string]any{
		"enabled": c.Enabled(),
		"config": map[string]any{
			"maxConcurrent": c.MaxConcurrent, "maxDuration": c.MaxDuration.String(), "maxBreadthV4": c.MaxBreadthV4, "maxBreadthV6": c.MaxBreadthV6,
			"breakGlassRequired": c.BreakGlass, "actorRate": fmt.Sprintf("%d/%s", c.RateCount, c.RateWindow),
		},
		"usage": s.store.RailsUsage(),
		"codes": leaserails.Codes,
		"note":  "Rails are off unless NETRA_LEASE_* variables are set (docs/lease-rails.md). They bound denyset lease creation and the enforce-mode lease duration; break-glass can waive only the catch-all and protected-destination rails.",
	}
	if s.leaseRailsErr != "" {
		out["configError"] = s.leaseRailsErr
	}
	writeJSON(w, 200, out)
}

// initLeaseRails loads the rail configuration from the environment. A
// malformed value is reported on the rails endpoint and in the log; the rails
// stay at their off defaults rather than guessing.
func (s *Server) initLeaseRails() {
	c, err := leaserails.ParseEnv(os.Getenv)
	if err != nil {
		s.leaseRailsErr = err.Error()
		s.log.Error("lease rails configuration ignored", "error", err)
		return
	}
	s.store.SetLeaseRails(c)
}

// railsForModeLease applies the max-duration rail to the enforce-mode lease.
// It returns false after writing the error response.
func (s *Server) railsForModeLease(w http.ResponseWriter, lease time.Duration) bool {
	c := s.store.LeaseRails()
	if c.MaxDuration > 0 && lease > c.MaxDuration {
		s.store.CountRailTrip(leaserails.CodeMaxDuration)
		codedError(w, http.StatusUnprocessableEntity, leaserails.CodeMaxDuration, fmt.Sprintf("lease %s exceeds the maximum %s", lease, c.MaxDuration), nil)
		return false
	}
	return true
}

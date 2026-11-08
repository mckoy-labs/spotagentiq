// Package inbox is the web UI and API where humans approve or reject held
// calls and read the audit trail.
package inbox

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gatekeeper-run/gatekeeper/internal/approvals"
	"github.com/gatekeeper-run/gatekeeper/internal/audit"
	"github.com/gatekeeper-run/gatekeeper/internal/policy"
)

//go:embed ui.html
var uiHTML []byte

// Server serves the inbox.
type Server struct {
	Store   *approvals.Store
	LogPath string
	Token   string
	Agent   string
	Policy  *policy.Policy
	Version string
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(uiHTML)
	})
	mux.Handle("GET /api/state", s.auth(s.handleState))
	mux.Handle("POST /api/decide", s.auth(s.handleDecide))
	mux.Handle("GET /api/log", s.auth(s.handleLog))
	mux.Handle("GET /api/verify", s.auth(s.handleVerify))
	mux.Handle("GET /api/policy", s.auth(s.handlePolicy))
	mux.Handle("GET /export.csv", s.auth(s.handleExport))
	return securityHeaders(mux)
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if tok == "" {
			tok = r.URL.Query().Get("token")
		}
		if tok == "" {
			if c, err := r.Cookie("gk_token"); err == nil {
				tok = c.Value
			}
		}
		if s.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	})
}

type stateResponse struct {
	Agent   string               `json:"agent"`
	Version string               `json:"version"`
	Now     time.Time            `json:"now"`
	Pending []*approvals.Request `json:"pending"`
	History []*approvals.Request `json:"history"`
	Recent  []audit.Entry        `json:"recent"`
	Chain   audit.VerifyResult   `json:"chain"`
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	entries, err := audit.ReadAll(s.LogPath)
	if err != nil {
		log.Printf("inbox: read log: %v", err)
	}
	recent := entries
	if len(recent) > 100 {
		recent = recent[len(recent)-100:]
	}
	// newest first
	rev := make([]audit.Entry, len(recent))
	for i, e := range recent {
		rev[len(recent)-1-i] = e
	}
	chain, _ := audit.Verify(s.LogPath)
	writeJSON(w, 200, stateResponse{
		Agent: s.Agent, Version: s.Version, Now: time.Now().UTC(),
		Pending: s.Store.Pending(), History: s.Store.History(), Recent: rev, Chain: chain,
	})
}

type decideRequest struct {
	ID       string `json:"id"`
	Decision string `json:"decision"` // approve | reject
	Approver string `json:"approver"`
	Note     string `json:"note"`
}

func (s *Server) handleDecide(w http.ResponseWriter, r *http.Request) {
	var req decideRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]any{"error": "bad json"})
		return
	}
	req.Approver = strings.TrimSpace(req.Approver)
	if req.Approver == "" {
		writeJSON(w, 400, map[string]any{"error": "approver name is required"})
		return
	}
	var status approvals.Status
	switch req.Decision {
	case "approve":
		status = approvals.StatusApproved
	case "reject":
		status = approvals.StatusRejected
	default:
		writeJSON(w, 400, map[string]any{"error": "decision must be approve or reject"})
		return
	}
	res, err := s.Store.Decide(req.ID, status, req.Approver, strings.TrimSpace(req.Note))
	if err != nil {
		code := 500
		if errors.Is(err, approvals.ErrNotFound) {
			code = 404
		}
		writeJSON(w, code, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handleLog(w http.ResponseWriter, r *http.Request) {
	entries, err := audit.ReadAll(s.LogPath)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	limit := 200
	if l, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil && l > 0 {
		limit = l
	}
	if len(entries) > limit {
		entries = entries[len(entries)-limit:]
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

func (s *Server) handleVerify(w http.ResponseWriter, _ *http.Request) {
	res, err := audit.Verify(s.LogPath)
	if err != nil {
		writeJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	writeJSON(w, 200, res)
}

func (s *Server) handlePolicy(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{"rules": s.Policy.Rules(), "default_action": s.Policy.DefaultAction()})
}

func (s *Server) handleExport(w http.ResponseWriter, r *http.Request) {
	entries, err := audit.ReadAll(s.LogPath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	// Optional ?since=RFC3339 and ?until=RFC3339 range.
	if since := r.URL.Query().Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			entries = filter(entries, func(e audit.Entry) bool { return !e.Time.Before(t) })
		}
	}
	if until := r.URL.Query().Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			entries = filter(entries, func(e audit.Entry) bool { return !e.Time.After(t) })
		}
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="gatekeeper-audit-%s.csv"`, time.Now().UTC().Format("20060102-150405")))
	if err := audit.WriteCSV(w, entries); err != nil {
		log.Printf("inbox: csv: %v", err)
	}
}

func filter(in []audit.Entry, keep func(audit.Entry) bool) []audit.Entry {
	out := in[:0:0]
	for _, e := range in {
		if keep(e) {
			out = append(out, e)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

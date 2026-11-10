// Package inbox is the web UI and API where humans approve or reject held
// calls and read the audit trail.
package inbox

import (
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/approvals"
	"github.com/mckoy-labs/spotagentiq/internal/audit"
	"github.com/mckoy-labs/spotagentiq/internal/policy"
)

//go:embed ui.html
var uiHTML []byte

// The fonts are Archivo and Martian Mono, both under the SIL Open Font
// License; the licence texts sit next to them in assets/.
//
//go:embed assets/archivo.woff2
var fontArchivo []byte

//go:embed assets/martian-mono.woff2
var fontMartianMono []byte

// uiCSP is the Content-Security-Policy for the inbox page. The page is the
// one place a person approves an agent's actions, and it displays text the
// agent chose (tool names, arguments, results). Everything is escaped, and
// this is the second line of defence: only the page's own stylesheet and
// script may run, identified by hash, so injected markup can't execute
// anything or load anything from elsewhere.
var uiCSP = func() string {
	hash := func(tag string) string {
		m := regexp.MustCompile(`(?s)<` + tag + `>(.*?)</` + tag + `>`).FindSubmatch(uiHTML)
		if m == nil {
			panic("inbox: ui.html has no <" + tag + "> block")
		}
		sum := sha256.Sum256(m[1])
		return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
	}
	return "default-src 'none'; script-src " + hash("script") + "; style-src " + hash("style") +
		"; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
}()

// Server serves the inbox.
type Server struct {
	Store   *approvals.Store
	LogPath string
	Token   string
	Agent   string
	Policy  *policy.Policy
	Version string

	guesses guessLimiter
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", uiCSP)
		w.Write(uiHTML)
	})
	font := func(b []byte) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "font/woff2")
			w.Header().Set("Cache-Control", "public, max-age=604800")
			w.Write(b)
		}
	}
	mux.HandleFunc("GET /assets/archivo.woff2", font(fontArchivo))
	mux.HandleFunc("GET /assets/martian-mono.woff2", font(fontMartianMono))
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

// auth requires the token in the Authorization header. It is deliberately not
// accepted from the query string or a cookie: a token in a URL ends up in
// proxy logs, browser history and Referer headers, and a cookie would make
// every endpoint a cross-site request forgery target.
func (s *Server) auth(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if wait := s.guesses.blockedFor(ip); wait > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many failed attempts; try again later"})
			return
		}
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || s.Token == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) != 1 {
			if s.guesses.fail(ip) {
				log.Printf("inbox: %d failed token attempts from %s; blocking it for %s", maxGuesses, ip, guessLockout)
			}
			writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "unauthorized"})
			return
		}
		next(w, r)
	})
}

// Token guessing is slowed to maxGuesses per guessWindow per client address,
// after which that address is refused for guessLockout. A 128-bit token
// can't be guessed either way; this protects short ones and keeps the log
// honest about who is trying.
const (
	maxGuesses   = 10
	guessWindow  = time.Minute
	guessLockout = 5 * time.Minute
)

type guessLimiter struct {
	mu sync.Mutex
	m  map[string]*guessState
}

type guessState struct {
	n       int
	first   time.Time
	blocked time.Time // zero unless locked out
}

func (g *guessLimiter) blockedFor(ip string) time.Duration {
	g.mu.Lock()
	defer g.mu.Unlock()
	if st, ok := g.m[ip]; ok && time.Now().Before(st.blocked) {
		return time.Until(st.blocked)
	}
	return 0
}

// fail records a wrong token and reports whether this one triggered a lockout.
func (g *guessLimiter) fail(ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := time.Now()
	if g.m == nil {
		g.m = map[string]*guessState{}
	}
	if len(g.m) > 10000 { // forget addresses that have gone quiet
		for k, st := range g.m {
			if now.Sub(st.first) > guessWindow && now.After(st.blocked) {
				delete(g.m, k)
			}
		}
	}
	st, ok := g.m[ip]
	if !ok || now.Sub(st.first) > guessWindow {
		st = &guessState{first: now}
		g.m[ip] = st
	}
	st.n++
	if st.n >= maxGuesses {
		st.blocked = now.Add(guessLockout)
		st.n, st.first = 0, now
		return true
	}
	return false
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
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="spotagentiq-audit-%s.csv"`, time.Now().UTC().Format("20060102-150405")))
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

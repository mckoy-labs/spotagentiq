package inbox

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/mckoy-labs/spotagentiq/internal/approvals"
	"github.com/mckoy-labs/spotagentiq/internal/policy"
)

func newServer(t *testing.T) http.Handler {
	t.Helper()
	pol, err := policy.Compile(nil, policy.Allow, nil)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{Store: approvals.New(nil), LogPath: filepath.Join(t.TempDir(), "audit.jsonl"), Token: "correct-horse-battery", Policy: pol}
	return s.Handler()
}

func get(h http.Handler, path, remote string, set func(*http.Request)) int {
	r := httptest.NewRequest("GET", path, nil)
	r.RemoteAddr = remote
	if set != nil {
		set(r)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}

func bearer(tok string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func TestTokenOnlyAcceptedInHeader(t *testing.T) {
	h := newServer(t)
	if c := get(h, "/api/state", "10.0.0.1:1", bearer("correct-horse-battery")); c != 200 {
		t.Fatalf("header auth: %d", c)
	}
	if c := get(h, "/api/state?token=correct-horse-battery", "10.0.0.2:1", nil); c != 401 {
		t.Errorf("token in the query string was accepted: %d", c)
	}
	if c := get(h, "/export.csv?token=correct-horse-battery", "10.0.0.2:1", nil); c != 401 {
		t.Errorf("export with token in the query string was accepted: %d", c)
	}
	if c := get(h, "/api/state", "10.0.0.3:1", func(r *http.Request) {
		r.AddCookie(&http.Cookie{Name: "gk_token", Value: "correct-horse-battery"})
	}); c != 401 {
		t.Errorf("token in a cookie was accepted: %d", c)
	}
	// Not "Bearer": the raw token as the whole header must not pass either.
	if c := get(h, "/api/state", "10.0.0.4:1", func(r *http.Request) { r.Header.Set("Authorization", "correct-horse-battery") }); c != 401 {
		t.Errorf("header without the Bearer scheme was accepted: %d", c)
	}
	if c := get(h, "/healthz", "10.0.0.5:1", nil); c != 200 {
		t.Errorf("healthz should not need a token: %d", c)
	}
}

func TestGuessingIsLockedOut(t *testing.T) {
	h := newServer(t)
	attacker, other := "203.0.113.7:5555", "198.51.100.2:5555"
	for i := 0; i < maxGuesses; i++ {
		if c := get(h, "/api/state", attacker, bearer("guess")); c != 401 {
			t.Fatalf("guess %d: %d", i+1, c)
		}
	}
	// Locked out now, even with the right token.
	if c := get(h, "/api/state", attacker, bearer("correct-horse-battery")); c != 429 {
		t.Errorf("after %d wrong guesses, want 429, got %d", maxGuesses, c)
	}
	// Someone else is unaffected.
	if c := get(h, "/api/state", other, bearer("correct-horse-battery")); c != 200 {
		t.Errorf("another address was locked out too: %d", c)
	}
	// A few mistakes by a real person don't lock them out.
	for i := 0; i < 3; i++ {
		get(h, "/api/state", other, bearer("typo"))
	}
	if c := get(h, "/api/state", other, bearer("correct-horse-battery")); c != 200 {
		t.Errorf("three typos locked a user out: %d", c)
	}
}

func TestPageIsLockedDownByCSP(t *testing.T) {
	h := newServer(t)
	r := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	csp := w.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'sha256-", "style-src 'sha256-", "frame-ancestors 'none'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP is missing %q: %s", want, csp)
		}
	}
	if strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "unsafe-eval") {
		t.Errorf("CSP must not allow unsafe-inline or unsafe-eval: %s", csp)
	}
	// The policy only works if the page never relies on what it forbids.
	page := w.Body.String()
	if m := regexp.MustCompile(`(?i)\son[a-z]+\s*=\s*["']`).FindString(page); m != "" {
		t.Errorf("inline event handler in ui.html (blocked by the CSP): %q", m)
	}
	if m := regexp.MustCompile(`(?i)\sstyle\s*=\s*["']`).FindString(page); m != "" {
		t.Errorf("inline style attribute in ui.html (blocked by the CSP): %q", m)
	}
	if n := strings.Count(page, "<script"); n != 1 {
		t.Errorf("want exactly one script block, got %d", n)
	}
	if m := regexp.MustCompile(`(?i)(src|href)\s*=\s*["']https?://|url\(\s*["']?https?://|@import`).FindString(page); m != "" {
		t.Errorf("the page must not load anything from another origin: %q", m)
	}
}

func TestFontsAreServed(t *testing.T) {
	h := newServer(t)
	for _, p := range []string{"/assets/archivo.woff2", "/assets/martian-mono.woff2"} {
		r := httptest.NewRequest("GET", p, nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Content-Type") != "font/woff2" || w.Body.Len() < 10000 || w.Body.String()[:4] != "wOF2" {
			t.Errorf("%s: %d %s %d bytes", p, w.Code, w.Header().Get("Content-Type"), w.Body.Len())
		}
	}
}

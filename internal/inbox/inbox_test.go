package inbox

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
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

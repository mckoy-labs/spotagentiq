// Package approvals holds tool calls that are waiting for a human decision.
package approvals

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"
)

// Status of a held call.
type Status string

const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusRejected Status = "rejected"
	StatusExpired  Status = "expired"
)

// Request is a tool call waiting for approval.
type Request struct {
	ID        string          `json:"id"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	Agent     string          `json:"agent"`
	Principal string          `json:"principal,omitempty"`
	Upstream  string          `json:"upstream"`
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args"` // redacted view for humans
	Reason    string          `json:"reason"`
	Rule      string          `json:"rule"`
	Status    Status          `json:"status"`
	DecidedAt *time.Time      `json:"decided_at,omitempty"`
	Approver  string          `json:"approver,omitempty"`
	Note      string          `json:"note,omitempty"`

	done chan Decision
}

// Decision is what a human (or a timeout) returned.
type Decision struct {
	Status   Status
	Approver string
	Note     string
}

// Store keeps pending and recently decided requests in memory.
type Store struct {
	mu      sync.Mutex
	reqs    map[string]*Request
	history []*Request // decided, newest last; bounded
	maxHist int
	onNew   func(*Request)
}

// New returns an empty store. onNew, if set, is called synchronously when a
// request is created (used for notifications).
func New(onNew func(*Request)) *Store {
	return &Store{reqs: map[string]*Request{}, maxHist: 500, onNew: onNew}
}

// Create registers a new pending request and returns it. The caller then
// blocks on Wait.
func (s *Store) Create(r Request, ttl time.Duration) *Request {
	r.ID = newID()
	r.CreatedAt = time.Now().UTC()
	r.ExpiresAt = r.CreatedAt.Add(ttl)
	r.Status = StatusPending
	r.done = make(chan Decision, 1)
	s.mu.Lock()
	s.reqs[r.ID] = &r
	s.mu.Unlock()
	if s.onNew != nil {
		s.onNew(&r)
	}
	return &r
}

// ErrNotFound is returned when the id is unknown or already decided.
var ErrNotFound = errors.New("approval request not found or already decided")

// Decide records a human decision and unblocks the waiting call.
func (s *Store) Decide(id string, status Status, approver, note string) (*Request, error) {
	if status != StatusApproved && status != StatusRejected {
		return nil, errors.New("decision must be approved or rejected")
	}
	s.mu.Lock()
	r, ok := s.reqs[id]
	if !ok || r.Status != StatusPending {
		s.mu.Unlock()
		return nil, ErrNotFound
	}
	now := time.Now().UTC()
	r.Status = status
	r.DecidedAt = &now
	r.Approver = approver
	r.Note = note
	delete(s.reqs, id)
	s.pushHistory(r)
	s.mu.Unlock()
	r.done <- Decision{Status: status, Approver: approver, Note: note}
	return r, nil
}

// Wait blocks until the request is decided or its deadline passes.
func (s *Store) Wait(r *Request) Decision {
	timer := time.NewTimer(time.Until(r.ExpiresAt))
	defer timer.Stop()
	select {
	case d := <-r.done:
		return d
	case <-timer.C:
		s.mu.Lock()
		if cur, ok := s.reqs[r.ID]; ok && cur.Status == StatusPending {
			now := time.Now().UTC()
			cur.Status = StatusExpired
			cur.DecidedAt = &now
			delete(s.reqs, r.ID)
			s.pushHistory(cur)
			s.mu.Unlock()
			return Decision{Status: StatusExpired}
		}
		s.mu.Unlock()
		// Decided in the race window; pick it up.
		return <-r.done
	}
}

func (s *Store) pushHistory(r *Request) {
	s.history = append(s.history, r)
	if len(s.history) > s.maxHist {
		s.history = s.history[len(s.history)-s.maxHist:]
	}
}

// Pending returns pending requests, oldest first.
func (s *Store) Pending() []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Request, 0, len(s.reqs))
	for _, r := range s.reqs {
		cp := *r
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// History returns decided requests, newest first.
func (s *Store) History() []*Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Request, 0, len(s.history))
	for i := len(s.history) - 1; i >= 0; i-- {
		cp := *s.history[i]
		out = append(out, &cp)
	}
	return out
}

func newID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "gk_" + hex.EncodeToString(b)
}

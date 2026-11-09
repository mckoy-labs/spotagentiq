// Package audit is a tamper-evident, append-only log of agent actions.
//
// Each entry carries the SHA-256 of the previous entry, so editing or deleting
// any line breaks the chain and Verify reports exactly where.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"sync"
	"time"
)

// Event types recorded in the log.
const (
	EventAllowed   = "call.allowed"   // policy let it through
	EventPending   = "call.pending"   // held for approval
	EventApproved  = "call.approved"  // human approved
	EventRejected  = "call.rejected"  // human rejected
	EventDenied    = "call.denied"    // policy blocked it
	EventTimeout   = "call.timeout"   // nobody decided in time
	EventCompleted = "call.completed" // upstream returned
	EventFailed    = "call.failed"    // upstream returned an error
	EventStartup   = "spotagentiq.start"
)

// Entry is one line in the log. Hash covers every field except Hash itself.
type Entry struct {
	Seq       int64           `json:"seq"`
	Time      time.Time       `json:"time"`
	Event     string          `json:"event"`
	CallID    string          `json:"call_id,omitempty"`
	Agent     string          `json:"agent,omitempty"`
	Principal string          `json:"principal,omitempty"` // human the agent acts for, if known
	Upstream  string          `json:"upstream,omitempty"`
	Tool      string          `json:"tool,omitempty"`
	Args      json.RawMessage `json:"args,omitempty"` // redacted
	Rule      string          `json:"rule,omitempty"`
	Reason    string          `json:"reason,omitempty"`
	Approver  string          `json:"approver,omitempty"`
	Result    string          `json:"result,omitempty"` // short summary of upstream result
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

// Log is an append-only hash-chained log backed by a JSONL file.
type Log struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	w        *bufio.Writer
	seq      int64
	lastHash string
}

// Genesis is the prev_hash of the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Open opens (or creates) the log at path and reads its tail so new entries
// continue the chain.
func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	l := &Log{path: path, f: f, w: bufio.NewWriter(f), lastHash: Genesis}
	// Read existing entries to find seq and last hash.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return nil, fmt.Errorf("audit: corrupt line after seq %d: %w", l.seq, err)
		}
		l.seq = e.Seq
		l.lastHash = e.Hash
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return nil, err
	}
	return l, nil
}

// Path returns the log file path.
func (l *Log) Path() string { return l.path }

// Append records e, filling Seq, Time (if zero), PrevHash and Hash.
func (l *Log) Append(e Entry) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq = l.seq
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	e.PrevHash = l.lastHash
	h, err := hashEntry(e)
	if err != nil {
		l.seq--
		return Entry{}, err
	}
	e.Hash = h
	b, err := json.Marshal(e)
	if err != nil {
		l.seq--
		return Entry{}, err
	}
	if _, err := l.w.Write(append(b, '\n')); err != nil {
		l.seq--
		return Entry{}, err
	}
	if err := l.w.Flush(); err != nil {
		l.seq--
		return Entry{}, err
	}
	if err := l.f.Sync(); err != nil {
		return Entry{}, err
	}
	l.lastHash = h
	return e, nil
}

// Close flushes and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.w.Flush(); err != nil {
		return err
	}
	return l.f.Close()
}

// hashEntry computes the chain hash over the entry with Hash cleared.
func hashEntry(e Entry) (string, error) {
	e.Hash = ""
	b, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// ReadAll returns every entry in the file, oldest first.
func ReadAll(path string) ([]Entry, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Entry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return out, fmt.Errorf("audit: corrupt line at seq %d: %w", len(out)+1, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// VerifyResult describes the outcome of a chain check.
type VerifyResult struct {
	Entries  int    `json:"entries"`
	OK       bool   `json:"ok"`
	BadSeq   int64  `json:"bad_seq,omitempty"`
	Problem  string `json:"problem,omitempty"`
	LastHash string `json:"last_hash,omitempty"`
}

// Verify walks the chain and reports the first break, if any.
func Verify(path string) (VerifyResult, error) {
	entries, err := ReadAll(path)
	if err != nil {
		return VerifyResult{}, err
	}
	res := VerifyResult{Entries: len(entries), OK: true, LastHash: Genesis}
	prev := Genesis
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			return VerifyResult{Entries: len(entries), BadSeq: e.Seq, Problem: fmt.Sprintf("sequence gap: expected %d got %d", i+1, e.Seq)}, nil
		}
		if e.PrevHash != prev {
			return VerifyResult{Entries: len(entries), BadSeq: e.Seq, Problem: "prev_hash does not match previous entry (line removed or reordered)"}, nil
		}
		want, err := hashEntry(e)
		if err != nil {
			return VerifyResult{}, err
		}
		if want != e.Hash {
			return VerifyResult{Entries: len(entries), BadSeq: e.Seq, Problem: "hash mismatch (entry was modified)"}, nil
		}
		prev = e.Hash
		res.LastHash = e.Hash
	}
	return res, nil
}

// WriteCSV writes entries as a CSV suitable for auditors and spreadsheets.
func WriteCSV(w io.Writer, entries []Entry) error {
	cw := csv.NewWriter(w)
	header := []string{"seq", "time_utc", "event", "call_id", "agent", "principal", "upstream", "tool", "args", "rule", "reason", "approver", "result", "prev_hash", "hash"}
	if err := cw.Write(header); err != nil {
		return err
	}
	for _, e := range entries {
		row := []string{
			strconv.FormatInt(e.Seq, 10),
			e.Time.UTC().Format(time.RFC3339),
			e.Event, cell(e.CallID), cell(e.Agent), cell(e.Principal), cell(e.Upstream), cell(e.Tool),
			cell(string(e.Args)), cell(e.Rule), cell(e.Reason), cell(e.Approver), cell(e.Result), e.PrevHash, e.Hash,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

// cell neutralises spreadsheet formulas. Tool names, arguments, results and
// approver notes are influenced by the agent and by whatever it read, and a
// value such as =HYPERLINK(...) would otherwise run when an auditor opens the
// export in Excel or Sheets. A leading apostrophe makes the cell plain text.
// The JSONL log is untouched; verify hashes against that, not the CSV.
func cell(v string) string {
	if v == "" {
		return v
	}
	switch v[0] {
	case '=', '+', '-', '@', 0x09, 0x0d: // 0x09 tab, 0x0d carriage return
		return "'" + v
	}
	return v
}

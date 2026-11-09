package audit

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChainAppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if _, err := l.Append(Entry{Event: EventAllowed, Tool: "t", Args: json.RawMessage(`{"i":` + string(rune('0'+i)) + `}`)}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK || res.Entries != 5 {
		t.Fatalf("verify: %+v", res)
	}

	// Reopen and continue the chain.
	l2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	e, err := l2.Append(Entry{Event: EventDenied, Tool: "u"})
	if err != nil {
		t.Fatal(err)
	}
	l2.Close()
	if e.Seq != 6 {
		t.Errorf("seq after reopen: %d", e.Seq)
	}
	res, _ = Verify(path)
	if !res.OK || res.Entries != 6 {
		t.Fatalf("verify after reopen: %+v", res)
	}
}

func TestVerifyDetectsModification(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(path)
	for i := 0; i < 3; i++ {
		l.Append(Entry{Event: EventAllowed, Tool: "safe_tool"})
	}
	l.Close()

	b, _ := os.ReadFile(path)
	tampered := bytes.Replace(b, []byte(`"tool":"safe_tool"`), []byte(`"tool":"evil_tool"`), 1)
	os.WriteFile(path, tampered, 0o600)

	res, err := Verify(path)
	if err != nil {
		t.Fatal(err)
	}
	if res.OK || res.BadSeq != 1 || !strings.Contains(res.Problem, "modified") {
		t.Fatalf("tamper not detected: %+v", res)
	}
}

func TestVerifyDetectsDeletedLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "a.jsonl")
	l, _ := Open(path)
	for i := 0; i < 3; i++ {
		l.Append(Entry{Event: EventAllowed})
	}
	l.Close()

	b, _ := os.ReadFile(path)
	lines := bytes.Split(bytes.TrimSpace(b), []byte("\n"))
	// Drop the middle line.
	out := append(append([]byte{}, lines[0]...), '\n')
	out = append(out, append(lines[2], '\n')...)
	os.WriteFile(path, out, 0o600)

	res, _ := Verify(path)
	if res.OK || res.BadSeq != 3 {
		t.Fatalf("deletion not detected: %+v", res)
	}
}

func TestCSV(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCSV(&buf, []Entry{{Seq: 1, Event: EventApproved, Tool: "send_email", Args: json.RawMessage(`{"to":"a@b"}`), Approver: "Jordan"}})
	if err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	if !strings.HasPrefix(s, "seq,time_utc,event") || !strings.Contains(s, "send_email") || !strings.Contains(s, "Jordan") {
		t.Errorf("csv: %s", s)
	}
}

func TestVerifyMissingFile(t *testing.T) {
	res, err := Verify(filepath.Join(t.TempDir(), "nope.jsonl"))
	if err != nil || !res.OK || res.Entries != 0 {
		t.Fatalf("missing file should verify as empty: %+v %v", res, err)
	}
}

// Text an agent can influence must not become a live spreadsheet formula.
func TestCSVNeutralisesFormulas(t *testing.T) {
	var buf bytes.Buffer
	err := WriteCSV(&buf, []Entry{{
		Seq: 1, Event: EventCompleted, Tool: "=cmd|' /C calc'!A0", Reason: "+SUM(1,1)", Approver: "@evil",
		Result: "-2+3", Args: json.RawMessage(`{"ok":true}`), Hash: "abc",
	}})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(&buf).ReadAll()
	if err != nil || len(rows) != 2 {
		t.Fatalf("csv: %v %d rows", err, len(rows))
	}
	col := map[string]string{}
	for i, name := range rows[0] {
		col[name] = rows[1][i]
	}
	for _, name := range []string{"tool", "reason", "approver", "result"} {
		if !strings.HasPrefix(col[name], "'") {
			t.Errorf("%s = %q, want a leading apostrophe", name, col[name])
		}
	}
	if col["args"] != `{"ok":true}` || col["hash"] != "abc" {
		t.Errorf("ordinary cells changed: args=%q hash=%q", col["args"], col["hash"])
	}
}

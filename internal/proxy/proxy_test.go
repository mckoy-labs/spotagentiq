package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gatekeeper-run/gatekeeper/internal/approvals"
	"github.com/gatekeeper-run/gatekeeper/internal/audit"
	"github.com/gatekeeper-run/gatekeeper/internal/config"
	"github.com/gatekeeper-run/gatekeeper/internal/demo"
	"github.com/gatekeeper-run/gatekeeper/internal/jsonrpc"
	"github.com/gatekeeper-run/gatekeeper/internal/policy"
)

// TestHelperUpstream is not a test: when GK_HELPER_UPSTREAM=1 the test binary
// re-executes itself as the fake CRM MCP server.
func TestHelperUpstream(t *testing.T) {
	if os.Getenv("GK_HELPER_UPSTREAM") != "1" {
		return
	}
	if err := demo.RunUpstream(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

type harness struct {
	t      *testing.T
	conn   *jsonrpc.Conn
	store  *approvals.Store
	log    string
	nextID int
	done   chan error
}

func newHarness(t *testing.T, upstreams int, rules []policy.Rule, def policy.Action, timeout string) *harness {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "audit.jsonl")
	cfg := &config.Config{Agent: "test-agent", Listen: "", Token: "", LogPath: logPath, ApprovalTimeout: timeout, DefaultAction: def, Rules: rules, Redact: []string{"card_number"}}
	for i := 0; i < upstreams; i++ {
		cfg.Upstreams = append(cfg.Upstreams, config.Upstream{
			Name: fmt.Sprintf("crm%d", i), Command: os.Args[0], Args: []string{"-test.run=TestHelperUpstream"},
			Env: map[string]string{"GK_HELPER_UPSTREAM": "1"},
		})
	}
	pol, err := policy.Compile(cfg.Rules, cfg.DefaultAction, cfg.Redact)
	if err != nil {
		t.Fatal(err)
	}
	lg, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	store := approvals.New(nil)

	clientR, proxyW := io.Pipe()
	proxyR, clientW := io.Pipe()
	p := New(cfg, pol, lg, store, proxyR, proxyW)
	done := make(chan error, 1)
	go func() { done <- p.Run(context.Background()); lg.Close() }()
	t.Cleanup(func() { clientW.Close(); <-done })

	h := &harness{t: t, conn: jsonrpc.NewConn(clientR, clientW), store: store, log: logPath, done: done}
	res := h.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t", "version": "0"}})
	if res.Error != nil {
		t.Fatalf("initialize: %v", res.Error)
	}
	n, _ := jsonrpc.NewNotification("notifications/initialized", nil)
	h.conn.Write(n)
	return h
}

func (h *harness) call(method string, params any) *jsonrpc.Message {
	h.t.Helper()
	h.nextID++
	req, _ := jsonrpc.NewRequest(h.nextID, method, params)
	if err := h.conn.Write(req); err != nil {
		h.t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for {
		type res struct {
			m   *jsonrpc.Message
			err error
		}
		ch := make(chan res, 1)
		go func() { m, err := h.conn.Read(); ch <- res{m, err} }()
		select {
		case r := <-ch:
			if r.err != nil {
				h.t.Fatal(r.err)
			}
			if r.m.IsResponse() && string(r.m.ID) == fmt.Sprint(h.nextID) {
				return r.m
			}
		case <-deadline:
			h.t.Fatalf("timeout waiting for %s", method)
		}
	}
}

func (h *harness) callTool(name string, args map[string]any) (text string, isErr bool) {
	h.t.Helper()
	m := h.call("tools/call", map[string]any{"name": name, "arguments": args})
	if m.Error != nil {
		h.t.Fatalf("tools/call %s: protocol error %v", name, m.Error)
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct{ Text string } `json:"content"`
	}
	json.Unmarshal(m.Result, &r)
	var sb strings.Builder
	for _, c := range r.Content {
		sb.WriteString(c.Text)
	}
	return sb.String(), r.IsError
}

func (h *harness) toolNames() []string {
	m := h.call("tools/list", map[string]any{})
	var r struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	json.Unmarshal(m.Result, &r)
	var out []string
	for _, t := range r.Tools {
		out = append(out, t.Name)
	}
	return out
}

func (h *harness) events() []string {
	entries, err := audit.ReadAll(h.log)
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Event)
	}
	return out
}

var standardRules = []policy.Rule{
	{Match: "*", Action: policy.Deny, IfArgsMatch: `\b\d{13,19}\b`, Reason: "card number"},
	{Match: "send_*", Action: policy.RequireApproval, Reason: "outbound"},
	{Match: "delete_*", Action: policy.RequireApproval, Reason: "destructive"},
}

func TestAllowPassesThrough(t *testing.T) {
	h := newHarness(t, 1, standardRules, policy.Allow, "5s")
	names := h.toolNames()
	if len(names) != 4 || names[0] != "get_customer" {
		t.Fatalf("tools: %v", names)
	}
	text, isErr := h.callTool("get_customer", map[string]any{"id": "c1"})
	if isErr || !strings.Contains(text, "Marisol") {
		t.Fatalf("get_customer: %q err=%v", text, isErr)
	}
	ev := h.events()
	if ev[len(ev)-2] != audit.EventAllowed || ev[len(ev)-1] != audit.EventCompleted {
		t.Fatalf("events: %v", ev)
	}
}

func TestDenyBlocksAndRedacts(t *testing.T) {
	h := newHarness(t, 1, standardRules, policy.Allow, "5s")
	text, isErr := h.callTool("charge_card", map[string]any{"customer_id": "c1", "amount": 1, "card_number": "4242424242424242"})
	if !isErr || !strings.Contains(text, "Blocked by Gatekeeper") || !strings.Contains(text, "card number") {
		t.Fatalf("deny result: %q err=%v", text, isErr)
	}
	entries, _ := audit.ReadAll(h.log)
	last := entries[len(entries)-1]
	if last.Event != audit.EventDenied {
		t.Fatalf("last event %s", last.Event)
	}
	if strings.Contains(string(last.Args), "4242") {
		t.Fatalf("card number leaked into log: %s", last.Args)
	}
}

func TestApprovalFlow(t *testing.T) {
	h := newHarness(t, 1, standardRules, policy.Allow, "10s")

	type result struct {
		text  string
		isErr bool
	}
	got := make(chan result, 1)
	go func() {
		txt, e := h.callTool("send_email", map[string]any{"to": "a@b.c", "subject": "hi", "body": "x"})
		got <- result{txt, e}
	}()

	// Wait for it to show up as pending.
	var pending []*approvals.Request
	for i := 0; i < 100 && len(pending) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		pending = h.store.Pending()
	}
	if len(pending) != 1 || pending[0].Tool != "send_email" || pending[0].Reason != "outbound" {
		t.Fatalf("pending: %+v", pending)
	}
	if _, err := h.store.Decide(pending[0].ID, approvals.StatusApproved, "Jordan", "looks fine"); err != nil {
		t.Fatal(err)
	}
	r := <-got
	if r.isErr || !strings.Contains(r.text, "Email sent") {
		t.Fatalf("approved call: %q err=%v", r.text, r.isErr)
	}
	ev := h.events()
	want := []string{audit.EventPending, audit.EventApproved, audit.EventCompleted}
	if !strings.HasSuffix(strings.Join(ev, ","), strings.Join(want, ",")) {
		t.Fatalf("events: %v", ev)
	}
	entries, _ := audit.ReadAll(h.log)
	if entries[len(entries)-2].Approver != "Jordan" {
		t.Fatalf("approver not recorded: %+v", entries[len(entries)-2])
	}
}

func TestRejectionFlow(t *testing.T) {
	h := newHarness(t, 1, standardRules, policy.Allow, "10s")
	got := make(chan string, 1)
	go func() {
		txt, isErr := h.callTool("delete_record", map[string]any{"table": "customers", "id": "c1"})
		if !isErr {
			txt = "NOT-AN-ERROR:" + txt
		}
		got <- txt
	}()
	var pending []*approvals.Request
	for i := 0; i < 100 && len(pending) == 0; i++ {
		time.Sleep(20 * time.Millisecond)
		pending = h.store.Pending()
	}
	if _, err := h.store.Decide(pending[0].ID, approvals.StatusRejected, "Jordan", "no way"); err != nil {
		t.Fatal(err)
	}
	txt := <-got
	if !strings.Contains(txt, "Rejected") || !strings.Contains(txt, "no way") || strings.HasPrefix(txt, "NOT-AN-ERROR") {
		t.Fatalf("rejected result: %q", txt)
	}
	if ev := h.events(); ev[len(ev)-1] != audit.EventRejected {
		t.Fatalf("events: %v", ev)
	}
	if len(h.store.History()) != 1 || h.store.History()[0].Status != approvals.StatusRejected {
		t.Fatalf("history: %+v", h.store.History())
	}
}

func TestApprovalTimeout(t *testing.T) {
	h := newHarness(t, 1, standardRules, policy.Allow, "300ms")
	txt, isErr := h.callTool("send_email", map[string]any{"to": "a", "subject": "b", "body": "c"})
	if !isErr || !strings.Contains(txt, "within the allowed time") {
		t.Fatalf("timeout result: %q err=%v", txt, isErr)
	}
	if ev := h.events(); ev[len(ev)-1] != audit.EventTimeout {
		t.Fatalf("events: %v", ev)
	}
}

func TestTwoUpstreamsPrefixCollisions(t *testing.T) {
	h := newHarness(t, 2, []policy.Rule{{Match: "crm1/*", Action: policy.Deny, Reason: "crm1 is read-only"}}, policy.Allow, "5s")
	names := h.toolNames()
	if len(names) != 8 {
		t.Fatalf("expected 8 tools, got %v", names)
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "crm0__") && !strings.HasPrefix(n, "crm1__") {
			t.Fatalf("unprefixed collision: %s", n)
		}
	}
	if txt, isErr := h.callTool("crm0__get_customer", map[string]any{"id": "x"}); isErr || !strings.Contains(txt, "Marisol") {
		t.Fatalf("crm0 call: %q %v", txt, isErr)
	}
	if txt, isErr := h.callTool("crm1__get_customer", map[string]any{"id": "x"}); !isErr || !strings.Contains(txt, "read-only") {
		t.Fatalf("crm1 should be denied by scoped rule: %q %v", txt, isErr)
	}
}

func TestUnknownToolIsAnError(t *testing.T) {
	h := newHarness(t, 1, nil, policy.Allow, "5s")
	m := h.call("tools/call", map[string]any{"name": "nope", "arguments": map[string]any{}})
	if m.Error == nil || m.Error.Code != jsonrpc.CodeInvalidParams {
		t.Fatalf("expected invalid params, got %+v", m)
	}
}

func TestChainIntactAfterSession(t *testing.T) {
	h := newHarness(t, 1, standardRules, policy.Allow, "5s")
	h.callTool("get_customer", map[string]any{"id": "1"})
	h.callTool("charge_card", map[string]any{"card_number": "4242424242424242"})
	res, err := audit.Verify(h.log)
	if err != nil || !res.OK || res.Entries < 4 {
		t.Fatalf("verify: %+v %v", res, err)
	}
}

package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/mckoy-labs/spotagentiq/internal/audit"
	"github.com/mckoy-labs/spotagentiq/internal/config"
	"github.com/mckoy-labs/spotagentiq/internal/jsonrpc"
	"github.com/mckoy-labs/spotagentiq/internal/policy"
)

// TestHelperProbe is not a test: when GK_HELPER_PROBE=1 the test binary
// re-executes itself as an MCP server that reports exactly what reached it.
//
//	echo            returns the raw bytes of its arguments
//	env             returns its environment
//	billing/charge  a tool with a slash in its name
//	resources/read  returns a "secret" document
func TestHelperProbe(t *testing.T) {
	if os.Getenv("GK_HELPER_PROBE") != "1" {
		return
	}
	conn := jsonrpc.NewConn(os.Stdin, os.Stdout)
	reply := func(id json.RawMessage, v any) {
		m, _ := jsonrpc.NewResult(id, v)
		_ = conn.Write(m)
	}
	text := func(s string) map[string]any {
		return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
	}
	obj := map[string]any{"type": "object"}
	for {
		m, err := conn.Read()
		if err != nil {
			os.Exit(0)
		}
		if !m.IsRequest() {
			continue
		}
		switch m.Method {
		case "initialize":
			reply(m.ID, map[string]any{"protocolVersion": "2025-06-18", "serverInfo": map[string]any{"name": "probe", "version": "0"},
				"capabilities": map[string]any{"tools": map[string]any{}, "resources": map[string]any{}}})
		case "tools/list":
			reply(m.ID, map[string]any{"tools": []map[string]any{
				{"name": "echo", "inputSchema": obj}, {"name": "env", "inputSchema": obj}, {"name": "billing/charge", "inputSchema": obj},
			}})
		case "tools/call":
			var p struct {
				Name      string          `json:"name"`
				Arguments json.RawMessage `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			switch p.Name {
			case "echo":
				reply(m.ID, text(string(p.Arguments)))
			case "env":
				reply(m.ID, text(strings.Join(os.Environ(), "\n")))
			default:
				reply(m.ID, text("ran "+p.Name))
			}
		case "resources/read":
			reply(m.ID, map[string]any{"contents": []map[string]any{{"uri": "file:///secret.txt", "text": "secret-data"}}})
		default:
			_ = conn.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not found: "+m.Method))
		}
	}
}

func probeUpstream(name string) config.Upstream {
	return config.Upstream{Name: name, Command: os.Args[0], Args: []string{"-test.run=TestHelperProbe"}, Env: map[string]string{"GK_HELPER_PROBE": "1"}}
}

func probeHarness(t *testing.T, rules []policy.Rule, def policy.Action) *harness {
	return newHarnessWith(t, &config.Config{Upstreams: []config.Upstream{probeUpstream("probe")}, Rules: rules, DefaultAction: def, ApprovalTimeout: "300ms"})
}

// rawTool sends a tools/call whose params are exact bytes, so tests control
// escapes, key order and duplicate keys.
func (h *harness) rawTool(params string) (text string, isErr bool) {
	h.t.Helper()
	m := h.call("tools/call", json.RawMessage(params))
	if m.Error != nil {
		h.t.Fatalf("tools/call %s: protocol error %v", params, m.Error)
	}
	var r struct {
		IsError bool                    `json:"isError"`
		Content []struct{ Text string } `json:"content"`
	}
	json.Unmarshal(m.Result, &r)
	var sb strings.Builder
	for _, c := range r.Content {
		sb.WriteString(c.Text)
	}
	return sb.String(), r.IsError
}

var backslash = string(rune(92))

// The upstream receives the canonical document policy evaluated, not the
// client's bytes.
func TestUpstreamReceivesCanonicalArguments(t *testing.T) {
	h := probeHarness(t, nil, policy.Allow)
	got, isErr := h.rawTool(`{"name":"echo","arguments":{ "b" : 1, "a":"x", "a":"last", "s":"` + backslash + `u0041" }}`)
	if want := `{"a":"last","b":1,"s":"A"}`; isErr || got != want {
		t.Fatalf("upstream got %s, want %s", got, want)
	}
	// Arguments that are not an object never reach policy or the upstream.
	if m := h.call("tools/call", json.RawMessage(`{"name":"echo","arguments":[1,2]}`)); m.Error == nil {
		t.Fatal("array arguments should be rejected")
	}
}

func TestEscapedCardNumberIsDenied(t *testing.T) {
	h := probeHarness(t, []policy.Rule{{Match: "*", Action: policy.Deny, IfArgsMatch: `\b\d{13,19}\b`, Reason: "card number"}}, policy.Allow)
	text, isErr := h.rawTool(`{"name":"echo","arguments":{"card":"4242424` + backslash + `u003242424242"}}`)
	if !isErr || !strings.Contains(text, "card number") {
		t.Fatalf("escaped card number got through: %q", text)
	}
}

// A duplicate key or a decoy can't turn an outside recipient into an allowed one.
func TestRecipientCannotBeSmuggledPastAllowRule(t *testing.T) {
	rules := []policy.Rule{
		{Match: "echo", Action: policy.Allow, Where: map[string]string{"to": `^[^@\s]+@yourcompany\.com$`}},
		{Match: "echo", Action: policy.RequireApproval, Reason: "outside recipient"},
	}
	h := probeHarness(t, rules, policy.Allow)
	if text, isErr := h.rawTool(`{"name":"echo","arguments":{"to":"a@yourcompany.com"}}`); isErr {
		t.Fatalf("legitimate call was held: %s", text)
	}
	for _, args := range []string{
		`{"to":"a@yourcompany.com","to":"thief@evil.com"}`,
		`{"to":"thief@evil.com","x":{"to":"a@yourcompany.com"}}`,
		`{"to":"thief@evil.com","note":"to: a@yourcompany.com"}`,
	} {
		text, isErr := h.rawTool(`{"name":"echo","arguments":` + args + `}`)
		if !isErr || !strings.Contains(text, "No human approved") {
			t.Errorf("%s reached the tool: %q", args, text)
		}
	}
}

func TestStarRuleCoversToolsWithSlashes(t *testing.T) {
	h := probeHarness(t, []policy.Rule{{Match: "*", Action: policy.Deny, IfArgsMatch: `\b\d{13,19}\b`, Reason: "card number"}}, policy.Allow)
	text, isErr := h.rawTool(`{"name":"billing/charge","arguments":{"card":"4242424242424242"}}`)
	if !isErr || !strings.Contains(text, "Blocked by SpotAgentIQ") {
		t.Fatalf("billing/charge ran: %q", text)
	}
}

// Upstreams must not see the inbox token or anything else from our environment.
func TestUpstreamEnvironment(t *testing.T) {
	t.Setenv("SPOTAGENTIQ_TOKEN", "tok-secret")
	t.Setenv("TOKEN_UNDER_ANOTHER_NAME", "tok-secret")
	t.Setenv("OTHER_SERVERS_API_KEY", "sk_other")

	minimal, inherit := probeUpstream("minimal"), probeUpstream("inherit")
	minimal.Env["ITS_OWN_KEY"] = "mine"
	inherit.InheritEnv = true
	h := newHarnessWith(t, &config.Config{Token: "tok-secret", Upstreams: []config.Upstream{minimal, inherit}, DefaultAction: policy.Allow, ApprovalTimeout: "1s"})

	env, _ := h.rawTool(`{"name":"minimal__env","arguments":{}}`)
	if !strings.Contains(env, "ITS_OWN_KEY=mine") || !strings.Contains(strings.ToUpper(env), "PATH=") {
		t.Errorf("minimal upstream is missing its own env or PATH")
	}
	for _, leak := range []string{"tok-secret", "sk_other", "SPOTAGENTIQ_TOKEN"} {
		if strings.Contains(env, leak) {
			t.Errorf("minimal upstream can see %q", leak)
		}
	}
	env, _ = h.rawTool(`{"name":"inherit__env","arguments":{}}`)
	if !strings.Contains(env, "OTHER_SERVERS_API_KEY=sk_other") {
		t.Errorf("inherit_env upstream should get the full environment")
	}
	if strings.Contains(env, "tok-secret") {
		t.Errorf("inherit_env upstream can see the inbox token")
	}
}

func auditEntries(t *testing.T, h *harness, tool string) []audit.Entry {
	t.Helper()
	all, err := audit.ReadAll(h.log)
	if err != nil {
		t.Fatal(err)
	}
	var out []audit.Entry
	for _, e := range all {
		if e.Tool == tool {
			out = append(out, e)
		}
	}
	return out
}

// resources/read used to pass straight through, unseen and unlogged.
func TestResourceReadsGoThroughPolicyAndLog(t *testing.T) {
	h := probeHarness(t, nil, policy.Allow)
	m := h.call("resources/read", map[string]any{"uri": "file:///secret.txt"})
	if m.Error != nil || !strings.Contains(string(m.Result), "secret-data") {
		t.Fatalf("allowed read failed: %v %s", m.Error, m.Result)
	}
	es := auditEntries(t, h, "resources/read")
	if len(es) != 2 || es[0].Event != audit.EventAllowed || es[1].Event != audit.EventCompleted || es[0].Upstream != config.ReservedUpstream {
		t.Fatalf("audit entries for an allowed read: %+v", es)
	}
	if !strings.Contains(string(es[0].Args), "secret.txt") {
		t.Errorf("the uri should be logged: %s", es[0].Args)
	}

	for _, match := range []string{"mcp/resources/read", "mcp/*", "*"} {
		h := probeHarness(t, []policy.Rule{{Match: match, Action: policy.Deny, Reason: "no reads"}}, policy.Allow)
		m := h.call("resources/read", map[string]any{"uri": "file:///secret.txt"})
		if m.Error == nil || m.Error.Code != codeBlocked || strings.Contains(string(m.Result), "secret-data") {
			t.Errorf("rule %q did not block the read: %v %s", match, m.Error, m.Result)
		}
		if es := auditEntries(t, h, "resources/read"); len(es) != 1 || es[0].Event != audit.EventDenied {
			t.Errorf("rule %q: audit entries %+v", match, es)
		}
	}

	// Under a locked-down default, a read waits for a person like anything else.
	h = probeHarness(t, nil, policy.RequireApproval)
	if m := h.call("resources/read", map[string]any{"uri": "file:///secret.txt"}); m.Error == nil || !strings.Contains(m.Error.Message, "No human approved") {
		t.Errorf("read under require_approval: %v %s", m.Error, m.Result)
	}
	// Listing what exists stays open.
	if m := h.call("resources/list", map[string]any{}); m.Error != nil {
		t.Errorf("resources/list should not be gated: %v", m.Error)
	}
}

// If the decision can't be recorded, the call must not run.
func TestFailsClosedWhenAuditLogIsUnwritable(t *testing.T) {
	h := probeHarness(t, nil, policy.Allow)
	if text, isErr := h.rawTool(`{"name":"echo","arguments":{"n":1}}`); isErr || text != `{"n":1}` {
		t.Fatalf("baseline call failed: %q", text)
	}
	h.audit.Close() // every later write fails, as with a full disk
	text, isErr := h.rawTool(`{"name":"echo","arguments":{"n":2}}`)
	if !isErr || !strings.Contains(text, "audit log") || strings.Contains(text, `"n":2`) {
		t.Fatalf("call ran without an audit record: %q", text)
	}
	if m := h.call("resources/read", map[string]any{"uri": "file:///secret.txt"}); m.Error == nil || strings.Contains(fmt.Sprint(string(m.Result)), "secret-data") {
		t.Fatalf("resource read ran without an audit record: %s", m.Result)
	}
}

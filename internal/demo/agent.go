package demo

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/jsonrpc"
)

// DemoConfig is written to disk and handed to `spotagentiq serve` by RunAgent.
func DemoConfig(selfBinary, logPath, token string, listen string) string {
	cfg := map[string]any{
		"agent":            "support-bot",
		"principal":        "jordan@acme.example",
		"listen":           listen,
		"token":            token,
		"log_path":         logPath,
		"approval_timeout": "10m",
		"default_action":   "allow",
		"upstreams": []map[string]any{
			{"name": "crm", "command": selfBinary, "args": []string{"demo-upstream"}},
		},
		"rules": []map[string]any{
			{"match": "*", "action": "deny", "if_args_match": `\b\d{13,19}\b`, "reason": "Argument looks like a card number"},
			{"match": "send_*", "action": "require_approval", "reason": "Outbound customer communication"},
			{"match": "delete_*", "action": "require_approval", "reason": "Destructive, irreversible"},
			{"match": "charge_*", "action": "require_approval", "reason": "Moves money"},
			{"match": "get_*", "action": "allow"},
		},
		"redact": []string{"card_number", "password", "token", "ssn"},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return string(b)
}

// RunAgent plays the part of an AI agent talking to SpotAgentIQ over MCP. It
// starts `spotagentiq serve` with a demo config, then makes a sequence of tool
// calls that exercise allow, deny and require_approval.
func RunAgent(selfBinary string, listen string) error {
	dir, err := os.MkdirTemp("", "spotagentiq-demo-*")
	if err != nil {
		return err
	}
	token := "demo-token"
	logPath := filepath.Join(dir, "audit.jsonl")
	cfgPath := filepath.Join(dir, "spotagentiq.json")
	if err := os.WriteFile(cfgPath, []byte(DemoConfig(selfBinary, logPath, token, listen)), 0o600); err != nil {
		return err
	}

	host := listen
	if strings.HasPrefix(host, ":") {
		host = "localhost" + host
	}
	url := "http://" + host

	say("")
	say("┌──────────────────────────────────────────────────────────────┐")
	say("│  SPOTAGENTIQ DEMO                                             │")
	say("│  An agent is about to use a CRM through SpotAgentIQ.          │")
	say("└──────────────────────────────────────────────────────────────┘")
	say("")
	say("  Inbox:  %s   (token: %s)", url, token)
	say("  Log:    %s", logPath)
	say("  Config: %s", cfgPath)
	say("")

	cmd := exec.Command(selfBinary, "serve", "--config", cfgPath)
	cmd.Stderr = os.Stderr
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return err
	}
	defer func() { _ = stdin.Close(); _ = cmd.Wait() }()
	conn := jsonrpc.NewConn(stdout, stdin)
	ctx := context.Background()
	var id int

	call := func(method string, params any) (*jsonrpc.Message, error) {
		id++
		req, _ := jsonrpc.NewRequest(id, method, params)
		if err := conn.Write(req); err != nil {
			return nil, err
		}
		for {
			m, err := conn.Read()
			if err != nil {
				return nil, err
			}
			if m.IsResponse() && string(m.ID) == fmt.Sprint(id) {
				return m, nil
			}
			if m.IsNotification() && m.Method == "notifications/progress" {
				var p struct{ Message string }
				_ = json.Unmarshal(m.Params, &p)
				say("      ⏳ %s", p.Message)
			}
		}
	}
	_ = ctx

	step(1, "Agent connects to SpotAgentIQ (initialize)")
	if _, err := call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "demo-agent", "version": "1"}}); err != nil {
		return err
	}
	n, _ := jsonrpc.NewNotification("notifications/initialized", nil)
	_ = conn.Write(n)

	step(2, "Agent lists the tools it can see")
	resp, err := call("tools/list", map[string]any{})
	if err != nil {
		return err
	}
	var tl struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	_ = json.Unmarshal(resp.Result, &tl)
	names := make([]string, 0, len(tl.Tools))
	for _, t := range tl.Tools {
		names = append(names, t.Name)
	}
	say("      → %s", strings.Join(names, ", "))

	step(3, "Agent reads a customer  (policy: allow → passes straight through)")
	show(call("tools/call", toolCall("get_customer", map[string]any{"id": "cus_1042"}, id+1)))

	step(4, "Agent tries to charge a card it pasted in  (policy: deny → blocked, logged)")
	show(call("tools/call", toolCall("charge_card", map[string]any{"customer_id": "cus_1042", "amount": 129, "card_number": "4242424242424242"}, id+1)))

	step(5, "Agent wants to email the customer  (policy: require_approval → HELD)")
	say("")
	say("      ▶ Open %s and approve or reject this call.", url)
	say("")
	show(call("tools/call", toolCall("send_email", map[string]any{
		"to": "marisol@example.com", "subject": "Your invoice is 30 days overdue",
		"body": "Hi Marisol, your balance of $129 is overdue. Reply to arrange payment."}, id+1)))

	step(6, "Agent wants to delete the customer record  (policy: require_approval → HELD)")
	say("")
	say("      ▶ Back to %s — try rejecting this one.", url)
	say("")
	show(call("tools/call", toolCall("delete_record", map[string]any{"table": "customers", "id": "cus_1042"}, id+1)))

	say("")
	say("  Done. Every step above is in the audit log, hash-chained:")
	say("      %s verify --log %s", selfBinary, logPath)
	say("  Or export it as CSV from the inbox.")
	say("")
	return nil
}

func toolCall(name string, args map[string]any, progressToken int) map[string]any {
	return map[string]any{"name": name, "arguments": args, "_meta": map[string]any{"progressToken": progressToken}}
}

func show(m *jsonrpc.Message, err error) {
	if err != nil {
		say("      ✗ transport error: %v", err)
		return
	}
	if m.Error != nil {
		say("      ✗ error %d: %s", m.Error.Code, m.Error.Message)
		return
	}
	var r struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	_ = json.Unmarshal(m.Result, &r)
	for _, c := range r.Content {
		if r.IsError {
			say("      ✗ %s", c.Text)
		} else {
			say("      ✓ %s", c.Text)
		}
	}
}

func step(n int, s string) {
	time.Sleep(400 * time.Millisecond)
	say("")
	say("  %d. %s", n, s)
}

func say(format string, a ...any) { fmt.Fprintf(os.Stdout, format+"\n", a...) }

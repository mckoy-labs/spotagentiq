package policy

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustCompile(t *testing.T, rules []Rule, def Action, redact []string) *Policy {
	t.Helper()
	p, err := Compile(rules, def, redact)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return p
}

func TestFirstMatchWins(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Match: "send_*", Action: RequireApproval, Reason: "outbound"},
		{Match: "send_internal", Action: Allow}, // never reached
		{Match: "delete_*", Action: Deny},
	}, Allow, nil)

	cases := map[string]Action{
		"send_email":    RequireApproval,
		"send_internal": RequireApproval,
		"delete_user":   Deny,
		"get_user":      Allow,
	}
	for tool, want := range cases {
		if got := p.Evaluate("crm", tool, json.RawMessage(`{}`)); got.Action != want {
			t.Errorf("%s: got %s want %s", tool, got.Action, want)
		}
	}
}

func TestScopedToUpstream(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Match: "prod/*", Action: RequireApproval},
	}, Allow, nil)
	if d := p.Evaluate("prod", "read", nil); d.Action != RequireApproval {
		t.Errorf("prod/read: %s", d.Action)
	}
	if d := p.Evaluate("staging", "read", nil); d.Action != Allow {
		t.Errorf("staging/read: %s", d.Action)
	}
}

func TestArgsRegex(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Match: "*", Action: Deny, IfArgsMatch: `\b\d{13,19}\b`, Reason: "card"},
	}, Allow, nil)
	if d := p.Evaluate("x", "charge", json.RawMessage(`{"card":"4242424242424242"}`)); d.Action != Deny {
		t.Errorf("card number not denied: %s", d.Action)
	}
	if d := p.Evaluate("x", "charge", json.RawMessage(`{"amount":42}`)); d.Action != Allow {
		t.Errorf("clean args denied: %s", d.Action)
	}
}

func TestDefaultAction(t *testing.T) {
	p := mustCompile(t, nil, RequireApproval, nil)
	d := p.Evaluate("x", "anything", nil)
	if d.Action != RequireApproval {
		t.Errorf("default: %s", d.Action)
	}
	if d.Reason != "default policy" || d.Rule != nil {
		t.Errorf("default reason/rule wrong: %+v", d)
	}
}

func TestApproveAlias(t *testing.T) {
	p := mustCompile(t, []Rule{{Match: "x", Action: "approve"}}, Allow, nil)
	if p.Rules()[0].Action != RequireApproval {
		t.Error("approve alias not normalised")
	}
}

func TestCompileErrors(t *testing.T) {
	if _, err := Compile([]Rule{{Match: "x", Action: "explode"}}, Allow, nil); err == nil {
		t.Error("bad action accepted")
	}
	if _, err := Compile([]Rule{{Match: "", Action: Allow}}, Allow, nil); err == nil {
		t.Error("empty match accepted")
	}
	if _, err := Compile([]Rule{{Match: "x", Action: Allow, IfArgsMatch: "("}}, Allow, nil); err == nil {
		t.Error("bad regex accepted")
	}
	if _, err := Compile(nil, "maybe", nil); err == nil {
		t.Error("bad default accepted")
	}
}

func TestRedact(t *testing.T) {
	p := mustCompile(t, nil, Allow, []string{"Password", "card_number"})
	in := json.RawMessage(`{"user":"a","password":"hunter2","nested":{"Card_Number":"4242","ok":1},"list":[{"password":"x"}]}`)
	out := string(p.Redact(in))
	if strings.Contains(out, "hunter2") || strings.Contains(out, "4242") {
		t.Errorf("secrets leaked: %s", out)
	}
	if !strings.Contains(out, `"user":"a"`) || !strings.Contains(out, `"ok":1`) {
		t.Errorf("non-secret fields damaged: %s", out)
	}
	if c := strings.Count(out, "[redacted]"); c != 3 {
		t.Errorf("expected 3 redactions, got %d: %s", c, out)
	}
}

func TestRedactNonObjectUnchanged(t *testing.T) {
	p := mustCompile(t, nil, Allow, []string{"x"})
	if got := string(p.Redact(json.RawMessage(`"just a string"`))); got != `"just a string"` {
		t.Errorf("string changed: %s", got)
	}
	if got := string(p.Redact(json.RawMessage(`not json`))); got != "not json" {
		t.Errorf("invalid json changed: %s", got)
	}
}

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

// eval canonicalizes first, the way the proxy does.
func eval(t *testing.T, p *Policy, upstream, tool, rawArgs string) Action {
	t.Helper()
	c, err := Canonicalize(json.RawMessage(rawArgs))
	if err != nil {
		t.Fatalf("canonicalize %s: %v", rawArgs, err)
	}
	return p.Evaluate(upstream, tool, c).Action
}

func TestCanonicalize(t *testing.T) {
	bs := string(rune(92)) // a backslash, so the escape survives to the JSON
	cases := map[string]string{
		`{"b":1,"a":2}`:                         `{"a":2,"b":1}`,
		`{ "a" : [ 1 , 2 ] }`:                   `{"a":[1,2]}`,
		`{"n":` + bs + `"x"}`:                   "", // invalid
		`{"card":"4242` + bs + `u00344242"}`:    `{"card":"424244242"}`,
		`{"to":"a@ours.com","to":"x@evil.com"}`: `{"to":"x@evil.com"}`,
		`{"big":4242424242424242,"f":1.50}`:     `{"big":4242424242424242,"f":1.50}`,
		`{"a":1} {"b":2}`:                       "", // trailing data
		`{"html":"<b>&</b>"}`:                   `{"html":"<b>&</b>"}`,
	}
	for in, want := range cases {
		got, err := Canonicalize(json.RawMessage(in))
		if want == "" {
			if err == nil {
				t.Errorf("%s: want error, got %s", in, got)
			}
			continue
		}
		if err != nil || string(got) != want {
			t.Errorf("%s:\n got %s (%v)\nwant %s", in, got, err, want)
		}
	}
}

// An agent can't hide a value from if_args_match with JSON escapes.
func TestEscapedValueCannotDodgeDenyRule(t *testing.T) {
	p := mustCompile(t, []Rule{{Match: "*", Action: Deny, IfArgsMatch: `\b\d{13,19}\b`}}, Allow, nil)
	bs := string(rune(92))
	if got := eval(t, p, "up", "charge", `{"card":"4242424`+bs+`u003242424242"}`); got != Deny {
		t.Fatalf("escaped card number: %s", got)
	}
	if got := eval(t, p, "up", "charge", `{"card":4242424242424242}`); got != Deny {
		t.Fatalf("card number as a JSON number: %s", got)
	}
}

// "*" must cover tools whose names contain a slash.
func TestStarMatchesToolNamesWithSlashes(t *testing.T) {
	p := mustCompile(t, []Rule{{Match: "*", Action: Deny}}, Allow, nil)
	for _, tool := range []string{"charge", "billing/charge", "a/b/c", "weird\nname"} {
		if got := eval(t, p, "up", tool, `{}`); got != Deny {
			t.Errorf("tool %q: %s", tool, got)
		}
	}
}

// The part before "/" is the real upstream, never a prefix of a tool name.
func TestToolNameCannotImpersonateUpstream(t *testing.T) {
	p := mustCompile(t, []Rule{{Match: "crm/get_*", Action: Allow}}, Deny, nil)
	if got := eval(t, p, "crm", "get_customer", `{}`); got != Allow {
		t.Errorf("real crm tool: %s", got)
	}
	if got := eval(t, p, "evil", "crm/get_customer", `{}`); got != Deny {
		t.Errorf("tool on another upstream named like crm's: %s", got)
	}
	// A tool whose own name has a slash is addressed through its upstream.
	p = mustCompile(t, []Rule{{Match: "up/billing/charge", Action: Deny}, {Match: "*/admin/*", Action: Deny}}, Allow, nil)
	if eval(t, p, "up", "billing/charge", `{}`) != Deny || eval(t, p, "x", "admin/reset", `{}`) != Deny {
		t.Error("scoped rules should reach tools with slashes in their names")
	}
}

func TestWhere(t *testing.T) {
	ours := `^[^@\s]+@yourcompany\.com$`
	p := mustCompile(t, []Rule{
		{Match: "send_email", Action: Allow, Where: map[string]string{"to": ours}},
		{Match: "refund", Action: RequireApproval, Where: map[string]string{"amount": `^\d{5,}$`}},
		{Match: "refund", Action: Allow},
		{Match: "update", Action: Allow, Where: map[string]string{"customer.plan": `^(free|pro)$`, "dry_run": `^true$`}},
	}, RequireApproval, nil)

	cases := []struct {
		tool, args string
		want       Action
	}{
		{"send_email", `{"to":"a@yourcompany.com"}`, Allow},
		{"send_email", `{"to":"thief@evil.com"}`, RequireApproval},
		// The three ways to smuggle a recipient past a whole-document regex:
		{"send_email", `{"to":"a@yourcompany.com","to":"thief@evil.com"}`, RequireApproval},
		{"send_email", `{"to":"thief@evil.com","x":{"to":"a@yourcompany.com"}}`, RequireApproval},
		{"send_email", `{"to":"thief@evil.com","note":"\"to\":\"a@yourcompany.com\""}`, RequireApproval},
		// Arrays: every element has to match.
		{"send_email", `{"to":["a@yourcompany.com","b@yourcompany.com"]}`, Allow},
		{"send_email", `{"to":["a@yourcompany.com","thief@evil.com"]}`, RequireApproval},
		{"send_email", `{"to":[]}`, RequireApproval},
		{"send_email", `{}`, RequireApproval},
		// Numbers are matched as written.
		{"refund", `{"amount":4900}`, Allow},
		{"refund", `{"amount":49000}`, RequireApproval},
		// Nested paths, and all conditions must hold.
		{"update", `{"customer":{"plan":"pro"},"dry_run":true}`, Allow},
		{"update", `{"customer":{"plan":"pro"},"dry_run":false}`, RequireApproval},
		{"update", `{"customer":"pro","dry_run":true}`, RequireApproval},
	}
	for _, c := range cases {
		if got := eval(t, p, "up", c.tool, c.args); got != c.want {
			t.Errorf("%s %s: got %s want %s", c.tool, c.args, got, c.want)
		}
	}
}

func TestWarnsOnAllowWithArgsRegex(t *testing.T) {
	p := mustCompile(t, []Rule{
		{Match: "send_email", Action: Allow, IfArgsMatch: `yourcompany`},
		{Match: "*", Action: Deny, IfArgsMatch: `\d{13}`},
	}, Allow, nil)
	if w := p.Warnings(); len(w) != 1 || !strings.Contains(w[0], "where") {
		t.Errorf("warnings: %v", w)
	}
	if _, err := Compile([]Rule{{Match: "x", Action: Allow, Where: map[string]string{"a": "("}}}, Allow, nil); err == nil {
		t.Error("bad where regex should fail to compile")
	}
}

func TestRedactKeepsLargeNumbersExact(t *testing.T) {
	p := mustCompile(t, nil, Allow, []string{"secret"})
	got := string(p.Redact(json.RawMessage(`{"id":4242424242424242,"secret":"x"}`)))
	if got != `{"id":4242424242424242,"secret":"[redacted]"}` {
		t.Errorf("redact: %s", got)
	}
}

// Package policy decides what happens to a tool call: pass it through, hold it
// for a human, or block it outright.
package policy

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
)

// Action is the outcome of evaluating a tool call against the rules.
type Action string

const (
	Allow           Action = "allow"
	RequireApproval Action = "require_approval"
	Deny            Action = "deny"
)

// Rule is one line in the policy. Rules are evaluated in order; the first
// rule whose Match glob fits the tool name (and whose IfArgsMatch regex, if
// set, matches the JSON-encoded arguments) wins.
type Rule struct {
	// Match is a glob against the tool name, e.g. "send_*", "delete_*", "*".
	// It may also be "upstream/tool" to scope a rule to one upstream server.
	Match string `json:"match"`
	// Action is allow, require_approval, or deny.
	Action Action `json:"action"`
	// IfArgsMatch is an optional regular expression tested against the
	// JSON-serialised arguments. Useful for "deny anything that looks like a
	// card number".
	IfArgsMatch string `json:"if_args_match,omitempty"`
	// Reason is shown to approvers and recorded in the audit log.
	Reason string `json:"reason,omitempty"`

	argsRe *regexp.Regexp
}

// Policy is a compiled rule set.
type Policy struct {
	rules         []Rule
	defaultAction Action
	redactKeys    map[string]bool
}

// Decision is the result of Evaluate.
type Decision struct {
	Action Action
	Rule   *Rule // nil when the default action applied
	Reason string
}

// Compile validates rules and compiles regexes. defaultAction applies when no
// rule matches; it must be allow, require_approval or deny. redactKeys lists
// argument keys (case-insensitive) whose values are masked in logs and the
// inbox.
func Compile(rules []Rule, defaultAction Action, redactKeys []string) (*Policy, error) {
	if defaultAction == "" {
		defaultAction = Allow
	}
	if err := validAction(defaultAction); err != nil {
		return nil, fmt.Errorf("default_action: %w", err)
	}
	p := &Policy{defaultAction: defaultAction, redactKeys: map[string]bool{}}
	for i := range rules {
		r := rules[i]
		if r.Match == "" {
			return nil, fmt.Errorf("rule %d: match is required", i)
		}
		if _, err := path.Match(r.Match, "x"); err != nil {
			return nil, fmt.Errorf("rule %d: bad glob %q: %w", i, r.Match, err)
		}
		if r.Action == "approve" {
			r.Action = RequireApproval
		}
		if err := validAction(r.Action); err != nil {
			return nil, fmt.Errorf("rule %d: %w", i, err)
		}
		if r.IfArgsMatch != "" {
			re, err := regexp.Compile(r.IfArgsMatch)
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad if_args_match: %w", i, err)
			}
			r.argsRe = re
		}
		p.rules = append(p.rules, r)
	}
	for _, k := range redactKeys {
		p.redactKeys[strings.ToLower(k)] = true
	}
	return p, nil
}

func validAction(a Action) error {
	switch a {
	case Allow, RequireApproval, Deny:
		return nil
	}
	return fmt.Errorf("unknown action %q (want allow, require_approval or deny)", a)
}

// Evaluate returns the decision for a call to tool (optionally scoped by
// upstream) with the given raw JSON arguments.
func (p *Policy) Evaluate(upstream, tool string, args json.RawMessage) Decision {
	scoped := upstream + "/" + tool
	for i := range p.rules {
		r := &p.rules[i]
		if !globMatch(r.Match, tool) && !globMatch(r.Match, scoped) {
			continue
		}
		if r.argsRe != nil && !r.argsRe.Match(args) {
			continue
		}
		reason := r.Reason
		if reason == "" {
			reason = fmt.Sprintf("matched rule %q", r.Match)
		}
		return Decision{Action: r.Action, Rule: r, Reason: reason}
	}
	return Decision{Action: p.defaultAction, Reason: "default policy"}
}

func globMatch(pattern, name string) bool {
	ok, _ := path.Match(pattern, name)
	return ok
}

// Redact returns a copy of the JSON arguments with values of sensitive keys
// replaced by "[redacted]". Non-object inputs are returned unchanged.
func (p *Policy) Redact(args json.RawMessage) json.RawMessage {
	if len(p.redactKeys) == 0 || len(args) == 0 {
		return args
	}
	var v any
	if err := json.Unmarshal(args, &v); err != nil {
		return args
	}
	p.redactValue(v)
	out, err := json.Marshal(v)
	if err != nil {
		return args
	}
	return out
}

func (p *Policy) redactValue(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if p.redactKeys[strings.ToLower(k)] {
				t[k] = "[redacted]"
				continue
			}
			p.redactValue(val)
		}
	case []any:
		for _, item := range t {
			p.redactValue(item)
		}
	}
}

// Rules returns the compiled rules (for display).
func (p *Policy) Rules() []Rule { return p.rules }

// DefaultAction returns the fallback action.
func (p *Policy) DefaultAction() Action { return p.defaultAction }

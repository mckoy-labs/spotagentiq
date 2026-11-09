// Package policy decides what happens to a tool call: pass it through, hold it
// for a human, or block it outright.
package policy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
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
// rule whose conditions all hold wins.
type Rule struct {
	// Match is a glob. Without a "/", it is tested against the tool name:
	// "send_*", "delete_*", "*". With a "/", the part before the first "/" is
	// tested against the upstream server's name and the rest against the tool
	// name: "stripe/*", "*/delete_*". "*" matches any run of characters,
	// including "/", and "?" any single character.
	//
	// The upstream part always refers to the real server, never to a prefix
	// of a tool's name, so a server cannot name a tool "crm/get_x" to pick up
	// a rule written for the crm server.
	Match string `json:"match"`
	// Action is allow, require_approval, or deny.
	Action Action `json:"action"`
	// IfArgsMatch is an optional regular expression tested against the whole
	// canonical JSON of the arguments (see Canonicalize). It matches anywhere
	// in the arguments, so it suits tripwires such as "deny anything that
	// looks like a card number". For "allow only when this argument is X",
	// use Where: a pattern over the whole document can be satisfied by a
	// decoy value in an unrelated field.
	IfArgsMatch string `json:"if_args_match,omitempty"`
	// Where maps an argument path ("to", "customer.email") to a regular
	// expression that the value at that path must match. Every entry must
	// hold. A missing path never matches. If the value is an array, every
	// element must match.
	Where map[string]string `json:"where,omitempty"`
	// Reason is shown to approvers and recorded in the audit log.
	Reason string `json:"reason,omitempty"`

	upRe   *regexp.Regexp // upstream part; nil when Match has no "/"
	toolRe *regexp.Regexp
	argsRe *regexp.Regexp
	where  []whereCond
}

type whereCond struct {
	path []string
	re   *regexp.Regexp
}

// Policy is a compiled rule set.
type Policy struct {
	rules         []Rule
	defaultAction Action
	redactKeys    map[string]bool
	warnings      []string
	needsDecode   bool
}

// Decision is the result of Evaluate.
type Decision struct {
	Action Action
	Rule   *Rule // nil when the default applied
	Reason string
}

// Compile validates rules and compiles patterns. defaultAction applies when no
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
		if up, tool, ok := strings.Cut(r.Match, "/"); ok {
			r.upRe, r.toolRe = globRegexp(up), globRegexp(tool)
		} else {
			r.toolRe = globRegexp(r.Match)
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
			if r.Action == Allow {
				p.warnings = append(p.warnings, fmt.Sprintf(
					"rule %d (%s): an allow rule with if_args_match can be satisfied by a matching value anywhere in the arguments; use \"where\" to test a specific argument", i, r.Match))
			}
		}
		paths := make([]string, 0, len(r.Where))
		for k := range r.Where {
			paths = append(paths, k)
		}
		sort.Strings(paths)
		for _, k := range paths {
			if k == "" {
				return nil, fmt.Errorf("rule %d: where has an empty path", i)
			}
			re, err := regexp.Compile(r.Where[k])
			if err != nil {
				return nil, fmt.Errorf("rule %d: bad where pattern for %q: %w", i, k, err)
			}
			r.where = append(r.where, whereCond{path: strings.Split(k, "."), re: re})
			p.needsDecode = true
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

// Warnings lists rules that are valid but probably weaker than intended.
func (p *Policy) Warnings() []string { return p.warnings }

// globRegexp compiles a glob where "*" is any run of characters (including
// "/") and "?" is any single character. Everything else is literal, so no
// pattern is invalid and none can silently fail to match.
func globRegexp(glob string) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString(`(?s)^`)
	for _, r := range glob {
		switch r {
		case '*':
			sb.WriteString(`.*`)
		case '?':
			sb.WriteString(`.`)
		default:
			sb.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	sb.WriteString(`$`)
	return regexp.MustCompile(sb.String())
}

func (r *Rule) matchesName(upstream, tool string) bool {
	if r.upRe != nil && !r.upRe.MatchString(upstream) {
		return false
	}
	return r.toolRe.MatchString(tool)
}

// Canonicalize parses JSON and re-serialises it in one fixed form: object keys
// sorted, no insignificant whitespace, no optional escapes (so "\u0034" becomes
// "4"), numbers kept exactly as written, and the last value kept when a key is
// repeated.
//
// The proxy evaluates policy on this form and forwards this same form to the
// tool server. That closes the gap between "what the rules saw" and "what the
// tool received" that different JSON parsers would otherwise open.
func Canonicalize(raw json.RawMessage) (json.RawMessage, error) {
	v, err := decode(raw)
	if err != nil {
		return nil, err
	}
	return encode(v)
}

func decode(raw json.RawMessage) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("unexpected data after JSON value")
	}
	return v, nil
}

func encode(v any) (json.RawMessage, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Evaluate returns the decision for a call to tool on upstream. args must be
// canonical JSON (see Canonicalize).
func (p *Policy) Evaluate(upstream, tool string, args json.RawMessage) Decision {
	var decoded any
	if p.needsDecode {
		decoded, _ = decode(args)
	}
	for i := range p.rules {
		r := &p.rules[i]
		if !r.matchesName(upstream, tool) {
			continue
		}
		if r.argsRe != nil && !r.argsRe.Match(args) {
			continue
		}
		if !whereHolds(r.where, decoded) {
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

func whereHolds(conds []whereCond, args any) bool {
	for _, c := range conds {
		v, ok := lookup(args, c.path)
		if !ok || !valueMatches(c.re, v) {
			return false
		}
	}
	return true
}

func lookup(v any, path []string) (any, bool) {
	for _, key := range path {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, false
		}
		if v, ok = obj[key]; !ok {
			return nil, false
		}
	}
	return v, true
}

// valueMatches tests one argument value. Strings are matched as-is, numbers
// and booleans as written, objects as canonical JSON. For an array every
// element must match, so "to": ["a@ours.com", "x@evil.com"] does not pass a
// rule meant to allow only our own domain.
func valueMatches(re *regexp.Regexp, v any) bool {
	switch t := v.(type) {
	case string:
		return re.MatchString(t)
	case json.Number:
		return re.MatchString(t.String())
	case bool:
		return re.MatchString(fmt.Sprint(t))
	case nil:
		return re.MatchString("null")
	case []any:
		if len(t) == 0 {
			return false
		}
		for _, item := range t {
			if !valueMatches(re, item) {
				return false
			}
		}
		return true
	default:
		b, err := encode(t)
		return err == nil && re.Match(b)
	}
}

// Redact returns a copy of the JSON arguments with values of sensitive keys
// replaced by "[redacted]". Non-object inputs are returned unchanged.
func (p *Policy) Redact(args json.RawMessage) json.RawMessage {
	if len(p.redactKeys) == 0 || len(args) == 0 {
		return args
	}
	v, err := decode(args)
	if err != nil {
		return args
	}
	p.redactValue(v)
	out, err := encode(v)
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

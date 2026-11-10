// Package proxy is the gate: it speaks MCP to the agent on one side and to the
// real tool servers on the other. Every tools/call, and every other request
// that reads data or changes state, passes through policy and the audit log.
package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/approvals"
	"github.com/mckoy-labs/spotagentiq/internal/audit"
	"github.com/mckoy-labs/spotagentiq/internal/config"
	"github.com/mckoy-labs/spotagentiq/internal/jsonrpc"
	"github.com/mckoy-labs/spotagentiq/internal/policy"
)

// Version is stamped into serverInfo.
var Version = "0.1.2"

// Proxy fronts one or more upstream MCP servers.
type Proxy struct {
	cfg       *config.Config
	policy    *policy.Policy
	log       *audit.Log
	approvals *approvals.Store
	client    *jsonrpc.Conn
	upstreams []*upstream

	// tool routing
	toolsMu  sync.RWMutex
	tools    map[string]toolRoute // exposed name -> route
	toolList []json.RawMessage    // cached tools/list result items

	// upstream-originated requests relayed to the client
	relayMu  sync.Mutex
	relay    map[string]relayEntry // our client-facing id -> origin
	relaySeq int64

	initialized chan struct{}
	initOnce    sync.Once
	clientInfo  json.RawMessage
}

type toolRoute struct {
	up       *upstream
	realName string
}

type relayEntry struct {
	up     *upstream
	origID json.RawMessage
}

// New wires a proxy. in/out are the agent-facing stdio streams.
func New(cfg *config.Config, pol *policy.Policy, lg *audit.Log, store *approvals.Store, in io.Reader, out io.Writer) *Proxy {
	return &Proxy{
		cfg:         cfg,
		policy:      pol,
		log:         lg,
		approvals:   store,
		client:      jsonrpc.NewConn(in, out),
		tools:       map[string]toolRoute{},
		relay:       map[string]relayEntry{},
		initialized: make(chan struct{}),
	}
}

// Run starts the upstreams and serves the client until it disconnects.
func (p *Proxy) Run(ctx context.Context) error {
	for _, uc := range p.cfg.Upstreams {
		u, err := startUpstream(uc, p.cfg.Token)
		if err != nil {
			p.shutdown()
			return err
		}
		u.onNotification = p.onUpstreamNotification
		u.onRequest = p.onUpstreamRequest
		p.upstreams = append(p.upstreams, u)
		log.Printf("spotagentiq: started upstream %q (%s)", uc.Name, uc.Command)
	}
	defer p.shutdown()

	// Refuse to run at all if the audit log can't be written.
	if err := p.record(audit.Entry{Event: audit.EventStartup, Agent: p.cfg.Agent, Principal: p.cfg.Principal,
		Reason: fmt.Sprintf("spotagentiq %s, %d upstream(s), %d rule(s), default %s", Version, len(p.upstreams), len(p.policy.Rules()), p.policy.DefaultAction())}); err != nil {
		return fmt.Errorf("audit log is not writable: %w", err)
	}
	for _, w := range p.policy.Warnings() {
		log.Printf("spotagentiq: policy warning: %s", w)
	}

	for {
		m, err := p.client.Read()
		if err != nil {
			if err == jsonrpc.ErrClosed {
				log.Printf("spotagentiq: client disconnected")
				return nil
			}
			return err
		}
		switch {
		case m.IsRequest():
			go p.handleRequest(ctx, m)
		case m.IsNotification():
			p.handleNotification(m)
		case m.IsResponse():
			p.handleClientResponse(m)
		}
	}
}

func (p *Proxy) shutdown() {
	for _, u := range p.upstreams {
		u.stop()
	}
}

// ---- client -> proxy ---------------------------------------------------

func (p *Proxy) handleRequest(ctx context.Context, m *jsonrpc.Message) {
	switch m.Method {
	case "initialize":
		p.handleInitialize(ctx, m)
	case "ping":
		p.reply(m.ID, map[string]any{})
	case "tools/list":
		p.waitInit()
		p.handleToolsList(ctx, m)
	case "tools/call":
		p.waitInit()
		p.handleToolsCall(ctx, m)
	case "resources/list", "resources/templates/list", "prompts/list":
		p.waitInit()
		p.handleMergedList(ctx, m)
	default:
		p.waitInit()
		if ungated[m.Method] {
			p.send(p.firstSuccess(ctx, m))
			return
		}
		p.handleGated(ctx, m)
	}
}

func (p *Proxy) waitInit() { <-p.initialized }

func (p *Proxy) handleInitialize(ctx context.Context, m *jsonrpc.Message) {
	p.clientInfo = m.Params
	var caps = map[string]any{"tools": map[string]any{"listChanged": true}}
	for _, u := range p.upstreams {
		ictx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err := u.callRaw(ictx, "initialize", m.Params)
		cancel()
		if err != nil || resp.Error != nil {
			log.Printf("spotagentiq: upstream %q failed to initialize: %v %v", u.name, err, resp)
			continue
		}
		var res struct {
			Capabilities json.RawMessage `json:"capabilities"`
			ServerInfo   json.RawMessage `json:"serverInfo"`
		}
		_ = json.Unmarshal(resp.Result, &res)
		u.capabilities = res.Capabilities
		u.serverInfo = res.ServerInfo
		var c map[string]json.RawMessage
		_ = json.Unmarshal(res.Capabilities, &c)
		for _, k := range []string{"resources", "prompts", "logging", "completions"} {
			if v, ok := c[k]; ok {
				if _, have := caps[k]; !have {
					caps[k] = v
				}
			}
		}
		_ = u.notify("notifications/initialized", nil)
	}
	p.refreshTools(ctx)
	p.reply(m.ID, map[string]any{
		"protocolVersion": protocolVersion(m.Params),
		"capabilities":    caps,
		"serverInfo":      map[string]any{"name": "spotagentiq", "version": Version},
		"instructions":    "Tool calls pass through SpotAgentIQ. Some calls are held for human approval and may take a while; others may be blocked by policy. If a call is blocked, tell the user why rather than retrying.",
	})
	p.initOnce.Do(func() { close(p.initialized) })
}

func protocolVersion(params json.RawMessage) string {
	var pv struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &pv)
	if pv.ProtocolVersion == "" {
		return "2025-06-18"
	}
	return pv.ProtocolVersion
}

func (p *Proxy) handleNotification(m *jsonrpc.Message) {
	switch m.Method {
	case "notifications/initialized":
		// Already sent to upstreams during initialize.
	case "notifications/cancelled":
		// Best effort: fan out so upstreams can stop work.
		for _, u := range p.upstreams {
			_ = u.write(m)
		}
	default:
		for _, u := range p.upstreams {
			_ = u.write(m)
		}
	}
}

// ---- tools -------------------------------------------------------------

func (p *Proxy) refreshTools(ctx context.Context) {
	type named struct {
		up   *upstream
		tool map[string]json.RawMessage
		name string
	}
	var all []named
	counts := map[string]int{}
	for _, u := range p.upstreams {
		lctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		resp, err := u.call(lctx, "tools/list", map[string]any{})
		cancel()
		if err != nil || resp.Error != nil {
			log.Printf("spotagentiq: tools/list from %q failed: %v", u.name, err)
			continue
		}
		var res struct {
			Tools []map[string]json.RawMessage `json:"tools"`
		}
		if err := json.Unmarshal(resp.Result, &res); err != nil {
			continue
		}
		for _, t := range res.Tools {
			var name string
			_ = json.Unmarshal(t["name"], &name)
			if name == "" {
				continue
			}
			all = append(all, named{up: u, tool: t, name: name})
			counts[name]++
		}
	}
	routes := map[string]toolRoute{}
	var list []json.RawMessage
	for _, n := range all {
		// Tools keep their real names unless two upstreams collide, in which
		// case both are prefixed with the upstream name.
		exposed := n.name
		if counts[n.name] > 1 {
			exposed = n.up.name + "__" + n.name
		}
		routes[exposed] = toolRoute{up: n.up, realName: n.name}
		nm, _ := json.Marshal(exposed)
		n.tool["name"] = nm
		b, _ := json.Marshal(n.tool)
		list = append(list, b)
	}
	p.toolsMu.Lock()
	p.tools = routes
	p.toolList = list
	p.toolsMu.Unlock()
}

func (p *Proxy) handleToolsList(ctx context.Context, m *jsonrpc.Message) {
	p.toolsMu.RLock()
	list := p.toolList
	p.toolsMu.RUnlock()
	if list == nil {
		list = []json.RawMessage{}
	}
	p.reply(m.ID, map[string]any{"tools": list})
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// record appends to the audit log. A failure is reported on stderr and
// returned, so callers can refuse to act on something they could not record.
func (p *Proxy) record(e audit.Entry) error {
	if _, err := p.log.Append(e); err != nil {
		log.Printf("spotagentiq: AUDIT LOG WRITE FAILED (%s %s): %v", e.Event, e.Tool, err)
		return err
	}
	return nil
}

const auditDownMsg = "SpotAgentIQ could not write to its audit log, so this action was not performed. An administrator needs to check the log file and disk"

// authorize is the gate. It evaluates policy for one request, records the
// decision and, when the policy says so, waits for a human.
//
// args must be canonical JSON: the caller forwards exactly these bytes, so
// what was evaluated, what the approver saw and what the upstream receives
// are the same document.
//
// It returns ok=false when the request must not be forwarded; refuse has then
// already been called with a message for the agent. The gate fails closed: if
// the decision cannot be written to the audit log, the request is refused.
func (p *Proxy) authorize(upName, name string, args, rawParams json.RawMessage, refuse func(msg string)) (base audit.Entry, ok bool) {
	redacted := p.policy.Redact(args)
	dec := p.policy.Evaluate(upName, name, args)
	ruleName := ""
	if dec.Rule != nil {
		ruleName = dec.Rule.Match
	}
	base = audit.Entry{
		CallID: fmt.Sprintf("call_%d_%s", time.Now().UnixNano(), name),
		Agent:  p.cfg.Agent, Principal: p.cfg.Principal,
		Upstream: upName, Tool: name, Args: redacted, Rule: ruleName, Reason: dec.Reason,
	}

	switch dec.Action {
	case policy.Deny:
		_ = p.record(withEvent(base, audit.EventDenied, ""))
		log.Printf("spotagentiq: DENIED %s (%s)", name, dec.Reason)
		refuse(fmt.Sprintf("Blocked by SpotAgentIQ policy: %s. This action was not performed.", dec.Reason))
		return base, false

	case policy.RequireApproval:
		if p.record(withEvent(base, audit.EventPending, "")) != nil {
			refuse(auditDownMsg + ".")
			return base, false
		}
		req := p.approvals.Create(approvals.Request{
			Agent: p.cfg.Agent, Principal: p.cfg.Principal, Upstream: upName, Tool: name,
			Args: redacted, Reason: dec.Reason, Rule: ruleName,
		}, p.cfg.Timeout())
		log.Printf("spotagentiq: HELD %s for approval (%s) id=%s", name, dec.Reason, req.ID)

		stopProgress := p.startProgress(progressToken(rawParams), req)
		d := p.approvals.Wait(req)
		stopProgress()

		switch d.Status {
		case approvals.StatusApproved:
			e := base
			e.Event, e.Approver, e.Reason = audit.EventApproved, d.Approver, nonEmpty(d.Note, dec.Reason)
			if p.record(e) != nil {
				refuse(auditDownMsg + ", even though it was approved.")
				return base, false
			}
			log.Printf("spotagentiq: APPROVED %s by %s", name, d.Approver)
		case approvals.StatusRejected:
			e := base
			e.Event, e.Approver, e.Reason = audit.EventRejected, d.Approver, nonEmpty(d.Note, "rejected")
			_ = p.record(e)
			log.Printf("spotagentiq: REJECTED %s by %s", name, d.Approver)
			msg := "Rejected by a human reviewer"
			if d.Approver != "" {
				msg += " (" + d.Approver + ")"
			}
			if d.Note != "" {
				msg += ": " + d.Note
			}
			refuse(msg + ". This action was not performed.")
			return base, false
		default:
			_ = p.record(withEvent(base, audit.EventTimeout, ""))
			log.Printf("spotagentiq: TIMEOUT waiting for approval of %s", name)
			refuse("No human approved this action within the allowed time. This action was not performed.")
			return base, false
		}

	default: // allow
		if p.record(withEvent(base, audit.EventAllowed, "")) != nil {
			refuse(auditDownMsg + ".")
			return base, false
		}
	}
	return base, true
}

// canonicalObject canonicalizes raw, which must be a JSON object (or absent).
func canonicalObject(raw json.RawMessage) (json.RawMessage, error) {
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	c, err := policy.Canonicalize(raw)
	if err != nil {
		return nil, err
	}
	if len(c) == 0 || c[0] != '{' {
		return nil, fmt.Errorf("must be a JSON object")
	}
	return c, nil
}

func progressToken(params json.RawMessage) json.RawMessage {
	var p struct {
		Meta struct {
			ProgressToken json.RawMessage `json:"progressToken"`
		} `json:"_meta"`
	}
	_ = json.Unmarshal(params, &p)
	return p.Meta.ProgressToken
}

func (p *Proxy) handleToolsCall(ctx context.Context, m *jsonrpc.Message) {
	var params toolCallParams
	if err := json.Unmarshal(m.Params, &params); err != nil || params.Name == "" {
		p.replyError(m.ID, jsonrpc.CodeInvalidParams, "tools/call: name is required")
		return
	}
	p.toolsMu.RLock()
	route, ok := p.tools[params.Name]
	p.toolsMu.RUnlock()
	if !ok {
		// Tool list may be stale; refresh once.
		p.refreshTools(ctx)
		p.toolsMu.RLock()
		route, ok = p.tools[params.Name]
		p.toolsMu.RUnlock()
		if !ok {
			p.replyError(m.ID, jsonrpc.CodeInvalidParams, "unknown tool: "+params.Name)
			return
		}
	}
	args, err := canonicalObject(params.Arguments)
	if err != nil {
		p.replyError(m.ID, jsonrpc.CodeInvalidParams, "tools/call: arguments "+err.Error())
		return
	}

	base, ok := p.authorize(route.up.name, route.realName, args, m.Params, func(msg string) { p.replyToolBlocked(m.ID, msg) })
	if !ok {
		return
	}

	// Forward to the real server with the real tool name and the canonical
	// arguments policy just evaluated: never the bytes the client sent.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(m.Params, &raw)
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	nm, _ := json.Marshal(route.realName)
	raw["name"] = nm
	raw["arguments"] = args
	fwd, _ := json.Marshal(raw)
	resp, err := route.up.callRaw(ctx, "tools/call", fwd)
	if err != nil {
		_ = p.record(withEvent(base, audit.EventFailed, err.Error()))
		p.replyError(m.ID, jsonrpc.CodeInternal, "upstream error: "+err.Error())
		return
	}
	if resp.Error != nil {
		_ = p.record(withEvent(base, audit.EventFailed, resp.Error.Message))
		p.send(&jsonrpc.Message{ID: m.ID, Error: resp.Error})
		return
	}
	_ = p.record(withEvent(base, audit.EventCompleted, summarizeResult(resp.Result)))
	p.send(&jsonrpc.Message{ID: m.ID, Result: resp.Result})
}

// ungated are requests that change nothing and return no data of their own.
// Every other non-tool request (resources/read, prompts/get, and any method
// this version has never heard of) goes through the gate like a tool call.
var ungated = map[string]bool{
	"logging/setLevel":      true,
	"completion/complete":   true,
	"resources/subscribe":   true,
	"resources/unsubscribe": true,
}

// codeBlocked is the JSON-RPC error code for a request refused by policy.
const codeBlocked = -32001

// handleGated applies policy and auditing to MCP requests other than
// tools/call. For policy they are a "tool" named after the method on the
// reserved upstream "mcp", so a rule reads {"match": "mcp/resources/read", ...}
// and a bare "*" covers them too.
func (p *Proxy) handleGated(ctx context.Context, m *jsonrpc.Message) {
	params, err := canonicalObject(m.Params)
	if err != nil {
		p.replyError(m.ID, jsonrpc.CodeInvalidParams, m.Method+": params "+err.Error())
		return
	}
	base, ok := p.authorize(config.ReservedUpstream, m.Method, params, m.Params, func(msg string) { p.replyError(m.ID, codeBlocked, msg) })
	if !ok {
		return
	}
	fwd := *m
	if len(m.Params) > 0 {
		fwd.Params = params
	}
	resp := p.firstSuccess(ctx, &fwd)
	if resp.Error != nil {
		_ = p.record(withEvent(base, audit.EventFailed, resp.Error.Message))
	} else {
		_ = p.record(withEvent(base, audit.EventCompleted, "ok"))
	}
	p.send(resp)
}

// startProgress keeps the client informed (and the connection warm) while a
// call waits for a human, if the client supplied a progress token.
func (p *Proxy) startProgress(token json.RawMessage, req *approvals.Request) func() {
	if len(token) == 0 || string(token) == "null" {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		send := func(msg string) {
			n, _ := jsonrpc.NewNotification("notifications/progress", map[string]any{
				"progressToken": token, "progress": 0, "message": msg,
			})
			_ = p.client.Write(n)
		}
		send(fmt.Sprintf("SpotAgentIQ: waiting for human approval of %s (%s)", req.Tool, req.ID))
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				send(fmt.Sprintf("SpotAgentIQ: still waiting for approval of %s; expires %s", req.Tool, req.ExpiresAt.UTC().Format(time.Kitchen)))
			}
		}
	}()
	return func() { close(stop) }
}

func withEvent(e audit.Entry, event, result string) audit.Entry {
	e.Event = event
	e.Result = result
	return e
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func summarizeResult(r json.RawMessage) string {
	var res struct {
		IsError bool `json:"isError"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.Unmarshal(r, &res); err != nil {
		return "ok"
	}
	var sb strings.Builder
	if res.IsError {
		sb.WriteString("error: ")
	}
	for _, c := range res.Content {
		if c.Type == "text" {
			sb.WriteString(c.Text)
			sb.WriteString(" ")
		} else {
			sb.WriteString("[" + c.Type + "] ")
		}
	}
	s := strings.TrimSpace(sb.String())
	if s == "" {
		s = "ok"
	}
	if len(s) > 240 {
		s = s[:240] + "…"
	}
	return s
}

// ---- generic forwarding -------------------------------------------------

func (p *Proxy) handleMergedList(ctx context.Context, m *jsonrpc.Message) {
	key := map[string]string{
		"resources/list":           "resources",
		"resources/templates/list": "resourceTemplates",
		"prompts/list":             "prompts",
	}[m.Method]
	merged := []json.RawMessage{}
	for _, u := range p.upstreams {
		resp, err := u.callRaw(ctx, m.Method, m.Params)
		if err != nil || resp.Error != nil {
			continue
		}
		var res map[string]json.RawMessage
		if json.Unmarshal(resp.Result, &res) != nil {
			continue
		}
		var items []json.RawMessage
		_ = json.Unmarshal(res[key], &items)
		merged = append(merged, items...)
	}
	p.reply(m.ID, map[string]any{key: merged})
}

// firstSuccess tries each upstream in order and returns the first non-error
// response (or the last error), addressed to the client's request ID.
func (p *Proxy) firstSuccess(ctx context.Context, m *jsonrpc.Message) *jsonrpc.Message {
	var last *jsonrpc.Message
	for _, u := range p.upstreams {
		resp, err := u.callRaw(ctx, m.Method, m.Params)
		if err != nil {
			last = jsonrpc.NewError(m.ID, jsonrpc.CodeInternal, err.Error())
			continue
		}
		if resp.Error == nil {
			return &jsonrpc.Message{ID: m.ID, Result: resp.Result}
		}
		last = &jsonrpc.Message{ID: m.ID, Error: resp.Error}
	}
	if last == nil {
		last = jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "no upstream handled "+m.Method)
	}
	return last
}

// ---- upstream -> client -------------------------------------------------

func (p *Proxy) onUpstreamNotification(u *upstream, m *jsonrpc.Message) {
	if m.Method == "notifications/tools/list_changed" {
		go func() {
			p.refreshTools(context.Background())
			_ = p.client.Write(m)
		}()
		return
	}
	_ = p.client.Write(m)
}

func (p *Proxy) onUpstreamRequest(u *upstream, m *jsonrpc.Message) {
	p.relayMu.Lock()
	p.relaySeq++
	id := fmt.Sprintf("gk-%d", p.relaySeq)
	p.relay[id] = relayEntry{up: u, origID: m.ID}
	p.relayMu.Unlock()
	idRaw, _ := json.Marshal(id)
	_ = p.client.Write(&jsonrpc.Message{JSONRPC: "2.0", ID: idRaw, Method: m.Method, Params: m.Params})
}

func (p *Proxy) handleClientResponse(m *jsonrpc.Message) {
	var id string
	if err := json.Unmarshal(m.ID, &id); err != nil {
		return
	}
	p.relayMu.Lock()
	entry, ok := p.relay[id]
	delete(p.relay, id)
	p.relayMu.Unlock()
	if !ok {
		return
	}
	_ = entry.up.write(&jsonrpc.Message{JSONRPC: "2.0", ID: entry.origID, Result: m.Result, Error: m.Error})
}

// ---- replies -----------------------------------------------------------

func (p *Proxy) send(m *jsonrpc.Message) {
	if err := p.client.Write(m); err != nil {
		log.Printf("spotagentiq: write to client failed: %v", err)
	}
}

func (p *Proxy) reply(id json.RawMessage, result any) {
	m, err := jsonrpc.NewResult(id, result)
	if err != nil {
		p.replyError(id, jsonrpc.CodeInternal, err.Error())
		return
	}
	p.send(m)
}

func (p *Proxy) replyError(id json.RawMessage, code int, msg string) {
	p.send(jsonrpc.NewError(id, code, msg))
}

// replyToolBlocked returns a tool result (not a protocol error) so the agent
// can read why and explain it to its user instead of crashing.
func (p *Proxy) replyToolBlocked(id json.RawMessage, text string) {
	p.reply(id, map[string]any{
		"isError": true,
		"content": []map[string]any{{"type": "text", "text": text}},
	})
}

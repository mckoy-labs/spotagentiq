// Package proxy is the gate: it speaks MCP to the agent on one side and to the
// real tool servers on the other, and every tools/call passes through policy.
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
var Version = "0.1.0"

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
		u, err := startUpstream(uc)
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

	_, _ = p.log.Append(audit.Entry{Event: audit.EventStartup, Agent: p.cfg.Agent, Principal: p.cfg.Principal,
		Reason: fmt.Sprintf("spotagentiq %s, %d upstream(s), %d rule(s), default %s", Version, len(p.upstreams), len(p.policy.Rules()), p.policy.DefaultAction())})

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
		p.forwardFirstSuccess(ctx, m)
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
	Meta      *struct {
		ProgressToken json.RawMessage `json:"progressToken"`
	} `json:"_meta,omitempty"`
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

	args := params.Arguments
	if len(args) == 0 {
		args = json.RawMessage("{}")
	}
	redacted := p.policy.Redact(args)
	callID := fmt.Sprintf("call_%d_%s", time.Now().UnixNano(), params.Name)
	dec := p.policy.Evaluate(route.up.name, route.realName, args)
	ruleName := ""
	if dec.Rule != nil {
		ruleName = dec.Rule.Match
	}
	base := audit.Entry{CallID: callID, Agent: p.cfg.Agent, Principal: p.cfg.Principal, Upstream: route.up.name, Tool: route.realName, Args: redacted, Rule: ruleName, Reason: dec.Reason}

	switch dec.Action {
	case policy.Deny:
		e := base
		e.Event = audit.EventDenied
		_, _ = p.log.Append(e)
		log.Printf("spotagentiq: DENIED %s (%s)", route.realName, dec.Reason)
		p.replyToolBlocked(m.ID, fmt.Sprintf("Blocked by SpotAgentIQ policy: %s. This action was not performed.", dec.Reason))
		return

	case policy.RequireApproval:
		e := base
		e.Event = audit.EventPending
		_, _ = p.log.Append(e)
		req := p.approvals.Create(approvals.Request{
			Agent: p.cfg.Agent, Principal: p.cfg.Principal, Upstream: route.up.name, Tool: route.realName,
			Args: redacted, Reason: dec.Reason, Rule: ruleName,
		}, p.cfg.Timeout())
		log.Printf("spotagentiq: HELD %s for approval (%s) id=%s", route.realName, dec.Reason, req.ID)

		stopProgress := p.startProgress(params, req)
		d := p.approvals.Wait(req)
		stopProgress()

		switch d.Status {
		case approvals.StatusApproved:
			e := base
			e.Event, e.Approver, e.Reason = audit.EventApproved, d.Approver, nonEmpty(d.Note, dec.Reason)
			_, _ = p.log.Append(e)
			log.Printf("spotagentiq: APPROVED %s by %s", route.realName, d.Approver)
		case approvals.StatusRejected:
			e := base
			e.Event, e.Approver, e.Reason = audit.EventRejected, d.Approver, nonEmpty(d.Note, "rejected")
			_, _ = p.log.Append(e)
			log.Printf("spotagentiq: REJECTED %s by %s", route.realName, d.Approver)
			msg := "Rejected by a human reviewer"
			if d.Approver != "" {
				msg += " (" + d.Approver + ")"
			}
			if d.Note != "" {
				msg += ": " + d.Note
			}
			p.replyToolBlocked(m.ID, msg+". This action was not performed.")
			return
		default:
			e := base
			e.Event = audit.EventTimeout
			_, _ = p.log.Append(e)
			log.Printf("spotagentiq: TIMEOUT waiting for approval of %s", route.realName)
			p.replyToolBlocked(m.ID, "No human approved this action within the allowed time. This action was not performed.")
			return
		}

	case policy.Allow:
		e := base
		e.Event = audit.EventAllowed
		_, _ = p.log.Append(e)
	}

	// Forward to the real server with the real tool name.
	var raw map[string]json.RawMessage
	_ = json.Unmarshal(m.Params, &raw)
	if raw == nil {
		raw = map[string]json.RawMessage{}
	}
	nm, _ := json.Marshal(route.realName)
	raw["name"] = nm
	fwd, _ := json.Marshal(raw)
	resp, err := route.up.callRaw(ctx, "tools/call", fwd)
	if err != nil {
		_, _ = p.log.Append(withEvent(base, audit.EventFailed, err.Error()))
		p.replyError(m.ID, jsonrpc.CodeInternal, "upstream error: "+err.Error())
		return
	}
	if resp.Error != nil {
		_, _ = p.log.Append(withEvent(base, audit.EventFailed, resp.Error.Message))
		p.send(&jsonrpc.Message{ID: m.ID, Error: resp.Error})
		return
	}
	_, _ = p.log.Append(withEvent(base, audit.EventCompleted, summarizeResult(resp.Result)))
	p.send(&jsonrpc.Message{ID: m.ID, Result: resp.Result})
}

// startProgress keeps the client informed (and the connection warm) while a
// call waits for a human, if the client supplied a progress token.
func (p *Proxy) startProgress(params toolCallParams, req *approvals.Request) func() {
	if params.Meta == nil || len(params.Meta.ProgressToken) == 0 {
		return func() {}
	}
	stop := make(chan struct{})
	go func() {
		t := time.NewTicker(15 * time.Second)
		defer t.Stop()
		send := func(msg string) {
			n, _ := jsonrpc.NewNotification("notifications/progress", map[string]any{
				"progressToken": params.Meta.ProgressToken, "progress": 0, "message": msg,
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

// forwardFirstSuccess tries each upstream in order and returns the first
// non-error response (or the last error).
func (p *Proxy) forwardFirstSuccess(ctx context.Context, m *jsonrpc.Message) {
	var last *jsonrpc.Message
	for _, u := range p.upstreams {
		resp, err := u.callRaw(ctx, m.Method, m.Params)
		if err != nil {
			last = jsonrpc.NewError(m.ID, jsonrpc.CodeInternal, err.Error())
			continue
		}
		if resp.Error == nil {
			p.send(&jsonrpc.Message{ID: m.ID, Result: resp.Result})
			return
		}
		last = &jsonrpc.Message{ID: m.ID, Error: resp.Error}
	}
	if last == nil {
		last = jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "no upstream handled "+m.Method)
	}
	p.send(last)
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

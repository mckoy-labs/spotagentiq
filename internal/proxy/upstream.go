package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/config"
	"github.com/mckoy-labs/spotagentiq/internal/jsonrpc"
)

// upstream is one child MCP server speaking JSON-RPC over its stdio.
type upstream struct {
	name string
	cfg  config.Upstream
	cmd  *exec.Cmd
	conn *jsonrpc.Conn

	nextID  atomic.Int64
	pending sync.Map // int64 -> chan *jsonrpc.Message

	capabilities json.RawMessage
	serverInfo   json.RawMessage

	// onNotification receives server->client notifications.
	onNotification func(u *upstream, m *jsonrpc.Message)
	// onRequest receives server->client requests (sampling, roots, elicitation).
	onRequest func(u *upstream, m *jsonrpc.Message)

	closed chan struct{}
	once   sync.Once
}

// baseEnv is what an upstream needs to start at all: where to find programs,
// a home and temp directory, locale, and proxy/CA settings. It matches the
// defaults MCP SDKs use for stdio servers, and deliberately leaves out
// everything else in our environment.
var baseEnv = []string{
	"PATH", "HOME", "USER", "LOGNAME", "SHELL", "TERM", "LANG", "LC_ALL", "LC_CTYPE", "TZ",
	"TMPDIR", "TMP", "TEMP",
	"HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy",
	"SSL_CERT_FILE", "SSL_CERT_DIR", "NODE_EXTRA_CA_CERTS",
	// Windows
	"SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "PATHEXT", "USERNAME", "USERPROFILE",
	"HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES",
	"PROGRAMFILES(X86)", "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS",
}

// upstreamEnv builds the environment for one upstream server.
//
// Upstreams are third-party code. If they inherited our environment they
// would see the inbox token (and could approve held calls themselves) and
// every other upstream's credentials. So by default each gets baseEnv plus
// only what its own "env" block lists. inherit_env opts a server back into
// the full environment, still without the token.
func upstreamEnv(cfg config.Upstream, parent []string, token string) []string {
	keep := func(name, value string) bool {
		if strings.EqualFold(name, "SPOTAGENTIQ_TOKEN") || (token != "" && value == token) {
			return false
		}
		if cfg.InheritEnv {
			return true
		}
		for _, b := range baseEnv {
			if strings.EqualFold(name, b) {
				return true
			}
		}
		return false
	}
	var env []string
	for _, kv := range parent {
		name, value, ok := strings.Cut(kv, "=")
		if ok && name != "" && keep(name, value) {
			env = append(env, kv)
		}
	}
	names := make([]string, 0, len(cfg.Env))
	for k := range cfg.Env {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		env = append(env, k+"="+cfg.Env[k])
	}
	return env
}

func startUpstream(cfg config.Upstream, token string) (*upstream, error) {
	cmd := exec.Command(cfg.Command, cfg.Args...)
	cmd.Env = upstreamEnv(cfg, os.Environ(), token)
	if cfg.Cwd != "" {
		cmd.Dir = cfg.Cwd
	}
	cmd.Stderr = &prefixWriter{prefix: "[" + cfg.Name + "] ", w: os.Stderr}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start upstream %q: %w", cfg.Name, err)
	}
	u := &upstream{
		name:   cfg.Name,
		cfg:    cfg,
		cmd:    cmd,
		conn:   jsonrpc.NewConn(stdout, stdin),
		closed: make(chan struct{}),
	}
	go u.readLoop()
	return u, nil
}

func (u *upstream) readLoop() {
	defer u.once.Do(func() { close(u.closed) })
	for {
		m, err := u.conn.Read()
		if err != nil {
			if !errors.Is(err, jsonrpc.ErrClosed) {
				log.Printf("upstream %s: read error: %v", u.name, err)
			}
			// Fail any pending calls.
			u.pending.Range(func(k, v any) bool {
				ch := v.(chan *jsonrpc.Message)
				select {
				case ch <- jsonrpc.NewError(nil, jsonrpc.CodeInternal, "upstream "+u.name+" disconnected"):
				default:
				}
				u.pending.Delete(k)
				return true
			})
			return
		}
		switch {
		case m.IsResponse():
			var id int64
			if err := json.Unmarshal(m.ID, &id); err != nil {
				log.Printf("upstream %s: response with non-numeric id %s", u.name, m.ID)
				continue
			}
			if chv, ok := u.pending.LoadAndDelete(id); ok {
				chv.(chan *jsonrpc.Message) <- m
			}
		case m.IsRequest():
			if u.onRequest != nil {
				u.onRequest(u, m)
			}
		case m.IsNotification():
			if u.onNotification != nil {
				u.onNotification(u, m)
			}
		}
	}
}

// call sends a request and waits for its response.
func (u *upstream) call(ctx context.Context, method string, params any) (*jsonrpc.Message, error) {
	var p json.RawMessage
	if params != nil {
		var err error
		if p, err = json.Marshal(params); err != nil {
			return nil, err
		}
	}
	return u.callRaw(ctx, method, p)
}

// callRaw forwards a request whose params are already encoded.
func (u *upstream) callRaw(ctx context.Context, method string, params json.RawMessage) (*jsonrpc.Message, error) {
	id := u.nextID.Add(1)
	idRaw, _ := json.Marshal(id)
	req := &jsonrpc.Message{JSONRPC: "2.0", ID: idRaw, Method: method, Params: params}
	ch := make(chan *jsonrpc.Message, 1)
	u.pending.Store(id, ch)
	if err := u.conn.Write(req); err != nil {
		u.pending.Delete(id)
		return nil, err
	}
	select {
	case resp := <-ch:
		return resp, nil
	case <-ctx.Done():
		u.pending.Delete(id)
		return nil, ctx.Err()
	case <-u.closed:
		return nil, fmt.Errorf("upstream %s exited", u.name)
	}
}

func (u *upstream) notify(method string, params any) error {
	n, err := jsonrpc.NewNotification(method, params)
	if err != nil {
		return err
	}
	return u.conn.Write(n)
}

// write sends an arbitrary message (used to relay client responses to
// upstream-originated requests).
func (u *upstream) write(m *jsonrpc.Message) error { return u.conn.Write(m) }

func (u *upstream) stop() {
	if u.cmd.Process == nil {
		return
	}
	// Closing stdin is the polite MCP shutdown; fall back to a kill.
	if w, ok := u.conn.Writer().(io.Closer); ok {
		_ = w.Close()
	}
	done := make(chan struct{})
	go func() { _ = u.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = u.cmd.Process.Kill()
		<-done
	}
}

// prefixWriter tags each line of upstream stderr so logs stay readable.
type prefixWriter struct {
	prefix string
	w      io.Writer
	mu     sync.Mutex
	buf    []byte
}

func (p *prefixWriter) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.buf = append(p.buf, b...)
	for {
		i := indexByte(p.buf, '\n')
		if i < 0 {
			break
		}
		line := p.buf[:i+1]
		_, _ = p.w.Write(append([]byte(p.prefix), line...))
		p.buf = p.buf[i+1:]
	}
	return len(b), nil
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

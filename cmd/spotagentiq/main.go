// Command spotagentiq puts a human approval step between an AI agent and the
// tools it calls, and keeps a tamper-evident log of everything.
//
//	spotagentiq serve --config spotagentiq.json   # run as an MCP server (stdio)
//	spotagentiq init  > spotagentiq.json          # write a starter config
//	spotagentiq verify --log audit.jsonl         # check the hash chain
//	spotagentiq export --log audit.jsonl > a.csv # CSV for auditors
//	spotagentiq demo                             # 60-second guided demo
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/approvals"
	"github.com/mckoy-labs/spotagentiq/internal/audit"
	"github.com/mckoy-labs/spotagentiq/internal/config"
	"github.com/mckoy-labs/spotagentiq/internal/demo"
	"github.com/mckoy-labs/spotagentiq/internal/inbox"
	"github.com/mckoy-labs/spotagentiq/internal/notify"
	"github.com/mckoy-labs/spotagentiq/internal/policy"
	"github.com/mckoy-labs/spotagentiq/internal/proxy"
)

var version = "0.1.0"

func main() {
	log.SetFlags(log.Ltime)
	log.SetOutput(os.Stderr) // stdout is the MCP channel; never log there
	proxy.Version = version

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = cmdServe(os.Args[2:])
	case "init":
		err = cmdInit(os.Args[2:])
	case "verify":
		err = cmdVerify(os.Args[2:])
	case "export":
		err = cmdExport(os.Args[2:])
	case "demo":
		err = cmdDemo(os.Args[2:])
	case "demo-upstream":
		err = demo.RunUpstream()
	case "version", "--version", "-v":
		fmt.Println("spotagentiq", version)
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `spotagentiq — human approval and audit for AI agent tool calls

Usage:
  spotagentiq serve  --config spotagentiq.json    Run as an MCP server over stdio
  spotagentiq init                               Print a starter config
  spotagentiq verify --log audit.jsonl           Verify the audit log hash chain
  spotagentiq export --log audit.jsonl           Write the audit log as CSV to stdout
  spotagentiq demo   [--listen 127.0.0.1:8484]   Guided demo with a fake CRM
  spotagentiq version

Point your agent (Claude Desktop, Claude Code, Cursor, your own code) at
"spotagentiq serve" instead of at the tool server. SpotAgentIQ launches the real
server, forwards everything, and holds or blocks calls according to your rules.
`)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "spotagentiq.json", "path to config file")
	_ = fs.Parse(args)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	pol, err := policy.Compile(cfg.Rules, cfg.DefaultAction, cfg.Redact)
	if err != nil {
		return err
	}
	lg, err := audit.Open(cfg.LogPath)
	if err != nil {
		return fmt.Errorf("open audit log: %w", err)
	}
	defer lg.Close()

	slack := &notify.Slack{WebhookURL: cfg.SlackWebhook, PublicURL: cfg.PublicURL}
	store := approvals.New(func(r *approvals.Request) { go slack.NotifyPending(r) })

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if cfg.Listen != "" {
		srv := &inbox.Server{Store: store, LogPath: cfg.LogPath, Token: cfg.Token, Agent: cfg.Agent, Policy: pol, Version: version}
		ln, err := net.Listen("tcp", cfg.Listen)
		if err != nil {
			return fmt.Errorf("inbox listen %s: %w", cfg.Listen, err)
		}
		if !loopbackOnly(cfg.Listen) {
			log.Printf("spotagentiq: WARNING: the inbox on %s is reachable from other machines over plain HTTP. Put TLS in front of it, or set \"listen\": \"127.0.0.1:8484\".", cfg.Listen)
			if len(cfg.Token) < 16 {
				log.Printf("spotagentiq: WARNING: the inbox token is short (%d characters). Generate one with: openssl rand -hex 16", len(cfg.Token))
			}
		}
		hs := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := hs.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("inbox: %v", err)
			}
		}()
		defer func() {
			sctx, scancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer scancel()
			_ = hs.Shutdown(sctx)
		}()
		log.Printf("spotagentiq: inbox at %s", cfg.PublicURL)
	}

	p := proxy.New(cfg, pol, lg, store, os.Stdin, os.Stdout)
	return p.Run(ctx)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	_ = fs.Parse(args)
	cfg := map[string]any{
		"agent":            "my-agent",
		"principal":        "",
		"listen":           "127.0.0.1:8484",
		"public_url":       "http://localhost:8484",
		"token":            "${SPOTAGENTIQ_TOKEN}",
		"log_path":         "spotagentiq.audit.jsonl",
		"approval_timeout": "10m",
		"default_action":   "allow",
		"slack_webhook":    "${SLACK_WEBHOOK_URL}",
		"upstreams": []map[string]any{
			{"name": "example", "command": "npx", "args": []string{"-y", "@modelcontextprotocol/server-filesystem", "/path/to/allowed/dir"}},
		},
		"rules": []map[string]any{
			{"match": "*", "action": "deny", "if_args_match": `\b\d{13,19}\b`, "reason": "Argument looks like a card number"},
			{"match": "send_*", "action": "require_approval", "reason": "Outbound communication"},
			{"match": "delete_*", "action": "require_approval", "reason": "Destructive action"},
			{"match": "pay_*", "action": "require_approval", "reason": "Moves money"},
			{"match": "write_*", "action": "require_approval", "reason": "Modifies data"},
		},
		"redact": []string{"password", "token", "api_key", "secret", "ssn", "card_number"},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	fmt.Println(string(b))
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	logPath := fs.String("log", "spotagentiq.audit.jsonl", "audit log path")
	asJSON := fs.Bool("json", false, "machine-readable output")
	_ = fs.Parse(args)
	res, err := audit.Verify(*logPath)
	if err != nil {
		return err
	}
	if *asJSON {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else if res.OK {
		fmt.Printf("OK: %d entries, chain intact. Last hash %s\n", res.Entries, res.LastHash)
	} else {
		fmt.Printf("TAMPERED: entry #%d — %s\n", res.BadSeq, res.Problem)
	}
	if !res.OK {
		os.Exit(3)
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	logPath := fs.String("log", "spotagentiq.audit.jsonl", "audit log path")
	_ = fs.Parse(args)
	entries, err := audit.ReadAll(*logPath)
	if err != nil {
		return err
	}
	return audit.WriteCSV(os.Stdout, entries)
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1:8484", "inbox address")
	_ = fs.Parse(args)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return demo.RunAgent(self, *listen)
}

// loopbackOnly reports whether a listen address accepts connections from this
// machine only.
func loopbackOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false // ":8484" binds every interface
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

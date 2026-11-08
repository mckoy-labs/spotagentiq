// Command gatekeeper puts a human approval step between an AI agent and the
// tools it calls, and keeps a tamper-evident log of everything.
//
//	gatekeeper serve --config gatekeeper.json   # run as an MCP server (stdio)
//	gatekeeper init  > gatekeeper.json          # write a starter config
//	gatekeeper verify --log audit.jsonl         # check the hash chain
//	gatekeeper export --log audit.jsonl > a.csv # CSV for auditors
//	gatekeeper demo                             # 60-second guided demo
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

	"github.com/gatekeeper-run/gatekeeper/internal/approvals"
	"github.com/gatekeeper-run/gatekeeper/internal/audit"
	"github.com/gatekeeper-run/gatekeeper/internal/config"
	"github.com/gatekeeper-run/gatekeeper/internal/demo"
	"github.com/gatekeeper-run/gatekeeper/internal/inbox"
	"github.com/gatekeeper-run/gatekeeper/internal/notify"
	"github.com/gatekeeper-run/gatekeeper/internal/policy"
	"github.com/gatekeeper-run/gatekeeper/internal/proxy"
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
		fmt.Println("gatekeeper", version)
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
	fmt.Fprint(os.Stderr, `gatekeeper — human approval and audit for AI agent tool calls

Usage:
  gatekeeper serve  --config gatekeeper.json    Run as an MCP server over stdio
  gatekeeper init                               Print a starter config
  gatekeeper verify --log audit.jsonl           Verify the audit log hash chain
  gatekeeper export --log audit.jsonl           Write the audit log as CSV to stdout
  gatekeeper demo   [--listen :8484]            Guided demo with a fake CRM
  gatekeeper version

Point your agent (Claude Desktop, Claude Code, Cursor, your own code) at
"gatekeeper serve" instead of at the tool server. Gatekeeper launches the real
server, forwards everything, and holds or blocks calls according to your rules.
`)
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "gatekeeper.json", "path to config file")
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
		log.Printf("gatekeeper: inbox at %s", cfg.PublicURL)
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
		"listen":           ":8484",
		"public_url":       "http://localhost:8484",
		"token":            "${GATEKEEPER_TOKEN}",
		"log_path":         "gatekeeper.audit.jsonl",
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
	logPath := fs.String("log", "gatekeeper.audit.jsonl", "audit log path")
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
	logPath := fs.String("log", "gatekeeper.audit.jsonl", "audit log path")
	_ = fs.Parse(args)
	entries, err := audit.ReadAll(*logPath)
	if err != nil {
		return err
	}
	return audit.WriteCSV(os.Stdout, entries)
}

func cmdDemo(args []string) error {
	fs := flag.NewFlagSet("demo", flag.ExitOnError)
	listen := fs.String("listen", ":8484", "inbox address")
	_ = fs.Parse(args)
	self, err := os.Executable()
	if err != nil {
		return err
	}
	return demo.RunAgent(self, *listen)
}

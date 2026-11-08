// Package config loads spotagentiq.json.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/policy"
)

// Upstream is an MCP server SpotAgentIQ launches and fronts.
type Upstream struct {
	Name    string            `json:"name"`
	Command string            `json:"command"`
	Args    []string          `json:"args,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
}

// Config is the on-disk configuration.
type Config struct {
	// Agent identifies the agent in logs and Slack messages.
	Agent string `json:"agent"`
	// Principal is the human the agent acts on behalf of (optional).
	Principal string `json:"principal,omitempty"`
	// Listen is the inbox HTTP address, e.g. ":8484". Empty disables the inbox
	// (approvals then always time out, so only do that with no approval rules).
	Listen string `json:"listen"`
	// PublicURL is the inbox URL as humans reach it, used in notifications.
	PublicURL string `json:"public_url,omitempty"`
	// Token protects the inbox. Supports ${ENV_VAR} expansion.
	Token string `json:"token"`
	// LogPath is the audit log file.
	LogPath string `json:"log_path"`
	// ApprovalTimeout is how long a held call waits, e.g. "10m".
	ApprovalTimeout string `json:"approval_timeout"`
	// DefaultAction applies when no rule matches.
	DefaultAction policy.Action `json:"default_action"`
	// SlackWebhook is an incoming-webhook URL. Supports ${ENV_VAR} expansion.
	SlackWebhook string `json:"slack_webhook,omitempty"`
	// Upstreams are the MCP servers behind the gate.
	Upstreams []Upstream `json:"upstreams"`
	// Rules are evaluated in order; first match wins.
	Rules []policy.Rule `json:"rules"`
	// Redact lists argument keys whose values are masked in logs and the inbox.
	Redact []string `json:"redact,omitempty"`
}

// Load reads and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	c.applyDefaults()
	c.Token = expandEnv(c.Token)
	c.SlackWebhook = expandEnv(c.SlackWebhook)
	for i := range c.Upstreams {
		for k, v := range c.Upstreams[i].Env {
			c.Upstreams[i].Env[k] = expandEnv(v)
		}
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) applyDefaults() {
	if c.Agent == "" {
		c.Agent = "agent"
	}
	if c.LogPath == "" {
		c.LogPath = "spotagentiq.audit.jsonl"
	}
	if c.ApprovalTimeout == "" {
		c.ApprovalTimeout = "10m"
	}
	if c.DefaultAction == "" {
		c.DefaultAction = policy.Allow
	}
	if c.PublicURL == "" && c.Listen != "" {
		host := c.Listen
		if host[0] == ':' {
			host = "localhost" + host
		}
		c.PublicURL = "http://" + host
	}
	if c.Token == "" {
		c.Token = os.Getenv("SPOTAGENTIQ_TOKEN")
	}
}

// Validate checks the config for obvious mistakes.
func (c *Config) Validate() error {
	if len(c.Upstreams) == 0 {
		return errors.New("config: at least one upstream is required")
	}
	seen := map[string]bool{}
	for i, u := range c.Upstreams {
		if u.Name == "" {
			return fmt.Errorf("config: upstreams[%d].name is required", i)
		}
		if u.Command == "" {
			return fmt.Errorf("config: upstreams[%d].command is required", i)
		}
		if seen[u.Name] {
			return fmt.Errorf("config: duplicate upstream name %q", u.Name)
		}
		seen[u.Name] = true
	}
	if _, err := time.ParseDuration(c.ApprovalTimeout); err != nil {
		return fmt.Errorf("config: approval_timeout: %w", err)
	}
	if _, err := policy.Compile(c.Rules, c.DefaultAction, c.Redact); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	needsInbox := c.DefaultAction == policy.RequireApproval
	for _, r := range c.Rules {
		if r.Action == policy.RequireApproval || r.Action == "approve" {
			needsInbox = true
		}
	}
	if needsInbox && c.Listen == "" {
		return errors.New("config: rules require approval but listen is empty; set listen (e.g. \":8484\")")
	}
	if c.Listen != "" && c.Token == "" {
		return errors.New("config: token is required when the inbox is enabled (set token or SPOTAGENTIQ_TOKEN)")
	}
	return nil
}

// Timeout returns the parsed approval timeout.
func (c *Config) Timeout() time.Duration {
	d, _ := time.ParseDuration(c.ApprovalTimeout)
	return d
}

var envRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

func expandEnv(s string) string {
	return envRe.ReplaceAllStringFunc(s, func(m string) string {
		name := envRe.FindStringSubmatch(m)[1]
		return os.Getenv(name)
	})
}

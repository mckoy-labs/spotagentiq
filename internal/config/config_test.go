package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func load(t *testing.T, body string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestExpandsEnvInArgsAndEnv(t *testing.T) {
	t.Setenv("DB_URL", "postgres://x")
	t.Setenv("KEY", "k123")
	c, err := load(t, `{"upstreams":[{"name":"db","command":"npx","args":["srv","${DB_URL}"],"env":{"API_KEY":"${KEY}"}}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if c.Upstreams[0].Args[1] != "postgres://x" || c.Upstreams[0].Env["API_KEY"] != "k123" {
		t.Errorf("not expanded: %+v", c.Upstreams[0])
	}
}

func TestRejectsAmbiguousUpstreamNames(t *testing.T) {
	for _, name := range []string{"a/b", "mcp", "has space", "star*"} {
		_, err := load(t, `{"upstreams":[{"name":"`+name+`","command":"x"}]}`)
		if err == nil || !strings.Contains(err.Error(), "upstream name") {
			t.Errorf("name %q: want an upstream name error, got %v", name, err)
		}
	}
}

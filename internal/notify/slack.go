// Package notify sends approval alerts to humans.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gatekeeper-run/gatekeeper/internal/approvals"
)

// Slack posts to an incoming-webhook URL.
type Slack struct {
	WebhookURL string
	PublicURL  string // base URL of the inbox, for the "Review" link
	Client     *http.Client
}

// NotifyPending posts a message about a request that needs a decision. Errors
// are logged, not returned: a notification failure must never block the agent.
func (s *Slack) NotifyPending(r *approvals.Request) {
	if s == nil || s.WebhookURL == "" {
		return
	}
	args := string(r.Args)
	if len(args) > 600 {
		args = args[:600] + "…"
	}
	link := strings.TrimRight(s.PublicURL, "/") + "/#" + r.ID
	text := fmt.Sprintf(":lock: *Gatekeeper: approval needed*\nAgent `%s` wants to call `%s`\n*Why held:* %s\n*Arguments:*\n```%s```\n<%s|Review in inbox> · expires %s",
		r.Agent, r.Tool, r.Reason, args, link, r.ExpiresAt.Format(time.Kitchen))
	payload, _ := json.Marshal(map[string]any{"text": text})

	client := s.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.WebhookURL, bytes.NewReader(payload))
	if err != nil {
		log.Printf("slack: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("slack: post failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		log.Printf("slack: webhook returned %s", resp.Status)
	}
}

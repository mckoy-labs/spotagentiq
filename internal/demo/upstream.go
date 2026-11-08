// Package demo contains a fake tool server and a scripted agent used to show
// SpotAgentIQ in action without any real systems attached.
package demo

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mckoy-labs/spotagentiq/internal/jsonrpc"
)

// RunUpstream serves a tiny MCP server over stdio with tools that look like a
// CRM: read a customer, email them, charge them, delete their record.
func RunUpstream() error {
	conn := jsonrpc.NewConn(os.Stdin, os.Stdout)
	tools := []map[string]any{
		{"name": "get_customer", "description": "Look up a customer by id.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"id": map[string]any{"type": "string"}}, "required": []string{"id"}}},
		{"name": "send_email", "description": "Send an email to a customer.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
				"to": map[string]any{"type": "string"}, "subject": map[string]any{"type": "string"}, "body": map[string]any{"type": "string"}}, "required": []string{"to", "subject", "body"}}},
		{"name": "charge_card", "description": "Charge a stored card.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
				"customer_id": map[string]any{"type": "string"}, "amount": map[string]any{"type": "number"}, "card_number": map[string]any{"type": "string"}}, "required": []string{"customer_id", "amount"}}},
		{"name": "delete_record", "description": "Permanently delete a record.",
			"inputSchema": map[string]any{"type": "object", "properties": map[string]any{
				"table": map[string]any{"type": "string"}, "id": map[string]any{"type": "string"}}, "required": []string{"table", "id"}}},
	}
	for {
		m, err := conn.Read()
		if err != nil {
			if err == jsonrpc.ErrClosed {
				return nil
			}
			return err
		}
		if !m.IsRequest() {
			continue
		}
		switch m.Method {
		case "initialize":
			reply(conn, m.ID, map[string]any{
				"protocolVersion": "2025-06-18",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "demo-crm", "version": "0.0.1"},
			})
		case "ping":
			reply(conn, m.ID, map[string]any{})
		case "tools/list":
			reply(conn, m.ID, map[string]any{"tools": tools})
		case "tools/call":
			var p struct {
				Name string         `json:"name"`
				Args map[string]any `json:"arguments"`
			}
			_ = json.Unmarshal(m.Params, &p)
			reply(conn, m.ID, text(handleTool(p.Name, p.Args)))
		default:
			_ = conn.Write(jsonrpc.NewError(m.ID, jsonrpc.CodeMethodNotFound, "method not found: "+m.Method))
		}
	}
}

func handleTool(name string, args map[string]any) string {
	time.Sleep(150 * time.Millisecond) // feel like a real API
	switch name {
	case "get_customer":
		return fmt.Sprintf(`{"id":%q,"name":"Marisol Vega","email":"marisol@example.com","plan":"pro","balance_due":129.00}`, str(args["id"]))
	case "send_email":
		return fmt.Sprintf("Email sent to %s with subject %q.", str(args["to"]), str(args["subject"]))
	case "charge_card":
		return fmt.Sprintf("Charged %v to customer %s.", args["amount"], str(args["customer_id"]))
	case "delete_record":
		return fmt.Sprintf("Deleted %s/%s. This cannot be undone.", str(args["table"]), str(args["id"]))
	}
	return "unknown tool"
}

func str(v any) string { s, _ := v.(string); return s }

func text(s string) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": s}}}
}

func reply(c *jsonrpc.Conn, id json.RawMessage, v any) {
	m, _ := jsonrpc.NewResult(id, v)
	_ = c.Write(m)
}

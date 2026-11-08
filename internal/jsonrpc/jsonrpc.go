// Package jsonrpc implements the minimal JSON-RPC 2.0 framing used by the
// Model Context Protocol over stdio: one JSON object per line.
package jsonrpc

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// Message is a loosely-typed JSON-RPC 2.0 envelope. A message is a request if
// it has both Method and ID, a notification if it has Method but no ID, and a
// response if it has ID but no Method.
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Error is a JSON-RPC error object.
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// Standard error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// IsRequest reports whether m is a request expecting a response.
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 && string(m.ID) != "null" }

// IsNotification reports whether m is a notification.
func (m *Message) IsNotification() bool {
	return m.Method != "" && (len(m.ID) == 0 || string(m.ID) == "null")
}

// IsResponse reports whether m is a response to an earlier request.
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// NewRequest builds a request message.
func NewRequest(id any, method string, params any) (*Message, error) {
	idRaw, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}
	var p json.RawMessage
	if params != nil {
		p, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}
	return &Message{JSONRPC: "2.0", ID: idRaw, Method: method, Params: p}, nil
}

// NewNotification builds a notification message.
func NewNotification(method string, params any) (*Message, error) {
	var p json.RawMessage
	if params != nil {
		var err error
		p, err = json.Marshal(params)
		if err != nil {
			return nil, err
		}
	}
	return &Message{JSONRPC: "2.0", Method: method, Params: p}, nil
}

// NewResult builds a successful response for the given request id.
func NewResult(id json.RawMessage, result any) (*Message, error) {
	r, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	return &Message{JSONRPC: "2.0", ID: id, Result: r}, nil
}

// NewError builds an error response for the given request id.
func NewError(id json.RawMessage, code int, msg string) *Message {
	return &Message{JSONRPC: "2.0", ID: id, Error: &Error{Code: code, Message: msg}}
}

// Conn reads and writes newline-delimited JSON-RPC messages.
type Conn struct {
	r  *bufio.Reader
	w  io.Writer
	mu sync.Mutex
}

// NewConn wraps a reader and writer.
func NewConn(r io.Reader, w io.Writer) *Conn {
	return &Conn{r: bufio.NewReaderSize(r, 1<<20), w: w}
}

// Writer exposes the underlying writer (for closing a child's stdin).
func (c *Conn) Writer() io.Writer { return c.w }

// ErrClosed is returned by Read when the underlying stream ends.
var ErrClosed = errors.New("jsonrpc: connection closed")

// Read reads the next message. Blank lines are skipped.
func (c *Conn) Read() (*Message, error) {
	for {
		line, err := c.r.ReadBytes('\n')
		if len(line) == 0 && err != nil {
			if errors.Is(err, io.EOF) {
				return nil, ErrClosed
			}
			return nil, err
		}
		trimmed := trimSpace(line)
		if len(trimmed) == 0 {
			if err != nil {
				return nil, ErrClosed
			}
			continue
		}
		var m Message
		if jerr := json.Unmarshal(trimmed, &m); jerr != nil {
			return nil, fmt.Errorf("jsonrpc: bad message: %w", jerr)
		}
		return &m, nil
	}
}

// Write serialises and writes one message followed by a newline. Writes are
// serialised so multiple goroutines may share a Conn.
func (c *Conn) Write(m *Message) error {
	if m.JSONRPC == "" {
		m.JSONRPC = "2.0"
	}
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.w.Write(append(b, '\n')); err != nil {
		return err
	}
	if f, ok := c.w.(interface{ Flush() error }); ok {
		return f.Flush()
	}
	return nil
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\r' || b[start] == '\n') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\r' || b[end-1] == '\n') {
		end--
	}
	return b[start:end]
}

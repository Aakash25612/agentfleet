// Package execclient is what the orchestrator (here: the demo and the
// tests) uses to call the executor.
package execclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"agentfleet/internal/executor"
)

type Client struct {
	Base, Token string
	HTTP        *http.Client
}

func New(base, token string) *Client {
	return &Client{Base: base, Token: token, HTTP: &http.Client{Timeout: 5 * time.Minute}}
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, _ := json.Marshal(in)
		body = bytes.NewReader(b)
	}
	req, _ := http.NewRequestWithContext(ctx, method, c.Base+path, body)
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e struct{ Error string }
		json.NewDecoder(resp.Body).Decode(&e)
		return fmt.Errorf("executor %s %s: %d %s", method, path, resp.StatusCode, e.Error)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) Create(ctx context.Context, req executor.CreateRequest) (*executor.Info, error) {
	var s executor.Info
	return &s, c.do(ctx, "POST", "/v1/sessions", req, &s)
}

func (c *Client) Exec(ctx context.Context, id string, req executor.ExecRequest) (*executor.ExecResult, error) {
	var r executor.ExecResult
	return &r, c.do(ctx, "POST", "/v1/sessions/"+id+"/exec", req, &r)
}

func (c *Client) Delete(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/v1/sessions/"+id, nil, nil)
}

func (c *Client) Metrics(ctx context.Context) (map[string]any, error) {
	var m map[string]any
	return m, c.do(ctx, "GET", "/v1/metrics", nil, &m)
}

func (c *Client) List(ctx context.Context) ([]executor.Info, error) {
	var out []executor.Info
	return out, c.do(ctx, "GET", "/v1/sessions", nil, &out)
}

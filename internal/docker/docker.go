// Package docker is the small slice of the Docker Engine API the executor
// needs, over the unix socket, stdlib only. In Kubernetes this role belongs
// to the Agent Sandbox controller (Sandbox/SandboxClaim CRDs), not to us.
package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	sock string
	hc   *http.Client
}

func New(sock string) *Client {
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}
	return &Client{sock: sock, hc: &http.Client{Transport: &http.Transport{DialContext: dial, MaxIdleConns: 64, MaxIdleConnsPerHost: 64}}}
}

type APIError struct {
	Status int
	Msg    string
}

func (e *APIError) Error() string { return fmt.Sprintf("docker: %d %s", e.Status, e.Msg) }

func IsNotFound(err error) bool {
	var ae *APIError
	return errors.As(err, &ae) && ae.Status == http.StatusNotFound
}

func (c *Client) do(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var m struct{ Message string }
		json.NewDecoder(resp.Body).Decode(&m)
		return &APIError{resp.StatusCode, m.Message}
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *Client) Runtimes(ctx context.Context) (map[string]any, error) {
	var info struct{ Runtimes map[string]any }
	err := c.do(ctx, "GET", "/info", nil, &info)
	return info.Runtimes, err
}

// ---- networks ----

type NetworkSpec struct {
	Name     string            `json:"Name"`
	Driver   string            `json:"Driver"`
	Internal bool              `json:"Internal"`
	Labels   map[string]string `json:"Labels,omitempty"`
	Options  map[string]string `json:"Options,omitempty"`
	IPAM     *IPAM             `json:"IPAM,omitempty"`
}

type IPAM struct {
	Config []IPAMConfig `json:"Config"`
}

type IPAMConfig struct {
	Subnet string `json:"Subnet"`
}

func (c *Client) CreateNetwork(ctx context.Context, spec NetworkSpec) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	err := c.do(ctx, "POST", "/networks/create", spec, &out)
	return out.ID, err
}

func (c *Client) RemoveNetwork(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/networks/"+id, nil, nil)
}

func (c *Client) Connect(ctx context.Context, network, container string) error {
	return c.do(ctx, "POST", "/networks/"+network+"/connect", map[string]string{"Container": container}, nil)
}

func (c *Client) Disconnect(ctx context.Context, network, container string) error {
	return c.do(ctx, "POST", "/networks/"+network+"/disconnect", map[string]any{"Container": container, "Force": true}, nil)
}

type Network struct {
	ID         string                                  `json:"Id"`
	Name       string                                  `json:"Name"`
	Labels     map[string]string                       `json:"Labels"`
	Containers map[string]struct{ IPv4Address string } `json:"Containers"`
}

func (c *Client) InspectNetwork(ctx context.Context, id string) (*Network, error) {
	var n Network
	err := c.do(ctx, "GET", "/networks/"+id, nil, &n)
	return &n, err
}

func labelFilter(label string) string {
	f, _ := json.Marshal(map[string][]string{"label": {label}})
	return url.QueryEscape(string(f))
}

func (c *Client) ListNetworks(ctx context.Context, label string) ([]Network, error) {
	var out []Network
	err := c.do(ctx, "GET", "/networks?filters="+labelFilter(label), nil, &out)
	return out, err
}

// ---- containers ----

type ContainerSpec struct {
	Image           string            `json:"Image"`
	Entrypoint      []string          `json:"Entrypoint,omitempty"`
	Cmd             []string          `json:"Cmd,omitempty"`
	Env             []string          `json:"Env,omitempty"`
	User            string            `json:"User,omitempty"`
	WorkingDir      string            `json:"WorkingDir,omitempty"`
	Hostname        string            `json:"Hostname,omitempty"`
	Labels          map[string]string `json:"Labels,omitempty"`
	NetworkDisabled bool              `json:"NetworkDisabled,omitempty"`
	HostConfig      HostConfig        `json:"HostConfig"`
}

type HostConfig struct {
	NetworkMode    string            `json:"NetworkMode,omitempty"`
	Runtime        string            `json:"Runtime,omitempty"`
	ReadonlyRootfs bool              `json:"ReadonlyRootfs"`
	CapDrop        []string          `json:"CapDrop,omitempty"`
	SecurityOpt    []string          `json:"SecurityOpt,omitempty"`
	Memory         int64             `json:"Memory,omitempty"`
	MemorySwap     int64             `json:"MemorySwap,omitempty"`
	NanoCPUs       int64             `json:"NanoCpus,omitempty"`
	PidsLimit      int64             `json:"PidsLimit,omitempty"`
	Tmpfs          map[string]string `json:"Tmpfs,omitempty"`
	IpcMode        string            `json:"IpcMode,omitempty"`
	Ulimits        []Ulimit          `json:"Ulimits,omitempty"`
	LogConfig      *LogConfig        `json:"LogConfig,omitempty"`
}

type Ulimit struct {
	Name string `json:"Name"`
	Soft int64  `json:"Soft"`
	Hard int64  `json:"Hard"`
}

type LogConfig struct {
	Type string `json:"Type"`
}

func (c *Client) CreateContainer(ctx context.Context, name string, spec ContainerSpec) (string, error) {
	var out struct {
		ID string `json:"Id"`
	}
	err := c.do(ctx, "POST", "/containers/create?name="+url.QueryEscape(name), spec, &out)
	return out.ID, err
}

func (c *Client) Start(ctx context.Context, id string) error {
	return c.do(ctx, "POST", "/containers/"+id+"/start", nil, nil)
}

func (c *Client) Remove(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/containers/"+id+"?force=1&v=1", nil, nil)
}

type ContainerState struct {
	ID    string `json:"Id"`
	State struct {
		Running   bool
		OOMKilled bool
		ExitCode  int
	}
	NetworkSettings struct {
		Networks map[string]struct{ IPAddress string }
	}
}

func (c *Client) Inspect(ctx context.Context, id string) (*ContainerState, error) {
	var s ContainerState
	err := c.do(ctx, "GET", "/containers/"+id+"/json", nil, &s)
	return &s, err
}

func (c *Client) ListContainers(ctx context.Context, label string) ([]string, error) {
	var out []struct {
		ID string `json:"Id"`
	}
	if err := c.do(ctx, "GET", "/containers/json?all=1&filters="+labelFilter(label), nil, &out); err != nil {
		return nil, err
	}
	ids := make([]string, len(out))
	for i, o := range out {
		ids[i] = o.ID
	}
	return ids, nil
}

// ---- exec ----

type ExecResult struct {
	ExitCode  int
	Stdout    []byte
	Stderr    []byte
	Truncated bool
}

// Exec runs cmd in a running container, feeding stdin and collecting at
// most maxOut bytes per stream (the rest is read and dropped so the
// process is never blocked on a full pipe).
func (c *Client) Exec(ctx context.Context, id string, cmd []string, stdin []byte, maxOut int) (*ExecResult, error) {
	var created struct {
		ID string `json:"Id"`
	}
	err := c.do(ctx, "POST", "/containers/"+id+"/exec", map[string]any{
		"AttachStdin": stdin != nil, "AttachStdout": true, "AttachStderr": true, "Cmd": cmd,
	}, &created)
	if err != nil {
		return nil, err
	}

	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", c.sock)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	req, _ := http.NewRequest("POST", "http://docker/exec/"+created.ID+"/start",
		bytes.NewReader([]byte(`{"Detach":false,"Tty":false}`)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if err := req.Write(conn); err != nil {
		return nil, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, &APIError{resp.StatusCode, string(b)}
	}

	if stdin != nil {
		go func() {
			conn.Write(stdin)
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				cw.CloseWrite()
			}
		}()
	}

	res := &ExecResult{}
	hdr := make([]byte, 8)
	for {
		if _, err := io.ReadFull(br, hdr); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
		n := int64(binary.BigEndian.Uint32(hdr[4:]))
		dst := &res.Stdout
		if hdr[0] == 2 {
			dst = &res.Stderr
		}
		room := int64(maxOut - len(*dst))
		if room < 0 {
			room = 0
		}
		keep := min(n, room)
		buf := make([]byte, keep)
		if _, err := io.ReadFull(br, buf); err != nil {
			return nil, err
		}
		*dst = append(*dst, buf...)
		if n > keep {
			res.Truncated = true
			if _, err := io.CopyN(io.Discard, br, n-keep); err != nil {
				return nil, err
			}
		}
	}

	// The stream can close a moment before the exec is marked finished.
	for i := 0; ; i++ {
		var st struct {
			Running  bool
			ExitCode int
		}
		if err := c.do(ctx, "GET", "/exec/"+created.ID+"/json", nil, &st); err != nil {
			return nil, err
		}
		if !st.Running || i == 50 {
			res.ExitCode = st.ExitCode
			return res, nil
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Package executor owns sandbox lifecycle: one sandbox per agent run,
// created on the run's first execution tool call, reused for the rest of
// the run, destroyed when the run ends or goes idle.
//
// Mapping to Kubernetes (what this stands in for):
//
//	docker network per session (internal, no gateway)  -> default-deny NetworkPolicy, egress only to the proxy
//	container with runtime=runsc                       -> Pod with runtimeClassName: gvisor (via SandboxClaim)
//	ReadonlyRootfs, CapDrop ALL, no-new-privileges     -> securityContext on the sandbox pod
//	Memory / NanoCPUs / PidsLimit / tmpfs size         -> resources.limits + pid limit + emptyDir sizeLimit
//	proxy admin registration                           -> controller writes pod IP -> run identity mapping
package executor

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"agentfleet/internal/audit"
	"agentfleet/internal/docker"
	"agentfleet/internal/policy"
)

type Config struct {
	Docker         *docker.Client
	Registry       *policy.Registry
	Audit          *audit.Log
	ProxyAdmin     string // http://ip:port of the proxy admin listener
	ProxyToken     string
	ProxyContainer string // container name, connected to every session network
	Runtime        string // "" = auto (runsc if the daemon has it)
	ImageOverride  string
	IdleTTL        time.Duration
	MaxOutput      int
}

type Phases struct {
	Network  int64 `json:"network_ms"`
	Create   int64 `json:"create_ms"`
	Start    int64 `json:"start_ms"`
	Register int64 `json:"register_ms"`
	Ready    int64 `json:"ready_ms"`
	Total    int64 `json:"total_ms"`
}

// Info is the observable state of a sandbox: what an operator sees.
type Info struct {
	ID       string    `json:"id"`
	Tenant   string    `json:"tenant"`
	Agent    string    `json:"agent"`
	Version  int       `json:"agent_version"`
	Run      string    `json:"run"`
	User     string    `json:"user"`
	Runtime  string    `json:"runtime"`
	IP       string    `json:"ip"`
	Created  time.Time `json:"created"`
	Cold     Phases    `json:"cold_start"`
	Execs    int       `json:"execs"`
	Current  string    `json:"current_command,omitempty"`
	LastUsed time.Time `json:"last_used"`
}

type Session struct {
	Info
	container, network string
	slot               int
	agent              *policy.Agent
	run                sync.Mutex // one command at a time per sandbox
	mu                 sync.Mutex // guards the observable fields above
}

type Manager struct {
	cfg  Config
	mu   sync.Mutex
	sess map[string]*Session
	used map[int]bool
	cas  map[string]string

	statsMu sync.Mutex
	cold    []int64
	warm    []int64
}

func New(cfg Config) *Manager {
	if cfg.MaxOutput == 0 {
		cfg.MaxOutput = 64 << 10
	}
	return &Manager{cfg: cfg, sess: map[string]*Session{}, used: map[int]bool{}, cas: map[string]string{}}
}

const label = "agentfleet.session"

// Init picks the runtime and removes sandboxes left behind by a previous
// executor process. Orphans are not adopted: their proxy registrations died
// with the old proxy state, and a run resumes by claiming a fresh sandbox.
func (m *Manager) Init(ctx context.Context) error {
	rts, err := m.cfg.Docker.Runtimes(ctx)
	if err != nil {
		return fmt.Errorf("docker unreachable: %w", err)
	}
	if m.cfg.Runtime == "" {
		m.cfg.Runtime = "runc"
		if _, ok := rts["runsc"]; ok {
			m.cfg.Runtime = "runsc"
		}
	} else if _, ok := rts[m.cfg.Runtime]; !ok {
		return fmt.Errorf("runtime %q not installed in docker (have %v)", m.cfg.Runtime, keys(rts))
	}
	log.Printf("sandbox runtime: %s", m.cfg.Runtime)
	ids, _ := m.cfg.Docker.ListContainers(ctx, label)
	for _, id := range ids {
		m.cfg.Docker.Remove(ctx, id)
	}
	nets, _ := m.cfg.Docker.ListNetworks(ctx, label)
	for _, n := range nets {
		m.cfg.Docker.Disconnect(ctx, n.ID, m.cfg.ProxyContainer)
		m.cfg.Docker.RemoveNetwork(ctx, n.ID)
	}
	if len(ids)+len(nets) > 0 {
		log.Printf("swept %d orphaned sandboxes and %d networks", len(ids), len(nets))
	}
	return nil
}

func keys(m map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (m *Manager) Runtime() string { return m.cfg.Runtime }

type CreateRequest struct {
	Tenant  string `json:"tenant"`
	Agent   string `json:"agent"`
	Version int    `json:"agent_version"`
	Run     string `json:"run"`
	User    string `json:"user"`
}

var ErrNotGranted = errors.New("not granted")

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Each session gets its own /28 out of 10.231.0.0/16 (4096 slots), so we
// never depend on Docker's small default address pool.
func (m *Manager) allocSlot() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := 0; i < 4096; i++ {
		if !m.used[i] {
			m.used[i] = true
			return i, nil
		}
	}
	return 0, errors.New("no free sandbox subnets")
}

func (m *Manager) freeSlot(i int) {
	if i < 0 {
		return
	}
	m.mu.Lock()
	delete(m.used, i)
	m.mu.Unlock()
}

func subnet(slot int) string {
	return fmt.Sprintf("10.231.%d.%d/28", slot/16, (slot%16)*16)
}

func (m *Manager) Create(ctx context.Context, req CreateRequest) (*Session, error) {
	if req.Run == "" || req.User == "" {
		return nil, errors.New("run and user are required: every sandbox is attributable")
	}
	a, err := m.cfg.Registry.Get(req.Tenant, req.Agent, req.Version)
	if err != nil {
		return nil, err
	}
	s := &Session{Info: Info{ID: "s-" + randHex(6), Tenant: a.Tenant, Agent: a.Name, Version: a.Version,
		Run: req.Run, User: req.User, Runtime: m.cfg.Runtime, Created: time.Now()}, agent: a, slot: -1}
	if a.Exec == nil {
		m.audit(s, audit.Event{Kind: "session", Decision: "deny", Reason: "agent has no execution tool grant"})
		return nil, fmt.Errorf("%w: %s has no execution tool", ErrNotGranted, a.Ref())
	}
	t0 := time.Now()
	lap := func() int64 { d := time.Since(t0).Milliseconds(); t0 = time.Now(); return d }
	ok := false
	defer func() {
		if !ok {
			m.teardown(context.Background(), s)
		}
	}()

	if s.slot, err = m.allocSlot(); err != nil {
		return nil, err
	}
	d := m.cfg.Docker
	labels := map[string]string{label: s.ID, "agentfleet.tenant": s.Tenant, "agentfleet.agent": s.Agent, "agentfleet.run": s.Run}
	s.network, err = d.CreateNetwork(ctx, docker.NetworkSpec{
		Name: "af-net-" + s.ID, Driver: "bridge", Internal: true, Labels: labels,
		IPAM: &docker.IPAM{Config: []docker.IPAMConfig{{Subnet: subnet(s.slot)}}},
		// No gateway address on the bridge. Without this an "internal"
		// network still lets the sandbox reach any service the docker host
		// listens on (verified while building this; see README).
		Options: map[string]string{"com.docker.network.bridge.inhibit_ipv4": "true"},
	})
	if err != nil {
		return nil, fmt.Errorf("create network: %w", err)
	}
	if err := d.Connect(ctx, s.network, m.cfg.ProxyContainer); err != nil {
		return nil, fmt.Errorf("attach proxy: %w", err)
	}
	n, err := d.InspectNetwork(ctx, s.network)
	if err != nil {
		return nil, err
	}
	var proxyIP string
	for _, c := range n.Containers {
		proxyIP, _, _ = strings.Cut(c.IPv4Address, "/")
	}
	if proxyIP == "" {
		return nil, errors.New("proxy has no address on session network")
	}
	ca, err := m.tenantCA(ctx, s.Tenant)
	if err != nil {
		return nil, err
	}
	s.Cold.Network = lap()

	secret := randHex(16)
	proxyURL := fmt.Sprintf("http://%s:%s@%s:3128", s.ID, secret, proxyIP)
	sentinel := "af-sentinel-" + s.ID
	lim := a.Exec.Limits
	image := a.Exec.Image
	if m.cfg.ImageOverride != "" {
		image = m.cfg.ImageOverride
	}
	s.container, err = d.CreateContainer(ctx, "af-sbx-"+s.ID, docker.ContainerSpec{
		Image:      image,
		Entrypoint: []string{"/usr/local/bin/af-init"},
		User:       "65534:65534",
		WorkingDir: "/workspace",
		Hostname:   "sandbox",
		Labels:     labels,
		Env: []string{
			"HTTPS_PROXY=" + proxyURL, "https_proxy=" + proxyURL,
			"HTTP_PROXY=" + proxyURL, "http_proxy=" + proxyURL, // plaintext goes to the proxy to be refused and logged
			"NO_PROXY=", "no_proxy=",
			"GH_TOKEN=" + sentinel, "GH_ENTERPRISE_TOKEN=" + sentinel, "GITHUB_TOKEN=" + sentinel,
			"GH_PROMPT_DISABLED=1", "GH_NO_UPDATE_NOTIFIER=1",
			"AF_CA_PEM=" + ca,
			"SSL_CERT_FILE=/tmp/.af/ca.pem", "CURL_CA_BUNDLE=/tmp/.af/ca.pem", "GIT_SSL_CAINFO=/tmp/.af/ca.pem",
			"REQUESTS_CA_BUNDLE=/tmp/.af/ca.pem", "NODE_EXTRA_CA_CERTS=/tmp/.af/ca.pem",
			"HOME=/workspace", "AF_SESSION=" + s.ID,
		},
		HostConfig: docker.HostConfig{
			NetworkMode:    "af-net-" + s.ID,
			Runtime:        m.cfg.Runtime,
			ReadonlyRootfs: true,
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges:true"},
			Memory:         lim.MemoryMB << 20,
			MemorySwap:     lim.MemoryMB << 20,
			NanoCPUs:       int64(lim.CPUs * 1e9),
			PidsLimit:      lim.Pids,
			IpcMode:        "private",
			Tmpfs: map[string]string{
				"/tmp":       "rw,nosuid,nodev,size=64m,mode=1777",
				"/workspace": fmt.Sprintf("rw,nosuid,nodev,size=%dm,uid=65534,gid=65534,mode=0700", lim.DiskMB),
			},
			Ulimits:   []docker.Ulimit{{Name: "nofile", Soft: 1024, Hard: 1024}},
			LogConfig: &docker.LogConfig{Type: "none"},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create sandbox: %w", err)
	}
	s.Cold.Create = lap()

	if err := d.Start(ctx, s.container); err != nil {
		return nil, fmt.Errorf("start sandbox: %w", err)
	}
	st, err := d.Inspect(ctx, s.container)
	if err != nil {
		return nil, err
	}
	for _, nw := range st.NetworkSettings.Networks {
		s.IP = nw.IPAddress
	}
	s.Cold.Start = lap()

	if err := m.proxyCall(ctx, "POST", "/admin/sessions", map[string]any{
		"id": s.ID, "secret": secret, "source_ip": s.IP, "tenant": s.Tenant, "agent": s.Agent,
		"agent_version": s.Version, "run": s.Run, "user": s.User,
	}); err != nil {
		return nil, fmt.Errorf("register with egress proxy: %w", err)
	}
	s.Cold.Register = lap()

	// Ready means a command actually runs and the CA landed.
	r, err := d.Exec(ctx, s.container, []string{"test", "-s", "/tmp/.af/ca.pem"}, nil, 1024)
	if err != nil || r.ExitCode != 0 {
		return nil, fmt.Errorf("sandbox not ready: %v", err)
	}
	s.Cold.Ready = lap()
	s.Cold.Total = s.Cold.Network + s.Cold.Create + s.Cold.Start + s.Cold.Register + s.Cold.Ready
	s.LastUsed = time.Now()

	m.mu.Lock()
	m.sess[s.ID] = s
	m.mu.Unlock()
	m.record(&m.cold, s.Cold.Total)
	m.audit(s, audit.Event{Kind: "session", Decision: "allow",
		Reason: fmt.Sprintf("sandbox created runtime=%s ip=%s cold_start_ms=%d", s.Runtime, s.IP, s.Cold.Total)})
	ok = true
	return s, nil
}

func (m *Manager) tenantCA(ctx context.Context, tenant string) (string, error) {
	m.mu.Lock()
	ca := m.cas[tenant]
	m.mu.Unlock()
	if ca != "" {
		return ca, nil
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", m.cfg.ProxyAdmin+"/admin/ca/"+tenant, nil)
	req.Header.Set("Authorization", "Bearer "+m.cfg.ProxyToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch tenant CA: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("fetch tenant CA: %d", resp.StatusCode)
	}
	m.mu.Lock()
	m.cas[tenant] = string(b)
	m.mu.Unlock()
	return string(b), nil
}

func (m *Manager) proxyCall(ctx context.Context, method, path string, body any) error {
	b, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, method, m.cfg.ProxyAdmin+path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+m.cfg.ProxyToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	return nil
}

func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sess[id]
	return s, ok
}

type ExecRequest struct {
	Call     string `json:"call"`
	Command  string `json:"command"`
	Stdin    string `json:"stdin,omitempty"`
	TimeoutS int    `json:"timeout_s,omitempty"`
}

type ExecResult struct {
	ExitCode   int    `json:"exit_code"`
	Stdout     string `json:"stdout"`
	Stderr     string `json:"stderr"`
	DurationMS int64  `json:"duration_ms"`
	TimedOut   bool   `json:"timed_out,omitempty"`
	Killed     bool   `json:"killed,omitempty"`
	Truncated  bool   `json:"truncated,omitempty"`
}

func (m *Manager) Exec(ctx context.Context, id string, req ExecRequest) (*ExecResult, error) {
	s, ok := m.Get(id)
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	if req.Call == "" || req.Command == "" {
		return nil, errors.New("call and command are required")
	}
	limit := s.agent.Exec.Limits.TimeoutS
	if req.TimeoutS > 0 && req.TimeoutS < limit {
		limit = req.TimeoutS
	}

	s.run.Lock()
	defer s.run.Unlock()
	if _, ok := m.Get(id); !ok {
		return nil, fmt.Errorf("session %s was closed", id)
	}
	s.mu.Lock()
	s.Current, s.LastUsed = req.Command, time.Now()
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.Current, s.LastUsed = "", time.Now()
		s.mu.Unlock()
	}()

	// The intent is recorded before anything runs. If we crash mid-command
	// the auditor still sees that it was started, by whom, and for which
	// tool call; the missing exec_result says it never finished.
	reqID := randHex(8)
	if err := m.audit(s, audit.Event{Kind: "exec", Decision: "allow", Call: req.Call, Req: reqID, Command: req.Command}); err != nil {
		return nil, fmt.Errorf("audit unavailable, refusing to run: %w", err)
	}
	if err := m.proxyCall(ctx, "PUT", "/admin/sessions/"+id+"/call", map[string]string{"call": req.Call}); err != nil {
		return nil, fmt.Errorf("tag egress with call id: %w", err)
	}
	defer m.proxyCall(context.Background(), "PUT", "/admin/sessions/"+id+"/call", map[string]string{"call": ""})

	var stdin []byte
	if req.Stdin != "" {
		stdin = []byte(req.Stdin)
	}
	cmd := []string{"timeout", "-k", "2", strconv.Itoa(limit), "bash", "-c", req.Command}
	// Outer guard: background children can hold stdout open past the
	// in-sandbox timeout; then we kill every process in the sandbox.
	ectx, cancel := context.WithTimeout(ctx, time.Duration(limit+5)*time.Second)
	defer cancel()
	start := time.Now()
	r, err := m.cfg.Docker.Exec(ectx, s.container, cmd, stdin, m.cfg.MaxOutput)
	out := &ExecResult{DurationMS: time.Since(start).Milliseconds()}
	switch {
	case err != nil && ectx.Err() != nil:
		m.cfg.Docker.Exec(context.Background(), s.container, []string{"kill", "-9", "-1"}, nil, 0)
		out.ExitCode, out.TimedOut, out.Killed = 137, true, true
		out.Stderr = "agentfleet: command exceeded its time limit; all processes in the sandbox were killed"
	case err != nil:
		st, ierr := m.cfg.Docker.Inspect(context.Background(), s.container)
		if ierr == nil && st.State.Running {
			m.audit(s, audit.Event{Kind: "exec_result", Decision: "info", Call: req.Call, Req: reqID, Reason: err.Error()})
			return nil, err
		}
		// The sandbox itself is gone (under gVisor an OOM takes the whole
		// sandbox, not one process). Report it as a result the model can act
		// on, and drop the session: the next exec call claims a fresh one.
		oom := ierr == nil && st.State.OOMKilled
		out.ExitCode, out.Killed = 137, true
		out.Stderr = fmt.Sprintf("agentfleet: sandbox terminated (oom_killed=%v); workspace lost, a new sandbox will be claimed", oom)
		go m.Delete(context.Background(), id, "sandbox terminated during exec")
	default:
		out.ExitCode, out.Truncated = r.ExitCode, r.Truncated
		out.Stdout, out.Stderr = string(r.Stdout), string(r.Stderr)
		out.TimedOut = r.ExitCode == 124 || (r.ExitCode == 137 && out.DurationMS >= int64(limit)*1000)
		out.Killed = r.ExitCode == 137
	}
	code := out.ExitCode
	m.audit(s, audit.Event{Kind: "exec_result", Decision: "info", Call: req.Call, Req: reqID,
		ExitCode: &code, DurationMS: out.DurationMS, TimedOut: out.TimedOut, Bytes: int64(len(out.Stdout) + len(out.Stderr))})

	s.mu.Lock()
	s.Execs++
	s.mu.Unlock()
	m.record(&m.warm, out.DurationMS)
	return out, nil
}

func (m *Manager) Delete(ctx context.Context, id string, reason string) error {
	m.mu.Lock()
	s, ok := m.sess[id]
	delete(m.sess, id)
	m.mu.Unlock()
	if !ok {
		return fmt.Errorf("session %s not found", id)
	}
	m.teardown(ctx, s)
	m.audit(s, audit.Event{Kind: "session", Decision: "info", Reason: "sandbox destroyed: " + reason})
	return nil
}

func (m *Manager) teardown(ctx context.Context, s *Session) {
	d := m.cfg.Docker
	m.proxyCall(ctx, "DELETE", "/admin/sessions/"+s.ID, nil)
	if s.container != "" {
		d.Remove(ctx, s.container)
	}
	if s.network != "" {
		d.Disconnect(ctx, s.network, m.cfg.ProxyContainer)
		if err := d.RemoveNetwork(ctx, s.network); err != nil && !docker.IsNotFound(err) {
			log.Printf("remove network %s: %v", s.network, err)
		}
	}
	m.freeSlot(s.slot)
}

// ReapIdle destroys sandboxes idle past the TTL. In the full design this is
// "hibernate": snapshot the workspace to object storage first so the next
// tool call rehydrates it. Here the workspace is simply dropped.
func (m *Manager) ReapIdle(ctx context.Context) {
	m.mu.Lock()
	var idle []string
	for id, s := range m.sess {
		s.mu.Lock()
		if s.Current == "" && time.Since(s.LastUsed) > m.cfg.IdleTTL {
			idle = append(idle, id)
		}
		s.mu.Unlock()
	}
	m.mu.Unlock()
	for _, id := range idle {
		s, ok := m.Get(id)
		// Never reap under a running command: holding the run lock means
		// any exec that arrives now waits, then sees the session is gone.
		if ok && s.run.TryLock() {
			m.Delete(ctx, id, "idle ttl")
			s.run.Unlock()
		}
	}
}

// snapshot copies the exported fields under the session lock.
func (s *Session) snapshot() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Info
}

func (m *Manager) List() []Info {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]Info, 0, len(m.sess))
	for _, s := range m.sess {
		out = append(out, s.snapshot())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out
}

func (m *Manager) audit(s *Session, e audit.Event) error {
	e.Tenant, e.Agent, e.AgentVersion, e.Run, e.User, e.Session = s.Tenant, s.Agent, s.Version, s.Run, s.User, s.ID
	err := m.cfg.Audit.Write(e)
	if err != nil {
		log.Printf("AUDIT WRITE FAILED: %v", err)
	}
	return err
}

func (m *Manager) record(dst *[]int64, v int64) {
	m.statsMu.Lock()
	*dst = append(*dst, v)
	m.statsMu.Unlock()
}

type Dist struct {
	N   int   `json:"n"`
	P50 int64 `json:"p50_ms"`
	P95 int64 `json:"p95_ms"`
	P99 int64 `json:"p99_ms"`
	Max int64 `json:"max_ms"`
}

func dist(xs []int64) Dist {
	if len(xs) == 0 {
		return Dist{}
	}
	s := append([]int64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	q := func(p float64) int64 { return s[int(p*float64(len(s)-1)+0.5)] }
	return Dist{len(s), q(.5), q(.95), q(.99), s[len(s)-1]}
}

func (m *Manager) Metrics() map[string]any {
	m.statsMu.Lock()
	defer m.statsMu.Unlock()
	return map[string]any{"runtime": m.cfg.Runtime, "cold_start": dist(m.cold), "exec": dist(m.warm), "active_sandboxes": len(m.List())}
}

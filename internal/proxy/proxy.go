// Package proxy is the sandbox egress proxy: the only network path out of a
// sandbox. For every request it
//
//  1. identifies the sandbox (per-session proxy credential AND source IP),
//  2. authorizes method/host/path against the agent's pinned definition,
//  3. injects the tenant credential the rule names (the sandbox only ever
//     holds a sentinel),
//  4. records the decision before the upstream call and the result after,
//  5. strips any credential value that comes back in the response.
//
// TLS from the sandbox is terminated with a per-tenant CA whose public cert
// is the only thing the sandbox is given.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agentfleet/internal/audit"
	"agentfleet/internal/certs"
	"agentfleet/internal/creds"
	"agentfleet/internal/netguard"
	"agentfleet/internal/policy"
)

type Config struct {
	Registry   *policy.Registry
	Creds      *creds.Store
	Audit      *audit.Log
	Upstream   http.RoundTripper
	MaxBody    int64
	AdminToken string
}

type Session struct {
	ID       string `json:"id"`
	Secret   string `json:"secret,omitempty"`
	SourceIP string `json:"source_ip"`
	Tenant   string `json:"tenant"`
	Agent    string `json:"agent"`
	Version  int    `json:"agent_version"`
	Run      string `json:"run"`
	User     string `json:"user"`

	Requests int64  `json:"requests"`
	Denied   int64  `json:"denied"`
	Call     string `json:"current_call,omitempty"`

	secret [32]byte
	agent  *policy.Agent
	mu     sync.Mutex
}

func (s *Session) call() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Call
}

func (s *Session) stamp(e audit.Event) audit.Event {
	e.Tenant, e.Agent, e.AgentVersion = s.Tenant, s.Agent, s.Version
	e.Run, e.User, e.Session, e.Call = s.Run, s.User, s.ID, s.call()
	return e
}

type Proxy struct {
	cfg      Config
	mu       sync.RWMutex
	sessions map[string]*Session
	cas      map[string]*certs.Authority
}

func New(cfg Config) *Proxy {
	if cfg.MaxBody == 0 {
		cfg.MaxBody = 16 << 20
	}
	return &Proxy{cfg: cfg, sessions: map[string]*Session{}, cas: map[string]*certs.Authority{}}
}

var errAuth = errors.New("proxy authentication failed")

func (p *Proxy) identify(r *http.Request) (*Session, error) {
	id, secret, ok := basicAuth(r.Header.Get("Proxy-Authorization"))
	if !ok {
		return nil, fmt.Errorf("%w: no session credential", errAuth)
	}
	p.mu.RLock()
	s := p.sessions[id]
	p.mu.RUnlock()
	if s == nil {
		return nil, fmt.Errorf("%w: unknown session %q", errAuth, id)
	}
	sum := sha256.Sum256([]byte(secret))
	if subtle.ConstantTimeCompare(sum[:], s.secret[:]) != 1 {
		return nil, fmt.Errorf("%w: bad secret for session %s", errAuth, id)
	}
	// The secret is readable inside the sandbox, so on its own it proves
	// nothing. Bound to the source IP it only works from that sandbox.
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ip != s.SourceIP {
		return nil, fmt.Errorf("%w: session %s presented from %s, bound to %s", errAuth, id, ip, s.SourceIP)
	}
	return s, nil
}

func basicAuth(h string) (user, pass string, ok bool) {
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return
	}
	b, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return
	}
	user, pass, ok = strings.Cut(string(b), ":")
	return
}

// ServeHTTP handles the sandbox-facing listener.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s, err := p.identify(r)
	if err != nil {
		p.write(audit.Event{Kind: "egress", Decision: "deny", Reason: err.Error(), Method: r.Method, Host: r.Host})
		w.Header().Set("Proxy-Authenticate", `Basic realm="agentfleet"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	atomic.AddInt64(&s.Requests, 1)
	if r.Method != http.MethodConnect {
		p.denyHTTP(w, s, r.Method, r.URL.Hostname(), r.URL.Path, "plaintext egress is not permitted; use https")
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		p.denyHTTP(w, s, "CONNECT", r.Host, "", "malformed CONNECT target")
		return
	}
	host = strings.ToLower(host)
	switch {
	case port != "443":
		p.denyHTTP(w, s, "CONNECT", r.Host, "", "only port 443 is permitted")
		return
	case net.ParseIP(strings.Trim(host, "[]")) != nil:
		p.denyHTTP(w, s, "CONNECT", host, "", "IP literal targets are not permitted; grants are by hostname")
		return
	case !s.agent.HostGranted(host):
		p.denyHTTP(w, s, "CONNECT", host, "", fmt.Sprintf("host %s not granted to %s/%s@v%d", host, s.Tenant, s.Agent, s.Version))
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	conn, brw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}
	p.tunnel(s, host, &bufConn{Conn: conn, r: brw.Reader})
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufConn) Read(b []byte) (int, error) { return c.r.Read(b) }

func (p *Proxy) tunnel(s *Session, host string, conn net.Conn) {
	ca, err := p.authority(s.Tenant)
	if err != nil {
		log.Printf("ca for %s: %v", s.Tenant, err)
		return
	}
	tc := tls.Server(conn, &tls.Config{
		// The cert is minted for the CONNECT host, never for SNI: the
		// client does not get to choose which name we vouch for.
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return ca.Leaf(host) },
		NextProtos:     []string{"http/1.1"},
		MinVersion:     tls.VersionTLS12,
	})
	tc.SetDeadline(time.Now().Add(10 * time.Second))
	if err := tc.Handshake(); err != nil {
		return
	}
	br := bufio.NewReader(tc)
	for {
		tc.SetDeadline(time.Now().Add(2 * time.Minute))
		req, err := http.ReadRequest(br)
		if err != nil {
			return
		}
		resp := p.forward(s, host, req)
		werr := resp.Write(tc)
		resp.Body.Close()
		if werr != nil || req.Close || resp.Close {
			return
		}
	}
}

var hopHeaders = []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade"}

func (p *Proxy) forward(s *Session, host string, req *http.Request) *http.Response {
	ev := s.stamp(audit.Event{Kind: "egress", Method: req.Method, Host: host, Path: req.URL.Path})
	if rh := strings.ToLower(req.Host); rh != host && rh != host+":443" {
		return p.denyResp(s, req, ev, "Host header does not match the CONNECT target")
	}
	d := s.agent.Authorize(req.Method, host, req.URL.Path)
	if !d.Allow {
		return p.denyResp(s, req, ev, d.Reason)
	}

	out := &http.Request{
		Method:        req.Method,
		URL:           &url.URL{Scheme: "https", Host: host, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery},
		Header:        req.Header.Clone(),
		Body:          req.Body,
		ContentLength: req.ContentLength,
		Host:          host,
	}
	for _, h := range hopHeaders {
		out.Header.Del(h)
	}
	// Ask for an identity body so redaction sees plaintext. The transport
	// negotiates gzip itself and decodes it before we look.
	out.Header.Del("Accept-Encoding")
	if name := d.Rule.Credential; name != "" {
		c, ok := p.cfg.Creds.Get(s.Tenant, name)
		if !ok {
			return p.denyResp(s, req, ev, fmt.Sprintf("credential %q is not provisioned for tenant %s", name, s.Tenant))
		}
		// Overwrite, never append: whatever the sandbox sent (a sentinel,
		// or a token it found somewhere) does not reach the upstream.
		out.Header.Set(c.Header, c.HeaderValue())
		ev.Credential = name
	}

	ev.Req = newID()
	ev.Decision = "allow"
	if err := p.write(ev); err != nil {
		return p.errResp(req, http.StatusServiceUnavailable, "audit log unavailable; failing closed")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res := ev
	res.Kind, res.Decision = "egress_result", "info"
	resp, err := p.cfg.Upstream.RoundTrip(out.WithContext(ctx))
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			// Policy said yes by name, but the name resolves somewhere we
			// never dial. That is a denial, not an upstream failure.
			return p.denyResp(s, req, res, be.Msg)
		}
		res.Status, res.Reason = http.StatusBadGateway, err.Error()
		p.write(res)
		return p.errResp(req, http.StatusBadGateway, "upstream: "+err.Error())
	}
	defer resp.Body.Close()

	if ce := resp.Header.Get("Content-Encoding"); ce != "" && ce != "identity" {
		res.Status, res.Reason = http.StatusBadGateway, "uninspectable content-encoding "+ce
		p.write(res)
		return p.errResp(req, http.StatusBadGateway, res.Reason)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, p.cfg.MaxBody+1))
	if err != nil || int64(len(body)) > p.cfg.MaxBody {
		// Fail closed: a body we could not fully inspect is not forwarded.
		res.Status, res.Reason = http.StatusBadGateway, "response exceeds inspection limit or failed to read"
		p.write(res)
		return p.errResp(req, http.StatusBadGateway, res.Reason)
	}

	secrets := p.cfg.Creds.AllValues()
	body, n := redact(body, secrets)
	hdr := http.Header{}
	for k, vs := range resp.Header {
		for _, v := range vs {
			rv, m := redact([]byte(v), secrets)
			n += m
			hdr.Add(k, string(rv))
		}
	}
	for _, h := range hopHeaders {
		hdr.Del(h)
	}
	hdr.Set("Content-Length", strconv.Itoa(len(body)))

	res.Status, res.Bytes, res.Redactions = resp.StatusCode, int64(len(body)), n
	p.write(res)
	return &http.Response{
		StatusCode: resp.StatusCode, ProtoMajor: 1, ProtoMinor: 1,
		Header: hdr, Body: io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)), Request: req,
	}
}

func redact(b []byte, secrets []string) ([]byte, int) {
	n := 0
	for _, s := range secrets {
		if c := bytes.Count(b, []byte(s)); c > 0 {
			n += c
			b = bytes.ReplaceAll(b, []byte(s), []byte("[REDACTED]"))
		}
	}
	return b, n
}

type denial struct {
	Error   string `json:"error"`
	Reason  string `json:"reason"`
	Session string `json:"session,omitempty"`
}

func (p *Proxy) denyResp(s *Session, req *http.Request, ev audit.Event, reason string) *http.Response {
	atomic.AddInt64(&s.Denied, 1)
	ev.Decision, ev.Reason, ev.Status = "deny", reason, http.StatusForbidden
	p.write(ev)
	body, _ := json.Marshal(denial{"egress_denied", reason, s.ID})
	r := p.jsonResp(req, http.StatusForbidden, body)
	r.Close = true // the request body was not consumed
	return r
}

func (p *Proxy) errResp(req *http.Request, code int, msg string) *http.Response {
	body, _ := json.Marshal(denial{Error: "egress_failed", Reason: msg})
	r := p.jsonResp(req, code, body)
	r.Close = true
	return r
}

func (p *Proxy) jsonResp(req *http.Request, code int, body []byte) *http.Response {
	h := http.Header{}
	h.Set("Content-Type", "application/json")
	h.Set("X-Agentfleet-Proxy", "1")
	return &http.Response{StatusCode: code, ProtoMajor: 1, ProtoMinor: 1, Header: h,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: req}
}

func (p *Proxy) denyHTTP(w http.ResponseWriter, s *Session, method, host, path, reason string) {
	atomic.AddInt64(&s.Denied, 1)
	p.write(s.stamp(audit.Event{Kind: "egress", Decision: "deny", Reason: reason,
		Method: method, Host: host, Path: path, Status: http.StatusForbidden}))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Agentfleet-Proxy", "1")
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(denial{"egress_denied", reason, s.ID})
}

func (p *Proxy) write(e audit.Event) error {
	err := p.cfg.Audit.Write(e)
	if err != nil {
		log.Printf("AUDIT WRITE FAILED: %v", err)
	}
	return err
}

func newID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func (p *Proxy) authority(tenant string) (*certs.Authority, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if ca := p.cas[tenant]; ca != nil {
		return ca, nil
	}
	ca, err := certs.NewAuthority("agentfleet egress CA (" + tenant + ")")
	if err != nil {
		return nil, err
	}
	p.cas[tenant] = ca
	return ca, nil
}

// ---- admin API: reachable only from the platform network ----

func (p *Proxy) Admin() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /admin/sessions", p.register)
	mux.HandleFunc("PUT /admin/sessions/{id}/call", p.setCall)
	mux.HandleFunc("DELETE /admin/sessions/{id}", p.deregister)
	mux.HandleFunc("GET /admin/sessions", p.list)
	mux.HandleFunc("GET /admin/ca/{tenant}", p.caPEM)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("ok"))
			return
		}
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, []byte("Bearer "+p.cfg.AdminToken)) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

func (p *Proxy) register(w http.ResponseWriter, r *http.Request) {
	var s Session
	if err := json.NewDecoder(r.Body).Decode(&s); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if s.ID == "" || len(s.Secret) < 16 || net.ParseIP(s.SourceIP) == nil || s.Run == "" || s.User == "" || s.Version == 0 {
		http.Error(w, "id, secret(>=16), source_ip, run, user and an exact agent_version are required", http.StatusBadRequest)
		return
	}
	a, err := p.cfg.Registry.Get(s.Tenant, s.Agent, s.Version)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	s.agent, s.secret, s.Secret = a, sha256.Sum256([]byte(s.Secret)), ""
	p.mu.Lock()
	if _, dup := p.sessions[s.ID]; dup {
		p.mu.Unlock()
		http.Error(w, "session exists", http.StatusConflict)
		return
	}
	for _, o := range p.sessions {
		if o.SourceIP == s.SourceIP {
			p.mu.Unlock()
			http.Error(w, "source ip already bound to session "+o.ID, http.StatusConflict)
			return
		}
	}
	p.sessions[s.ID] = &s
	p.mu.Unlock()
	p.write(s.stamp(audit.Event{Kind: "session", Decision: "info", Reason: "egress session registered from " + s.SourceIP}))
	w.WriteHeader(http.StatusCreated)
}

func (p *Proxy) setCall(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Call string `json:"call"`
	}
	json.NewDecoder(r.Body).Decode(&body)
	p.mu.RLock()
	s := p.sessions[r.PathValue("id")]
	p.mu.RUnlock()
	if s == nil {
		http.NotFound(w, r)
		return
	}
	s.mu.Lock()
	s.Call = body.Call
	s.mu.Unlock()
	w.WriteHeader(http.StatusNoContent)
}

func (p *Proxy) deregister(w http.ResponseWriter, r *http.Request) {
	p.mu.Lock()
	s := p.sessions[r.PathValue("id")]
	delete(p.sessions, r.PathValue("id"))
	p.mu.Unlock()
	if s != nil {
		p.write(s.stamp(audit.Event{Kind: "session", Decision: "info", Reason: "egress session closed"}))
	}
	w.WriteHeader(http.StatusNoContent)
}

func (p *Proxy) list(w http.ResponseWriter, r *http.Request) {
	p.mu.RLock()
	out := make([]map[string]any, 0, len(p.sessions))
	for _, s := range p.sessions {
		out = append(out, map[string]any{"id": s.ID, "tenant": s.Tenant, "agent": s.Agent, "run": s.Run,
			"source_ip": s.SourceIP, "requests": atomic.LoadInt64(&s.Requests),
			"denied": atomic.LoadInt64(&s.Denied), "current_call": s.call()})
	}
	p.mu.RUnlock()
	json.NewEncoder(w).Encode(out)
}

func (p *Proxy) caPEM(w http.ResponseWriter, r *http.Request) {
	ca, err := p.authority(r.PathValue("tenant"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(ca.PEM)
}

package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"agentfleet/internal/audit"
	"agentfleet/internal/creds"
	"agentfleet/internal/policy"
)

const realToken = "ghs_REAL_acme_0123456789abcdef"

type harness struct {
	proxyURL  string
	admin     *httptest.Server
	upstream  *httptest.Server
	auditPath string
	hits      atomic.Int64
	lastAuth  atomic.Value
}

func setup(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "agents", "acme"), 0o755)
	os.WriteFile(filepath.Join(dir, "agents", "acme", "triager.v1.json"), []byte(`{
		"tenant":"acme","name":"triager","version":1,
		"exec":{"image":"x","limits":{"cpus":1,"memory_mb":256,"pids":64,"disk_mb":64,"timeout_s":10},"egress":[
			{"host":"github.test","methods":["GET"],"paths":["/api/v3/**"],"credential":"github"},
			{"host":"github.test","methods":["POST"],"paths":["/api/v3/repos/acme/*/issues"],"credential":"github"}]}}`), 0o644)
	os.WriteFile(filepath.Join(dir, "creds.json"), []byte(`{"acme":{"github":
		{"header":"Authorization","format":"token %s","value":"`+realToken+`"}}}`), 0o644)

	reg, err := policy.LoadRegistry(filepath.Join(dir, "agents"))
	if err != nil {
		t.Fatal(err)
	}
	cs, err := creds.Load(filepath.Join(dir, "creds.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{auditPath: filepath.Join(dir, "egress.jsonl")}
	al, err := audit.Open(h.auditPath, "egress")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { al.Close() })

	h.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.hits.Add(1)
		h.lastAuth.Store(r.Header.Get("Authorization"))
		// A careless upstream that echoes the caller's credential back.
		io.WriteString(w, `{"you_sent":"`+r.Header.Get("Authorization")+`"}`)
	}))
	t.Cleanup(h.upstream.Close)

	up := h.upstream.Client().Transport.(*http.Transport).Clone()
	up.TLSClientConfig.ServerName = "example.com" // httptest's cert name
	up.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, h.upstream.Listener.Addr().String())
	}
	p := New(Config{Registry: reg, Creds: cs, Audit: al, Upstream: up, AdminToken: "admintoken"})
	ps := httptest.NewServer(p)
	t.Cleanup(ps.Close)
	h.proxyURL = ps.URL
	h.admin = httptest.NewServer(p.Admin())
	t.Cleanup(h.admin.Close)
	return h
}

func (h *harness) adminDo(t *testing.T, method, path string, body any) *http.Response {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.admin.URL+path, rd)
	req.Header.Set("Authorization", "Bearer admintoken")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

func (h *harness) register(t *testing.T, id, sourceIP string) {
	resp := h.adminDo(t, "POST", "/admin/sessions", map[string]any{
		"id": id, "secret": "s3cret-s3cret-s3cret", "source_ip": sourceIP,
		"tenant": "acme", "agent": "triager", "agent_version": 1, "run": "run-1", "user": "alice@acme.com"})
	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("register: %d %s", resp.StatusCode, b)
	}
}

// client behaves like gh/curl inside a sandbox: proxy URL with the session
// credential, the tenant CA as its only trust root, a sentinel token.
func (h *harness) client(t *testing.T, id string) *http.Client {
	resp := h.adminDo(t, "GET", "/admin/ca/acme", nil)
	pem, _ := io.ReadAll(resp.Body)
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("bad CA pem")
	}
	pu, _ := url.Parse(h.proxyURL)
	pu.User = url.UserPassword(id, "s3cret-s3cret-s3cret")
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(pu), TLSClientConfig: &tls.Config{RootCAs: pool}}}
}

func get(c *http.Client, method, u string) (int, string, error) {
	req, _ := http.NewRequest(method, u, strings.NewReader(`{"title":"x"}`))
	req.Header.Set("Authorization", "token af-sentinel")
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

func TestCredentialInjectedAndRedacted(t *testing.T) {
	h := setup(t)
	h.register(t, "s1", "127.0.0.1")
	code, body, err := get(h.client(t, "s1"), "GET", "https://github.test/api/v3/user")
	if err != nil || code != 200 {
		t.Fatalf("code=%d err=%v body=%s", code, err, body)
	}
	if got := h.lastAuth.Load(); got != "token "+realToken {
		t.Fatalf("upstream saw %q, want the injected real token", got)
	}
	if strings.Contains(body, realToken) || !strings.Contains(body, "[REDACTED]") {
		t.Fatalf("echoed credential reached the sandbox: %s", body)
	}
	raw, _ := os.ReadFile(h.auditPath)
	if strings.Contains(string(raw), realToken) {
		t.Fatal("credential value written to audit log")
	}
	if !strings.Contains(string(raw), `"credential":"github"`) {
		t.Fatal("audit does not record which credential was used")
	}
}

func TestDenials(t *testing.T) {
	h := setup(t)
	h.register(t, "s1", "127.0.0.1")
	c := h.client(t, "s1")

	// Inside the tunnel: wrong path / method → 403 from the proxy.
	for _, tc := range []struct{ method, url string }{
		{"POST", "https://github.test/api/v3/repos/evil/x/issues"},
		{"DELETE", "https://github.test/api/v3/repos/acme/x"},
	} {
		code, body, err := get(c, tc.method, tc.url)
		if err != nil || code != 403 || !strings.Contains(body, "egress_denied") {
			t.Errorf("%s %s: code=%d err=%v body=%s", tc.method, tc.url, code, err, body)
		}
	}
	// At CONNECT: ungranted host never gets a tunnel.
	if _, _, err := get(c, "GET", "https://exfil.test/?t=x"); err == nil || !strings.Contains(err.Error(), "Forbidden") {
		t.Errorf("ungranted host: %v", err)
	}
	// Plaintext is refused outright.
	if code, _, _ := get(c, "GET", "http://github.test/api/v3/user"); code != 403 {
		t.Errorf("plaintext: %d", code)
	}
	if n := h.hits.Load(); n != 0 {
		t.Fatalf("upstream received %d requests; every one should have been denied", n)
	}
}

func TestSessionBoundToSourceIP(t *testing.T) {
	h := setup(t)
	h.register(t, "s1", "10.9.9.9") // a different sandbox's address
	_, _, err := get(h.client(t, "s1"), "GET", "https://github.test/api/v3/user")
	if err == nil || !strings.Contains(err.Error(), "Proxy Authentication Required") {
		t.Fatalf("stolen session credential worked from another IP: %v", err)
	}
	if h.hits.Load() != 0 {
		t.Fatal("upstream reached")
	}
}

func TestAdminRequiresToken(t *testing.T) {
	h := setup(t)
	resp, _ := http.Get(h.admin.URL + "/admin/ca/acme")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("admin without token: %d", resp.StatusCode)
	}
}

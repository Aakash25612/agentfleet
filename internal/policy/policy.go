// Package policy holds agent definitions and decides whether a network
// request made on behalf of an agent is allowed.
//
// The same Authorize function is meant to back both enforcement points in
// the design: the API tool gateway and the sandbox egress proxy. Only the
// egress proxy is built in this PoC.
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Rule grants an agent access to one upstream host.
type Rule struct {
	Host       string   `json:"host"`
	Methods    []string `json:"methods"`
	Paths      []string `json:"paths"`                // segment globs: "*" = one segment, trailing "**" = rest
	Credential string   `json:"credential,omitempty"` // name in the tenant's credential store
}

type Limits struct {
	CPUs     float64 `json:"cpus"`
	MemoryMB int64   `json:"memory_mb"`
	Pids     int64   `json:"pids"`
	DiskMB   int64   `json:"disk_mb"`
	TimeoutS int     `json:"timeout_s"`
}

type ExecTool struct {
	Image  string `json:"image"`
	Limits Limits `json:"limits"`
	Egress []Rule `json:"egress"`
}

// Agent is an immutable, versioned agent definition. A run is pinned to
// exactly one (tenant, name, version).
type Agent struct {
	Tenant       string    `json:"tenant"`
	Name         string    `json:"name"`
	Version      int       `json:"version"`
	Owner        string    `json:"owner"`
	Model        string    `json:"model"`
	Trust        string    `json:"trust"`
	SystemPrompt string    `json:"system_prompt"`
	Exec         *ExecTool `json:"exec,omitempty"`
}

func (a *Agent) Ref() string { return fmt.Sprintf("%s/%s@v%d", a.Tenant, a.Name, a.Version) }

type Decision struct {
	Allow  bool
	Reason string
	Rule   *Rule
}

func deny(format string, args ...any) Decision {
	return Decision{Reason: fmt.Sprintf(format, args...)}
}

// HostGranted reports whether any egress rule names host. The proxy uses it
// to refuse a CONNECT before any TLS is spoken.
func (a *Agent) HostGranted(host string) bool {
	if a.Exec == nil {
		return false
	}
	host = strings.ToLower(host)
	for _, r := range a.Exec.Egress {
		if r.Host == host {
			return true
		}
	}
	return false
}

// Authorize is default-deny. p must be the decoded URL path.
func (a *Agent) Authorize(method, host, p string) Decision {
	if a.Exec == nil || len(a.Exec.Egress) == 0 {
		return deny("agent %s has no egress grants", a.Ref())
	}
	host = strings.ToLower(host)
	if !canonical(p) {
		return deny("non-canonical path %q", p)
	}
	hostSeen := false
	for i := range a.Exec.Egress {
		r := &a.Exec.Egress[i]
		if r.Host != host {
			continue
		}
		hostSeen = true
		if !hasMethod(r.Methods, method) {
			continue
		}
		for _, pat := range r.Paths {
			if matchPath(pat, p) {
				return Decision{Allow: true, Rule: r}
			}
		}
	}
	if !hostSeen {
		return deny("host %s not granted to %s", host, a.Ref())
	}
	return deny("%s %s not granted on %s", method, p, host)
}

func hasMethod(ms []string, m string) bool {
	for _, x := range ms {
		if strings.EqualFold(x, m) {
			return true
		}
	}
	return false
}

// canonical rejects anything path.Clean would rewrite ("..", "//", "/./"),
// so a grant on /repos/acme/** cannot be escaped with /repos/acme/../evil.
func canonical(p string) bool {
	if p == "" || p[0] != '/' {
		return false
	}
	c := path.Clean(p)
	return c == p || c+"/" == p
}

func matchPath(pat, p string) bool {
	ps := strings.Split(strings.Trim(pat, "/"), "/")
	xs := strings.Split(strings.Trim(p, "/"), "/")
	for i, seg := range ps {
		if seg == "**" {
			return true
		}
		if i >= len(xs) {
			return false
		}
		if seg != "*" && seg != xs[i] {
			return false
		}
	}
	return len(ps) == len(xs)
}

// Registry is a read-only view of agents/<tenant>/<name>.v<N>.json.
type Registry struct {
	agents map[string]*Agent // key: tenant/name@vN
	latest map[string]int    // key: tenant/name
}

func LoadRegistry(dir string) (*Registry, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*", "*.json"))
	if err != nil {
		return nil, err
	}
	reg := &Registry{agents: map[string]*Agent{}, latest: map[string]int{}}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var a Agent
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&a); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if err := a.validate(filepath.Base(filepath.Dir(f))); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		if _, dup := reg.agents[a.Ref()]; dup {
			return nil, fmt.Errorf("%s: duplicate definition %s", f, a.Ref())
		}
		reg.agents[a.Ref()] = &a
		k := a.Tenant + "/" + a.Name
		if a.Version > reg.latest[k] {
			reg.latest[k] = a.Version
		}
	}
	if len(reg.agents) == 0 {
		return nil, fmt.Errorf("no agent definitions under %s", dir)
	}
	return reg, nil
}

func (a *Agent) validate(dirTenant string) error {
	switch {
	case a.Tenant == "" || a.Name == "" || a.Version < 1:
		return fmt.Errorf("tenant, name and version are required")
	case a.Tenant != dirTenant:
		// A file in acme/ must not be able to define an agent for globex.
		return fmt.Errorf("tenant %q does not match directory %q", a.Tenant, dirTenant)
	}
	if a.Exec == nil {
		return nil
	}
	if l := a.Exec.Limits; l.CPUs <= 0 || l.MemoryMB <= 0 || l.Pids <= 0 || l.DiskMB <= 0 || l.TimeoutS <= 0 {
		// Zero means "unlimited" to the container runtime. Make it explicit.
		return fmt.Errorf("exec.limits: cpus, memory_mb, pids, disk_mb and timeout_s must all be set")
	}
	for i, r := range a.Exec.Egress {
		if r.Host == "" || r.Host != strings.ToLower(r.Host) || strings.ContainsAny(r.Host, "*/:") {
			return fmt.Errorf("egress[%d]: host must be a lowercase exact hostname", i)
		}
		if len(r.Methods) == 0 || len(r.Paths) == 0 {
			return fmt.Errorf("egress[%d]: methods and paths are required", i)
		}
	}
	return nil
}

// Get returns a specific version, or the latest when version is 0.
func (r *Registry) Get(tenant, name string, version int) (*Agent, error) {
	if version == 0 {
		version = r.latest[tenant+"/"+name]
	}
	a, ok := r.agents[fmt.Sprintf("%s/%s@v%d", tenant, name, version)]
	if !ok {
		return nil, fmt.Errorf("agent %s/%s@v%d not found", tenant, name, version)
	}
	return a, nil
}

func (r *Registry) Refs() []string {
	var out []string
	for k := range r.agents {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

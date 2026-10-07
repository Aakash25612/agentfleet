// Package creds is the stand-in for Vault / a GitHub App token minter.
// Only the egress proxy (and the API tool gateway in the full design)
// ever constructs a Store; the executor and sandboxes have no path to it.
package creds

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type Credential struct {
	Header string `json:"header"` // e.g. Authorization
	Format string `json:"format"` // e.g. "token %s"
	Value  string `json:"value"`
}

func (c Credential) HeaderValue() string { return fmt.Sprintf(c.Format, c.Value) }

type Store struct {
	byTenant map[string]map[string]Credential
}

func Load(path string) (*Store, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	s := &Store{}
	if err := json.Unmarshal(b, &s.byTenant); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	for t, m := range s.byTenant {
		for n, c := range m {
			if c.Header == "" || !strings.Contains(c.Format, "%s") || len(c.Value) < 12 {
				return nil, fmt.Errorf("credential %s/%s is malformed", t, n)
			}
		}
	}
	return s, nil
}

// Get is tenant-scoped by construction: there is no lookup by name alone.
func (s *Store) Get(tenant, name string) (Credential, bool) {
	c, ok := s.byTenant[tenant][name]
	return c, ok
}

// AllValues is for redaction across tenants: if tenant B's secret ever
// shows up in tenant A's traffic something is very wrong, but it should
// still not reach the model.
func (s *Store) AllValues() []string {
	var out []string
	for _, m := range s.byTenant {
		for _, c := range m {
			out = append(out, c.Value)
		}
	}
	sort.Slice(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

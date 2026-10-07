package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func triager() *Agent {
	return &Agent{Tenant: "acme", Name: "triager", Version: 1, Exec: &ExecTool{Egress: []Rule{
		{Host: "github.internal", Methods: []string{"GET"}, Paths: []string{"/api/v3/**"}, Credential: "github"},
		{Host: "github.internal", Methods: []string{"POST"}, Paths: []string{"/api/v3/repos/acme/*/issues"}, Credential: "github"},
	}}}
}

func TestAuthorize(t *testing.T) {
	a := triager()
	cases := []struct {
		method, host, path string
		allow              bool
	}{
		{"GET", "github.internal", "/api/v3/user", true},
		{"GET", "GitHub.Internal", "/api/v3/user", true},
		{"POST", "github.internal", "/api/v3/repos/acme/webapp/issues", true},
		{"POST", "github.internal", "/api/v3/repos/evil/webapp/issues", false},
		{"POST", "github.internal", "/api/v3/repos/acme/webapp/issues/1", false},
		{"DELETE", "github.internal", "/api/v3/repos/acme/webapp", false},
		{"POST", "github.internal", "/api/v3/repos/acme/x/../../evil/x/issues", false},
		{"GET", "github.internal", "//api/v3/user", false},
		{"GET", "github.internal", "/api/v4/user", false},
		{"GET", "exfil.internal", "/", false},
		{"GET", "github.internal.evil.com", "/api/v3/user", false},
	}
	for _, c := range cases {
		d := a.Authorize(c.method, c.host, c.path)
		if d.Allow != c.allow {
			t.Errorf("%s %s%s: allow=%v want %v (%s)", c.method, c.host, c.path, d.Allow, c.allow, d.Reason)
		}
		if d.Allow && d.Rule.Credential != "github" {
			t.Errorf("%s %s: wrong rule", c.method, c.path)
		}
	}
}

func TestNoExecToolDeniesEverything(t *testing.T) {
	a := &Agent{Tenant: "acme", Name: "chat", Version: 1}
	if a.Authorize("GET", "github.internal", "/").Allow || a.HostGranted("github.internal") {
		t.Fatal("agent without exec tool must have no egress")
	}
}

func TestRegistryRejectsCrossTenantDefinition(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "acme"), 0o755)
	os.WriteFile(filepath.Join(dir, "acme", "sneaky.v1.json"),
		[]byte(`{"tenant":"globex","name":"sneaky","version":1}`), 0o644)
	if _, err := LoadRegistry(dir); err == nil {
		t.Fatal("definition in acme/ claiming tenant globex was accepted")
	}
}

func TestRegistryRejectsWildcardHost(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "acme"), 0o755)
	os.WriteFile(filepath.Join(dir, "acme", "a.v1.json"), []byte(`{"tenant":"acme","name":"a","version":1,
		"exec":{"image":"x","limits":`+limits+`,"egress":[{"host":"*.github.com","methods":["GET"],"paths":["/**"]}]}}`), 0o644)
	if _, err := LoadRegistry(dir); err == nil {
		t.Fatal("wildcard host accepted")
	}
}

const limits = `{"cpus":1,"memory_mb":256,"pids":64,"disk_mb":64,"timeout_s":10}`

func TestRegistryRejectsMissingLimits(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "acme"), 0o755)
	os.WriteFile(filepath.Join(dir, "acme", "a.v1.json"), []byte(`{"tenant":"acme","name":"a","version":1,
		"exec":{"image":"x","limits":{"cpus":1},"egress":[]}}`), 0o644)
	if _, err := LoadRegistry(dir); err == nil {
		t.Fatal("exec tool without explicit limits accepted (zero means unlimited)")
	}
}

func TestRegistryLatestAndPinned(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "acme"), 0o755)
	for _, v := range []string{"1", "2"} {
		os.WriteFile(filepath.Join(dir, "acme", "a.v"+v+".json"),
			[]byte(`{"tenant":"acme","name":"a","version":`+v+`}`), 0o644)
	}
	reg, err := LoadRegistry(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a, _ := reg.Get("acme", "a", 0); a.Version != 2 {
		t.Fatalf("latest = v%d", a.Version)
	}
	if a, _ := reg.Get("acme", "a", 1); a.Version != 1 {
		t.Fatal("pinned version not honoured")
	}
	if _, err := reg.Get("globex", "a", 0); err == nil {
		t.Fatal("other tenant's agent resolved")
	}
}

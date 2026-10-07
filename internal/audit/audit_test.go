package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeN(t *testing.T, path string, n int) {
	l, err := Open(path, "test")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for i := 0; i < n; i++ {
		if err := l.Write(Event{Kind: "exec", Decision: "allow", Tenant: "acme", Agent: "a", Command: "echo hi"}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestChainSurvivesReopen(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.jsonl")
	writeN(t, p, 3)
	writeN(t, p, 2)
	evs, err := ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 5 || evs[4].Seq != 5 {
		t.Fatalf("got %d events", len(evs))
	}
	if err := Verify(evs); err != nil {
		t.Fatal(err)
	}
}

func TestTamperingIsDetected(t *testing.T) {
	tamper := map[string]func([]string) []string{
		"edit": func(ls []string) []string {
			ls[1] = strings.Replace(ls[1], "echo hi", "echo bye", 1)
			return ls
		},
		"delete":        func(ls []string) []string { return append(ls[:1], ls[2:]...) },
		"truncate-head": func(ls []string) []string { return ls[1:] },
	}
	for name, fn := range tamper {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "a.jsonl")
			writeN(t, p, 4)
			b, _ := os.ReadFile(p)
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			os.WriteFile(p, []byte(strings.Join(fn(lines), "\n")+"\n"), 0o644)
			evs, err := ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			if Verify(evs) == nil {
				t.Fatal("tampered log verified")
			}
			if _, err := Open(p, "test"); err == nil {
				t.Fatal("Open extended a broken chain")
			}
		})
	}
}

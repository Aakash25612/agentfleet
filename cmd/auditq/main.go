// auditq answers "show me every command agent X ran last Tuesday".
//
//	auditq -dir /audit -tenant acme -agent repo-triager -since 2026-10-06T00:00:00Z -until 2026-10-07T00:00:00Z -kind exec
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"agentfleet/internal/audit"
)

func main() {
	dir := flag.String("dir", "/audit", "directory holding *.jsonl audit logs")
	var f audit.Filter
	flag.StringVar(&f.Tenant, "tenant", "", "")
	flag.StringVar(&f.Agent, "agent", "", "")
	flag.StringVar(&f.Run, "run", "", "")
	flag.StringVar(&f.Kind, "kind", "", "exec | exec_result | egress | egress_result | session")
	since := flag.String("since", "", "RFC3339")
	until := flag.String("until", "", "RFC3339")
	asJSON := flag.Bool("json", false, "print raw events")
	flag.Parse()

	for _, p := range []struct {
		s string
		t *time.Time
	}{{*since, &f.Since}, {*until, &f.Until}} {
		if p.s == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, p.s)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		*p.t = t
	}
	paths, _ := filepath.Glob(filepath.Join(*dir, "*.jsonl"))
	evs, err := audit.Query(paths, f)
	if err != nil {
		fmt.Fprintln(os.Stderr, "audit chain verification failed:", err)
		os.Exit(1)
	}
	for _, e := range evs {
		if *asJSON {
			b, _ := json.Marshal(e)
			fmt.Println(string(b))
			continue
		}
		what := e.Command
		if e.Kind != "exec" {
			what = fmt.Sprintf("%s %s%s %s", e.Method, e.Host, e.Path, e.Reason)
		}
		fmt.Printf("%s %-6s %-13s %s/%s@v%d run=%s user=%s call=%s  %s\n",
			e.TS.Format(time.RFC3339), e.Decision, e.Kind, e.Tenant, e.Agent, e.AgentVersion, e.Run, e.User, e.Call, what)
	}
	fmt.Fprintf(os.Stderr, "%d events from %d verified logs\n", len(evs), len(paths))
}

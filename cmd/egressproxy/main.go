// egressproxy: the only way out of a sandbox. See internal/proxy.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"agentfleet/internal/audit"
	"agentfleet/internal/creds"
	"agentfleet/internal/envx"
	"agentfleet/internal/netguard"
	"agentfleet/internal/policy"
	"agentfleet/internal/proxy"
)

func main() {
	envx.Healthcheck(os.Args)
	reg, err := policy.LoadRegistry(envx.Get("AF_AGENTS_DIR", "/etc/agentfleet/agents"))
	if err != nil {
		log.Fatal(err)
	}
	cs, err := creds.Load(envx.Get("AF_CREDS", "/run/secrets/tenant-credentials.json"))
	if err != nil {
		log.Fatal(err)
	}
	al, err := audit.Open(envx.Get("AF_AUDIT", "/var/log/agentfleet/egress.jsonl"), "egress")
	if err != nil {
		log.Fatal(err)
	}

	roots, err := x509.SystemCertPool()
	if err != nil {
		roots = x509.NewCertPool()
	}
	if dir := os.Getenv("AF_UPSTREAM_CA_DIR"); dir != "" {
		files, _ := filepath.Glob(filepath.Join(dir, "*.pem"))
		for _, f := range files {
			b, _ := os.ReadFile(f)
			if !roots.AppendCertsFromPEM(b) {
				log.Fatalf("bad upstream CA %s", f)
			}
			log.Printf("trusting upstream CA %s", f)
		}
	}
	internal := map[string]bool{}
	for _, h := range strings.Split(os.Getenv("AF_INTERNAL_UPSTREAMS"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			internal[h] = true
		}
	}
	dialer := &netguard.Dialer{Internal: internal, Timeout: 5 * time.Second}
	upstream := &http.Transport{
		DialContext:           dialer.DialContext,
		TLSClientConfig:       &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
		MaxIdleConnsPerHost:   32,
		IdleConnTimeout:       90 * time.Second,
	}

	p := proxy.New(proxy.Config{Registry: reg, Creds: cs, Audit: al, Upstream: upstream,
		AdminToken: envx.Must("AF_ADMIN_TOKEN")})

	admin := envx.Get("AF_ADMIN_LISTEN", "127.0.0.1:9090")
	go func() {
		log.Printf("admin API on %s", admin)
		log.Fatal((&http.Server{Addr: admin, Handler: p.Admin(), ReadHeaderTimeout: 5 * time.Second}).ListenAndServe())
	}()
	listen := envx.Get("AF_LISTEN", ":3128")
	log.Printf("egress proxy on %s; agents: %v", listen, reg.Refs())
	log.Fatal((&http.Server{Addr: listen, Handler: p, ReadHeaderTimeout: 10 * time.Second}).ListenAndServe())
}

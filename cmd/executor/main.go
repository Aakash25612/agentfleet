// executor: the execution-tool service. Creates and drives sandboxes.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"agentfleet/internal/audit"
	"agentfleet/internal/docker"
	"agentfleet/internal/envx"
	"agentfleet/internal/executor"
	"agentfleet/internal/policy"
)

func main() {
	envx.Healthcheck(os.Args)
	reg, err := policy.LoadRegistry(envx.Get("AF_AGENTS_DIR", "/etc/agentfleet/agents"))
	if err != nil {
		log.Fatal(err)
	}
	al, err := audit.Open(envx.Get("AF_AUDIT", "/var/log/agentfleet/exec.jsonl"), "executor")
	if err != nil {
		log.Fatal(err)
	}
	ttl, err := time.ParseDuration(envx.Get("AF_IDLE_TTL", "15m"))
	if err != nil {
		log.Fatal(err)
	}
	m := executor.New(executor.Config{
		Docker:         docker.New(envx.Get("AF_DOCKER_SOCK", "/var/run/docker.sock")),
		Registry:       reg,
		Audit:          al,
		ProxyAdmin:     envx.Must("AF_PROXY_ADMIN"),
		ProxyToken:     envx.Must("AF_PROXY_TOKEN"),
		ProxyContainer: envx.Get("AF_PROXY_CONTAINER", "af-egressproxy"),
		Runtime:        os.Getenv("AF_RUNTIME"),
		ImageOverride:  os.Getenv("AF_IMAGE_OVERRIDE"),
		IdleTTL:        ttl,
	})
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := m.Init(ctx); err != nil {
		log.Fatal(err)
	}
	go func() {
		for t := time.NewTicker(30 * time.Second); ; {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				m.ReapIdle(ctx)
			}
		}
	}()

	srv := &http.Server{Addr: envx.Get("AF_LISTEN", ":8080"), Handler: m.Handler(envx.Must("AF_TOKEN")), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		log.Printf("executor on %s", srv.Addr)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv.Shutdown(sctx)
	for _, s := range m.List() {
		m.Delete(sctx, s.ID, "executor shutdown")
	}
	log.Print("all sandboxes torn down")
}

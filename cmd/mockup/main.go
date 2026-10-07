// mockup plays the outside world for the demo, one role per container:
//
//	github   - a GitHub Enterprise-shaped API that only accepts the real tenant tokens
//	sink     - an exfiltration endpoint that records anything that reaches it
//	metadata - a cloud metadata service handing out "instance credentials"
//
// Each role also serves /_mock/stats on :8080 (platform network only) so
// tests can ask "did anything actually arrive here?".
package main

import (
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"agentfleet/internal/certs"
	"agentfleet/internal/envx"
)

type hit struct {
	Method string `json:"method"`
	Host   string `json:"host"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
	Auth   string `json:"auth"` // classified, never the raw value
}

type recorder struct {
	mu     sync.Mutex
	hits   []hit
	tokens map[string]string // token -> login
}

func (rc *recorder) classify(h string) string {
	tok := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(h, "token "), "Bearer "))
	switch {
	case h == "":
		return "none"
	case strings.HasPrefix(tok, "af-sentinel-"):
		return "sentinel"
	case rc.tokens[tok] != "":
		return "real:" + rc.tokens[tok]
	}
	return "unknown"
}

func (rc *recorder) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rc.mu.Lock()
		rc.hits = append(rc.hits, hit{r.Method, r.Host, r.URL.Path, r.URL.RawQuery, rc.classify(r.Header.Get("Authorization"))})
		rc.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (rc *recorder) stats(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if r.Method == http.MethodDelete {
		rc.hits = nil
	}
	json.NewEncoder(w).Encode(map[string]any{"count": len(rc.hits), "hits": rc.hits})
}

func main() {
	envx.Healthcheck(os.Args)
	role := flag.String("role", "", "github | sink | metadata")
	flag.Parse()

	rc := &recorder{tokens: map[string]string{}}
	for _, kv := range strings.Split(os.Getenv("MOCK_TOKENS"), ",") {
		if tok, login, ok := strings.Cut(kv, "="); ok {
			rc.tokens[tok] = login
		}
	}
	admin := http.NewServeMux()
	admin.HandleFunc("/_mock/stats", rc.stats)
	admin.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	go func() { log.Fatal(http.ListenAndServe(":8080", admin)) }()

	switch *role {
	case "github":
		serveTLS(rc.wrap(githubAPI(rc)), "github.internal")
	case "sink":
		h := rc.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprintln(w, "thanks for the data") }))
		go func() { log.Fatal(http.ListenAndServe(":80", h)) }()
		serveTLS(h, "exfil.internal")
	case "metadata":
		h := rc.wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// What an attacker wants from a real cloud: the node's IAM creds.
			fmt.Fprintln(w, `{"AccessKeyId":"ASIAFAKENODEROLE","SecretAccessKey":"node-role-secret","Token":"..."}`)
		}))
		log.Fatal(http.ListenAndServe(":80", h))
	default:
		log.Fatalf("unknown role %q", *role)
	}
}

func serveTLS(h http.Handler, host string) {
	ca, err := certs.NewAuthority("mock upstream CA (" + host + ")")
	if err != nil {
		log.Fatal(err)
	}
	if out := os.Getenv("CA_OUT"); out != "" {
		if err := os.WriteFile(out, ca.PEM, 0o644); err != nil {
			log.Fatal(err)
		}
	}
	leaf, err := ca.Leaf(host)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Addr: ":443", Handler: h, TLSConfig: &tls.Config{Certificates: []tls.Certificate{*leaf}}}
	log.Printf("serving %s on :443", host)
	log.Fatal(srv.ListenAndServeTLS("", ""))
}

func githubAPI(rc *recorder) http.Handler {
	var mu sync.Mutex
	issues := map[string][]map[string]any{}
	login := func(r *http.Request) string {
		h := r.Header.Get("Authorization")
		return rc.tokens[strings.TrimSpace(strings.TrimPrefix(h, "token "))]
	}
	reply := func(w http.ResponseWriter, code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(v)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/user", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]any{"login": login(r), "type": "Bot"})
	})
	mux.HandleFunc("GET /api/v3/repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		reply(w, 200, append([]map[string]any{}, issues[r.PathValue("owner")+"/"+r.PathValue("repo")]...))
	})
	mux.HandleFunc("POST /api/v3/repos/{owner}/{repo}/issues", func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		json.NewDecoder(r.Body).Decode(&in)
		key := r.PathValue("owner") + "/" + r.PathValue("repo")
		mu.Lock()
		is := map[string]any{"number": len(issues[key]) + 1, "title": in["title"], "user": map[string]string{"login": login(r)}}
		issues[key] = append(issues[key], is)
		mu.Unlock()
		reply(w, 201, is)
	})
	// A badly behaved endpoint that reflects the caller's Authorization
	// header, standing in for any API that echoes credentials in errors.
	mux.HandleFunc("GET /api/v3/debug/echo", func(w http.ResponseWriter, r *http.Request) {
		reply(w, 200, map[string]string{"authorization": r.Header.Get("Authorization")})
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if login(r) == "" {
			reply(w, 401, map[string]string{"message": "Bad credentials"})
			return
		}
		mux.ServeHTTP(w, r)
	})
}

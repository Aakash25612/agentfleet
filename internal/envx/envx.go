// Package envx holds the tiny helpers every main needs.
package envx

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

func Get(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func Must(k string) string {
	v := os.Getenv(k)
	if v == "" {
		log.Fatalf("%s must be set", k)
	}
	return v
}

// Healthcheck lets scratch images implement compose healthchecks with
// their own binary: `<bin> -healthcheck http://127.0.0.1:port/healthz`.
func Healthcheck(args []string) {
	if len(args) == 3 && args[1] == "-healthcheck" {
		c := http.Client{Timeout: 2 * time.Second}
		resp, err := c.Get(args[2])
		if err != nil || resp.StatusCode != 200 {
			fmt.Fprintln(os.Stderr, "unhealthy:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
}

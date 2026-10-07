// af-init is PID 1 inside every sandbox. It writes the tenant CA where
// TLS clients expect it, then reaps orphans so zombie processes left by an
// agent's commands never eat into the sandbox's pid limit.
package main

import (
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	if pem := os.Getenv("AF_CA_PEM"); pem != "" {
		os.MkdirAll("/tmp/.af", 0o755)
		if err := os.WriteFile("/tmp/.af/ca.pem", []byte(pem), 0o444); err != nil {
			os.Stderr.WriteString("af-init: " + err.Error() + "\n")
			os.Exit(1)
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() { <-sig; os.Exit(0) }()
	for {
		var ws syscall.WaitStatus
		if _, err := syscall.Wait4(-1, &ws, 0, nil); err == syscall.ECHILD {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

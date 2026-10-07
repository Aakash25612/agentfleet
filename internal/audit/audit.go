// Package audit is an append-only, hash-chained JSONL log.
//
// Each record carries the hash of the previous one, so deleting or editing a
// line breaks verification from that point on. In production these records
// go to a WORM bucket and a query store; the chain is what lets us tell an
// auditor the file they are reading is the file we wrote.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"sync"
	"time"
)

type Event struct {
	Seq       int64     `json:"seq"`
	TS        time.Time `json:"ts"`
	Component string    `json:"component"` // egress | executor
	Kind      string    `json:"kind"`      // egress | exec | session
	Decision  string    `json:"decision"`  // allow | deny | info
	Reason    string    `json:"reason,omitempty"`

	// Attribution. Every event carries the full chain: who, for whom, why.
	Tenant       string `json:"tenant,omitempty"`
	Agent        string `json:"agent,omitempty"`
	AgentVersion int    `json:"agent_version,omitempty"`
	Run          string `json:"run,omitempty"`
	User         string `json:"user,omitempty"`
	Session      string `json:"session,omitempty"`
	Call         string `json:"call,omitempty"` // tool call id from the orchestrator
	Req          string `json:"req,omitempty"`  // links a decision to its result

	// egress
	Method     string `json:"method,omitempty"`
	Host       string `json:"host,omitempty"`
	Path       string `json:"path,omitempty"`
	Status     int    `json:"status,omitempty"`
	Credential string `json:"credential,omitempty"` // name only, never the value
	Redactions int    `json:"redactions,omitempty"`
	Bytes      int64  `json:"bytes,omitempty"`

	// exec
	Command    string `json:"command,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	TimedOut   bool   `json:"timed_out,omitempty"`

	Prev string `json:"prev"`
	Hash string `json:"hash"`
}

func (e Event) digest() string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type Log struct {
	mu        sync.Mutex
	f         *os.File
	component string
	seq       int64
	last      string
}

// Open appends to path, continuing the chain if the file already exists.
func Open(path, component string) (*Log, error) {
	l := &Log{component: component}
	evs, err := ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if n := len(evs); n > 0 {
		if err := Verify(evs); err != nil {
			return nil, fmt.Errorf("refusing to extend a broken chain in %s: %w", path, err)
		}
		l.seq, l.last = evs[n-1].Seq, evs[n-1].Hash
	}
	l.f, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
	return l, err
}

// Write stamps, chains and fsyncs one event. If it fails the caller must
// treat the action as not allowed: we never do something we cannot record.
func (l *Log) Write(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e.Seq, e.Component, e.Prev = l.seq, l.component, l.last
	if e.TS.IsZero() {
		e.TS = time.Now().UTC()
	}
	e.Hash = e.digest()
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		l.seq--
		return err
	}
	// The line is in the file even if fsync fails, so the chain moves on;
	// the caller still gets the error and refuses to act.
	l.last = e.Hash
	return l.f.Sync()
}

func (l *Log) Close() error { return l.f.Close() }

func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<24)
	for line := 1; sc.Scan(); line++ {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Verify checks one component's chain end to end.
func Verify(evs []Event) error {
	prev := ""
	for i, e := range evs {
		if e.Seq != int64(i+1) {
			return fmt.Errorf("seq %d at position %d: record missing or reordered", e.Seq, i+1)
		}
		if e.Prev != prev {
			return fmt.Errorf("seq %d: prev hash mismatch", e.Seq)
		}
		if e.digest() != e.Hash {
			return fmt.Errorf("seq %d: content does not match hash", e.Seq)
		}
		prev = e.Hash
	}
	return nil
}

type Filter struct {
	Tenant, Agent, Run, Kind, Session string
	Since, Until                      time.Time
}

func (f Filter) match(e Event) bool {
	return (f.Tenant == "" || e.Tenant == f.Tenant) &&
		(f.Agent == "" || e.Agent == f.Agent) &&
		(f.Run == "" || e.Run == f.Run) &&
		(f.Kind == "" || e.Kind == f.Kind) &&
		(f.Session == "" || e.Session == f.Session) &&
		(f.Since.IsZero() || !e.TS.Before(f.Since)) &&
		(f.Until.IsZero() || e.TS.Before(f.Until))
}

// Query merges several component logs, verifying each chain first.
func Query(paths []string, f Filter) ([]Event, error) {
	var out []Event
	for _, p := range paths {
		evs, err := ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if err := Verify(evs); err != nil {
			return nil, fmt.Errorf("%s: %w", p, err)
		}
		for _, e := range evs {
			if f.match(e) {
				out = append(out, e)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].TS.Before(out[j].TS) })
	return out, nil
}

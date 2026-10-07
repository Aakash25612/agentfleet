package netguard

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestCheck(t *testing.T) {
	cases := []struct {
		ip           string
		allowPrivate bool
		ok           bool
	}{
		{"169.254.169.254", true, false},
		{"::ffff:169.254.169.254", true, false},
		{"127.0.0.1", true, false},
		{"100.100.100.200", true, false},
		{"fd00:ec2::254", true, false},
		{"10.1.2.3", false, false},
		{"10.1.2.3", true, true},
		{"140.82.112.6", false, true},
	}
	for _, c := range cases {
		err := Check(netip.MustParseAddr(c.ip), c.allowPrivate)
		if (err == nil) != c.ok {
			t.Errorf("%s private=%v: err=%v", c.ip, c.allowPrivate, err)
		}
	}
}

func TestDialRefusesLiteralsAndRebinding(t *testing.T) {
	d := &Dialer{Resolver: &net.Resolver{PreferGo: true}}
	if _, err := d.DialContext(context.Background(), "tcp", "169.254.169.254:80"); err == nil ||
		!strings.Contains(err.Error(), "IP literal") {
		t.Fatalf("literal: %v", err)
	}
	// "localhost" is the simplest name that resolves into a blocked range,
	// standing in for an attacker-controlled name pointed at metadata.
	d.Internal = map[string]bool{"localhost": true}
	if _, err := d.DialContext(context.Background(), "tcp", "localhost:80"); err == nil ||
		!strings.Contains(err.Error(), "blocked range") {
		t.Fatalf("rebinding: %v", err)
	}
}

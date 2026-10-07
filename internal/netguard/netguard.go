// Package netguard decides which IPs the egress proxy may dial.
//
// Policy is written in hostnames, but packets go to IPs. A grant on
// "docs.example.com" is worthless if that name can be made to resolve to
// 169.254.169.254, so we resolve once, check every address, and dial the
// address we checked (no second lookup, no rebinding window).
package netguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

var blocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), // link-local: cloud metadata lives here
	netip.MustParsePrefix("100.64.0.0/10"),  // CGNAT: some clouds put metadata here too
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
	netip.MustParsePrefix("fd00:ec2::/32"), // AWS IPv6 metadata
}

var private = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// BlockedError means policy, not the network, stopped the dial.
type BlockedError struct{ Msg string }

func (e *BlockedError) Error() string { return e.Msg }

func blockedf(format string, a ...any) error { return &BlockedError{fmt.Sprintf(format, a...)} }

// Check returns nil if addr may be dialled. Private ranges are only allowed
// for hosts explicitly registered as internal upstreams.
func Check(addr netip.Addr, allowPrivate bool) error {
	addr = addr.Unmap()
	for _, p := range blocked {
		if p.Contains(addr) {
			return blockedf("address %s is in blocked range %s", addr, p)
		}
	}
	if !allowPrivate {
		for _, p := range private {
			if p.Contains(addr) {
				return blockedf("address %s is private and host is not an internal upstream", addr)
			}
		}
	}
	return nil
}

type Dialer struct {
	Resolver *net.Resolver
	Internal map[string]bool // hostnames allowed to resolve to private IPs
	Timeout  time.Duration
}

// DialContext is shaped for http.Transport. It refuses IP literals: grants
// are by name, so a literal can only be an attempt to sidestep them.
func (d *Dialer) DialContext(ctx context.Context, network, hostport string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return nil, err
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil, blockedf("refusing to dial IP literal %s", host)
	}
	r := d.Resolver
	if r == nil {
		r = net.DefaultResolver
	}
	addrs, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	// Every answer must pass, not just the first: otherwise an attacker
	// controlling DNS returns [good, metadata] and waits for a retry.
	for _, a := range addrs {
		if err := Check(a, d.Internal[host]); err != nil {
			return nil, blockedf("%s resolved to a forbidden address: %v", host, err)
		}
	}
	nd := net.Dialer{Timeout: d.Timeout}
	var last error
	for _, a := range addrs {
		c, err := nd.DialContext(ctx, network, net.JoinHostPort(a.String(), port))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

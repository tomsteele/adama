package dnspin

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func query(t *testing.T, address, network, name string, typ uint16) *dns.Msg {
	t.Helper()
	m, _, err := (&dns.Client{Net: network, Timeout: time.Second}).Exchange(new(dns.Msg).SetQuestion(name, typ), address)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestBindingsAreIsolatedAndDoNotLeakOtherAddresses(t *testing.T) {
	for _, ip := range []string{"192.0.2.4", "2001:db8::4"} {
		r, err := Start(context.Background(), "app.example", ip, []string{"127.0.0.1:1"})
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		for _, network := range []string{"udp", "tcp"} {
			for _, typ := range []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeHTTPS} {
				m := query(t, r.Address, network, "APP.Example.", typ)
				want := typ == dns.TypeA && net.ParseIP(ip).To4() != nil || typ == dns.TypeAAAA && net.ParseIP(ip).To4() == nil
				if m.Rcode != dns.RcodeSuccess || (len(m.Answer) == 1) != want {
					t.Fatalf("%s %d: %v", ip, typ, m)
				}
				if want {
					switch rr := m.Answer[0].(type) {
					case *dns.A:
						if rr.A.String() != ip {
							t.Fatal(rr)
						}
					case *dns.AAAA:
						if rr.AAAA.String() != ip {
							t.Fatal(rr)
						}
					}
				}
			}
		}
	}
}

func TestOtherNamesForwardWithoutRebinding(t *testing.T) {
	upstream, err := Start(context.Background(), "other.example", "192.0.2.99", []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	r, err := Start(context.Background(), "app.example", "192.0.2.1", []string{upstream.Address})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	m := query(t, r.Address, "udp", "other.example.", dns.TypeA)
	if r.Used() || !upstream.Used() {
		t.Fatal("unrelated DNS query counted as use of the target binding")
	}
	if len(m.Answer) != 1 || m.Answer[0].(*dns.A).A.String() != "192.0.2.99" {
		t.Fatal(m)
	}
}

func TestCancellationClosesBothListeners(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	r, err := Start(ctx, "app.example", "192.0.2.1", []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	r.Close() // Wait for shutdown, including a concurrent context callback.
	for _, network := range []string{"udp", "tcp"} {
		_, _, err := (&dns.Client{Net: network, Timeout: 50 * time.Millisecond}).Exchange(new(dns.Msg).SetQuestion("app.example.", dns.TypeA), r.Address)
		if err == nil {
			t.Fatalf("%s listener survived cancellation", network)
		}
	}
}

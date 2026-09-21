// Package dnspin provides a task-local DNS override for CLI tools. It binds one
// name to one address without changing the worker's or container's resolver.
package dnspin

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type Resolver struct {
	Address  string
	udp, tcp *dns.Server
	once     sync.Once
	done     chan struct{}
	cancel   context.CancelFunc
	answers  atomic.Uint64
}

// Used reports whether the tool requested an address answer for the bound name.
// It is configuration-use evidence, not proof of a subsequent connection.
func (r *Resolver) Used() bool { return r.answers.Load() > 0 }

// Start answers address queries for name with ip. Other names use upstreams,
// or the system resolv.conf when upstreams is empty. It listens only on loopback
// and needs no privileged port. Each task gets an independent override.
func Start(ctx context.Context, name, ip string, upstreams []string) (*Resolver, error) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return nil, fmt.Errorf("DNS binding IP: %w", err)
	}
	name = dns.Fqdn(strings.ToLower(name))
	if _, ok := dns.IsDomainName(name); !ok || name == "." {
		return nil, fmt.Errorf("invalid DNS binding name %q", name)
	}
	if len(upstreams) == 0 {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("upstream resolvers: %w", err)
		}
		for _, server := range cfg.Servers {
			upstreams = append(upstreams, net.JoinHostPort(server, cfg.Port))
		}
	}
	upstreams = append([]string(nil), upstreams...)
	udp, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tcp, err := net.Listen("tcp4", udp.LocalAddr().String())
	if err != nil {
		udp.Close()
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	r := &Resolver{Address: udp.LocalAddr().String(), done: make(chan struct{}), cancel: cancel}
	h := dns.HandlerFunc(func(w dns.ResponseWriter, q *dns.Msg) {
		answer := new(dns.Msg).SetReply(q)
		answer.RecursionAvailable = true
		if len(q.Question) != 1 {
			answer.Rcode = dns.RcodeFormatError
		} else if question := q.Question[0]; strings.EqualFold(question.Name, name) {
			// No alternate family, CNAME, or HTTPS/SVCB route may undo this
			// task's binding. This is routing data, not DNS scan evidence.
			if question.Qclass == dns.ClassINET {
				header := dns.RR_Header{Name: question.Name, Class: dns.ClassINET, Rrtype: question.Qtype}
				if question.Qtype == dns.TypeA && addr.Unmap().Is4() {
					answer.Answer = []dns.RR{&dns.A{Hdr: header, A: net.IP(addr.Unmap().AsSlice())}}
				} else if question.Qtype == dns.TypeAAAA && addr.Is6() && !addr.Is4In6() {
					answer.Answer = []dns.RR{&dns.AAAA{Hdr: header, AAAA: net.IP(addr.AsSlice())}}
				}
				if len(answer.Answer) > 0 {
					r.answers.Add(1)
				}
			}
		} else {
			answer.Rcode = dns.RcodeServerFailure
			forwardCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			for _, upstream := range upstreams {
				client := &dns.Client{Timeout: time.Second}
				response, _, err := client.ExchangeContext(forwardCtx, q, upstream)
				if err == nil && response.Truncated {
					client.Net = "tcp"
					response, _, err = client.ExchangeContext(forwardCtx, q, upstream)
				}
				if err == nil && response.Rcode != dns.RcodeServerFailure {
					answer = response
					break
				}
			}
		}
		_ = w.WriteMsg(answer)
	})
	r.udp = &dns.Server{PacketConn: udp, Handler: h}
	r.tcp = &dns.Server{Listener: tcp, Handler: h}
	for _, server := range []*dns.Server{r.udp, r.tcp} {
		ready, failed := make(chan struct{}), make(chan error, 1)
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { failed <- server.ActivateAndServe() }()
		select {
		case <-ready:
		case err := <-failed:
			r.Close()
			udp.Close()
			tcp.Close()
			return nil, fmt.Errorf("start task DNS resolver: %w", err)
		case <-ctx.Done():
			r.Close()
			udp.Close()
			tcp.Close()
			return nil, ctx.Err()
		}
	}
	go func() {
		select {
		case <-ctx.Done():
			r.Close()
		case <-r.done:
		}
	}()
	return r, nil
}

func (r *Resolver) Close() {
	r.once.Do(func() {
		close(r.done)
		r.cancel()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = r.udp.ShutdownContext(ctx)
		_ = r.tcp.ShutdownContext(ctx)
	})
}

//go:build integration

package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"adama/event"
	"adama/internal/dnspin"
)

func integrationProfile(t *testing.T, file, template string) profile {
	t.Helper()
	p, err := loadProfile("../../profiles/" + file)
	if err != nil {
		t.Fatal(err)
	}
	p.NucleiArgs = append(p.NucleiArgs, "-t", template, "-ni", "-timeout", "2", "-retries", "0")
	p.Resolvers = []string{"127.0.0.1:1"}
	return p
}

func TestIntegrationHTTPBindings(t *testing.T) {
	p := integrationProfile(t, "nuclei.yaml", "testdata/http.yaml,testdata/http-raw.yaml")
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			port := "0"
			for _, ip := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
				network := "tcp4"
				if strings.Contains(ip, ":") {
					network = "tcp6"
				}
				ln, err := net.Listen(network, net.JoinHostPort(ip, port))
				if err != nil {
					t.Fatal(err)
				}
				_, port, _ = net.SplitHostPort(ln.Addr().String())
				authority := "vhost.adama.invalid:" + port
				var requests, bad atomic.Int32
				s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					requests.Add(1)
					if r.Host != authority || r.URL.Path != "/Admin" || r.URL.RawQuery != "Token=AbC" || scheme == "https" && r.TLS.ServerName != "vhost.adama.invalid" {
						bad.Add(1)
						t.Logf("unexpected request Host=%q URL=%q TLS=%+v", r.Host, r.URL.String(), r.TLS)
					}
					fmt.Fprintf(w, "<html>adama-backend=%s</html>", ip)
				}))
				s.Listener.Close()
				s.Listener = ln
				if scheme == "https" {
					s.StartTLS()
				} else {
					s.Start()
				}
				t.Cleanup(s.Close)
				t.Run(ip, func(t *testing.T) {
					t.Parallel()
					u := scheme + "://" + authority + "/Admin?Token=AbC"
					target, _ := event.URLTarget(u)
					target.Host = ip
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					out, err := scan(ctx, p, event.Event{Kind: event.KindURL, Value: u, Target: target})
					if err != nil {
						t.Fatalf("%d findings, %d requests, %d wrong: %v", len(out), requests.Load(), bad.Load(), err)
					}
					if len(out) != 2 || requests.Load() != 2 || bad.Load() != 0 {
						t.Fatalf("findings=%d requests=%d wrong requests=%d", len(out), requests.Load(), bad.Load())
					}
					for _, ev := range out {
						if ev.Host != ip || ev.Name != "vhost.adama.invalid" || ev.Info["endpoint_binding"] != "task_dns" {
							t.Fatalf("wrong identity %+v", ev)
						}
						if _, err := ev.Canonical(); err != nil {
							t.Fatal(err)
						}
					}
				})
			}
		})
	}
}

func TestIntegrationCleanNonMatchAndFailedRequests(t *testing.T) {
	p := integrationProfile(t, "nuclei.yaml", "testdata/http.yaml")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "clean response") }))
	defer s.Close()
	target, _ := event.URLTarget(s.URL)
	u := strings.Replace(s.URL, "127.0.0.1", "vhost.adama.invalid", 1)
	boundTarget, _ := event.URLTarget(u)
	boundTarget.Host = target.Host
	in := event.Event{Kind: event.KindURL, Value: u, Target: boundTarget}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := scan(ctx, p, in)
	if err != nil || len(out) != 0 {
		t.Fatalf("clean non-match: %d findings %v", len(out), err)
	}
	s.Close()
	out, err = scan(ctx, p, in)
	if err == nil || len(out) != 0 || ctx.Err() != nil {
		t.Fatalf("failed request: %d findings %v", len(out), err)
	}
}

func TestIntegrationIgnoredBindingCannotCompleteCleanScan(t *testing.T) {
	p := integrationProfile(t, "nuclei.yaml", "testdata/http.yaml")
	// Simulate a custom profile that accidentally omits the resolver flag.
	p.BoundArgs = []string{"-retries", "0"}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "clean response") }))
	defer s.Close()
	u := strings.Replace(s.URL, "127.0.0.1", "localhost", 1)
	target, _ := event.URLTarget(u)
	target.Host = "127.0.0.1"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, event.Event{Kind: event.KindURL, Value: u, Target: target})
	if err == nil || !strings.Contains(err.Error(), "did not use") || len(out) != 0 {
		t.Fatalf("unverified binding completed: %d findings %v", len(out), err)
	}
}

func TestIntegrationRedirectUsesOtherNamesActualBackend(t *testing.T) {
	p := integrationProfile(t, "nuclei.yaml", "testdata/http.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	upstream, err := dnspin.Start(ctx, "destination.adama.invalid", "127.0.0.2", []string{"127.0.0.1:1"})
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	p.Resolvers = []string{upstream.Address}
	var destinationURL string
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, destinationURL, http.StatusFound) }))
	defer source.Close()
	_, port, _ := net.SplitHostPort(source.Listener.Addr().String())
	var visited atomic.Bool
	destination := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited.Store(true)
		fmt.Fprint(w, "adama-backend=redirect")
	}))
	destination.Listener.Close()
	destination.Listener, err = net.Listen("tcp4", net.JoinHostPort("127.0.0.2", port))
	if err != nil {
		t.Fatal(err)
	}
	destination.Start()
	defer destination.Close()
	destinationURL = "http://destination.adama.invalid:" + port + "/Final"
	u := "http://vhost.adama.invalid:" + port
	target, _ := event.URLTarget(u)
	target.Host = "127.0.0.1"
	out, err := scan(ctx, p, event.Event{Kind: event.KindURL, Value: u, Target: target})
	if err != nil || len(out) != 1 || !visited.Load() {
		t.Fatalf("redirect: visited=%v findings=%+v err=%v", visited.Load(), out, err)
	}
	if out[0].Info["endpoint_evidence"] != "scanner_reported" {
		t.Fatal("overstated redirect evidence")
	}
}

func TestIntegrationTCPRequests(t *testing.T) {
	p := integrationProfile(t, "nuclei-net.yaml", "testdata/tcp.yaml")
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.ReadFull(c, make([]byte, 7))
			fmt.Fprint(c, "adama-backend=tcp\r\n")
			c.Close()
		}
	}()
	defer func() { ln.Close(); wg.Wait() }()
	host, port, _ := event.SplitHostPort(ln.Addr().String())
	in := event.Event{Kind: event.KindService, Value: ln.Addr().String() + "/unknown", Service: "unknown", Target: event.Target{Host: host, Port: port, Proto: event.TCP}}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := scan(ctx, p, in)
	if err != nil || len(out) != 1 || out[0].Host != host || out[0].Port != port || out[0].Proto != event.TCP {
		t.Fatalf("TCP findings=%+v err=%v", out, err)
	}
	ln.Close()
	out, err = scan(ctx, p, in)
	if err == nil || len(out) != 0 || ctx.Err() != nil {
		t.Fatalf("TCP failure: %d findings %v", len(out), err)
	}
}

func TestIntegrationPartialFailureRetainsFinding(t *testing.T) {
	p := integrationProfile(t, "nuclei.yaml", "testdata/http-partial.yaml")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/broken" {
			c, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				c.Close()
			}
			return
		}
		fmt.Fprint(w, "adama-backend=partial")
	}))
	defer s.Close()
	target, _ := event.URLTarget(s.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, event.Event{Kind: event.KindURL, Value: s.URL, Target: target})
	if err == nil || len(out) != 1 || out[0].Info["scan_request_errors"] == "0" || ctx.Err() != nil {
		t.Fatalf("partial scan: %d findings, %v", len(out), err)
	}
}

func TestIntegrationDeadlineCannotReportCompletion(t *testing.T) {
	p := integrationProfile(t, "nuclei.yaml", "testdata/http.yaml")
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	target, _ := event.URLTarget(s.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := scan(ctx, p, event.Event{Kind: event.KindURL, Value: s.URL, Target: target})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline was lost: %v", err)
	}
}

func TestIntegrationNetworkBindings(t *testing.T) {
	for _, protocol := range []string{"tcp", "ssl"} {
		t.Run(protocol, func(t *testing.T) {
			p := integrationProfile(t, "nuclei-net.yaml", "testdata/"+protocol+".yaml")
			if protocol == "ssl" {
				// TLSX treats this as total attempts, so zero sends no request.
				p.NucleiArgs = append(p.NucleiArgs, "-retries", "1")
			}
			port := "0"
			for _, ip := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
				ln, err := net.Listen("tcp", net.JoinHostPort(ip, port))
				if err != nil {
					t.Fatal(err)
				}
				_, port, _ = net.SplitHostPort(ln.Addr().String())
				var requests, badSNI atomic.Int32
				if protocol == "tcp" {
					serveTCPFixture(t, ln, &requests)
				} else {
					s := httptest.NewUnstartedServer(http.NotFoundHandler())
					s.Listener.Close()
					s.Listener = ln
					s.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
						requests.Add(1)
						if hello.ServerName != "vhost.adama.invalid" {
							badSNI.Add(1)
						}
						return nil, nil
					}}
					s.StartTLS()
					t.Cleanup(s.Close)
				}
				t.Run(ip, func(t *testing.T) {
					t.Parallel()
					_, number, _ := event.SplitHostPort(ln.Addr().String())
					in := event.Event{Kind: event.KindService, Value: "vhost.adama.invalid:" + port + "/" + protocol, Service: protocol,
						Target: event.Target{Host: ip, Name: "vhost.adama.invalid", NameRole: event.NameRequested, Port: number, Proto: event.TCP}}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					out, err := scan(ctx, p, in)
					if err != nil || len(out) != 1 || requests.Load() == 0 || badSNI.Load() != 0 {
						t.Fatalf("%s findings=%+v requests=%d bad SNI=%d err=%v", protocol, out, requests.Load(), badSNI.Load(), err)
					}
					if out[0].Host != ip || out[0].Name != in.Name || out[0].Port != number || out[0].Proto != event.TCP {
						t.Fatalf("wrong endpoint: %+v", out[0])
					}
					if _, err := out[0].Canonical(); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func serveTCPFixture(t *testing.T, ln net.Listener, requests *atomic.Int32) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			requests.Add(1)
			_ = c.SetDeadline(time.Now().Add(3 * time.Second))
			_, _ = io.ReadFull(c, make([]byte, 7))
			fmt.Fprint(c, "adama-backend=tcp\r\n")
			c.Close()
		}
	}()
	t.Cleanup(func() { ln.Close(); wg.Wait() })
}

func TestIntegrationWrongPortCannotComplete(t *testing.T) {
	requested, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var requestedCount, otherCount atomic.Int32
	serveTCPFixture(t, requested, &requestedCount)
	other, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveTCPFixture(t, other, &otherCount)
	fixture, err := os.ReadFile("testdata/tcp-other-port.yaml")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "other-port.yaml")
	if err := os.WriteFile(path, []byte(strings.ReplaceAll(string(fixture), "{{Host}}:{{OtherPort}}", other.Addr().String())), 0o600); err != nil {
		t.Fatal(err)
	}
	p := integrationProfile(t, "nuclei-net.yaml", path)
	host, port, _ := event.SplitHostPort(requested.Addr().String())
	in := event.Event{Kind: event.KindService, Value: requested.Addr().String() + "/unknown", Service: "unknown", Target: event.Target{Host: host, Port: port, Proto: event.TCP}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, in)
	if len(out) != 0 || err == nil || !strings.Contains(err.Error(), "service coverage") || otherCount.Load() != 1 || requestedCount.Load() != 0 {
		t.Fatalf("wrong-port non-match: findings=%+v requested=%d other=%d err=%v", out, requestedCount.Load(), otherCount.Load(), err)
	}
	// Positive results also keep the actual endpoint, even while the requested
	// service task fails. A reporting sink must not upsert them under the input.
	matching := strings.ReplaceAll(string(fixture), "{{Host}}:{{OtherPort}}", other.Addr().String())
	matching = strings.ReplaceAll(matching, "never-matches", "adama-backend")
	if err := os.WriteFile(path, []byte(matching), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err = scan(ctx, p, in)
	_, otherPort, _ := event.SplitHostPort(other.Addr().String())
	if err == nil || len(out) != 1 || out[0].Port != otherPort || out[0].Info["requested_endpoint_status"] != "mismatch" || requestedCount.Load() != 0 {
		t.Fatalf("wrong-port match: findings=%+v requested=%d other=%d err=%v", out, requestedCount.Load(), otherCount.Load(), err)
	}
}

func TestIntegrationSyntheticDNSIsNotPublishedAsFinding(t *testing.T) {
	p := integrationProfile(t, "nuclei-net.yaml", "testdata/dns.yaml")
	// Simulate an edited profile mixing DNS evidence with backend routing.
	p.NucleiArgs = append(p.NucleiArgs, "-pt", "dns")
	in := event.Event{Kind: event.KindService, Value: "vhost.adama.invalid:12345/unknown", Target: event.Target{
		Host: "127.0.0.2", Name: "vhost.adama.invalid", NameRole: event.NameRequested, Port: 12345, Proto: event.TCP,
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, in)
	if len(out) != 0 || err == nil || !strings.Contains(err.Error(), "synthetic backend resolver") {
		t.Fatalf("synthetic DNS findings=%+v err=%v", out, err)
	}
}

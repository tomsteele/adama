package webprobe

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"adama/event"
	"adama/internal/asurl"
)

func endpoint(t *testing.T, raw string) event.Event {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	value, _ := event.PortValue("unresolvable.invalid", port)
	ev, err := (event.Event{Kind: event.KindService, Value: value + "/unknown",
		Target: event.Target{Host: u.Hostname(), Name: "unresolvable.invalid", NameRole: event.NameRequested, Port: port, Proto: event.TCP}, Service: "unknown"}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestHTTPUsesBoundIPAndHostWithoutFollowingRedirect(t *testing.T) {
	var redirected atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Add(1) }))
	defer other.Close()
	var host string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host = r.Host
		http.Redirect(w, r, other.URL, http.StatusFound)
	}))
	defer s.Close()
	in := endpoint(t, s.URL)
	out, err := probe(context.Background(), in, "http", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if out.Host != in.Host || out.Name != in.Name || host != "unresolvable.invalid:"+strconv.Itoa(in.Port) || redirected.Load() != 0 {
		t.Fatalf("lost binding or followed redirect: %+v host=%s redirected=%d", out, host, redirected.Load())
	}
	child, ok := asurl.Event(out)
	if !ok || child.Host != in.Host || child.Name != in.Name || child.Port != in.Port || child.Info["status_code"] != "302" {
		t.Fatalf("missing downstream URL: %+v", child)
	}
}

func TestHTTPSUsesRequestedSNIOnBoundBackend(t *testing.T) {
	var sni string
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(401) }))
	s.TLS = &tls.Config{GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) { sni = hello.ServerName; return nil, nil }}
	s.StartTLS()
	defer s.Close()
	in := endpoint(t, s.URL)
	out, err := probe(context.Background(), in, "https", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if sni != in.Name || out.Host != in.Host || !out.TLS || out.Service != "https" || out.Info["status_code"] != "401" {
		t.Fatalf("lost HTTPS identity: %+v sni=%s", out, sni)
	}
}

func TestNegativeProbeIsFiniteAndDoesNotFeedItself(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var calls atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			calls.Add(1)
			_, _ = io.WriteString(conn, "SSH-2.0-test\r\n")
			conn.Close()
		}
	}()
	in := endpoint(t, "http://"+listener.Addr().String())
	out, err := Probe(context.Background(), in, time.Second)
	listener.Close()
	<-done
	if err != nil || len(out) != 1 || out[0].Info["http_probe_status"] != "not_detected" || calls.Load() != 2 {
		t.Fatalf("negative outcome: %+v %v calls=%d", out, err, calls.Load())
	}
	out[0].Source = "web-probe"
	if Accept(out[0]) {
		t.Fatal("negative observation would probe again")
	}
	in.Proto = event.UDP
	if Accept(in) {
		t.Fatal("UDP service accepted as TCP")
	}
}

func TestTimeoutIsInconclusiveAndCancellationStops(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer s.Close()
	in := endpoint(t, s.URL)
	out, err := Probe(context.Background(), in, 30*time.Millisecond)
	if err == nil || len(out) != 1 || out[0].Info["http_probe_status"] != "inconclusive" {
		t.Fatalf("timeout marked negative: %+v %v", out, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Probe(ctx, in, time.Second); err != context.Canceled {
		t.Fatalf("cancellation lost: %v", err)
	}
}

//go:build integration

package main

import (
	"bytes"
	"context"
	"fmt"
	"image"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"adama/event"
)

// Run inside the HTTPX image, with networking disabled. All targets, DNS, and
// browser traffic needed by these tests live on the container's loopback.
func TestIntegrationBoundScreenshots(t *testing.T) {
	if _, err := exec.LookPath("httpx"); err != nil {
		t.Fatal("integration tests require HTTPX and Chromium")
	}
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// Exercise the shipped profile, with short timeouts and no update checks.
	p.HttpxArgs = append(p.HttpxArgs, "-timeout", "3", "-retries", "0", "-duc")
	p.Resolvers = []string{"127.0.0.1:1"}
	for _, scheme := range []string{"http", "https"} {
		t.Run(scheme, func(t *testing.T) {
			root := t.TempDir()
			port := "0"
			for i, ip := range []string{"127.0.0.1", "127.0.0.2", "::1"} {
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
				var browser, probe, bad atomic.Int32
				color := []string{"#ff0000", "#0000ff"}[i%2]
				server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.Host != authority || scheme == "https" && r.TLS.ServerName != "vhost.adama.invalid" {
						bad.Add(1)
					}
					if r.URL.Path == "/Admin" && r.URL.RawQuery == "Token=AbC" {
						probe.Add(1)
					}
					if r.URL.Path == "/browser-check" {
						browser.Add(1)
						w.WriteHeader(http.StatusNoContent)
						return
					}
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprintf(w, "<html><head><title>%s</title></head><body style='margin:0;background:%s'><script>fetch('/browser-check')</script></body></html>", ip, color)
				}))
				server.Listener.Close()
				server.Listener = ln
				server.Config.ErrorLog = log.New(io.Discard, "", 0) // JARM deliberately sends incompatible TLS probes.
				if scheme == "https" {
					server.StartTLS()
				} else {
					server.Start()
				}
				t.Cleanup(server.Close)
				t.Run(ip, func(t *testing.T) {
					t.Parallel()
					ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
					defer cancel()
					u := scheme + "://" + authority + "/Admin?Token=AbC"
					target, _ := event.URLTarget(u)
					target.Host = ip
					out, err := scan(ctx, p, root, event.Event{Kind: event.KindURL, Value: u, Target: target})
					if err != nil {
						t.Fatalf("scan: %v (%d observations)", err, len(out))
					}
					if len(out) != 1 {
						t.Fatalf("got %d observations", len(out))
					}
					shot := out[0]
					if _, err := shot.Canonical(); err != nil {
						t.Fatalf("invalid observation: %v", err)
					}
					if shot.Host != ip || shot.Info["title"] != ip || shot.Info["endpoint_binding"] == "" {
						t.Fatalf("wrong endpoint: host=%s info=%v", shot.Host, shot.Info)
					}
					if shot.Info["a"] != "" || shot.Info["aaaa"] != "" || shot.Info["cname"] != "" {
						t.Fatal("task DNS override exported as DNS evidence")
					}
					img, _, err := image.Decode(bytes.NewReader(shot.Data))
					if err != nil {
						t.Fatal(err)
					}
					r, g, b, _ := img.At(50, 50).RGBA()
					if g > 2000 || i%2 == 0 && (r < 60000 || b > 2000) || i%2 == 1 && (b < 60000 || r > 2000) {
						t.Fatalf("screenshot from wrong backend: pixel=%d,%d,%d", r, g, b)
					}
					if browser.Load() == 0 || probe.Load() < 2 || bad.Load() != 0 {
						t.Fatalf("Host/SNI/path: browser=%d probe=%d bad=%d", browser.Load(), probe.Load(), bad.Load())
					}
				})
			}
		})
	}
}

func TestIntegrationUnavailableBackendFails(t *testing.T) {
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.HttpxArgs = append(p.HttpxArgs, "-timeout", "1", "-retries", "0", "-duc")
	p.Resolvers = []string{"127.0.0.1:1"}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	ln.Close()
	u := "http://unavailable.adama.invalid:" + port
	target, _ := event.URLTarget(u)
	target.Host = "127.0.0.1"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, t.TempDir(), event.Event{Kind: event.KindURL, Value: u, Target: target})
	if err == nil {
		t.Fatalf("unavailable backend completed: %d observations", len(out))
	}
	if ctx.Err() != nil {
		t.Fatalf("scanner did not stop within its configured timeout: %v", err)
	}
}

func TestIntegrationRedirectDoesNotAssertBrowserEndpoint(t *testing.T) {
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.HttpxArgs = append(p.HttpxArgs, "-timeout", "3", "-retries", "0", "-duc")
	p.Resolvers = []string{"127.0.0.1:1"}
	var visited atomic.Bool
	destination := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visited.Store(true)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body style='margin:0;background:#0000ff'></body></html>")
	}))
	destination.Listener.Close()
	destination.Listener, err = net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	destination.Start()
	defer destination.Close()
	initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL+"/Landing", http.StatusFound)
	}))
	defer initial.Close()
	_, port, _ := net.SplitHostPort(initial.Listener.Addr().String())
	u := "http://redirect.adama.invalid:" + port
	target, _ := event.URLTarget(u)
	target.Host = "127.0.0.1"
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := scan(ctx, p, t.TempDir(), event.Event{Kind: event.KindURL, Value: u, Target: target})
	if err != nil || len(out) != 1 {
		t.Fatalf("redirect: %d observations, %v", len(out), err)
	}
	shot := out[0]
	if !visited.Load() || shot.Host != "127.0.0.1" || shot.Info["endpoint_evidence"] != "http_probe" || shot.Info["browser_endpoint_evidence"] != "unreported" {
		t.Fatalf("redirect attribution: %v", shot.Info)
	}
	img, _, err := image.Decode(bytes.NewReader(shot.Data))
	if err != nil {
		t.Fatal(err)
	}
	r, g, b, _ := img.At(50, 50).RGBA()
	if r > 2000 || g > 2000 || b < 60000 {
		t.Fatal("did not capture the redirected page")
	}
}

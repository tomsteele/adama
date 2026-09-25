//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	"adama/internal/browsercapture"
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

func TestIntegrationRedirectReportsBrowserEndpoint(t *testing.T) {
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
	if err != nil || len(out) != 2 {
		t.Fatalf("redirect: %d observations, %v", len(out), err)
	}
	shot := out[0]
	if !visited.Load() || shot.Host != "127.0.0.2" || shot.URL != destination.URL+"/Landing" || shot.Info["endpoint_evidence"] != "browser_document" || shot.Info["browser_endpoint_evidence"] != "cdp_response" {
		t.Fatalf("redirect attribution: %v", shot.Info)
	}
	if out[1].Kind != event.KindURL || out[1].URL != shot.URL || out[1].Host != shot.Host || out[1].Meta["redirect_depth"] != "1" {
		t.Fatalf("redirect destination not queued: %+v", out[1])
	}
	for _, ev := range out {
		if _, err := ev.Canonical(); err != nil {
			t.Fatal(err)
		}
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

func TestIntegrationRedirectKindsPreserveFinalDocument(t *testing.T) {
	for _, mode := range []string{"http", "meta", "javascript"} {
		t.Run(mode, func(t *testing.T) {
			p, err := loadProfile("../../profiles/httpx.yaml")
			if err != nil {
				t.Fatal(err)
			}
			p.HttpxArgs = append(p.HttpxArgs, "-timeout", "2", "-retries", "0", "-duc")
			p.Browser.Idle, p.Browser.Timeout = "250ms", "10s"
			p.Resolvers = []string{"127.0.0.1:1"}
			var childVisits, finalVisits, cookieVisits atomic.Int32
			child := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				childVisits.Add(1)
				fmt.Fprint(w, "<html><body style='background:red'></body></html>")
			}))
			defer child.Close()
			destination := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/Landing" || r.URL.RawQuery != "Token=AbC" {
					w.WriteHeader(404)
					return
				}
				finalVisits.Add(1)
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, "<html><head><title>Final page</title></head><body style='margin:0;background:blue'><iframe style='position:absolute;left:300px;top:300px' src=%q></iframe></body></html>", child.URL)
			}))
			destination.Listener.Close()
			destination.Listener, err = net.Listen("tcp6", "[::1]:0")
			if err != nil {
				t.Fatal(err)
			}
			destination.StartTLS()
			defer destination.Close()
			finalURL := destination.URL + "/Landing?Token=AbC#Section"
			initial := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				if mode == "http" {
					if r.URL.Path == "/Start" {
						http.SetCookie(w, &http.Cookie{Name: "gate", Value: "ready", Path: "/"})
						http.Redirect(w, r, "/middle?Case=Yes", http.StatusFound)
						return
					}
					if r.URL.Path == "/middle" {
						if c, err := r.Cookie("gate"); err == nil && c.Value == "ready" {
							cookieVisits.Add(1)
						} else {
							http.Error(w, "missing cookie", 403)
							return
						}
						http.Redirect(w, r, finalURL, http.StatusTemporaryRedirect)
						return
					}
					w.WriteHeader(404)
				} else if mode == "meta" {
					fmt.Fprintf(w, `<html><head><meta http-equiv="refresh" content="0;url=%s"></head><body>Initial page</body></html>`, finalURL)
				} else {
					fmt.Fprintf(w, `<html><head><title>Initial page</title></head><body><script>alert('fixture');setTimeout(()=>location.href=%q,100)</script></body></html>`, finalURL)
				}
			}))
			defer initial.Close()
			_, port, _ := net.SplitHostPort(initial.Listener.Addr().String())
			u := "http://redirect.adama.invalid:" + port + "/Start"
			target, _ := event.URLTarget(u)
			target.Host = "127.0.0.1"
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			out, err := scan(ctx, p, t.TempDir(), event.Event{Kind: event.KindURL, Value: u, Target: target})
			if err != nil || len(out) < 2 {
				t.Fatalf("observations=%d err=%v", len(out), err)
			}
			shot := out[0]
			if shot.URL != finalURL || shot.Host != "::1" || !shot.TLS || shot.Info["title"] != "Final page" || shot.Info["initial_host"] != "127.0.0.1" {
				t.Fatalf("wrong screenshot endpoint: %+v info=%v", shot.Target, shot.Info)
			}
			if finalVisits.Load() == 0 || childVisits.Load() == 0 || mode == "http" && cookieVisits.Load() == 0 {
				t.Fatal("fixture navigation incomplete")
			}
			var hops []browsercapture.Hop
			if err := json.Unmarshal([]byte(shot.Info["redirect_chain"]), &hops); err != nil {
				t.Fatal(err)
			}
			want := 2
			if mode == "http" {
				want = 3
			}
			if len(hops) != want || hops[0].Host != "127.0.0.1" || hops[len(hops)-1].Host != "::1" {
				t.Fatalf("bad chain %+v", hops)
			}
			for _, ev := range out {
				if _, err := ev.Canonical(); err != nil {
					t.Fatal(err)
				}
			}
			img, _, err := image.Decode(bytes.NewReader(shot.Data))
			if err != nil {
				t.Fatal(err)
			}
			r, g, b, _ := img.At(50, 50).RGBA()
			if r > 2000 || g > 2000 || b < 60000 {
				t.Fatal("image did not belong to final document")
			}
		})
	}
}

func TestIntegrationRedirectLoopStopsAtBudget(t *testing.T) {
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.HttpxArgs = append(p.HttpxArgs, "-timeout", "1", "-retries", "0", "-duc")
	p.Browser.MaxRedirects = 2
	p.Browser.Timeout = "5s"
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Redirect(w, r, "/loop", http.StatusFound)
	}))
	defer s.Close()
	target, _ := event.URLTarget(s.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, t.TempDir(), event.Event{Kind: event.KindURL, Value: s.URL, Target: target})
	if err == nil || !strings.Contains(err.Error(), "redirect loop or limit") || ctx.Err() != nil {
		t.Fatalf("loop did not stop: %v", err)
	}
	for _, ev := range out {
		if ev.Kind == event.KindScreenshot && len(ev.Data) > 0 {
			t.Fatal("redirect loop produced a completed screenshot")
		}
	}
	if requests.Load() > 10 {
		t.Fatalf("unbounded loop: %d requests", requests.Load())
	}
}

func TestIntegrationBrokenRedirectRetainsResponse(t *testing.T) {
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.HttpxArgs = append(p.HttpxArgs, "-timeout", "1", "-retries", "0", "-duc")
	p.Browser.Timeout = "5s"
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	failedURL := "http://" + ln.Addr().String() + "/unavailable"
	ln.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, failedURL, http.StatusFound) }))
	defer s.Close()
	target, _ := event.URLTarget(s.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := scan(ctx, p, t.TempDir(), event.Event{Kind: event.KindURL, Value: s.URL, Target: target})
	if err == nil || len(out) != 1 || len(out[0].Data) != 0 || out[0].Info["screenshot_status"] != "missing" || !strings.Contains(out[0].Info["redirect_chain"], failedURL) {
		t.Fatalf("lost failed redirect response: observations=%+v err=%v", out, err)
	}
}

func TestIntegrationRedirectToAnotherHostnameUsesItsOwnIP(t *testing.T) {
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	p.HttpxArgs = append(p.HttpxArgs, "-timeout", "1", "-retries", "0", "-duc")
	p.Browser.Idle = "100ms"
	p.Resolvers = []string{"127.0.0.1:1"}
	var visits, bad atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		visits.Add(1)
		if r.TLS.ServerName != "destination.localhost" || !strings.HasPrefix(r.Host, "destination.localhost:") {
			bad.Add(1)
		}
		fmt.Fprint(w, "<html><head><title>Destination</title></head><body>final</body></html>")
	}))
	defer destination.Close()
	_, destinationPort, _ := net.SplitHostPort(destination.Listener.Addr().String())
	finalURL := "https://destination.localhost:" + destinationPort + "/Landing"
	source := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, finalURL, http.StatusFound) }))
	source.Listener.Close()
	source.Listener, err = net.Listen("tcp4", "127.0.0.2:0")
	if err != nil {
		t.Fatal(err)
	}
	source.Start()
	defer source.Close()
	_, sourcePort, _ := net.SplitHostPort(source.Listener.Addr().String())
	u := "http://initial.adama.invalid:" + sourcePort
	target, _ := event.URLTarget(u)
	target.Host = "127.0.0.2"
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := scan(ctx, p, t.TempDir(), event.Event{Kind: event.KindURL, Value: u, Target: target})
	if err != nil || len(out) != 2 || visits.Load() == 0 || bad.Load() != 0 {
		t.Fatalf("observations=%d visits=%d bad=%d err=%v", len(out), visits.Load(), bad.Load(), err)
	}
	for _, ev := range out {
		if ev.Host != "127.0.0.1" || ev.Name != "destination.localhost" || ev.URL != finalURL || ev.SNI != "destination.localhost" {
			t.Fatalf("redirect inherited initial identity: %+v", ev.Target)
		}
		if _, err := ev.Canonical(); err != nil {
			t.Fatal(err)
		}
	}
}

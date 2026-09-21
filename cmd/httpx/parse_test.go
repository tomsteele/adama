package main

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"adama/event"
)

func screenshotPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestLoadProfile(t *testing.T) {
	p, err := loadProfile("../../profiles/httpx.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "httpx" || len(p.Kinds) != 1 || p.Kinds[0] != "url" {
		t.Fatalf("%+v", p)
	}
	if p.ackWait().Minutes() != 5 {
		t.Fatalf("ack %s", p.ackWait())
	}
}

func TestParseResult(t *testing.T) {
	raw := []byte(`{"url":"https://example.com","title":"Example","webserver":"nginx","status_code":200,"tech":["nginx"],"jarm":"abc","cdn":true,"cdn_name":"cloudflare","a":["1.2.3.4"],"cname":["edge.example"],"asn":{"as_number":"AS13335","as_name":"CLOUDFLARENET","as_country":"US"},"screenshot_bytes":"iVBORw0KGgo="}
`)
	raw = []byte(strings.Replace(string(raw), "iVBORw0KGgo=", base64.StdEncoding.EncodeToString(screenshotPNG(t)), 1))
	r, ok, err := parseResult(raw)
	if err != nil || !ok {
		t.Fatalf("parse %v %v", ok, err)
	}
	in := event.Event{Value: "https://example.com", Meta: map[string]string{"host": "example.com", "port": "443", "product": "nginx"}}
	ev := toEvent(in, r)
	if ev.Kind != event.KindScreenshot || ev.Value != "https://example.com" {
		t.Fatalf("%+v", ev)
	}
	if ev.Meta["title"] != "Example" || ev.Meta["status_code"] != "200" || ev.Meta["tech"] != "nginx" {
		t.Fatalf("meta %+v", ev.Meta)
	}
	if ev.Meta["asn"] != "AS13335" || ev.Meta["as_name"] != "CLOUDFLARENET" || ev.Meta["cdn"] != "true" {
		t.Fatalf("asn/cdn %+v", ev.Meta)
	}
	if ev.Host != "" || ev.Name != "example.com" || ev.Port != 443 || ev.Proto != event.TCP || ev.MediaType != "image/png" || len(ev.Data) == 0 {
		t.Fatalf("shot %+v", ev)
	}
}

func TestParseResultPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "shot.png")
	png := screenshotPNG(t)
	if err := os.WriteFile(p, png, 0o644); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"url":"https://example.com","status_code":200,"screenshot_path":"` + p + `"}`)
	r, ok, err := parseResult(raw)
	if err != nil || !ok {
		t.Fatalf("parse %v %v", ok, err)
	}
	ev := toEvent(event.Event{Value: "https://example.com"}, r)
	if string(ev.Data) != string(png) || ev.MediaType != "image/png" {
		t.Fatalf("%+v", ev)
	}
}

func TestParseResultSkipFailed(t *testing.T) {
	_, ok, err := parseResult([]byte(`{"url":"https://dead.invalid","failed":true}`))
	if err != nil || ok {
		t.Fatalf("want skip, ok=%v err=%v", ok, err)
	}
}

func TestAllHTTPResultsRetainActualBackend(t *testing.T) {
	results, err := parseResults([]byte("{\"url\":\"https://app.example.com:8443/Admin?Token=AbC\",\"host_ip\":\"192.0.2.2\",\"status_code\":200}\n{\"url\":\"https://app.example.com:8443/Admin?Token=AbC\",\"host\":\"192.0.2.3\",\"status_code\":200}\n"))
	if err != nil || len(results) != 2 {
		t.Fatalf("%+v %v", results, err)
	}
	in := event.Event{Kind: event.KindURL, Value: "https://app.example.com:8443/Admin?Token=AbC", Target: event.Target{Host: "192.0.2.1"}}
	for i, r := range results {
		ev, err := toEvent(in, r).Canonical()
		if err != nil {
			t.Fatal(err)
		}
		want := []string{"192.0.2.2", "192.0.2.3"}[i]
		if ev.Host != want || ev.Name != "app.example.com" || ev.Port != 8443 || ev.Value != in.Value {
			t.Fatalf("incorrect endpoint %+v", ev)
		}
		if ev.Info["screenshot_status"] != "missing" {
			t.Fatal("missing screenshot not identified")
		}
	}
}

func TestHTTPMissingAddressDoesNotInheritDNSCandidates(t *testing.T) {
	in := event.Event{Kind: event.KindURL, Value: "https://app.example.com", Target: event.Target{Host: "192.0.2.1"}, Meta: map[string]string{"host": "192.0.2.1"}}
	ev, err := toEvent(in, result{URL: in.Value, A: []string{"192.0.2.2"}, StatusCode: 200}).Canonical()
	if err != nil || ev.Host != "" {
		t.Fatalf("guessed connected IP %+v %v", ev, err)
	}
}

func TestRedirectDoesNotAssertFinalEndpoint(t *testing.T) {
	ev := toEvent(event.Event{Value: "https://initial.example.com"}, result{URL: "https://initial.example.com", HostIP: "192.0.2.1", FinalURL: "https://other.example.com/Login", StatusCode: 200})
	if ev.Name != "initial.example.com" || ev.Info["redirect_endpoint"] != "unverified" || ev.Info["final_url"] != "https://other.example.com/Login" {
		t.Fatalf("misattributed redirect %+v", ev)
	}
}

func TestMissingOrInvalidScreenshotIsNotCaptured(t *testing.T) {
	for _, r := range []result{{ScreenshotPath: filepath.Join(t.TempDir(), "missing.png")}, {ScreenshotBytes: []byte("broken image")}} {
		ev := toEvent(event.Event{Value: "https://example.com"}, r)
		if len(ev.Data) != 0 || ev.Info["screenshot_status"] != "missing" || ev.Info["screenshot_error"] == "" {
			t.Fatalf("false screenshot completion %+v", ev)
		}
	}
}

func TestScreenshotOutcomeDoesNotCompleteWrongBackend(t *testing.T) {
	in := event.Event{Kind: event.KindURL, Value: "https://app.example.com", Target: event.Target{Host: "192.0.2.1"}}
	out, err := screenshotEvents(in, []result{{URL: in.Value, HostIP: "192.0.2.2", ScreenshotBytes: screenshotPNG(t)}})
	if err == nil || len(out) != 1 || out[0].Host != "192.0.2.2" || out[0].Info["requested_endpoint_status"] != "mismatch" {
		t.Fatalf("wrong backend reported complete %+v %v", out, err)
	}
	if _, err := screenshotEvents(in, nil); err == nil {
		t.Fatal("empty output completed screenshot task")
	}
	if _, err := screenshotEvents(in, []result{{URL: in.Value, HostIP: in.Host}}); err == nil {
		t.Fatal("missing image completed screenshot task")
	}
	if _, err := screenshotEvents(in, []result{{URL: in.Value, HostIP: in.Host, ScreenshotBytes: screenshotPNG(t)}}); err != nil {
		t.Fatal(err)
	}
}

func TestScreenshotOutcomeRequiresRequestedURL(t *testing.T) {
	in := event.Event{Kind: event.KindURL, Value: "https://app.example.com:8443/Admin?Token=AbC", Target: event.Target{Host: "192.0.2.1"}}
	for _, changed := range []string{"http://app.example.com:8443/Admin?Token=AbC", "https://app.example.com/Admin?Token=AbC", "https://other.example.com:8443/Admin?Token=AbC", "https://app.example.com:8443/admin?Token=AbC", "https://app.example.com:8443/Admin?Token=abc"} {
		out, err := screenshotEvents(in, []result{{URL: changed, HostIP: in.Host, ScreenshotBytes: screenshotPNG(t)}})
		if err == nil || len(out) != 1 || out[0].Info["requested_url_status"] != "mismatch" {
			t.Fatalf("wrong URL completed: %s", changed)
		}
	}
	if !sameURL("https://app.example.com", "https://APP.example.com:443/") {
		t.Fatal("equivalent URL rejected")
	}
}

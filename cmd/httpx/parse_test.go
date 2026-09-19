package main

import (
	"os"
	"path/filepath"
	"testing"

	"adama/event"
)

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
	if ev.Meta["product"] != "nginx" || ev.MediaType != "image/png" || len(ev.Data) == 0 {
		t.Fatalf("shot %+v", ev)
	}
}

func TestParseResultPath(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "shot.png")
	png := []byte{0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a}
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

func TestStripShot(t *testing.T) {
	got := stripShot([]string{"-silent", "-json", "-ss", "-system-chrome", "-ho", "--no-sandbox", "-title", "-u", "http://x"})
	want := []string{"-silent", "-json", "-title", "-u", "http://x"}
	if len(got) != len(want) {
		t.Fatalf("%v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%v", got)
		}
	}
}

func TestChromeMissing(t *testing.T) {
	if !chromeMissing([]byte("Could not create runner: the chrome browser is not installed")) {
		t.Fatal("want match")
	}
	if chromeMissing([]byte("timeout")) {
		t.Fatal("false positive")
	}
}

func TestParseResultSkipFailed(t *testing.T) {
	_, ok, err := parseResult([]byte(`{"url":"https://dead.invalid","failed":true}`))
	if err != nil || ok {
		t.Fatalf("want skip, ok=%v err=%v", ok, err)
	}
}

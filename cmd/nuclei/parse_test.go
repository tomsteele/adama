package main

import (
	"testing"

	"adama/event"
)

func TestLoadProfile(t *testing.T) {
	p, err := loadProfile("../../profiles/nuclei.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "nuclei" || p.Kinds[0] != "url" || len(p.NucleiArgs) == 0 {
		t.Fatalf("%+v", p)
	}
	n, err := loadProfile("../../profiles/nuclei-net.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if n.Name != "nuclei-net" || n.Kinds[0] != "service" || len(n.NucleiArgs) == 0 {
		t.Fatalf("%+v", n)
	}
}

func TestTarget(t *testing.T) {
	u, ok := target(event.Event{Kind: event.KindURL, Value: "https://x"})
	if !ok || u != "https://x" {
		t.Fatalf("url %q %v", u, ok)
	}
	ssh, ok := target(event.Event{Kind: event.KindService, Value: "1.1.1.1:22/ssh", Meta: map[string]string{"name": "ssh", "host": "1.1.1.1", "port": "22"}})
	if !ok || ssh != "1.1.1.1:22" {
		t.Fatalf("ssh %q %v", ssh, ok)
	}
	if _, ok := target(event.Event{Kind: event.KindService, Value: "1.1.1.1:80/http", Meta: map[string]string{"name": "http", "host": "1.1.1.1", "port": "80"}}); ok {
		t.Fatal("http")
	}
}

func TestParseHits(t *testing.T) {
	raw := []byte(`{"template-id":"self-signed-ssl","type":"ssl","ip":"1.2.3.4","matched-at":"https://x","matcher-name":["expired"],"extracted-results":["CN=x"],"curl-command":"curl https://x","info":{"name":"Self Signed","severity":"low","description":"cert","tags":["ssl","tls"]}}
`)
	got := parseHits(raw, event.Event{Value: "https://x", Meta: map[string]string{"host": "x"}})
	if len(got) != 1 || got[0].Kind != event.KindFinding {
		t.Fatalf("%+v", got)
	}
	m := got[0].Meta
	if m["template"] != "self-signed-ssl" || m["matcher"] != "expired" || m["extracted"] != "CN=x" || m["tags"] != "ssl,tls" {
		t.Fatalf("%+v", m)
	}
}

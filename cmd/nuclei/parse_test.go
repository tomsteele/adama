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
	if p.taskTimeout().Minutes() != 15 || n.taskTimeout().Minutes() != 10 {
		t.Fatal("missing worker deadlines")
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
	got, err := parseHits(raw, event.Event{Value: "https://x", Meta: map[string]string{"host": "x"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != event.KindFinding {
		t.Fatalf("%+v", got)
	}
	m := got[0].Meta
	if m["template"] != "self-signed-ssl" || m["matcher"] != "expired" || m["extracted"] != "CN=x" || m["tags"] != "ssl,tls" {
		t.Fatalf("%+v", m)
	}
}

func TestFindingUsesMatchedEndpoint(t *testing.T) {
	in := event.Event{Kind: event.KindURL, Value: "https://original.example.com", Target: event.Target{Host: "192.0.2.1", Name: "original.example.com", Port: 443, Proto: event.TCP}}
	got, err := parseHits([]byte(`{"template-id":"test","type":"http","ip":"192.0.2.2","matched-at":"https://actual.example.com:8443/Admin?Token=AbC","info":{"name":"Test"}}`), in)
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	ev, err := got[0].Canonical()
	if err != nil || ev.Host != "192.0.2.2" || ev.Name != "actual.example.com" || ev.Port != 8443 || ev.URL != "https://actual.example.com:8443/Admin?Token=AbC" {
		t.Fatalf("misattributed finding %+v %v", ev, err)
	}
}

func TestSSLFindingWithExplicitURLPort(t *testing.T) {
	got, err := parseHits([]byte(`{"template-id":"self-signed-ssl","type":"ssl","ip":"2001:db8::2","matched-at":"https://actual.example.com:8443","info":{"name":"Self Signed"}}`), event.Event{Kind: event.KindService, Value: "original.example.com:443/ssl"})
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	ev, err := got[0].Canonical()
	if err != nil || ev.Host != "2001:db8::2" || ev.Name != "actual.example.com" || ev.Port != 8443 || ev.Proto != event.TCP || !ev.TLS {
		t.Fatalf("lost SSL endpoint %+v %v", ev, err)
	}
}

func TestNetworkFindingDoesNotInheritUnobservedIdentity(t *testing.T) {
	in := event.Event{Kind: event.KindService, Value: "old.example:53/domain", Target: event.Target{Host: "192.0.2.1", Name: "old.example", NameRole: event.NameRequested, Port: 53, Proto: event.UDP, SNI: "old.example", HTTPHost: "old.example", URL: "https://old.example"}}
	for _, matched := range []string{"192.0.2.2:5353", ""} {
		hit := nucleiHit{Type: "tcp", IP: "192.0.2.2", MatchedAt: matched}
		target := findingTarget(hit, in)
		if target.Host != "192.0.2.2" || target.Name != "" || target.Proto != event.TCP || target.SNI != "" || target.HTTPHost != "" || target.URL != "" {
			t.Fatalf("inherited unrelated identity: %+v", target)
		}
		if matched == "" && target.Port != 0 || matched != "" && target.Port != 5353 {
			t.Fatal(target)
		}
	}
}

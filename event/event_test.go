package event

import (
	"strings"
	"testing"
)

func TestCanon(t *testing.T) {
	d, err := (Event{Kind: KindDomain, Value: "Example.COM."}).Canonical()
	if err != nil || d.Value != "example.com" {
		t.Fatalf("domain: %+v %v", d, err)
	}
	if g := CanonFQDN("Example.COM."); g != "example.com" {
		t.Fatalf("fqdn: %q", g)
	}
	ip, err := CanonIP("192.168.1.1")
	if err != nil || ip != "192.168.1.1" {
		t.Fatalf("ip: %q %v", ip, err)
	}
	v, err := PortValue("Example.COM.", 443)
	if err != nil || v != "example.com:443" {
		t.Fatalf("port: %q %v", v, err)
	}
	ev, err := (Event{Kind: KindPort, Value: "Example.COM:443"}).Canonical()
	if err != nil || ev.Value != "example.com:443" || ev.Meta["host"] != "example.com" {
		t.Fatalf("canon port: %+v %v", ev, err)
	}
	if !strings.HasPrefix(DedupKey("httpx", Event{Kind: KindPort, Value: "example.com:443"}), "v2/") {
		t.Fatalf("key: %s", DedupKey("httpx", Event{Kind: KindPort, Value: "example.com:443"}))
	}
	if DedupKey("httpx", Event{Kind: KindIP, Value: "1.2.3.4", Meta: map[string]string{"scope": "web"}}) == DedupKey("httpx", Event{Kind: KindIP, Value: "1.2.3.4"}) {
		t.Fatal("scope key")
	}
	if !Allowed("nuclei", nil) || !Allowed("nuclei", map[string]string{}) {
		t.Fatal("default allow")
	}
	if Allowed("nuclei", map[string]string{"deny": "nuclei,nmap-full"}) {
		t.Fatal("deny")
	}
	if !Allowed("httpx", map[string]string{"allow": "httpx,nuclei"}) || Allowed("nmap-full", map[string]string{"allow": "httpx,nuclei"}) {
		t.Fatal("allow")
	}
	child := InheritGate(Event{Meta: map[string]string{"deny": "nuclei", "scope": "web"}}, Event{Meta: map[string]string{"host": "x"}})
	if child.Meta["deny"] != "nuclei" || child.Meta["scope"] != "web" || child.Meta["host"] != "x" {
		t.Fatalf("%+v", child.Meta)
	}
	p, err := CanonPrefix("10.1.2.3/24")
	if err != nil || p != "10.1.2.0/24" {
		t.Fatalf("prefix: %q %v", p, err)
	}
	nb, err := (Event{Kind: KindNetblock, Value: "10.1.2.3/16"}).Canonical()
	if err != nil || nb.Value != "10.1.0.0/16" {
		t.Fatalf("canon netblock: %+v %v", nb, err)
	}
	if Live(Event{}) || !Live(Event{Meta: MarkLive(nil)}) {
		t.Fatal("alive")
	}
}

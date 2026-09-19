package event

import "testing"

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
	if DedupKey("httpx", KindPort, "example.com:443") != "httpx/port/example.com_443" {
		t.Fatalf("key: %s", DedupKey("httpx", KindPort, "example.com:443"))
	}
	p, err := CanonPrefix("10.1.2.3/24")
	if err != nil || p != "10.1.2.0/24" {
		t.Fatalf("prefix: %q %v", p, err)
	}
	nb, err := (Event{Kind: KindNetblock, Value: "10.1.2.3/16"}).Canonical()
	if err != nil || nb.Value != "10.1.0.0/16" {
		t.Fatalf("canon netblock: %+v %v", nb, err)
	}
}

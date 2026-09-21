package event

import (
	"encoding/json"
	"regexp"
	"testing"
)

func TestObservationRoundTrip(t *testing.T) {
	in := Event{Kind: KindURL, Value: "https://Admin.Example.com:8443/Admin?Token=AbC", Target: Target{Host: "2001:db8::1"}}
	in, err := in.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	ev := Event{SchemaVersion: SchemaVersion, ID: "result", RunID: "run", ScanID: "scan", ParentID: "parent",
		Kind: KindScreenshot, Value: in.Value, Target: in.Target, Input: in.AsInput(), Probe: "screenshot",
		Info: map[string]string{"title": "Admin"}, Data: []byte("image")}
	ev, err = ev.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := ev.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Host != "2001:db8::1" || got.Name != "admin.example.com" || got.Port != 8443 || got.Proto != TCP || got.Input.Host != got.Host || got.ScanID != "scan" || got.Info["title"] != "Admin" {
		t.Fatalf("lost observation identity: %s", raw)
	}
	if got.Value != "https://admin.example.com:8443/Admin?Token=AbC" {
		t.Fatalf("URL changed: %s", got.Value)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if fields["host"] != "2001:db8::1" || fields["schema_version"] != float64(2) {
		t.Fatalf("wrong wire shape: %s", raw)
	}
}

func TestLegacyAliasesAreNotEndpointEvidence(t *testing.T) {
	ev, err := (Event{Kind: KindService, Value: "example.com:443/https", Meta: map[string]string{
		"host": "example.com", "port": "443", "ips": "192.0.2.1,192.0.2.2", "name": "https", "product": "nginx"}}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if ev.Host != "" || ev.Name != "example.com" || ev.Service != "https" || ev.Info["product"] != "nginx" {
		t.Fatalf("bad legacy promotion: %+v", ev)
	}
	ev = Event{SchemaVersion: SchemaVersion, Kind: KindFQDN, Value: "cert.example.com", Target: Target{Name: "cert.example.com", NameRole: NameCertSAN}, Meta: map[string]string{"host": "192.0.2.9"}}
	ev, err = ev.Canonical()
	if err != nil || ev.Host != "" {
		t.Fatalf("v2 copied unverified legacy host: %+v %v", ev, err)
	}
}

func TestWorkIdentityIncludesEndpoint(t *testing.T) {
	a := Event{Kind: KindPort, Value: "example.com:53", Target: Target{Host: "192.0.2.1", Name: "example.com", NameRole: NameRequested, Port: 53, Proto: TCP}}
	b := a
	b.Proto = UDP
	c := a
	c.Host = "192.0.2.2"
	if DedupKey("svc", a) == DedupKey("svc", b) || DedupKey("svc", a) == DedupKey("svc", c) {
		t.Fatal("distinct endpoints collapsed")
	}
	d := a
	d.Meta = map[string]string{"product": "new evidence"}
	if DedupKey("svc", a) != DedupKey("svc", d) {
		t.Fatal("non-identity enrichment changed work identity")
	}
	plain := Event{Kind: KindService, Value: "example.com:8443/http", Target: a.Target}
	tls := plain
	tls.TLS = true
	if DedupKey("as-url", plain) == DedupKey("as-url", tls) {
		t.Fatal("TLS tunnel was suppressed by a plaintext service")
	}
	x := Event{Kind: KindURL, Value: "https://x/a", Meta: map[string]string{"scope": "b"}}
	y := Event{Kind: KindURL, Value: "https://x/a/b"}
	if DedupKey("httpx", x) == DedupKey("httpx", y) {
		t.Fatal("scope delimiter collision")
	}
	valid := regexp.MustCompile(`^v2/[0-9a-f]{64}$`)
	for _, value := range []string{"https://[2001:db8::1]/Admin?Token=AbC", "https://example.com/a%2Fb?q=a&b=c"} {
		if !valid.MatchString(DedupKey("httpx", Event{Kind: KindURL, Value: value})) {
			t.Fatal("unsafe KV key")
		}
	}
}

func TestTargetValidation(t *testing.T) {
	for _, target := range []Target{
		{Host: "example.com"}, {Host: "192.0.2.1", Port: 65536}, {NameRole: NameCertSAN},
		{Name: "x", NameRole: "unknown"}, {Host: "192.0.2.1", Proto: "bogus"}, {Host: "192.0.2.1", Port: 80, Proto: ICMP},
	} {
		if _, err := target.Canonical(); err == nil {
			t.Fatalf("accepted invalid target %+v", target)
		}
	}
	if _, err := (Event{SchemaVersion: 99, Kind: KindIP, Value: "192.0.2.1"}).Canonical(); err == nil {
		t.Fatal("accepted future incompatible schema")
	}
}

func TestCanonicalDoesNotMutateParent(t *testing.T) {
	meta := map[string]string{"host": "EXAMPLE.com", "port": "0443"}
	_, err := (Event{Kind: KindPort, Value: "EXAMPLE.com:443", Meta: meta}).Canonical()
	if err != nil {
		t.Fatal(err)
	}
	if meta["host"] != "EXAMPLE.com" || meta["port"] != "0443" {
		t.Fatal("canonicalization mutated shared metadata")
	}
}

func TestValueAndTargetMustAgree(t *testing.T) {
	for _, ev := range []Event{
		{Kind: KindIP, Value: "192.0.2.1", Target: Target{Host: "192.0.2.2"}},
		{Kind: KindPort, Value: "example.com:443", Target: Target{Port: 8443}},
		{Kind: KindService, Value: "example.com:443/http", Service: "ssh"},
		{Kind: KindURL, Value: "https://example.com", Target: Target{Name: "other.example.com"}},
		{Kind: KindURL, Value: "https://example.com/A", Target: Target{URL: "https://example.com/a"}},
		{Kind: KindFQDN, Value: "example.com,other=argument"},
	} {
		if _, err := ev.Canonical(); err == nil {
			t.Fatalf("accepted conflicting or invalid identity %+v", ev)
		}
	}
	ev := Event{Kind: KindService, Value: "[2001:db8::1]:443/HTTP", Target: Target{Host: "2001:0db8::1", Port: 443, Proto: TCP}}
	if got, err := ev.Canonical(); err != nil || got.Service != "http" || got.Host != "2001:db8::1" {
		t.Fatalf("rejected equivalent endpoint %+v %v", got, err)
	}
}

func TestNameEvidenceControlsProbeTarget(t *testing.T) {
	for _, role := range []NameRole{NameCertSAN, NameCertCN, NamePTR, NameCT} {
		ev := Event{Kind: KindFQDN, Value: "discovered.example.com", Target: Target{Host: "192.0.2.1", Name: "discovered.example.com", NameRole: role}}
		if ev.TargetHost() != ev.Value {
			t.Fatalf("%s reused the mentioning server as a DNS mapping", role)
		}
	}
	ev := Event{Kind: KindFQDN, Value: "resolved.example.com", Target: Target{Host: "2001:db8::1", NameRole: NameDNSAAAA}}
	if ev.TargetHost() != ev.Host {
		t.Fatal("lost explicitly resolved backend")
	}
}

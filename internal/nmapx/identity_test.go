package nmapx

import (
	"adama/event"
	"adama/internal/asurl"
	"testing"
)

func TestEndpointAssociationAndTransport(t *testing.T) {
	data := []byte(`<nmaprun>
<host><address addr="192.0.2.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="53"><state state="open"/></port>
<port protocol="udp" portid="53"><state state="open"/></port></ports></host>
<host><address addr="2001:db8::2" addrtype="ipv6"/><ports>
<port protocol="tcp" portid="8443"><state state="open"/></port></ports></host></nmaprun>`)
	scans, err := ParseXML(data)
	if err != nil {
		t.Fatal(err)
	}
	trigger := event.Event{Kind: event.KindFQDN, Value: "app.example.com", Meta: map[string]string{"ips": "192.0.2.99", "fqdns": "unrelated.example.com"}}
	events := Expand(trigger, scans)
	var ports int
	keys := map[string]bool{}
	for _, ev := range events {
		if ev.Kind != event.KindPort {
			continue
		}
		ports++
		if ev.Host == "192.0.2.99" || ev.Name == "unrelated.example.com" {
			t.Fatalf("manufactured relation %+v", ev)
		}
		if (ev.Host == "192.0.2.1" && ev.Port != 53) || (ev.Host == "2001:db8::2" && ev.Port != 8443) {
			t.Fatalf("cross-product endpoint %+v", ev)
		}
		key := event.DedupKey("svc", ev)
		if keys[key] {
			t.Fatalf("collapsed work identity %+v", ev)
		}
		keys[key] = true
	}
	if ports != 6 {
		t.Fatalf("got %d IP/named endpoint observations, want 6", ports)
	}
}

func TestServiceUsesObservedEndpointAndTLS(t *testing.T) {
	data := []byte(`<nmaprun><host><address addr="192.0.2.2" addrtype="ipv4"/><ports><port protocol="tcp" portid="8443"><state state="open"/><service name="http" tunnel="ssl" product="nginx"/></port></ports></host></nmaprun>`)
	svcs, err := ParseServices(data)
	if err != nil {
		t.Fatal(err)
	}
	trigger := event.Event{Kind: event.KindPort, Value: "app.example.com:8443", Target: event.Target{Host: "192.0.2.1", Name: "app.example.com", NameRole: event.NameRequested, Port: 8443, Proto: event.TCP}}
	got := ServiceEvents(trigger, svcs)
	if len(got) != 1 || got[0].Host != "192.0.2.2" || got[0].Name != "app.example.com" || !got[0].TLS || got[0].Service != "http" {
		t.Fatalf("bad service %+v", got)
	}
	u, ok := asurl.Event(got[0])
	if !ok || u.Value != "https://app.example.com:8443" || u.Host != "192.0.2.2" {
		t.Fatalf("bad URL %+v", u)
	}
}

func TestPTRDoesNotBecomeLiveVhost(t *testing.T) {
	hosts, err := ParseDiscovery([]byte(`<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/><hostnames><hostname name="ptr.example.com" type="PTR"/></hostnames></host><host><address addr="192.0.2.2" addrtype="ipv4"/></host></nmaprun>`))
	if err != nil || len(hosts) != 1 {
		t.Fatalf("%+v %v", hosts, err)
	}
	events := DiscoverEvents(event.Event{Kind: event.KindFQDN, Value: "requested.example.com"}, hosts)
	for _, ev := range events {
		if ev.Name == "ptr.example.com" && (event.Live(ev) || ev.NameRole != event.NamePTR) {
			t.Fatalf("PTR is not liveness evidence: %+v", ev)
		}
		if ev.Name == "requested.example.com" && (!event.Live(ev) || ev.Host != "192.0.2.1") {
			t.Fatalf("lost probed binding %+v", ev)
		}
	}
}

func TestServiceProfileSelectsTransportAndName(t *testing.T) {
	p, err := LoadProfile("../../profiles/nmap-svc.yaml")
	if err != nil {
		t.Fatal(err)
	}
	args := p.Args(event.Event{Kind: event.KindPort, Target: event.Target{Host: "2001:db8::1", Name: "app.example.com", NameRole: event.NameRequested, Proto: event.UDP}})
	want := map[string]bool{"-6": false, "-sU": false, "tls.servername=app.example.com,http.host=app.example.com": false}
	for _, arg := range args {
		if _, ok := want[arg]; ok {
			want[arg] = true
		}
	}
	for arg, ok := range want {
		if !ok {
			t.Fatalf("missing %s in %v", arg, args)
		}
	}
}

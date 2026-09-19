package nmapx

import (
	"strings"
	"testing"

	"adama/event"
)

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

func TestParseXML(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <address addr="1.2.3.4" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/></port>
      <port protocol="tcp" portid="443"><state state="open"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/></port>
      <port protocol="tcp" portid="8080"><state state="filtered"/></port>
      <port protocol="tcp" portid="8443"><state state="open|filtered"/></port>
    </ports>
  </host>
</nmaprun>`
	addrs, ports, err := ParseXML([]byte(xml))
	if err != nil {
		t.Fatal(err)
	}
	if len(addrs) != 1 || addrs[0] != "1.2.3.4" {
		t.Fatalf("addrs: %v", addrs)
	}
	if len(ports) != 2 {
		t.Fatalf("ports: %v", ports)
	}
}

func TestExpandFQDN(t *testing.T) {
	got := Expand(event.Event{Kind: event.KindFQDN, Value: "example.com"}, []string{"1.2.3.4"}, []int{80, 443})
	want := map[string]event.Kind{
		"1.2.3.4":         event.KindIP,
		"example.com:80":  event.KindPort,
		"example.com:443": event.KindPort,
		"1.2.3.4:80":      event.KindPort,
		"1.2.3.4:443":     event.KindPort,
	}
	if len(got) != 5 {
		t.Fatalf("got %d events: %+v", len(got), got)
	}
	for _, ev := range got {
		k, ok := want[ev.Value]
		if !ok || k != ev.Kind {
			t.Fatalf("unexpected %+v", ev)
		}
		if ev.Meta["fqdns"] != "example.com" || ev.Meta["ips"] != "1.2.3.4" {
			t.Fatalf("aliases %+v", ev)
		}
	}
}

func TestParseServices(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="Vercel" version="2" extrainfo="proxy"/>
        <script id="ssl-cert" output="x"/>
        <script id="http-title" output="y"/>
      </port>
    </ports>
  </host>
</nmaprun>`
	svcs, err := ParseServices([]byte(xml))
	if err != nil || len(svcs) != 1 {
		t.Fatalf("%v %+v", err, svcs)
	}
	if svcs[0].Name != "https" || svcs[0].Product != "Vercel" || svcs[0].Scripts["ssl-cert"] != "x" || svcs[0].Scripts["http-title"] != "y" {
		t.Fatalf("%+v", svcs[0])
	}
	got := ServiceEvents(event.Event{Kind: event.KindPort, Value: "example.com:443", Meta: map[string]string{"host": "example.com", "port": "443"}}, svcs)
	if len(got) != 1 || got[0].Kind != event.KindService || got[0].Value != "example.com:443/https" {
		t.Fatalf("%+v", got)
	}
	if got[0].Meta["scripts"] == "" || !containsAll(got[0].Meta["scripts"], "ssl-cert", "http-title", `"x"`) {
		t.Fatalf("scripts %s", got[0].Meta["scripts"])
	}
}

func TestParseDiscovery(t *testing.T) {
	const xml = `<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.7" addrtype="ipv4"/>
    <hostnames>
      <hostname name="Router.Local." type="PTR"/>
    </hostnames>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.8" addrtype="ipv4"/>
  </host>
</nmaprun>`
	hosts, err := ParseDiscovery([]byte(xml))
	if err != nil || len(hosts) != 1 || hosts[0].IP != "10.0.0.7" || hosts[0].Names[0] != "router.local" {
		t.Fatalf("%v %+v", err, hosts)
	}
	got := DiscoverEvents(event.Event{Kind: event.KindNetblock, Value: "10.0.0.0/24"}, hosts)
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	kinds := map[string]event.Kind{}
	for _, ev := range got {
		kinds[ev.Value] = ev.Kind
		if ev.Meta["netblock"] != "10.0.0.0/24" {
			t.Fatalf("meta %+v", ev)
		}
	}
	if kinds["10.0.0.7"] != event.KindIP || kinds["router.local"] != event.KindFQDN {
		t.Fatalf("%v", kinds)
	}

	liveIP := DiscoverEvents(event.Event{Kind: event.KindIP, Value: "10.0.0.7"}, hosts)
	if len(liveIP) < 1 || liveIP[0].Kind != event.KindIP || liveIP[0].Value != "10.0.0.7" || liveIP[0].Meta["netblock"] != "" || !event.Live(liveIP[0]) {
		t.Fatalf("live ip %+v", liveIP)
	}

	liveName := DiscoverEvents(event.Event{Kind: event.KindFQDN, Value: "Www.Example.COM"}, hosts)
	var gotIP, gotName bool
	for _, ev := range liveName {
		if ev.Meta["netblock"] != "" {
			t.Fatalf("fqdn trigger netblock %+v", ev)
		}
		if ev.Kind == event.KindIP && ev.Value == "10.0.0.7" && ev.Meta["fqdns"] != "" {
			gotIP = true
		}
		if ev.Kind == event.KindFQDN && ev.Value == "www.example.com" {
			gotName = true
		}
	}
	if !gotIP || !gotName {
		t.Fatalf("live name %+v", liveName)
	}
}

func TestExpandKeepsNetblock(t *testing.T) {
	got := Expand(event.Event{Kind: event.KindIP, Value: "10.0.0.7", Meta: map[string]string{"netblock": "10.0.0.0/24"}}, []string{"10.0.0.7"}, []int{443})
	if len(got) == 0 || got[0].Meta["netblock"] != "10.0.0.0/24" {
		t.Fatalf("%+v", got)
	}
}

func TestExpandDoesNotEchoIP(t *testing.T) {
	got := Expand(event.Event{Kind: event.KindIP, Value: "1.2.3.4", Meta: map[string]string{"fqdns": "example.com"}}, []string{"1.2.3.4"}, []int{443})
	for _, ev := range got {
		if ev.Kind == event.KindIP && ev.Value == "1.2.3.4" {
			t.Fatal("echoed trigger ip")
		}
	}
}

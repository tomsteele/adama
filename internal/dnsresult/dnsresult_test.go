package dnsresult

import (
	"adama/event"
	"testing"
)

func TestSeparateAddressRelationships(t *testing.T) {
	events, err := Parse([]byte("{\"host\":\"App.Example.COM\",\"a\":[\"192.0.2.1\",\"192.0.2.2\"],\"aaaa\":[\"2001:db8::1\"]}\n{\"host\":\"other.example.com\",\"a\":[\"192.0.2.3\"]}\n"), "dnsx", "example.com")
	if err != nil || len(events) != 4 {
		t.Fatalf("%+v %v", events, err)
	}
	for _, ev := range events {
		if ev.Host == "192.0.2.3" && ev.Name != "other.example.com" {
			t.Fatal("misassociated DNS answer")
		}
		if ev.Host == "2001:db8::1" && ev.NameRole != event.NameDNSAAAA {
			t.Fatal("lost AAAA role")
		}
		if event.Live(ev) || ev.Port != 0 || ev.Proto != "" {
			t.Fatal("DNS resolution invented liveness or endpoint")
		}
		if _, err := ev.Canonical(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestInvalidAddressRejected(t *testing.T) {
	if _, err := Parse([]byte(`{"host":"x.example","a":["2001:db8::1"]}`), "dnsx", "example"); err == nil {
		t.Fatal("accepted wrong address family")
	}
}

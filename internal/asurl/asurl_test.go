package asurl

import (
	"testing"

	"adama/event"
)

func TestURL(t *testing.T) {
	ev := event.Event{Meta: map[string]string{"name": "https", "host": "example.com", "port": "443", "product": "Vercel"}}
	out, ok := Event(ev)
	if !ok || out.Value != "https://example.com" || out.Kind != event.KindURL || out.Meta["product"] != "Vercel" {
		t.Fatalf("%v %+v", ok, out)
	}
	if _, ok := Event(event.Event{Meta: map[string]string{"name": "ssh", "host": "example.com", "port": "22"}}); ok {
		t.Fatal("ssh should not be a url")
	}
}

func TestSchemeAndPortAreIndependent(t *testing.T) {
	for _, tc := range []struct {
		name string
		tls  bool
		port int
		want string
	}{
		{"http", true, 8443, "https://example.com:8443"},
		{"ssl/http", false, 8443, "https://example.com:8443"},
		{"https", false, 80, "https://example.com:80"},
		{"http", false, 443, "http://example.com:443"},
		{"http", false, 80, "http://example.com"},
	} {
		ev := event.Event{Service: tc.name, TLS: tc.tls, Target: event.Target{Host: "192.0.2.1", Name: "example.com", NameRole: event.NameRequested, Port: tc.port, Proto: event.TCP}}
		got, ok := URL(ev)
		if !ok || got != tc.want {
			t.Fatalf("%+v: got %s", tc, got)
		}
	}
	if _, ok := URL(event.Event{Service: "http", Target: event.Target{Host: "192.0.2.1", Port: 80, Proto: event.UDP}}); ok {
		t.Fatal("UDP service became TCP URL")
	}
}

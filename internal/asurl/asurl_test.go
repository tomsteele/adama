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

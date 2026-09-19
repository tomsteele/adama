package main

import (
	"testing"

	"adama/event"
)

func TestParseTLSX(t *testing.T) {
	raw := []byte(`{"subject_cn":"unifi.local","subject_an":["unifi.local","localhost"],"issuer_cn":"UniFi","tls_version":"tls13","not_after":"2030-01-01"}
`)
	got := parseTLSX(raw, event.Event{Meta: map[string]string{"host": "192.168.1.1", "port": "8443"}})
	if len(got) != 2 {
		t.Fatalf("%+v", got)
	}
	if got[0].Value != "unifi.local" || got[0].Meta["cn"] != "unifi.local" || got[0].Meta["issuer"] != "UniFi" || got[0].Meta["port"] != "8443" {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Value != "localhost" {
		t.Fatalf("%+v", got[1])
	}
}

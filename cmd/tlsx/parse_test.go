package main

import (
	"testing"

	"adama/event"
)

func TestParseTLSX(t *testing.T) {
	raw := []byte(`{"ip":"192.168.1.2","port":"8443","subject_cn":"unifi.local","subject_an":["unifi.local","localhost"],"issuer_cn":"UniFi","tls_version":"tls13","not_after":"2030-01-01"}
`)
	got, err := parseTLSX(raw, event.Event{Meta: map[string]string{"host": "192.168.1.1", "port": "8443"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if got[0].Value != "unifi.local" || got[0].Meta["cn"] != "unifi.local" || got[0].Meta["issuer"] != "UniFi" || got[0].Meta["port"] != "8443" {
		t.Fatalf("%+v", got[0])
	}
	if got[2].Value != "localhost" {
		t.Fatalf("%+v", got[2])
	}
	if got[0].Host != "192.168.1.2" || got[0].NameRole != event.NameCertCN || got[1].NameRole != event.NameCertSAN || got[2].Proto != event.TCP {
		t.Fatalf("lost endpoint or evidence role: %+v", got)
	}
}

func TestTLSMissingAddressDoesNotInheritEmitter(t *testing.T) {
	got, err := parseTLSX([]byte(`{"subject_an":["api.example.com"]}`), event.Event{Target: event.Target{Host: "192.0.2.1", Port: 443}, Meta: map[string]string{"host": "192.0.2.1"}})
	if err != nil || len(got) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	ev, err := got[0].Canonical()
	if err != nil || ev.Host != "" || ev.NameRole != event.NameCertSAN {
		t.Fatalf("guessed TLS peer %+v %v", ev, err)
	}
}

func TestCertificateDescriptionIsNotAHostname(t *testing.T) {
	got, err := parseTLSX([]byte(`{"ip":"192.0.2.1","port":"443","subject_cn":"Example Device Certificate","subject_an":["api.example.com"]}`), event.Event{})
	if err != nil || len(got) != 1 || got[0].Name != "api.example.com" || got[0].Meta["cn"] != "Example Device Certificate" {
		t.Fatalf("lost valid SAN or descriptive CN: %+v %v", got, err)
	}
	if _, err := got[0].Canonical(); err != nil {
		t.Fatal(err)
	}
}

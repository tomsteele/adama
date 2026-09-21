package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"adama/event"
)

func TestRequestFailuresCannotLookLikeCleanScans(t *testing.T) {
	for _, tc := range []struct {
		name, log     string
		total, failed int
		bad           bool
	}{
		{"clean non-match", `{"template":"test.yaml","type":"http","error":"none"}`, 1, 0, false},
		{"failed request", `{"template":"test.yaml","type":"http","error":"connection refused"}`, 1, 1, true},
		{"partial success", `{"template":"ok.yaml","type":"http","error":"none"}{"template":"bad.yaml","type":"tcp","error":"timeout"}`, 2, 1, true},
		{"empty", "", 0, 0, true},
		{"truncated", `{"template":`, 0, 0, true},
		{"missing outcome", `{"template":"test.yaml","type":"http"}`, 0, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, err := parseTrace(strings.NewReader(tc.log), event.Event{})
			if (err != nil) != tc.bad || s.Total != tc.total || s.Failed != tc.failed {
				t.Fatalf("%+v %v", s, err)
			}
		})
	}
}

func TestServiceRequestEvidenceChecksEndpointAndTransport(t *testing.T) {
	for _, tc := range []struct {
		name, kind, address string
		proto               event.Protocol
		bad                 bool
	}{
		{"tcp", "tcp", "vhost.example:8443", event.TCP, false},
		{"ssl", "ssl", "vhost.example:8443", event.TCP, false},
		{"wrong port", "tcp", "vhost.example:443", event.TCP, true},
		{"wrong host", "tcp", "other.example:8443", event.TCP, true},
		{"missing endpoint", "tcp", "", event.TCP, true},
		{"tcp does not cover udp", "tcp", "vhost.example:8443", event.UDP, true},
		{"dns is not service evidence", "dns", "vhost.example:8443", event.TCP, true},
		{"javascript transport unknown", "javascript", "vhost.example:8443", event.TCP, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := event.Event{Kind: event.KindService, Target: event.Target{Host: "192.0.2.1", Name: "vhost.example", NameRole: event.NameRequested, Port: 8443, Proto: tc.proto}}
			raw, _ := json.Marshal(map[string]string{"template": "test.yaml", "type": tc.kind, "input": tc.address, "error": "none"})
			s, err := parseTrace(strings.NewReader(string(raw)), in)
			if (err != nil) != tc.bad || (s.OffEndpoint > 0) != tc.bad || s.Total != 1 {
				t.Fatalf("%+v %v", s, err)
			}
		})
	}
}

func TestUnsupportedTransportDoesNotLaunchScanner(t *testing.T) {
	p, err := loadProfile("../../profiles/nuclei-net.yaml")
	if err != nil {
		t.Fatal(err)
	}
	// No scanner is available: the transport diagnostic must precede execution.
	t.Setenv("PATH", t.TempDir())
	out, err := scan(context.Background(), p, event.Event{Kind: event.KindService, Value: "192.0.2.1:53/domain", Target: event.Target{Host: "192.0.2.1", Port: 53, Proto: event.UDP}})
	if len(out) != 0 || err == nil || !strings.Contains(err.Error(), "does not support service transport") {
		t.Fatalf("%+v %v", out, err)
	}
}

func TestNonMatchesAndExecutionErrorsAreNotFindings(t *testing.T) {
	out, err := parseHits([]byte(`{"template-id":"negative","matcher-status":false}
{"template-id":"broken","matcher-status":false,"error":"connection refused"}
{"template-id":"positive","matcher-status":true,"type":"http","matched-at":"http://app.example","ip":"192.0.2.1"}
`), event.Event{Kind: event.KindURL, Value: "http://app.example"})
	if err == nil || len(out) != 1 || out[0].Probe != "positive" {
		t.Fatalf("%+v %v", out, err)
	}
}

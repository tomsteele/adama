package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"adama/event"
)

type tlsxHit struct {
	Timestamp  time.Time `json:"timestamp"`
	Host       string    `json:"host"`
	IP         string    `json:"ip"`
	Port       string    `json:"port"`
	SubjectCN  string    `json:"subject_cn"`
	SubjectAN  []string  `json:"subject_an"`
	IssuerCN   string    `json:"issuer_cn"`
	TLSVersion string    `json:"tls_version"`
	NotAfter   string    `json:"not_after"`
	SNI        string    `json:"sni"`
}

func parseTLSX(stdout []byte, trigger event.Event) ([]event.Event, error) {
	host := trigger.Meta["host"]
	seen := map[string]bool{}
	var evs []event.Event
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var hit tlsxHit
		if err := json.Unmarshal(line, &hit); err != nil {
			return evs, fmt.Errorf("tlsx result: %w", err)
		}
		ip, _ := event.CanonIP(hit.IP)
		if ip == "" {
			ip, _ = event.CanonIP(hit.Host)
		}
		port, _ := strconv.Atoi(hit.Port)
		if port == 0 {
			port = trigger.Port
		}
		if port == 0 {
			port, _ = strconv.Atoi(trigger.Meta["port"])
		}
		meta := map[string]string{
			"via":         "tlsx",
			"host":        host,
			"port":        trigger.Meta["port"],
			"fqdns":       trigger.Meta["fqdns"],
			"ips":         trigger.Meta["ips"],
			"netblock":    trigger.Meta["netblock"],
			"cn":          hit.SubjectCN,
			"san":         event.JoinMetaList(hit.SubjectAN),
			"issuer":      hit.IssuerCN,
			"tls_version": hit.TLSVersion,
			"not_after":   hit.NotAfter,
			"sni":         hit.SNI,
		}
		for i, name := range append([]string{hit.SubjectCN}, hit.SubjectAN...) {
			name = event.CanonFQDN(strings.TrimSpace(name))
			if name == "" || strings.Contains(name, "*") {
				continue
			}
			if _, err := event.CanonIP(name); err == nil {
				continue
			}
			// A certificate CN can be descriptive text instead of a hostname.
			// Keep that text in the certificate details, not on the FQDN queue.
			if _, err := (event.Target{Name: name}).Canonical(); err != nil {
				continue
			}
			role := event.NameCertSAN
			if i == 0 {
				role = event.NameCertCN
			}
			key := fmt.Sprintf("%s/%d/%s/%s", ip, port, role, name)
			if seen[key] {
				continue
			}
			seen[key] = true
			evs = append(evs, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindFQDN, Value: name,
				Target: event.Target{Host: ip, Name: name, NameRole: role, Port: port, Proto: event.TCP, SNI: hit.SNI},
				TLS:    true, Probe: "tls-certificate", Observed: hit.Timestamp, Meta: meta})
		}
	}
	return evs, sc.Err()
}

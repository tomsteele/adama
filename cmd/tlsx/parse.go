package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"

	"adama/event"
)

type tlsxHit struct {
	SubjectCN  string   `json:"subject_cn"`
	SubjectAN  []string `json:"subject_an"`
	IssuerCN   string   `json:"issuer_cn"`
	TLSVersion string   `json:"tls_version"`
	NotAfter   string   `json:"not_after"`
	SNI        string   `json:"sni"`
}

func parseTLSX(stdout []byte, trigger event.Event) []event.Event {
	host := trigger.Meta["host"]
	seen := map[string]bool{}
	var evs []event.Event
	sc := bufio.NewScanner(bytes.NewReader(stdout))
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var hit tlsxHit
		if json.Unmarshal(line, &hit) != nil {
			continue
		}
		meta := map[string]string{
			"via":         "tlsx",
			"host":        host,
			"port":        "443",
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
		for _, name := range append([]string{hit.SubjectCN}, hit.SubjectAN...) {
			name = event.CanonFQDN(strings.TrimSpace(name))
			if name == "" || strings.Contains(name, "*") {
				continue
			}
			if _, err := event.CanonIP(name); err == nil {
				continue
			}
			if seen[name] {
				continue
			}
			seen[name] = true
			evs = append(evs, event.Event{Kind: event.KindFQDN, Value: name, Meta: meta})
		}
	}
	return evs
}

// Package dnsresult turns DNSX JSONL answers into explicit name/address facts.
package dnsresult

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"time"

	"adama/event"
)

type answer struct {
	Host      string    `json:"host"`
	A         []string  `json:"a"`
	AAAA      []string  `json:"aaaa"`
	CNAME     []string  `json:"cname"`
	Resolver  []string  `json:"resolver"`
	Status    string    `json:"status_code"`
	Timestamp time.Time `json:"timestamp"`
}

func Parse(data []byte, via, parent string) ([]event.Event, error) {
	var out []event.Event
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var a answer
		if err := json.Unmarshal(line, &a); err != nil {
			return nil, fmt.Errorf("dnsx result: %w", err)
		}
		name := event.CanonFQDN(a.Host)
		if name == "" {
			return nil, fmt.Errorf("dnsx result missing hostname")
		}
		for _, group := range []struct {
			addresses []string
			role      event.NameRole
		}{{a.A, event.NameDNSA}, {a.AAAA, event.NameDNSAAAA}} {
			for _, raw := range group.addresses {
				ip, err := netip.ParseAddr(raw)
				if err != nil {
					return nil, fmt.Errorf("dnsx address: %w", err)
				}
				if (group.role == event.NameDNSA && !ip.Is4()) || (group.role == event.NameDNSAAAA && !ip.Is6()) {
					return nil, fmt.Errorf("dnsx address family disagrees with record type")
				}
				info := map[string]string{"via": via, "parent": parent, "status_code": a.Status}
				if len(a.CNAME) > 0 {
					b, _ := json.Marshal(a.CNAME)
					info["cname"] = string(b)
				}
				if len(a.Resolver) > 0 {
					b, _ := json.Marshal(a.Resolver)
					info["resolver"] = string(b)
				}
				out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindFQDN, Value: name,
					Target: event.Target{Host: ip.String(), Name: name, NameRole: group.role}, Probe: string(group.role), Observed: a.Timestamp,
					Info: info, Meta: map[string]string{"parent": parent, "via": via}})
			}
		}
	}
	return out, sc.Err()
}

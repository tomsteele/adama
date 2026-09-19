package nmapx

import (
	"encoding/json"
	"encoding/xml"
	"strconv"

	"adama/event"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status      nmapStatus    `xml:"status"`
	Addresses   []nmapAddr    `xml:"address"`
	Hostnames   nmapHostnames `xml:"hostnames"`
	Ports       nmapPorts     `xml:"ports"`
	HostScripts []nmapScript  `xml:"hostscript>script"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapHostnames struct {
	Names []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	PortID  string       `xml:"portid,attr"`
	State   nmapState    `xml:"state"`
	Service nmapService  `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extra   string `xml:"extrainfo,attr"`
}

type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type nmapState struct {
	State string `xml:"state,attr"`
}

func ParseXML(data []byte) (addrs []string, ports []int, err error) {
	var run nmapRun
	if err = xml.Unmarshal(data, &run); err != nil {
		return nil, nil, err
	}
	seenAddr := map[string]bool{}
	seenPort := map[int]bool{}
	for _, h := range run.Hosts {
		for _, a := range h.Addresses {
			if a.AddrType != "ipv4" && a.AddrType != "ipv6" {
				continue
			}
			ip, err := event.CanonIP(a.Addr)
			if err != nil {
				continue
			}
			if !seenAddr[ip] {
				seenAddr[ip] = true
				addrs = append(addrs, ip)
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			n, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			if !seenPort[n] {
				seenPort[n] = true
				ports = append(ports, n)
			}
		}
	}
	return addrs, ports, nil
}

type Host struct {
	IP    string
	Names []string
}

func ParseDiscovery(data []byte) ([]Host, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var out []Host
	for _, h := range run.Hosts {
		if h.Status.State != "" && h.Status.State != "up" {
			continue
		}
		var ip string
		for _, a := range h.Addresses {
			if a.AddrType != "ipv4" && a.AddrType != "ipv6" {
				continue
			}
			v, err := event.CanonIP(a.Addr)
			if err != nil {
				continue
			}
			ip = v
			break
		}
		if ip == "" {
			continue
		}
		var names []string
		seen := map[string]bool{}
		for _, n := range h.Hostnames.Names {
			fq := event.CanonFQDN(n.Name)
			if fq == "" || seen[fq] {
				continue
			}
			if _, err := event.CanonIP(fq); err == nil {
				continue
			}
			seen[fq] = true
			names = append(names, fq)
		}
		out = append(out, Host{IP: ip, Names: names})
	}
	return out, nil
}

func DiscoverEvents(trigger event.Event, hosts []Host) []event.Event {
	var out []event.Event
	for _, h := range hosts {
		meta := map[string]string{
			"ips":      h.IP,
			"fqdns":    event.JoinMetaList(h.Names),
			"netblock": trigger.Value,
		}
		if trigger.Kind != event.KindIP || h.IP != trigger.Value {
			out = append(out, event.Event{Kind: event.KindIP, Value: h.IP, Meta: meta})
		}
		for _, n := range h.Names {
			if trigger.Kind == event.KindFQDN && n == trigger.Value {
				continue
			}
			out = append(out, event.Event{Kind: event.KindFQDN, Value: n, Meta: meta})
		}
	}
	return out
}

type Svc struct {
	Port    int
	Name    string
	Product string
	Version string
	Extra   string
	Scripts map[string]string
}

func ParseServices(data []byte) ([]Svc, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var out []Svc
	for _, h := range run.Hosts {
		hostScripts := map[string]string{}
		for _, sc := range h.HostScripts {
			if sc.ID != "" {
				hostScripts[sc.ID] = sc.Output
			}
		}
		for _, p := range h.Ports.Ports {
			if p.State.State != "open" {
				continue
			}
			n, err := strconv.Atoi(p.PortID)
			if err != nil {
				continue
			}
			s := Svc{Port: n, Name: p.Service.Name, Product: p.Service.Product, Version: p.Service.Version, Extra: p.Service.Extra, Scripts: map[string]string{}}
			if s.Name == "" {
				s.Name = "unknown"
			}
			for id, out := range hostScripts {
				s.Scripts[id] = out
			}
			for _, sc := range p.Scripts {
				if sc.ID != "" {
					s.Scripts[sc.ID] = sc.Output
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

func ServiceEvents(trigger event.Event, svcs []Svc) []event.Event {
	var out []event.Event
	for _, s := range svcs {
		ev := event.Event{
			Kind:  event.KindService,
			Value: trigger.Value + "/" + s.Name,
			Meta: map[string]string{
				"host":     trigger.Meta["host"],
				"port":     trigger.Meta["port"],
				"fqdns":    trigger.Meta["fqdns"],
				"ips":      trigger.Meta["ips"],
				"netblock": trigger.Meta["netblock"],
				"name":     s.Name,
				"product":  s.Product,
				"version":  s.Version,
				"extra":    s.Extra,
			},
		}
		if len(s.Scripts) > 0 {
			if b, err := json.Marshal(s.Scripts); err == nil {
				ev.Meta["scripts"] = string(b)
			}
		}
		out = append(out, ev)
	}
	return out
}

// Expand turns a scan result into derived identities. Never echoes the trigger.
func Expand(trigger event.Event, addrs []string, ports []int) []event.Event {
	var names, ips []string
	switch trigger.Kind {
	case event.KindFQDN:
		names = append(names, trigger.Value)
	case event.KindIP:
		ips = append(ips, trigger.Value)
	}
	names = append(names, event.SplitMetaList(trigger.Meta["fqdns"])...)
	ips = append(ips, event.SplitMetaList(trigger.Meta["ips"])...)
	ips = append(ips, addrs...)

	names = uniqHosts(names, false)
	ips = uniqHosts(ips, true)

	metaFQDN := event.JoinMetaList(names)
	metaIPs := event.JoinMetaList(ips)

	var out []event.Event
	for _, ip := range ips {
		if trigger.Kind == event.KindIP && ip == trigger.Value {
			continue
		}
		out = append(out, event.Event{
			Kind:  event.KindIP,
			Value: ip,
			Meta:  aliasMeta(trigger, metaFQDN, metaIPs),
		})
	}
	for _, n := range names {
		for _, p := range ports {
			if ev, ok := portEvent(trigger, n, p, metaFQDN, metaIPs); ok {
				out = append(out, ev)
			}
		}
	}
	for _, ip := range ips {
		for _, p := range ports {
			if ev, ok := portEvent(trigger, ip, p, metaFQDN, metaIPs); ok {
				out = append(out, ev)
			}
		}
	}
	return out
}

func portEvent(trigger event.Event, host string, port int, fqdns, ips string) (event.Event, bool) {
	val, err := event.PortValue(host, port)
	if err != nil {
		return event.Event{}, false
	}
	if trigger.Kind == event.KindPort && val == trigger.Value {
		return event.Event{}, false
	}
	h, _, _ := event.CanonHost(host)
	return event.Event{
		Kind:  event.KindPort,
		Value: val,
		Meta:  aliasMeta(trigger, fqdns, ips, "host", h, "port", strconv.Itoa(port)),
	}, true
}

func aliasMeta(trigger event.Event, fqdns, ips string, extra ...string) map[string]string {
	m := map[string]string{"fqdns": fqdns, "ips": ips}
	if nb := trigger.Meta["netblock"]; nb != "" {
		m["netblock"] = nb
	}
	for i := 0; i+1 < len(extra); i += 2 {
		m[extra[i]] = extra[i+1]
	}
	return m
}

func uniqHosts(in []string, asIP bool) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		var v string
		if asIP {
			ip, err := event.CanonIP(s)
			if err != nil {
				continue
			}
			v = ip
		} else {
			v = event.CanonFQDN(s)
			if v == "" {
				continue
			}
			if _, err := event.CanonIP(v); err == nil {
				continue
			}
		}
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}

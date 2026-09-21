package nmapx

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"strconv"

	"adama/event"
)

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Names []struct {
		Name string `xml:"name,attr"`
		Type string `xml:"type,attr"`
	} `xml:"hostnames>hostname"`
	Ports   []nmapPort   `xml:"ports>port"`
	Scripts []nmapScript `xml:"hostscript>script"`
}
type nmapPort struct {
	Port  int            `xml:"portid,attr"`
	Proto event.Protocol `xml:"protocol,attr"`
	State struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service struct {
		Name    string `xml:"name,attr"`
		Product string `xml:"product,attr"`
		Version string `xml:"version,attr"`
		Extra   string `xml:"extrainfo,attr"`
		Tunnel  string `xml:"tunnel,attr"`
	} `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}
type nmapScript struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

type Host struct {
	IP     string
	Names  []string
	Roles  map[string]event.NameRole
	Reason string
}
type OpenPort struct {
	Port  int
	Proto event.Protocol
}
type Scan struct {
	Host
	Ports []OpenPort
}

func hostIdentity(h nmapHost) Host {
	out := Host{Roles: map[string]event.NameRole{}, Reason: h.Status.Reason}
	for _, a := range h.Addresses {
		if a.Type != "ipv4" && a.Type != "ipv6" {
			continue
		}
		if ip, err := event.CanonIP(a.Addr); err == nil {
			out.IP = ip
			break
		}
	}
	for _, n := range h.Names {
		name := event.CanonFQDN(n.Name)
		if name == "" {
			continue
		}
		if _, err := event.CanonIP(name); err == nil {
			continue
		}
		if _, ok := out.Roles[name]; ok {
			continue
		}
		role := event.NameObserved
		if n.Type == "PTR" {
			role = event.NamePTR
		}
		if n.Type == "user" {
			role = event.NameRequested
		}
		out.Names = append(out.Names, name)
		out.Roles[name] = role
	}
	return out
}

// ParseXML preserves the host and transport of every open port.
func ParseXML(data []byte) ([]Scan, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var out []Scan
	for _, h := range run.Hosts {
		scan := Scan{Host: hostIdentity(h)}
		seen := map[OpenPort]bool{}
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			if scan.IP == "" {
				return nil, fmt.Errorf("open port without observed IP")
			}
			if p.Port < 1 || p.Port > 65535 || (p.Proto != event.TCP && p.Proto != event.UDP) {
				return nil, fmt.Errorf("invalid nmap endpoint %s/%d", p.Proto, p.Port)
			}
			endpoint := OpenPort{Port: p.Port, Proto: p.Proto}
			if !seen[endpoint] {
				scan.Ports = append(scan.Ports, endpoint)
				seen[endpoint] = true
			}
		}
		if scan.IP != "" {
			out = append(out, scan)
		}
	}
	return out, nil
}

func ParseDiscovery(data []byte) ([]Host, error) {
	var run nmapRun
	if err := xml.Unmarshal(data, &run); err != nil {
		return nil, err
	}
	var out []Host
	for _, h := range run.Hosts {
		if h.Status.State != "up" {
			continue
		}
		id := hostIdentity(h)
		if id.IP != "" {
			out = append(out, id)
		}
	}
	return out, nil
}

func DiscoverEvents(trigger event.Event, hosts []Host) []event.Event {
	var out []event.Event
	for _, h := range hosts {
		meta := event.MarkLive(map[string]string{"ips": h.IP, "fqdns": event.JoinMetaList(h.Names)})
		if trigger.Kind == event.KindNetblock {
			meta["netblock"] = trigger.Value
		}
		out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindIP, Value: h.IP, Target: event.Target{Host: h.IP},
			Probe: "host-discovery", Info: map[string]string{"reason": h.Reason}, Meta: meta})
		names := append([]string{}, h.Names...)
		if trigger.Kind == event.KindFQDN {
			names = append(names, event.CanonFQDN(trigger.Value))
		}
		seen := map[string]bool{}
		for _, name := range names {
			if seen[name] {
				continue
			}
			seen[name] = true
			role := h.Roles[name]
			if role == "" {
				role = event.NameObserved
			}
			m := map[string]string{"ips": h.IP}
			if trigger.Kind == event.KindFQDN && name == event.CanonFQDN(trigger.Value) {
				role = event.NameRequested
				m = event.MarkLive(m)
			}
			if trigger.Kind == event.KindNetblock {
				m["netblock"] = trigger.Value
			}
			out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindFQDN, Value: name,
				Target: event.Target{Host: h.IP, Name: name, NameRole: role}, Probe: "host-discovery", Meta: m})
		}
	}
	return out
}

type Svc struct {
	Host    string
	Port    int
	Proto   event.Protocol
	Name    string
	TLS     bool
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
		ip := hostIdentity(h).IP
		for _, p := range h.Ports {
			if p.State.State != "open" {
				continue
			}
			if ip == "" {
				return nil, fmt.Errorf("service without observed IP")
			}
			if p.Port < 1 || p.Port > 65535 || (p.Proto != event.TCP && p.Proto != event.UDP) {
				return nil, fmt.Errorf("invalid service endpoint")
			}
			s := Svc{Host: ip, Port: p.Port, Proto: p.Proto, Name: p.Service.Name, TLS: p.Service.Tunnel == "ssl",
				Product: p.Service.Product, Version: p.Service.Version, Extra: p.Service.Extra, Scripts: map[string]string{}}
			if s.Name == "" {
				s.Name = "unknown"
			}
			for _, sc := range append(append([]nmapScript{}, h.Scripts...), p.Scripts...) {
				if sc.ID != "" {
					s.Scripts[sc.ID] = sc.Output
				}
			}
			out = append(out, s)
		}
	}
	return out, nil
}

func requestedName(trigger event.Event) string {
	if trigger.Kind == event.KindFQDN {
		return event.CanonFQDN(trigger.Value)
	}
	if trigger.NameRole == event.NameRequested {
		return trigger.Name
	}
	if h := trigger.Meta["host"]; h != "" {
		if _, err := event.CanonIP(h); err != nil {
			return event.CanonFQDN(h)
		}
	}
	return ""
}

func ServiceEvents(trigger event.Event, svcs []Svc) []event.Event {
	var out []event.Event
	for _, s := range svcs {
		t := event.Target{Host: s.Host, Port: s.Port, Proto: s.Proto, Name: requestedName(trigger)}
		if t.Name != "" {
			t.NameRole = event.NameRequested
		}
		authority := t.Authority()
		value, err := event.PortValue(authority, s.Port)
		if err != nil {
			continue
		}
		info := map[string]string{"product": s.Product, "version": s.Version, "extra": s.Extra}
		if len(s.Scripts) > 0 {
			b, _ := json.Marshal(s.Scripts)
			info["scripts"] = string(b)
		}
		meta := map[string]string{"host": authority, "port": strconv.Itoa(s.Port), "ips": s.Host,
			"name": s.Name, "product": s.Product, "version": s.Version, "extra": s.Extra, "netblock": trigger.Meta["netblock"]}
		if info["scripts"] != "" {
			meta["scripts"] = info["scripts"]
		}
		out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindService, Value: value + "/" + s.Name, Target: t,
			Service: s.Name, TLS: s.TLS, Probe: "service-detection", Info: info, Meta: meta})
	}
	return out
}

// Expand keeps observed IP/port pairs together. Only the requested hostname is
// attached; PTR names and inherited alias lists are not expanded into vhosts.
func Expand(trigger event.Event, scans []Scan) []event.Event {
	var out []event.Event
	for _, scan := range scans {
		if trigger.Kind != event.KindIP || scan.IP != trigger.Value {
			out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindIP, Value: scan.IP, Target: event.Target{Host: scan.IP}, Probe: "port-scan",
				Meta: map[string]string{"netblock": trigger.Meta["netblock"]}})
		}
		name := requestedName(trigger)
		for _, p := range scan.Ports {
			for _, n := range []string{"", name} {
				t := event.Target{Host: scan.IP, Name: n, Port: p.Port, Proto: p.Proto}
				if n != "" {
					t.NameRole = event.NameRequested
				}
				v, _ := event.PortValue(t.Authority(), p.Port)
				meta := map[string]string{"host": t.Authority(), "port": strconv.Itoa(p.Port), "ips": scan.IP,
					"fqdns": name, "netblock": trigger.Meta["netblock"]}
				out = append(out, event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindPort, Value: v, Target: t, Probe: "port-scan", Meta: meta})
				if name == "" {
					break
				}
			}
		}
	}
	return out
}

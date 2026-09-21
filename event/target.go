package event

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

const SchemaVersion = 2

type Protocol string

const (
	TCP    Protocol = "tcp"
	UDP    Protocol = "udp"
	ICMP   Protocol = "icmp"
	ICMPv6 Protocol = "icmpv6"
	ARP    Protocol = "arp"
)

type NameRole string

const (
	NameRequested NameRole = "requested"
	NameObserved  NameRole = "observed"
	NameDNSA      NameRole = "dns_a"
	NameDNSAAAA   NameRole = "dns_aaaa"
	NamePTR       NameRole = "ptr"
	NameCertCN    NameRole = "certificate_cn"
	NameCertSAN   NameRole = "certificate_san"
	NameCT        NameRole = "certificate_transparency"
)

// Target describes one observed subject, never a Cartesian product of aliases.
// Host is an IP only. An absent Host means the address has not been established.
// NameRole states the evidence connecting Name to Host; a certificate name is
// not a DNS assertion. Port zero is omitted and means no port is specified.
type Target struct {
	Host     string   `json:"host,omitempty"`
	Name     string   `json:"name,omitempty"`
	NameRole NameRole `json:"name_role,omitempty"`
	Port     int      `json:"port,omitempty"`
	Proto    Protocol `json:"proto,omitempty"`
	URL      string   `json:"url,omitempty"`
	SNI      string   `json:"sni,omitempty"`
	HTTPHost string   `json:"http_host,omitempty"`
}

// Input is the triggering subject, not a copy of its results or ancestry.
type Input struct {
	Kind  Kind   `json:"kind"`
	Value string `json:"value"`
	Target
}

// BoundName distinguishes forward/requested bindings from names merely
// mentioned in certificates or PTR records.
func BoundName(ev Event) bool {
	return ev.Host != "" && ev.Name != "" && (ev.NameRole == NameDNSA || ev.NameRole == NameDNSAAAA || ev.NameRole == NameRequested)
}

func (e Event) AsInput() *Input {
	return &Input{Kind: e.Kind, Value: e.Value, Target: e.Target}
}

// TargetHost selects the subject to probe. A certificate/PTR association must
// not redirect a scan of the discovered name to the server that mentioned it.
func (e Event) TargetHost() string {
	if e.Kind == KindFQDN {
		if e.Host != "" && (e.NameRole == NameRequested || e.NameRole == NameDNSA || e.NameRole == NameDNSAAAA) {
			return e.Host
		}
		return e.Value
	}
	if e.Kind == KindDomain || e.Kind == KindNetblock {
		return e.Value
	}
	if e.Host != "" {
		return e.Host
	}
	if e.Name != "" {
		return e.Name
	}
	return e.Value
}

func (t Target) Authority() string {
	if t.Name != "" && t.NameRole == NameRequested {
		return t.Name
	}
	return t.Host
}

func (t Target) Canonical() (Target, error) {
	var err error
	if t.Host != "" {
		t.Host, err = CanonIP(t.Host)
		if err != nil {
			return t, fmt.Errorf("host must be an IP: %w", err)
		}
	}
	if t.Name != "" {
		t.Name = CanonFQDN(t.Name)
		if !validName(t.Name) {
			return t, fmt.Errorf("invalid hostname %q", t.Name)
		}
		if t.NameRole == "" {
			t.NameRole = NameObserved
		}
	} else if t.NameRole != "" {
		return t, fmt.Errorf("name_role requires name")
	}
	switch t.NameRole {
	case "", NameRequested, NameObserved, NameDNSA, NameDNSAAAA, NamePTR, NameCertCN, NameCertSAN, NameCT:
	default:
		return t, fmt.Errorf("unknown name_role %q", t.NameRole)
	}
	if t.Port < 0 || t.Port > 65535 {
		return t, fmt.Errorf("invalid port %d", t.Port)
	}
	switch t.Proto {
	case "", TCP, UDP, ICMP, ICMPv6, ARP:
	default:
		return t, fmt.Errorf("unknown protocol %q", t.Proto)
	}
	if t.Port != 0 && t.Proto != "" && t.Proto != TCP && t.Proto != UDP {
		return t, fmt.Errorf("protocol %s does not have ports", t.Proto)
	}
	if t.URL != "" {
		t.URL, err = CanonURL(t.URL)
		if err != nil {
			return t, err
		}
	}
	t.SNI = CanonFQDN(t.SNI)
	return t, nil
}

func validName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

func (t Target) bindAuthority(host string, port int) (Target, error) {
	if t.Port != 0 && t.Port != port {
		return t, fmt.Errorf("value and port disagree")
	}
	t.Port = port
	if ip, err := CanonIP(host); err == nil {
		if t.Host != "" && t.Host != ip {
			return t, fmt.Errorf("value and host disagree")
		}
		t.Host = ip
	} else {
		name := CanonFQDN(host)
		if t.Name != "" && t.Name != name {
			return t, fmt.Errorf("value and hostname disagree")
		}
		if t.Name == "" {
			t.Name, t.NameRole = name, NameRequested
		}
	}
	return t, nil
}

// CanonURL preserves path, query and fragment case and encoding.
func CanonURL(s string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	u.Scheme = strings.ToLower(u.Scheme)
	if (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
		return "", fmt.Errorf("invalid HTTP URL %q", s)
	}
	h, _, err := CanonHost(u.Hostname())
	if err != nil {
		return "", err
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", fmt.Errorf("invalid URL port %q", p)
		}
		u.Host = net.JoinHostPort(h, p)
	} else if ip, err := netip.ParseAddr(h); err == nil && ip.Is6() {
		u.Host = "[" + h + "]"
	} else {
		u.Host = h
	}
	return u.String(), nil
}

// URLTarget describes the URL authority, without guessing a resolved address.
func URLTarget(raw string) (Target, error) {
	v, err := CanonURL(raw)
	if err != nil {
		return Target{}, err
	}
	u, _ := url.Parse(v)
	t := Target{URL: v, Proto: TCP, Port: 80}
	if u.Scheme == "https" {
		t.Port = 443
	}
	if u.Port() != "" {
		t.Port, _ = strconv.Atoi(u.Port())
	}
	if ip, err := CanonIP(u.Hostname()); err == nil {
		t.Host = ip
	} else {
		t.Name, t.NameRole = CanonFQDN(u.Hostname()), NameRequested
		if u.Scheme == "https" {
			t.SNI = t.Name
		}
	}
	t.HTTPHost = u.Host
	return t, nil
}

func cloneMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// normalize promotes legacy fields conservatively. Alias lists are never
// interpreted as proof of which IP served a result. Meta remains readable for
// old consumers; new consumers use Target, Service, TLS and Info.
func (e Event) normalize() (Event, error) {
	if e.Info == nil {
		e.Info = map[string]string{}
	}
	for k, v := range e.Meta {
		switch k {
		case "allow", "deny", "scope", "profile", "alive", "host", "port", "ip", "ips", "fqdns":
			continue
		}
		if _, ok := e.Info[k]; !ok {
			e.Info[k] = v
		}
	}
	if e.SchemaVersion < SchemaVersion && e.Host == "" {
		for _, k := range []string{"ip", "host"} {
			if ip, err := CanonIP(e.Meta[k]); err == nil {
				e.Host = ip
				break
			}
		}
	}
	if e.SchemaVersion < SchemaVersion && e.Port == 0 && e.Meta["port"] != "" {
		p, err := strconv.Atoi(e.Meta["port"])
		if err != nil {
			return e, err
		}
		e.Port = p
	}
	if e.SchemaVersion < SchemaVersion && e.Proto == "" {
		e.Proto = Protocol(e.Meta["proto"])
	}
	if e.SchemaVersion < SchemaVersion && e.Service == "" && (e.Kind == KindService || e.Kind == KindURL || e.Kind == KindScreenshot) {
		e.Service = e.Meta["name"]
	}
	if e.SchemaVersion < SchemaVersion && e.Meta["tunnel"] == "ssl" {
		e.TLS = true
	}
	var err error
	e.Target, err = e.Target.Canonical()
	if err != nil {
		return e, err
	}
	switch e.Kind {
	case KindIP:
		if e.Host != "" && e.Host != e.Value {
			return e, fmt.Errorf("IP value and host disagree")
		}
		e.Host = e.Value
	case KindFQDN, KindDomain:
		if e.Name != "" && e.Name != e.Value {
			return e, fmt.Errorf("value and hostname disagree")
		}
		if e.Name == "" {
			e.Name = e.Value
		}
	case KindPort:
		h, p, _ := SplitHostPort(e.Value)
		e.Target, err = e.Target.bindAuthority(h, p)
		if err != nil {
			return e, err
		}
		if e.Proto == "" {
			e.Proto = TCP
		} // Legacy/seed ports default to TCP.
	case KindService:
		endpoint, service, ok := strings.Cut(e.Value, "/")
		if !ok || service == "" {
			return e, fmt.Errorf("service value requires host:port/name")
		}
		h, p, err := SplitHostPort(endpoint)
		if err != nil {
			return e, err
		}
		e.Target, err = e.Target.bindAuthority(h, p)
		if err != nil {
			return e, err
		}
		endpoint, err = PortValue(h, p)
		if err != nil {
			return e, err
		}
		service = strings.ToLower(service)
		if e.Service != "" && strings.ToLower(e.Service) != service {
			return e, fmt.Errorf("value and service disagree")
		}
		e.Service = service
		e.Value = endpoint + "/" + service
	case KindURL, KindScreenshot:
		t, err := URLTarget(e.Value)
		if err != nil {
			return e, err
		}
		if e.URL != "" && e.URL != t.URL {
			return e, fmt.Errorf("value and URL disagree")
		}
		e.URL = t.URL
		e.Target, err = e.Target.bindAuthority(t.Authority(), t.Port)
		if err != nil {
			return e, err
		}
		if e.Proto == "" {
			e.Proto = t.Proto
		}
		if e.HTTPHost == "" {
			e.HTTPHost = t.HTTPHost
		}
		if e.SNI == "" {
			e.SNI = t.SNI
		}
		e.TLS = strings.HasPrefix(e.URL, "https://")
	}
	e.Target, err = e.Target.Canonical()
	if err != nil {
		return e, err
	}
	if e.Input != nil {
		input := *e.Input
		input.Target, err = input.Target.Canonical()
		if err != nil {
			return e, fmt.Errorf("input: %w", err)
		}
		e.Input = &input
	}
	e.SchemaVersion = SchemaVersion
	return e, nil
}

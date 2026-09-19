package event

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

type Kind string

const (
	KindFQDN       Kind = "fqdn"
	KindDomain     Kind = "domain"
	KindIP         Kind = "ip"
	KindPort       Kind = "port"
	KindScreenshot Kind = "screenshot"
	KindService    Kind = "service"
	KindNetblock   Kind = "netblock"
	KindURL        Kind = "url"
	KindFinding    Kind = "finding"
)

const SubjectPrefix = "adama.event."

type Event struct {
	ID        string            `json:"id"`
	Kind      Kind              `json:"kind"`
	Value     string            `json:"value"`
	Source    string            `json:"source"`
	ParentID  string            `json:"parent_id,omitempty"`
	Observed  time.Time         `json:"observed_at"`
	Meta      map[string]string `json:"meta,omitempty"`
	Data      []byte            `json:"data,omitempty"`
	MediaType string            `json:"media_type,omitempty"`
}

func Subject(k Kind) string { return SubjectPrefix + string(k) }

func (e Event) Bytes() ([]byte, error) { return json.Marshal(e) }

func Decode(b []byte) (Event, error) {
	var e Event
	err := json.Unmarshal(b, &e)
	return e, err
}

func CanonFQDN(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(s, ".")
	return strings.ToLower(s)
}

func CanonPrefix(s string) (string, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	return p.Masked().String(), nil
}

func CanonIP(s string) (string, error) {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return "", err
	}
	return ip.String(), nil
}

func CanonHost(s string) (string, bool, error) {
	s = strings.TrimSpace(s)
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.String(), true, nil
	}
	if s == "" {
		return "", false, fmt.Errorf("empty host")
	}
	return CanonFQDN(s), false, nil
}

func SplitHostPort(value string) (host string, port int, err error) {
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("bad ipv6 port value %q", value)
		}
		host = value[1:end]
		rest := value[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("bad ipv6 port value %q", value)
		}
		port, err = strconv.Atoi(rest[1:])
		return host, port, err
	}
	i := strings.LastIndex(value, ":")
	if i < 0 {
		return "", 0, fmt.Errorf("port value missing colon: %q", value)
	}
	port, err = strconv.Atoi(value[i+1:])
	return value[:i], port, err
}

func PortValue(host string, port int) (string, error) {
	h, isIP, err := CanonHost(host)
	if err != nil {
		return "", err
	}
	if isIP {
		if ip, e := netip.ParseAddr(h); e == nil && ip.Is6() {
			return fmt.Sprintf("[%s]:%d", h, port), nil
		}
	}
	return fmt.Sprintf("%s:%d", h, port), nil
}

func (e Event) Canonical() (Event, error) {
	switch e.Kind {
	case KindFQDN, KindDomain:
		e.Value = CanonFQDN(e.Value)
		if e.Value == "" {
			return e, fmt.Errorf("empty fqdn")
		}
	case KindIP:
		v, err := CanonIP(e.Value)
		if err != nil {
			return e, err
		}
		e.Value = v
	case KindNetblock:
		v, err := CanonPrefix(e.Value)
		if err != nil {
			return e, err
		}
		e.Value = v
	case KindPort:
		host, port, err := SplitHostPort(e.Value)
		if err != nil {
			return e, err
		}
		val, err := PortValue(host, port)
		if err != nil {
			return e, err
		}
		e.Value = val
		if e.Meta == nil {
			e.Meta = map[string]string{}
		}
		h, _, _ := CanonHost(host)
		e.Meta["host"] = h
		e.Meta["port"] = strconv.Itoa(port)
	case KindScreenshot, KindService, KindURL, KindFinding:
		e.Value = strings.ToLower(strings.TrimSpace(e.Value))
		if e.Value == "" {
			return e, fmt.Errorf("empty %s", e.Kind)
		}
	default:
		return e, fmt.Errorf("unknown kind %q", e.Kind)
	}
	return e, nil
}

func Live(ev Event) bool { return ev.Meta["alive"] == "true" }

func MarkLive(meta map[string]string) map[string]string {
	if meta == nil {
		meta = map[string]string{}
	}
	meta["alive"] = "true"
	return meta
}

func DedupKey(tool string, ev Event) string {
	// KV keys cannot contain ':'
	v := strings.ReplaceAll(ev.Value, ":", "_")
	key := tool + "/" + string(ev.Kind) + "/" + v
	if s := ev.Meta["scope"]; s != "" {
		key += "/" + strings.ReplaceAll(s, ":", "_")
	}
	return key
}

// Allowed is true unless this event names a deny or a non-empty allow that omits the tool.
func Allowed(tool string, meta map[string]string) bool {
	for _, d := range SplitMetaList(meta["deny"]) {
		if d == tool {
			return false
		}
	}
	allow := SplitMetaList(meta["allow"])
	if len(allow) == 0 {
		return true
	}
	for _, a := range allow {
		if a == tool {
			return true
		}
	}
	return false
}

func InheritGate(parent, child Event) Event {
	if child.Meta == nil {
		child.Meta = map[string]string{}
	}
	for _, k := range []string{"allow", "deny", "scope", "profile"} {
		if child.Meta[k] == "" && parent.Meta[k] != "" {
			child.Meta[k] = parent.Meta[k]
		}
	}
	return child
}

func SplitMetaList(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func JoinMetaList(ss []string) string { return strings.Join(ss, ",") }

package asurl

import (
	"net/netip"
	"strconv"
	"strings"

	"adama/event"
)

var web = map[string]bool{
	"http": true, "https": true, "http-proxy": true, "https-alt": true,
	"http-alt": true, "ssl/http": true, "ssl/https": true,
}

func IsWeb(name string) bool {
	return web[strings.ToLower(strings.TrimSpace(name))]
}

func URL(ev event.Event) (string, bool) {
	name := strings.ToLower(ev.Service)
	if name == "" {
		name = strings.ToLower(ev.Meta["name"])
	}
	if !IsWeb(name) {
		return "", false
	}
	if ev.Proto != "" && ev.Proto != event.TCP {
		return "", false
	}
	host := ev.Target.Authority()
	if host == "" {
		host = ev.Meta["host"]
	}
	port := ev.Port
	if port == 0 {
		port, _ = strconv.Atoi(ev.Meta["port"])
	}
	if host == "" {
		return "", false
	}
	scheme := "http"
	if ev.TLS || ev.Meta["tunnel"] == "ssl" || strings.HasPrefix(name, "ssl/") || strings.Contains(name, "https") {
		scheme = "https"
	}
	h := host
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		h = "[" + host + "]"
	}
	if port != 0 && !(scheme == "http" && port == 80) && !(scheme == "https" && port == 443) {
		return scheme + "://" + h + ":" + strconv.Itoa(port), true
	}
	return scheme + "://" + h, true
}

func Event(trigger event.Event) (event.Event, bool) {
	u, ok := URL(trigger)
	if !ok {
		return event.Event{}, false
	}
	meta := map[string]string{
		"host":     trigger.Meta["host"],
		"port":     trigger.Meta["port"],
		"fqdns":    trigger.Meta["fqdns"],
		"ips":      trigger.Meta["ips"],
		"netblock": trigger.Meta["netblock"],
		"name":     trigger.Meta["name"],
		"product":  trigger.Meta["product"],
		"version":  trigger.Meta["version"],
	}
	t, err := event.URLTarget(u)
	if err != nil {
		return event.Event{}, false
	}
	if trigger.Host != "" {
		t.Host = trigger.Host
	}
	service := trigger.Service
	if service == "" {
		service = trigger.Meta["name"]
	}
	return event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindURL, Value: u, Target: t, Service: service,
		TLS: strings.HasPrefix(u, "https://"), Probe: "http-service-url", Info: trigger.Info, Meta: meta}, true
}

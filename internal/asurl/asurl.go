package asurl

import (
	"net/netip"
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
	name := strings.ToLower(ev.Meta["name"])
	if !IsWeb(name) {
		return "", false
	}
	host := ev.Meta["host"]
	port := ev.Meta["port"]
	if host == "" {
		return "", false
	}
	scheme := "http"
	if strings.Contains(name, "https") || port == "443" {
		scheme = "https"
	}
	h := host
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is6() {
		h = "[" + host + "]"
	}
	if port != "" && port != "80" && port != "443" {
		return scheme + "://" + h + ":" + port, true
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
	return event.Event{Kind: event.KindURL, Value: u, Meta: meta}, true
}

// Package webprobe confirms HTTP on unclassified open TCP services. It dials
// the observed IP while retaining the requested Host and TLS SNI.
package webprobe

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"adama/event"
	"adama/sdk"
)

func InputRule() sdk.Rule {
	return sdk.All(sdk.FieldIn("kind", string(event.KindService)), sdk.Not(sdk.FieldIn("source", "web-probe")),
		sdk.FieldIn("proto", string(event.TCP)), sdk.Has("host"), sdk.Has("port"),
		sdk.FieldIn("service", "unknown", "ssl", "tls", "ssl/unknown", "tcpwrapped"))
}

func Accept(ev event.Event) bool { return InputRule().Match(ev) }

// Probe makes at most one request per scheme, without redirects, HTTP retries,
// environment proxies, DNS resolution, or reading an unbounded response body.
// A negative observation distinguishes non-HTTP from an inconclusive timeout.
func Probe(ctx context.Context, in event.Event, timeout time.Duration) ([]event.Event, error) {
	if !Accept(in) {
		return nil, fmt.Errorf("web probe requires an unclassified, IP-bound TCP service")
	}
	if timeout <= 0 {
		return nil, fmt.Errorf("web probe timeout must be positive")
	}
	schemes := []string{"http", "https"}
	if in.TLS || in.Service == "ssl" || in.Service == "tls" || strings.HasPrefix(in.Service, "ssl/") {
		schemes = []string{"https", "http"}
	}
	var out []event.Event
	info := map[string]string{"http_probe_status": "not_detected"}
	var inconclusive bool
	for _, scheme := range schemes {
		if ctx.Err() != nil {
			return out, ctx.Err()
		}
		result, err := probe(ctx, in, scheme, timeout)
		if err == nil {
			out = append(out, result)
			continue
		}
		info[scheme+"_error"] = err.Error()
		var networkError net.Error
		if errors.As(err, &networkError) && networkError.Timeout() {
			inconclusive = true
		}
	}
	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	if len(out) > 0 {
		return out, nil
	}
	negative := event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindService,
		Value: in.Value, Target: in.Target, Service: in.Service, TLS: in.TLS,
		Probe: "http-identification", Info: info}
	if inconclusive {
		negative.Info["http_probe_status"] = "inconclusive"
		// Terminal by default: the finite scheme pass is the whole probe budget.
		return []event.Event{negative}, fmt.Errorf("HTTP identification timed out without confirming a protocol")
	}
	return []event.Event{negative}, nil
}

func probe(ctx context.Context, in event.Event, scheme string, timeout time.Duration) (event.Event, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	authority := in.Target.Authority()
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(authority, strconv.Itoa(in.Port)), Path: "/"}
	if (scheme == "http" && in.Port == 80) || (scheme == "https" && in.Port == 443) {
		u.Host = authority
		if strings.Contains(authority, ":") {
			u.Host = "[" + authority + "]"
		}
	}
	dialer := &net.Dialer{Timeout: timeout}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, net.JoinHostPort(in.Host, strconv.Itoa(in.Port)))
		},
		// Certificate validation is a separate finding, not a prerequisite for
		// identifying an HTTPS service with a self-signed/expired certificate.
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, ServerName: authority},
		DisableKeepAlives: true, MaxResponseHeaderBytes: 64 << 10,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return event.Event{}, err
	}
	req.Header.Set("User-Agent", "Adama HTTP identification")
	resp, err := client.Do(req)
	if err != nil {
		return event.Event{}, err
	}
	defer resp.Body.Close()
	target := in.Target
	target.URL, target.HTTPHost, target.SNI = "", u.Host, ""
	if scheme == "https" && target.NameRole == event.NameRequested {
		target.SNI = target.Name
	}
	value, _ := event.PortValue(authority, in.Port)
	return event.Event{SchemaVersion: event.SchemaVersion, Kind: event.KindService,
		Value: value + "/" + scheme, Target: target, Service: scheme, TLS: scheme == "https",
		Probe: "http-identification", Info: map[string]string{
			"http_probe_status": "confirmed", "status_code": strconv.Itoa(resp.StatusCode),
			"server": resp.Header.Get("Server"), "location": resp.Header.Get("Location"),
			"endpoint_evidence": "direct_ip_connection",
		}}, nil
}

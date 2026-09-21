package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"adama/event"
	"adama/internal/dnspin"
	"adama/internal/toolrun"
	"adama/sdk"
)

func scan(ctx context.Context, p profile, root string, ev event.Event) ([]event.Event, error) {
	u, err := url.Parse(ev.Value)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid screenshot URL %q", ev.Value)
	}
	args := append([]string(nil), p.HttpxArgs...)
	bound := ev.Host != "" && u.Hostname() != ev.Host
	if bound {
		ip, err := netip.ParseAddr(ev.Host)
		if err != nil {
			return nil, err
		}
		if len(p.BoundArgs) == 0 {
			return nil, sdk.ToolUnavailable(fmt.Errorf("profile %s needs bound_args for named backend screenshots", p.Name))
		}
		// Browser mapping rules are space/comma delimited. Do not let a
		// target name supply additional rules or Chromium options.
		if strings.ContainsAny(u.Hostname(), " \t\r\n,=*") {
			return nil, fmt.Errorf("invalid binding hostname %q", u.Hostname())
		}
		resolver, err := dnspin.Start(ctx, u.Hostname(), ip.String(), p.Resolvers)
		if err != nil {
			return nil, err
		}
		defer resolver.Close()
		literal := ip.String()
		if ip.Is6() {
			literal = "[" + literal + "]"
		}
		r := strings.NewReplacer("{resolver}", resolver.Address, "{name}", u.Hostname(), "{ip}", literal)
		for _, arg := range p.BoundArgs {
			args = append(args, r.Replace(arg))
		}
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, err
	}
	// HTTPX names artifacts by URL. Different IPs for the same URL must not
	// share a directory, even across replicas or repeated worker attempts.
	dir, err := os.MkdirTemp(root, "capture-*")
	if err != nil {
		return nil, err
	}
	args = append(args, "-u", ev.Value, "-srd", dir)
	out, runErr := toolrun.Run(ctx, "httpx", args, nil)
	results, parseErr := parseResults(out)
	if bound {
		for i := range results {
			// The resolver supplied routing data. Do not export it as an
			// independent observation of the hostname's real DNS records.
			results[i].A, results[i].AAAA, results[i].CNames = nil, nil, nil
		}
	}
	events, outcomeErr := screenshotEvents(ev, results)
	for i := range events {
		if bound {
			events[i].Info["endpoint_binding"] = "task_dns_and_browser_rule"
			events[i].Info["dns_evidence"] = "task_override"
		}
		events[i].Info["artifact_dir"] = dir
		// HTTPX does not expose the browser's final connected IP. A mapping
		// constrains initial navigation; it is not evidence about redirects.
		events[i].Info["browser_endpoint_evidence"] = "unreported"
	}
	return events, errors.Join(runErr, parseErr, outcomeErr)
}

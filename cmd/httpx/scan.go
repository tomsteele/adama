package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"adama/event"
	"adama/internal/browsercapture"
	"adama/internal/dnspin"
	"adama/internal/toolrun"
	"adama/sdk"
)

func scan(ctx context.Context, p profile, root string, ev event.Event) ([]event.Event, error) {
	u, err := url.Parse(ev.Value)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid screenshot URL %q", ev.Value)
	}
	depth, err := redirectDepth(ev)
	if err != nil {
		return nil, err
	}
	if depth > p.Browser.MaxRedirects {
		return nil, fmt.Errorf("redirect discovery limit exceeded")
	}
	args := append([]string(nil), p.HttpxArgs...)
	bound := ev.Host != "" && u.Hostname() != ev.Host
	if bound {
		ip, err := netip.ParseAddr(ev.Host)
		if err != nil {
			return nil, err
		}
		if len(p.BoundArgs) == 0 || len(p.Browser.BoundArgs) == 0 {
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
	// Different backends and worker replicas must not share artifact paths.
	dir, err := os.MkdirTemp(root, "capture-*")
	if err != nil {
		return nil, err
	}
	args = append(args, "-u", ev.Value)
	out, runErr := toolrun.Run(ctx, "httpx", args, nil)
	results, parseErr := parseResults(out)
	if bound {
		for i := range results {
			// The resolver supplied routing data. Do not export it as an
			// independent observation of the hostname's real DNS records.
			results[i].A, results[i].AAAA, results[i].CNames = nil, nil, nil
		}
	}
	// Capture the redirect evidence and the image in one browser session. An
	// independent follow-up request cannot establish what served the screenshot.
	browserConfig := p.Browser
	browserConfig.MaxRedirects -= depth
	capture, browserErr := browsercapture.Run(ctx, browserConfig, ev.Value, ev.Host)
	events, outcomeErr := browserEvents(ev, results, capture, p.Browser.MaxRedirects)
	if len(capture.PNG) > 0 {
		if err := os.WriteFile(filepath.Join(dir, "screenshot.png"), capture.PNG, 0o644); err != nil {
			outcomeErr = errors.Join(outcomeErr, err)
		}
	}
	for i := range events {
		if bound {
			events[i].Info["endpoint_binding"] = "task_dns_and_browser_rule"
			events[i].Info["binding_name"], events[i].Info["binding_host"] = u.Hostname(), ev.Host
			events[i].Info["dns_evidence"] = "task_override"
		}
		if browserErr != nil && events[i].Kind == event.KindScreenshot && len(events[i].Data) == 0 {
			events[i].Info["screenshot_error"] = browserErr.Error()
		}
		events[i].Info["artifact_dir"] = dir
	}
	return events, errors.Join(runErr, parseErr, browserErr, outcomeErr)
}

func redirectDepth(ev event.Event) (int, error) {
	if ev.Meta["redirect_depth"] == "" {
		return 0, nil
	}
	d, err := strconv.Atoi(ev.Meta["redirect_depth"])
	if err != nil || d < 0 {
		return 0, fmt.Errorf("invalid redirect depth %q", ev.Meta["redirect_depth"])
	}
	return d, nil
}

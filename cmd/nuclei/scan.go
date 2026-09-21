package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"adama/event"
	"adama/internal/dnspin"
	"adama/internal/toolrun"
	"adama/sdk"
)

func scan(ctx context.Context, p profile, in event.Event) ([]event.Event, error) {
	if in.Kind == event.KindService && !slices.Contains(p.ServiceTransports, in.Proto) {
		return nil, fmt.Errorf("profile %s does not support service transport %q at %s; endpoint was not scanned", p.Name, in.Proto, in.Value)
	}
	u, ok := target(in)
	if !ok {
		return nil, fmt.Errorf("invalid nuclei target %q", in.Value)
	}
	if len(p.TraceArgs) == 0 {
		return nil, sdk.ToolUnavailable(fmt.Errorf("profile %s needs trace_args to account for failed requests", p.Name))
	}
	dir, err := os.MkdirTemp("", "adama-nuclei-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	args := append([]string(nil), p.NucleiArgs...)
	name := bindingName(in, u)
	bound := name != "" && in.Host != ""
	var binding *dnspin.Resolver
	if bound {
		if len(p.BoundArgs) == 0 {
			return nil, sdk.ToolUnavailable(fmt.Errorf("profile %s needs bound_args for named backends", p.Name))
		}
		ip, err := netip.ParseAddr(in.Host)
		if err != nil {
			return nil, err
		}
		resolver, err := dnspin.Start(ctx, name, ip.String(), p.Resolvers)
		if err != nil {
			return nil, err
		}
		defer resolver.Close()
		binding = resolver
		resolverFile := filepath.Join(dir, "resolvers.txt")
		if err := os.WriteFile(resolverFile, []byte(resolver.Address+"\n"), 0o600); err != nil {
			return nil, err
		}
		for _, arg := range p.BoundArgs {
			args = append(args, strings.ReplaceAll(arg, "{resolver_file}", resolverFile))
		}
	}
	traceFile := filepath.Join(dir, "requests.jsonl")
	for _, arg := range p.TraceArgs {
		args = append(args, strings.ReplaceAll(arg, "{trace_file}", traceFile))
	}
	args = append(args, "-u", u)
	out, runErr := toolrun.Run(ctx, "nuclei", args, nil)
	events, parseErr := parseHits(out, in)
	requests, traceErr := readTrace(traceFile, in)
	if runErr == nil && errors.Is(traceErr, os.ErrNotExist) {
		// A clean CLI exit that ignored the trace-file setting is a shared
		// configuration/compatibility fault, not a reason to fail every input.
		traceErr = sdk.ToolUnavailable(traceErr)
	}
	if binding != nil && !binding.Used() {
		traceErr = errors.Join(traceErr, fmt.Errorf("nuclei did not use the requested hostname/IP binding"))
	}
	if bound && (requests.DNS || slices.ContainsFunc(events, func(ev event.Event) bool { return ev.Info["type"] == "dns" })) {
		traceErr = errors.Join(traceErr, sdk.ToolUnavailable(fmt.Errorf("profile %s ran DNS templates against a synthetic backend resolver; separate DNS checks from bound endpoint scans", p.Name)))
		// Never publish locally synthesized answers as DNS scan findings.
		events = slices.DeleteFunc(events, func(ev event.Event) bool { return ev.Info["type"] == "dns" })
	}
	for i := range events {
		ev := &events[i]
		ev.Info["scan_requests"] = strconv.Itoa(requests.Total)
		ev.Info["scan_request_errors"] = strconv.Itoa(requests.Failed)
		if in.Kind == event.KindService {
			ev.Info["scan_off_endpoint_requests"] = strconv.Itoa(requests.OffEndpoint)
		}
		if bound {
			ev.Info["endpoint_binding"] = "task_dns"
			// Keep a result for an unexpected backend, but never let it
			// establish completion of the requested hostname/IP pair.
			if strings.EqualFold(ev.Name, name) && ev.Host != in.Host {
				ev.Info["requested_endpoint_status"] = "mismatch"
				parseErr = errors.Join(parseErr, fmt.Errorf("nuclei reported IP %q for requested backend %s", ev.Host, in.Host))
			}
		}
		if in.Kind == event.KindService && (ev.Host != in.Host || ev.Port != in.Port || ev.Proto != in.Proto || !strings.EqualFold(ev.Name, name)) {
			ev.Info["requested_endpoint_status"] = "mismatch"
			parseErr = errors.Join(parseErr, fmt.Errorf("nuclei finding endpoint differs from requested %s/%s", u, in.Proto))
		}
	}
	return events, errors.Join(runErr, parseErr, traceErr)
}

func bindingName(in event.Event, target string) string {
	var host string
	if in.Kind == event.KindURL {
		u, err := url.Parse(target)
		if err == nil {
			host = u.Hostname()
		}
	} else if in.Kind == event.KindService {
		host, _, _ = event.SplitHostPort(target)
	}
	if _, err := event.CanonIP(host); err == nil {
		return ""
	}
	return host
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"adama/event"
	"adama/sdk"

	"gopkg.in/yaml.v3"
)

type runProfile struct {
	Allow []string `yaml:"allow"`
	Deny  []string `yaml:"deny"`
}

func main() {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	allow := fs.String("allow", "", "comma tool names that may run (default: all)")
	deny := fs.String("deny", "", "comma tool names that must not run")
	profile := fs.String("profile", "", "run profile name or path (profiles/runs/<name>.yaml)")
	scope := fs.String("scope", "", "dedup scope so the same value can be seeded again")
	runID := fs.String("run", "", "group seed observations into this run (default: generated)")
	proto := fs.String("proto", "", "transport for a port seed: tcp (default) or udp")
	fs.Parse(os.Args[1:])

	kind, value, err := parseArgs(fs.Args())
	if err != nil {
		slog.Error("usage: seed [-allow] [-deny] [-profile] [-scope] [-run] [-proto] <kind> <value> | seed host:port")
		os.Exit(2)
	}
	if *proto != "" && (kind != event.KindPort || (*proto != "tcp" && *proto != "udp")) {
		slog.Error("--proto requires a port seed and must be tcp or udp")
		os.Exit(2)
	}
	al, dn := *allow, *deny
	if *profile != "" {
		p, err := loadRun(*profile)
		if err != nil {
			slog.Error("profile", "err", err)
			os.Exit(2)
		}
		if al == "" {
			al = event.JoinMetaList(p.Allow)
		}
		if dn == "" {
			dn = event.JoinMetaList(p.Deny)
		}
	}
	meta := map[string]string{}
	if al != "" {
		meta["allow"] = al
	}
	if dn != "" {
		meta["deny"] = dn
	}
	if *scope != "" {
		meta["scope"] = *scope
	}
	if *profile != "" {
		meta["profile"] = *profile
	}
	ev := event.Event{Kind: kind, Value: value, Source: "seed", RunID: *runID, Meta: meta,
		Target: event.Target{Proto: event.Protocol(*proto)}}
	if err := sdk.Seed(context.Background(), sdk.NATSURL(), ev); err != nil {
		slog.Error("seed", "err", err)
		os.Exit(1)
	}
	slog.Info("seeded", "kind", ev.Kind, "value", ev.Value, "allow", al, "deny", dn, "scope", *scope)
}

func parseArgs(args []string) (event.Kind, string, error) {
	switch len(args) {
	case 1:
		if _, _, err := event.SplitHostPort(args[0]); err != nil {
			return "", "", err
		}
		return event.KindPort, args[0], nil
	case 2:
		return event.Kind(args[0]), args[1], nil
	default:
		return "", "", fmt.Errorf("need kind+value or host:port")
	}
}

func loadRun(name string) (runProfile, error) {
	path := name
	if _, err := os.Stat(path); err != nil {
		dir := os.Getenv("SEED_RUNS")
		if dir == "" {
			dir = "profiles/runs"
		}
		path = filepath.Join(dir, name+".yaml")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return runProfile{}, err
	}
	var p runProfile
	if err := yaml.Unmarshal(b, &p); err != nil {
		return runProfile{}, err
	}
	return p, nil
}

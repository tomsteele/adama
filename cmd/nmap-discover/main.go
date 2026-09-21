package main

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/nmapx"
	"adama/sdk"
)

func main() {
	path := os.Getenv("NMAP_PROFILE")
	if path == "" {
		path = "profiles/nmap-discover.yaml"
	}
	p, err := nmapx.LoadProfile(path)
	if err != nil {
		slog.Error("profile", "err", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	err = sdk.Run(ctx, sdk.Config{
		Name:    p.Name,
		Kinds:   p.EventKinds(),
		AckWait: p.Ack(),
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			if event.Live(ev) {
				return nil, nil
			}
			args := append(p.Args(ev), "-oX", "-", ev.TargetHost())
			out, err := exec.CommandContext(ctx, "nmap", args...).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("nmap-discover exit", "tool", p.Name, "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			hosts, err := nmapx.ParseDiscovery(out)
			if err != nil {
				return nil, err
			}
			slog.Info("nmap-discover", "kind", ev.Kind, "value", ev.Value, "generated_ips", len(hosts))
			return nmapx.DiscoverEvents(ev, hosts), nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

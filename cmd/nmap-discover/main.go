package main

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"adama/event"
	"adama/internal/nmapx"
	"adama/internal/reconcile"
	"adama/internal/toolrun"
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
		RequiredTools: []string{"nmap"},
		Name:          p.Name,
		Kinds:         p.EventKinds(),
		AckWait:       p.Ack(),
		Accept: func(ev event.Event) bool {
			return !event.Live(ev) && (ev.Kind != event.KindFQDN || reconcile.BoundName(ev))
		},
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			if event.Live(ev) {
				return nil, nil
			}
			if ev.Kind == event.KindFQDN && !reconcile.BoundName(ev) {
				return nil, nil
			}
			args := append(p.Args(ev), "-oX", "-", ev.TargetHost())
			out, runErr := toolrun.Run(ctx, "nmap", args, nil)
			hosts, err := nmapx.ParseDiscovery(out)
			if err != nil {
				return nil, errors.Join(runErr, err)
			}
			slog.Info("nmap-discover", "kind", ev.Kind, "value", ev.Value, "generated_ips", len(hosts))
			return nmapx.DiscoverEvents(ev, hosts), runErr
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

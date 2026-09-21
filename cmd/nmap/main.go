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
	"adama/internal/toolrun"
	"adama/sdk"
)

func main() {
	path := os.Getenv("NMAP_PROFILE")
	if path == "" {
		path = "profiles/nmap-quick.yaml"
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
		NeedLive:      true,
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			args := append(p.Args(ev), "-oX", "-", ev.TargetHost())
			out, runErr := toolrun.Run(ctx, "nmap", args, nil)
			runErr = errors.Join(runErr, nmapx.CompletionError(out))
			scans, err := nmapx.ParseXML(out)
			if err != nil {
				return nil, errors.Join(runErr, err)
			}
			slog.Info("nmap", "tool", p.Name, "host", ev.Value, "results", len(scans))
			return nmapx.Expand(ev, scans), runErr
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}

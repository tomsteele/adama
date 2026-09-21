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
		Name:     p.Name,
		Kinds:    p.EventKinds(),
		AckWait:  p.Ack(),
		NeedLive: true,
		Handle: func(ctx context.Context, ev event.Event) ([]event.Event, error) {
			args := append(p.Args(ev), "-oX", "-", ev.TargetHost())
			out, err := exec.CommandContext(ctx, "nmap", args...).Output()
			if err != nil {
				if x, ok := err.(*exec.ExitError); ok {
					slog.Warn("nmap exit", "tool", p.Name, "err", err, "stderr", string(x.Stderr))
				} else {
					return nil, err
				}
			}
			scans, err := nmapx.ParseXML(out)
			if err != nil {
				return nil, err
			}
			slog.Info("nmap", "tool", p.Name, "host", ev.Value, "results", len(scans))
			return nmapx.Expand(ev, scans), nil
		},
	})
	if err != nil && ctx.Err() == nil {
		slog.Error("run", "err", err)
		os.Exit(1)
	}
}
